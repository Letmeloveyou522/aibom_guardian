"""
sbom_generator.py
-----------------------------------
Generates a CycloneDX-format SBOM from a requirements.txt file, then
enriches it with the vulnerability and license findings from our own
scan (see scanner.py). The result is a single standard-compliant JSON
file that also carries AIBOM-Guard's own risk analysis.

Under the hood this just shells out to the `cyclonedx-py` CLI tool
(from the cyclonedx-bom package) to build the base SBOM, then merges
our extra data into it.
"""

import json
import re
import subprocess
import sys

from osv_client import parse_cvss_v3_vector


def generate_base_sbom(requirements_path: str, tmp_output_path: str = "_base_sbom.json") -> dict:
    """
    Calls the cyclonedx-py CLI to generate a standard CycloneDX SBOM
    from requirements.txt, then loads and returns it as a dict.
    """
    cmd = [
        "cyclonedx-py", "requirements", requirements_path,
        "-o", tmp_output_path,
        "--sv", "1.6",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("[WARNING] cyclonedx-py not found. Install with: pip install cyclonedx-bom")
        return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}

    if result.returncode != 0:
        print("[WARNING] cyclonedx-py failed to run:")
        print(result.stderr)
        return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}

    with open(tmp_output_path, "r", encoding="utf-8") as f:
        return json.load(f)


def enrich_sbom_with_findings(sbom: dict, scan_report: list[dict]) -> dict:
    """
    Adds our scan findings (license status + vulnerabilities) into the
    base SBOM.

    - License status gets added into each component's "licenses" field.
    - Vulnerabilities get added into a top-level "vulnerabilities" array,
      which is a field CycloneDX supports natively for exactly this
      purpose (see the CycloneDX spec: bom.vulnerabilities).
    """
    # Build a lookup: package name (lowercase) -> bom-ref, so we can
    # link vulnerabilities back to the right component.
    name_to_ref = {}
    for component in sbom.get("components", []):
        name_to_ref[component["name"].lower()] = component["bom-ref"]

        # attach license info onto the component itself, in addition to
        # whatever cyclonedx-py already put there
        for item in scan_report:
            if item["package"].lower() == component["name"].lower():
                component["properties"] = component.get("properties", [])
                component["properties"].append({
                    "name": "aibom-guard:license_status",
                    "value": item["license_status"],
                })
                component["properties"].append({
                    "name": "aibom-guard:trust_score",
                    "value": str(item["trust_score"]),
                })
                component["properties"].append({
                    "name": "aibom-guard:verdict",
                    "value": item["verdict"],
                })
                component["properties"].extend(_supply_chain_properties(item))

    vulnerabilities = []
    for item in scan_report:
        ref = name_to_ref.get(item["package"].lower())
        if not ref:
            continue
        for vuln in item["vulnerabilities"]:
            rating = {
                "source": {"name": "OSV"},
                "severity": _map_severity(vuln.get("severity")),
            }
            # osv_client parses the CVSS vector into a numeric base score, so
            # the rating can carry the real number instead of a null.
            if vuln.get("cvss_score") is not None:
                rating["score"] = float(vuln["cvss_score"])
                rating["method"] = "CVSSv31"
            else:
                rating["method"] = "other"

            entry = {
                "id": vuln["id"],
                "description": vuln.get("summary") or vuln.get("detail") or "",
                "ratings": [rating],
                "affects": [{"ref": ref}],
            }
            # Alias identifiers are how a reader finds the same flaw in
            # another database; CycloneDX has a field for exactly this.
            if vuln.get("aliases"):
                entry["references"] = [
                    {"id": alias, "source": {"name": _source_of(alias)}}
                    for alias in vuln["aliases"]
                ]
            vulnerabilities.append(entry)

    if vulnerabilities:
        sbom["vulnerabilities"] = vulnerabilities

    return sbom


def _supply_chain_properties(item: dict) -> list:
    """
    Expose module 2's findings as CycloneDX component properties.

    scanner.py collects supply-chain trust under --supply-chain, but without
    this the data never reached the SBOM - the document recorded the verdict
    while dropping the evidence behind it. OpenSSF score, repository
    activity and signature status are exactly what a downstream consumer
    wants to see next to a component.
    """
    supply = item.get("supply_chain")
    if not isinstance(supply, dict):
        return []

    fields = (
        ("repository", supply.get("repository")),
        ("openssf_score", supply.get("openssf_score")),
        ("supply_chain_trust", supply.get("trust_score")),
        ("supply_chain_verdict", supply.get("verdict")),
        ("github_star", supply.get("github_star")),
        ("last_commit", supply.get("last_commit")),
        ("signature", supply.get("signature")),
        ("provenance", supply.get("provenance")),
    )

    properties = []
    for name, value in fields:
        if value is None or value == "":
            continue
        if isinstance(value, bool):
            value = str(value).lower()
        properties.append({"name": f"aibom-guard:{name}", "value": str(value)})
    return properties


def _source_of(vuln_id: str) -> str:
    """Which database an identifier belongs to."""
    prefix = str(vuln_id).upper()
    if prefix.startswith("GHSA-"):
        return "GitHub Advisory Database"
    if prefix.startswith("PYSEC-"):
        return "PyPI Advisory Database"
    if prefix.startswith("CVE-"):
        return "NVD"
    return "OSV"


# ---------------------------------------------------------------------------
# ML-BOM: AI models as first-class SBOM components
# ---------------------------------------------------------------------------

def _license_entry(model: dict) -> list:
    """
    CycloneDX licenses array for a model.

    Open-weight model licenses are almost never SPDX identifiers - Llama,
    Gemma and the RAIL family have no SPDX id at all - so they go in as
    `license.name` rather than `license.id`, which is what the spec says to
    do for a named-but-not-SPDX license.
    """
    license_id = model.get("license")
    if not license_id:
        return []

    entry = {"name": model.get("license_name") or license_id}
    if model.get("license_link"):
        entry["url"] = model["license_link"]
    return [{"license": entry}]


def _model_purl(model: dict) -> str:
    """
    Package URL for a Hugging Face model.

    Format per the purl spec: pkg:huggingface/<namespace>/<name>@<revision>,
    with the commit SHA as the version so the reference is immutable.
    """
    model_id = model.get("model_id") or model.get("model_name") or "unknown"
    revision = model.get("commit_sha") or "main"
    return f"pkg:huggingface/{model_id}@{revision}"


def build_model_component(model: dict) -> dict:
    """
    Turn one model_checker report into a CycloneDX machine-learning-model
    component with a modelCard.

    This is what makes the output an *AI* BOM rather than a plain SBOM:
    CycloneDX 1.6 defines `type: "machine-learning-model"` and the
    `modelCard` object for exactly this, and a consumer that already reads
    CycloneDX gets the model inventory for free.
    """
    model_id = model.get("model_id") or "unknown"
    bom_ref = f"model:{model_id}@{model.get('commit_sha') or 'main'}"

    formats = model.get("file_formats") or {}
    card = model.get("model_card") or {}

    component = {
        "type": "machine-learning-model",
        "bom-ref": bom_ref,
        "name": model_id,
        "version": model.get("commit_sha") or "main",
        "purl": _model_purl(model),
        "description": f"Hugging Face model {model_id}"
                       + (f" ({model['pipeline']})" if model.get("pipeline") else ""),
        "externalReferences": [
            {"type": "distribution", "url": model.get("url")
             or f"https://huggingface.co/{model_id}"},
        ],
    }

    licenses = _license_entry(model)
    if licenses:
        component["licenses"] = licenses

    if model.get("author"):
        component["publisher"] = model["author"]

    # -- modelCard -----------------------------------------------------------
    model_parameters = {}
    if model.get("pipeline"):
        model_parameters["task"] = model["pipeline"]
    if model.get("architectures"):
        model_parameters["modelArchitecture"] = ", ".join(model["architectures"])
    if model.get("library"):
        model_parameters["architectureFamily"] = model["library"]

    datasets = [
        {"type": "dataset", "name": name}
        for name in (model.get("datasets") or [])
    ]
    if datasets:
        model_parameters["datasets"] = datasets

    model_card = {"bom-ref": f"{bom_ref}#modelcard"}
    if model_parameters:
        model_card["modelParameters"] = model_parameters

    # `considerations` is where CycloneDX expects the governance narrative.
    # Recording that a card is missing or unfilled is itself the finding.
    considerations = {}
    if not card.get("present"):
        considerations["ethicalConsiderations"] = [{
            "name": "No model card",
            "mitigationStrategy": "The repository ships no README.md, so "
                                  "intended use, limitations and training "
                                  "data are undocumented.",
        }]
    elif card.get("is_unedited_template"):
        considerations["ethicalConsiderations"] = [{
            "name": "Unedited model card template",
            "mitigationStrategy": (
                f"{card.get('placeholder_count', 0)} '[More Information "
                f"Needed]' placeholders remain; the card documents nothing."),
        }]
    if considerations:
        model_card["considerations"] = considerations

    component["modelCard"] = model_card

    # -- AIBOM-Guard findings as properties ---------------------------------
    properties = [
        ("aibom-guard:trust_score", str(model.get("risk_score", ""))),
        ("aibom-guard:verdict", str(model.get("verdict", ""))),
        ("aibom-guard:license_status", str(model.get("license_status", ""))),
        ("aibom-guard:license_family", str(model.get("license_family", ""))),
        ("aibom-guard:weight_formats:safetensors", str(len(formats.get("safetensors") or []))),
        ("aibom-guard:weight_formats:pickle", str(len(formats.get("pickle") or []))),
        ("aibom-guard:pickle_only", str(bool(formats.get("pickle_only"))).lower()),
        ("aibom-guard:trust_remote_code", str(bool(model.get("trust_remote_code"))).lower()),
        ("aibom-guard:model_card_completeness", str(card.get("completeness", ""))),
        ("aibom-guard:pickle_scan_status",
         str((model.get("pickle_scan") or {}).get("status", ""))),
    ]
    for repo in model.get("external_code_repos") or []:
        properties.append(("aibom-guard:external_code_repo", repo))

    component["properties"] = [
        {"name": name, "value": value} for name, value in properties if value
    ]

    return component


def add_models_to_sbom(sbom: dict, model_reports: list) -> dict:
    """
    Append machine-learning-model components and their findings.

    Model issues become CycloneDX `vulnerabilities` entries the same way
    package CVEs do, so one consumer reads both. A dangerous pickle global
    is a vulnerability in every sense that matters here.
    """
    if not model_reports:
        return sbom

    components = sbom.setdefault("components", [])
    vulnerabilities = sbom.setdefault("vulnerabilities", [])

    for model in model_reports:
        component = build_model_component(model)
        components.append(component)

        for index, issue in enumerate(model.get("issues") or []):
            vulnerabilities.append({
                "id": issue.get("id")
                      or f"AIBOM-{component['name']}-{issue.get('type')}-{index}",
                "description": issue.get("message") or issue.get("detail") or "",
                "ratings": [{
                    "source": {"name": "AIBOM-Guard"},
                    "severity": _map_severity(issue.get("severity")),
                    "method": "other",
                }],
                "affects": [{"ref": component["bom-ref"]}],
            })

    if not vulnerabilities:
        sbom.pop("vulnerabilities", None)

    # Declare the ML-BOM profile so a consumer knows models are in here.
    sbom.setdefault("metadata", {}).setdefault("properties", []).append(
        {"name": "aibom-guard:profile", "value": "ml-bom"}
    )
    return sbom


# CycloneDX only accepts these; anything else is a schema violation.
_CYCLONEDX_SEVERITIES = {"critical", "high", "medium", "low", "none", "info",
                         "unknown"}


def _map_severity(raw_severity) -> str:
    """
    Map a severity onto CycloneDX's allowed set.

    osv_client normally normalises severities to critical/high/medium/low/
    unknown before they reach here. When a raw CVSS v3 vector still arrives,
    it is parsed and scored: AC:H means Attack Complexity High (harder to
    exploit), which *lowers* the base score - it is not severity "high".
    The previous substring map graded CVSS:3.1/AV:N/AC:H/... (base 5.3,
    medium) as high; that path is gone.
    """
    if raw_severity is None:
        return "unknown"

    original = str(raw_severity).strip()
    raw = original.lower()
    if not raw:
        return "unknown"
    if raw in _CYCLONEDX_SEVERITIES:
        return raw

    # CVSS vector → Base Score → qualitative severity (AC:H reduces score).
    if original.upper().startswith("CVSS:3"):
        parsed = parse_cvss_v3_vector(original)
        if parsed and parsed.get("severity") in _CYCLONEDX_SEVERITIES:
            return parsed["severity"]

    # Tolerate a label that arrived with extra wording, e.g. "High severity".
    # Word boundaries keep "AC:H" / "highest" from matching "high".
    for level in ("critical", "high", "medium", "low"):
        if re.search(rf"\b{level}\b", raw):
            return level
    return "unknown"


def build_final_sbom(
    requirements_path: str,
    scan_report: list[dict],
    output_path: str = "sbom.json",
    model_reports: list[dict] | None = None,
):
    """
    Full pipeline: generate base SBOM, enrich it, add models, write it out.

    `model_reports` are model_checker.check_model() results. When present the
    output is an ML-BOM: packages and AI models side by side in one
    CycloneDX document.
    """
    base_sbom = generate_base_sbom(requirements_path)
    final_sbom = enrich_sbom_with_findings(base_sbom, scan_report)
    final_sbom = add_models_to_sbom(final_sbom, model_reports or [])

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(final_sbom, f, ensure_ascii=False, indent=2)

    model_count = len(model_reports or [])
    suffix = f" ({model_count} AI model component(s))" if model_count else ""
    print(f"[Saved] Enriched CycloneDX SBOM -> {output_path}{suffix}")


if __name__ == "__main__":
    # Manual test: reuse the JSON report scanner.py already saved
    if len(sys.argv) != 2:
        print("Usage: python3 sbom_generator.py <requirements.txt>")
        sys.exit(1)

    with open("scan_report.json", "r", encoding="utf-8") as f:
        report = json.load(f)

    build_final_sbom(sys.argv[1], report)
