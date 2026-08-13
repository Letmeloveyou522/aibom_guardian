"""
sbom_generator.py
-----------------------------------
Builds a CycloneDX SBOM from a requirements.txt, then merges in this scan's
vulnerability and license findings, so one standard file carries both.

Shells out to the `cyclonedx-py` CLI (from cyclonedx-bom) for the base
document. With model results present, components become
``machine-learning-model`` with a CycloneDX ``modelCard`` and the metadata
profile is tagged ``ml-bom``.

Driven by scanner.py only; the MCP tools return JSON and never call this.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .osv_client import parse_cvss_v3_vector

logger = logging.getLogger(__name__)

# Goes into the SBOM's metadata.tools entry, so it must track the real version
# rather than a literal that stops matching after a release.
AIBOM_GUARD_VERSION = __version__
AIBOM_GUARD_TOOL_NAME = "AIBOM-Guard"


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
        logger.warning(
            "cyclonedx-py not found; the SBOM will have no base components. "
            "Install with: pip install cyclonedx-bom"
        )
        return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}

    if result.returncode != 0:
        logger.warning("cyclonedx-py failed to run: %s", result.stderr.strip())
        return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}

    with open(tmp_output_path, "r", encoding="utf-8") as f:
        return json.load(f)


def ensure_cyclonedx_metadata(
    sbom: dict,
    *,
    profile: str = "sbom",
    subject: str | None = None,
) -> dict:
    """
    Fill the G7 Metadata cluster: who wrote this document, with what, when,
    at which point in the lifecycle, and about what.

    The G7 "SBOM for AI - Minimum Elements" paper keeps SBOM author and
    Producer apart: the author is whoever ran the tool, the producer is
    whoever made the thing being described. `manufacturer` covers the second;
    `authors` was missing entirely, and so was any statement of *when* in the
    build the document was produced - a scan of a requirements file describes
    intent, not a built artifact, and a reader cannot tell those apart
    without being told.

    Safe to call more than once — existing values are preserved; the
    AIBOM-Guard tool entry and profile property are added only if missing.
    """
    metadata = sbom.setdefault("metadata", {})
    if not metadata.get("timestamp"):
        metadata["timestamp"] = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    if "manufacturer" not in metadata:
        metadata["manufacturer"] = {"name": AIBOM_GUARD_TOOL_NAME}

    if "authors" not in metadata:
        metadata["authors"] = [{"name": AIBOM_GUARD_TOOL_NAME}]

    # G7 "SBOM generation context". CycloneDX spells it `lifecycles`.
    # "pre-build" is the honest phase: this reads a declared dependency list,
    # not a built artifact, so it states what the project intends to install.
    if "lifecycles" not in metadata:
        metadata["lifecycles"] = [{"phase": "pre-build"}]

    # G7 System Level Properties need a subject for the document to be about.
    # Without `metadata.component` the SBOM is a bag of dependencies with no
    # statement of what they belong to.
    if subject and "component" not in metadata:
        metadata["component"] = {
            "type": "application",
            "bom-ref": f"subject:{subject}",
            "name": subject,
        }

    # CycloneDX 1.5+ tools object; fall back if a legacy list is already there.
    tools = metadata.get("tools")
    if tools is None:
        tools = {"components": []}
        metadata["tools"] = tools
    if isinstance(tools, dict):
        tool_components = tools.setdefault("components", [])
        already = any(
            isinstance(c, dict) and c.get("name") == AIBOM_GUARD_TOOL_NAME
            for c in tool_components
        )
        if not already:
            tool_components.append({
                "type": "application",
                "name": AIBOM_GUARD_TOOL_NAME,
                "version": AIBOM_GUARD_VERSION,
            })
    elif isinstance(tools, list):
        already = any(
            isinstance(t, dict)
            and (
                t.get("name") == AIBOM_GUARD_TOOL_NAME
                or (t.get("components") or [{}])[0].get("name") == AIBOM_GUARD_TOOL_NAME
            )
            for t in tools
        )
        if not already:
            tools.append({
                "vendor": AIBOM_GUARD_TOOL_NAME,
                "name": AIBOM_GUARD_TOOL_NAME,
                "version": AIBOM_GUARD_VERSION,
            })

    props = metadata.setdefault("properties", [])
    profile_prop = next(
        (p for p in props
         if isinstance(p, dict) and p.get("name") == "aibom-guard:profile"),
        None,
    )
    if profile_prop is None:
        props.append({"name": "aibom-guard:profile", "value": profile})
    elif profile == "ml-bom":
        # Upgrade sbom → ml-bom when models are attached; never downgrade.
        profile_prop["value"] = "ml-bom"
    return sbom


# A CycloneDX `licenses` entry is either a single license object or an SPDX
# expression, never both.
#
# The operators are case-sensitive in the SPDX spec, and that matters here:
# psycopg2 declares "LGPL with exceptions", which is prose, not an expression.
# Matching case-insensitively emitted it as `expression` and produced an SBOM
# no validator would accept. Lowercase "with" is a word; uppercase WITH is an
# operator.
_SPDX_OPERATORS = re.compile(r"\b(?:AND|OR|WITH)\b")


def _apply_license(component: dict, item: dict) -> None:
    """
    Put the resolved license into the component's standard `licenses` field.

    Without this the SBOM carried no license at all for anything that was not
    installed locally - `cyclonedx-py` reads installed metadata, and a
    requirements file names packages this environment does not have. Every
    component came out with `licenses: null` while the scan report held the
    SPDX identifier, so the finding never reached the document that is
    supposed to carry it.

    An identifier resolved from the pinned release is preferred over whatever
    the base generator found, because it describes the version being scanned
    rather than the version that happens to be installed. When the two
    disagree the original is kept as a property so the difference is visible
    rather than silently overwritten.
    """
    spdx_id = (item.get("license_spdx_id") or "").strip()
    raw = (item.get("license_raw") or "").strip()

    entry = None
    if spdx_id:
        entry = {"license": {"id": spdx_id}}
    elif raw and raw.upper() not in ("UNKNOWN", "NOT_INSTALLED"):
        # No SPDX id, but the string is still what the project declared.
        entry = ({"expression": raw} if _SPDX_OPERATORS.search(raw)
                 else {"license": {"name": raw[:120]}})

    if entry is None:
        return

    existing = component.get("licenses")
    if existing and existing != [entry]:
        component.setdefault("properties", []).append({
            "name": "aibom-guard:license_declared_by_generator",
            "value": json.dumps(existing, ensure_ascii=False)[:200],
        })
    component["licenses"] = [entry]

    properties = component.setdefault("properties", [])
    for name, value in (
        ("license_spdx_id", spdx_id),
        ("license_family", item.get("license_family")),
        ("license_source", item.get("license_source")),
        ("license_declared", raw[:120]),
    ):
        if value:
            properties.append({"name": f"aibom-guard:{name}", "value": str(value)})

    if item.get("license_unverified"):
        properties.append({"name": "aibom-guard:license_unverified",
                           "value": "true"})

    # The obligation is the part a reader has to act on; "REVIEW" alone is not
    # an instruction.
    for index, obligation in enumerate(item.get("license_obligations") or []):
        properties.append({
            "name": f"aibom-guard:license_obligation:{index}",
            "value": str(obligation),
        })


def _add_missing_components(sbom: dict, scan_report: list[dict]) -> None:
    """
    Add components for scanned packages the base SBOM does not list.

    ``cyclonedx-py requirements`` reads the file, so it only ever emits the
    direct requirements. Anything the scan resolved transitively would
    otherwise be findings attached to nothing - and an SBOM that omits what
    gets installed is the thing an SBOM exists to prevent.
    """
    components = sbom.setdefault("components", [])
    present = {c.get("name", "").lower() for c in components}

    for item in scan_report:
        name = item.get("package", "")
        if not name or name.lower() in present:
            continue
        present.add(name.lower())
        version = item.get("version") or ""
        components.append({
            "type": "library",
            "bom-ref": f"pkg:pypi/{name.lower()}@{version}",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name.lower()}@{version}",
        })


def enrich_sbom_with_findings(sbom: dict, scan_report: list[dict]) -> dict:
    """
    Adds our scan findings (license status + vulnerabilities) into the
    base SBOM.

    - License status gets added into each component's "licenses" field.
    - Vulnerabilities get added into a top-level "vulnerabilities" array,
      which is a field CycloneDX supports natively for exactly this
      purpose (see the CycloneDX spec: bom.vulnerabilities).

    When ``item["vulnerabilities"]`` is ``None`` (OSV unverified), no CVE
    entries are emitted for that package — an empty list means verified
    clean; ``None`` must not be iterated as if it were clean.
    """
    # Build a lookup: package name (lowercase) -> bom-ref, so we can
    # link vulnerabilities back to the right component.
    by_name = {item["package"].lower(): item for item in scan_report}
    _add_missing_components(sbom, scan_report)
    name_to_ref = {}
    for component in sbom.get("components", []):
        name_to_ref[component["name"].lower()] = component["bom-ref"]
        item = by_name.get(component["name"].lower())
        if not item:
            continue
        _apply_license(component, item)

        component["properties"] = component.get("properties", [])
        if "direct" in item:
            component["properties"].append({
                "name": "aibom-guard:dependency",
                "value": "direct" if item["direct"] else "transitive",
            })
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
        if item.get("osv_unverified") or (
            "vulnerabilities" in item and item["vulnerabilities"] is None
        ):
            component["properties"].append({
                "name": "aibom-guard:osv_unverified",
                "value": "true",
            })
        component["properties"].extend(_supply_chain_properties(item))

    vulnerabilities = []
    for item in scan_report:
        ref = name_to_ref.get(item["package"].lower())
        if not ref:
            continue
        vulns = item.get("vulnerabilities")
        if vulns is None:
            # OSV failed — do not treat as zero CVEs.
            continue
        for vuln in vulns:
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

    ensure_cyclonedx_metadata(sbom, profile="sbom")
    return sbom


def _supply_chain_properties(item: dict) -> list:
    """
    Expose repository_checker's findings as CycloneDX component properties.

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


def _primary_weight_file(model: dict) -> str | None:
    """
    The file that best stands for the model: the largest safetensors shard,
    or the largest pickle when there is no safetensors at all.
    """
    formats = model.get("file_formats") or {}
    for key in ("safetensors", "pickle"):
        entries = [f for f in (formats.get(key) or []) if f.get("path")]
        if entries:
            return max(entries, key=lambda f: f.get("size_bytes") or 0)["path"]
    return None


def _weight_hashes(model: dict) -> list:
    """
    CycloneDX `hashes` for the model component.

    The Hub publishes a SHA-256 for every LFS-tracked file, which is every
    weight file. Only the primary weight file goes in `hashes` - that array
    describes one artifact under different algorithms, so listing nine
    same-algorithm digests there would misuse it. The rest are recorded as
    properties, where a per-file map belongs.
    """
    digests = model.get("file_hashes") or {}
    primary = _primary_weight_file(model)
    if not primary or primary not in digests:
        return []
    return [{"alg": "SHA-256", "content": digests[primary]}]


def _base_model_ancestors(model: dict) -> list:
    """
    The models this one was derived from, as CycloneDX pedigree ancestors.

    model_checker already parses the Hub's `base_model` metadata, including
    the relation (finetune, quantized, merge, adapter), but it never reached
    the document - so an ML-BOM described a fine-tune as if it had been
    trained from nothing.
    """
    ancestors = []
    for entry in model.get("base_model") or []:
        if isinstance(entry, dict):
            # model_checker emits `repo_id`; accept `repo` too so a caller
            # passing the shorter spelling is not silently dropped.
            repo = entry.get("repo_id") or entry.get("repo")
        else:
            repo = str(entry)
        if not repo:
            continue
        ancestor = {
            "type": "machine-learning-model",
            "bom-ref": f"model:{repo}",
            "name": repo,
            "purl": f"pkg:huggingface/{repo}",
            "externalReferences": [
                {"type": "distribution", "url": f"https://huggingface.co/{repo}"},
            ],
        }
        relation = entry.get("relation") if isinstance(entry, dict) else None
        if relation:
            ancestor["properties"] = [
                {"name": "aibom-guard:base_model_relation", "value": str(relation)},
            ]
        ancestors.append(ancestor)
    return ancestors


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

    hashes = _weight_hashes(model)
    if hashes:
        component["hashes"] = hashes

    ancestors = _base_model_ancestors(model)
    if ancestors:
        # G7 calls this the model's lineage - "how its weights were produced".
        # A fine-tune inherits both the capabilities and the licence terms of
        # what it was trained from, so the parent belongs in the document.
        component["pedigree"] = {"ancestors": ancestors}

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

    # G7 "Model timestamp": when the weights last changed. The commit SHA
    # pins *which* revision; this says how old it is.
    if model.get("last_modified"):
        properties.append(("aibom-guard:last_modified", str(model["last_modified"])))

    # Every weight file's digest, so a consumer can verify more than the one
    # artifact named in `hashes`.
    for path, digest in sorted((model.get("file_hashes") or {}).items()):
        if path in {f.get("path") for f in
                    ((model.get("file_formats") or {}).get("safetensors") or [])
                    + ((model.get("file_formats") or {}).get("pickle") or [])}:
            properties.append((f"aibom-guard:sha256:{path}", digest))

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

    Each model becomes ``type: "machine-learning-model"`` with a
    ``modelCard`` (CycloneDX 1.6 / G7 ML-BOM). Metadata profile is set to
    ``ml-bom``.
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

    # G7 / ML-BOM: stamp metadata and upgrade profile to ml-bom.
    ensure_cyclonedx_metadata(sbom, profile="ml-bom")
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


def _packages_and_models(
    scan_report: list[dict] | dict,
    model_reports: list[dict] | None,
) -> tuple[list[dict], list[dict]]:
    """
    Accept either a package list (legacy) or the scan_report.json document
    ``{"packages", "models", "unscanned"}``.
    """
    if isinstance(scan_report, dict) and (
        "packages" in scan_report or "models" in scan_report
    ):
        packages = list(scan_report.get("packages") or [])
        models = list(scan_report.get("models") or [])
        if model_reports:
            models = list(model_reports)
        return packages, models
    return list(scan_report or []), list(model_reports or [])


def build_final_sbom(
    requirements_path: str,
    scan_report: list[dict] | dict,
    output_path: str = "sbom.json",
    model_reports: list[dict] | None = None,
):
    """
    Full pipeline: generate base SBOM, enrich it, add models, write it out.

    ``scan_report`` may be the package list or the full scan_report.json
    document. ``model_reports`` are model_checker / scan_model results.
    When models are present the output is an ML-BOM: packages and AI
    models side by side in one CycloneDX 1.6 document with modelCard
    metadata (G7).
    """
    packages, models = _packages_and_models(scan_report, model_reports)

    base_sbom = generate_base_sbom(requirements_path)
    final_sbom = enrich_sbom_with_findings(base_sbom, packages)
    final_sbom = add_models_to_sbom(final_sbom, models)
    ensure_cyclonedx_metadata(
        final_sbom,
        profile="ml-bom" if models else "sbom",
        # The requirements file names the thing this document is about. It is
        # a weak subject, but it beats a document that describes nothing.
        subject=Path(requirements_path).stem or None,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(final_sbom, f, ensure_ascii=False, indent=2)

    model_count = len(models)
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
