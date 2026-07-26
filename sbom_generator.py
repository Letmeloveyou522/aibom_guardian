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
import subprocess
import sys


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

    vulnerabilities = []
    for item in scan_report:
        ref = name_to_ref.get(item["package"].lower())
        if not ref:
            continue
        for vuln in item["vulnerabilities"]:
            vulnerabilities.append({
                "id": vuln["id"],
                "description": vuln["summary"],
                "ratings": [
                    {
                        "source": {"name": "OSV"},
                        "score": None,
                        "severity": _map_severity(vuln["severity"]),
                        "method": "CVSSv3" if "CVSS" in str(vuln["severity"]) else "other",
                    }
                ],
                "affects": [
                    {"ref": ref}
                ],
            })

    if vulnerabilities:
        sbom["vulnerabilities"] = vulnerabilities

    return sbom


def _map_severity(raw_severity: str) -> str:
    """
    Maps whatever severity string OSV gave us into one of CycloneDX's
    allowed severity levels: none, low, medium, high, critical.
    This is intentionally rough - good enough for an MVP.
    """
    raw = str(raw_severity).upper()
    if "CRITICAL" in raw:
        return "critical"
    if "HIGH" in raw or "AC:H" in raw:
        return "high"
    if "MEDIUM" in raw:
        return "medium"
    if "LOW" in raw:
        return "low"
    return "unknown"


def build_final_sbom(requirements_path: str, scan_report: list[dict], output_path: str = "sbom.json"):
    """
    Full pipeline: generate base SBOM, enrich it, write it out.
    """
    base_sbom = generate_base_sbom(requirements_path)
    final_sbom = enrich_sbom_with_findings(base_sbom, scan_report)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(final_sbom, f, ensure_ascii=False, indent=2)

    print(f"[Saved] Enriched CycloneDX SBOM -> {output_path}")


if __name__ == "__main__":
    # Manual test: reuse the JSON report scanner.py already saved
    if len(sys.argv) != 2:
        print("Usage: python3 sbom_generator.py <requirements.txt>")
        sys.exit(1)

    with open("scan_report.json", "r", encoding="utf-8") as f:
        report = json.load(f)

    build_final_sbom(sys.argv[1], report)
