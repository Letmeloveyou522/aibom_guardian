"""
scanner.py
-----------------------------------
AIBOM-Guard personal MVP - main CLI.

Takes a requirements.txt file and:
1) Checks the license of each package (license_checker.py)
2) Queries the OSV API for known vulnerabilities (osv_client.py)
3) Prints a summary table
4) Saves a JSON report file

Usage:
    python3 scanner.py requirements.txt
"""

import sys
import json
import re
from importlib.metadata import version as installed_version, PackageNotFoundError, metadata

from osv_client import query_vulnerabilities
from license_checker import classify_license
from sbom_generator import build_final_sbom
from ai_explainer import explain_results

try:
    from prettytable import PrettyTable
    HAS_PRETTYTABLE = True
except ImportError:
    HAS_PRETTYTABLE = False


def parse_requirements(path: str) -> list[tuple[str, str]]:
    """
    Very simple requirements.txt parser.
    Only supports the 'package==version' format (good enough for this MVP).
    """
    packages = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([A-Za-z0-9_\-.]+)\s*==\s*([A-Za-z0-9_.\-]+)", line)
            if match:
                packages.append((match.group(1), match.group(2)))
            else:
                print(f"[INFO] Skipping line (not in 'name==version' format): {line}")
    return packages


def get_license_for_package(package_name: str) -> str:
    """
    Reads license metadata for the package as currently installed in this
    Python environment.

    NOTE: this is the license of the *installed* version, which might not
    match the version pinned in requirements.txt. For an exact check you'd
    want to install that exact version in a clean venv first. Keeping it
    simple for the MVP.
    """
    try:
        meta = metadata(package_name)
        lic = meta.get("License", "")
        if not lic or lic.upper() == "UNKNOWN":
            # Many newer packages put the license in a Classifier instead
            classifiers = meta.get_all("Classifier") or []
            for c in classifiers:
                if c.startswith("License ::"):
                    lic = c.split("::")[-1].strip()
                    break
        return lic or "UNKNOWN"
    except PackageNotFoundError:
        return "NOT_INSTALLED"


def score_package(license_status: str, vulns: list) -> tuple[int, str]:
    """
    Very simple risk score (0-100).
    For the real competition submission, refine this using the 7-category
    weighted scoring described in the design doc. For now this is just a
    rough signal based on license + vulnerability count.
    """
    score = 100

    if license_status == "BLOCKED":
        score -= 60
    elif license_status == "REVIEW":
        score -= 20
    elif license_status == "UNKNOWN":
        score -= 15

    critical_count = sum(1 for v in vulns if str(v.get("severity", "")).upper() in ("CRITICAL", "HIGH"))
    other_count = len(vulns) - critical_count

    score -= critical_count * 30
    score -= other_count * 10

    score = max(score, 0)

    if score >= 80:
        verdict = "ALLOW"
    elif score >= 50:
        verdict = "CONDITIONAL"
    else:
        verdict = "BLOCK"

    return score, verdict


def run_scan(requirements_path: str):
    packages = parse_requirements(requirements_path)
    if not packages:
        print("No packages found to scan. Check your requirements.txt format.")
        return

    report = []

    for name, version in packages:
        print(f"[Scanning] {name}=={version} ...")
        lic_raw = get_license_for_package(name)
        lic_status = classify_license(lic_raw)
        vulns = query_vulnerabilities(name, version)
        score, verdict = score_package(lic_status, vulns)

        report.append({
            "package": name,
            "version": version,
            "license_raw": lic_raw,
            "license_status": lic_status,
            "vulnerabilities": vulns,
            "trust_score": score,
            "verdict": verdict,
        })

    print_report(report)
    save_report(report, "scan_report.json")
    build_final_sbom(requirements_path, report, "sbom.json")

    print("\n===== AI Explanation (local model via Ollama) =====\n")
    print(explain_results(report))


def print_report(report: list[dict]):
    print("\n===== AIBOM-Guard Scan Results =====\n")

    if HAS_PRETTYTABLE:
        table = PrettyTable()
        table.field_names = ["Package", "Version", "License Status", "Vulns", "Trust Score", "Verdict"]
        for item in report:
            table.add_row([
                item["package"],
                item["version"],
                item["license_status"],
                len(item["vulnerabilities"]),
                item["trust_score"],
                item["verdict"],
            ])
        print(table)
    else:
        for item in report:
            print(f"{item['package']}=={item['version']} | license:{item['license_status']} | "
                  f"vulns:{len(item['vulnerabilities'])} | score:{item['trust_score']} | {item['verdict']}")

    # Show details for anything that isn't a clean ALLOW
    risky = [i for i in report if i["verdict"] != "ALLOW"]
    if risky:
        print("\n[Packages needing attention]")
        for item in risky:
            print(f"- {item['package']}=={item['version']} ({item['verdict']})")
            if item["license_status"] in ("REVIEW", "BLOCKED", "UNKNOWN"):
                print(f"    License: {item['license_raw']} -> {item['license_status']}")
            for v in item["vulnerabilities"]:
                print(f"    Vuln {v['id']} (severity {v['severity']}): {v['summary']}")


def save_report(report: list[dict], out_path: str):
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n[Saved] {out_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 scanner.py <path to requirements.txt>")
        sys.exit(1)

    run_scan(sys.argv[1])
