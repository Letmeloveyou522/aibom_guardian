"""
scanner.py
-----------------------------------
AIBOM-Guard - main CLI.

Takes a requirements.txt file and, for each pinned package:

  1) classifies the license                  license_checker.py
  2) queries OSV for known vulnerabilities   osv_client.py        (3)
  3) detects typosquatting / hallucinated /
     deprecated packages and suggests fixes  recommendation.py    (3)
  4) optionally checks supply-chain trust    repository_checker.py (2)
  5) scores everything into one verdict      score_engine.py      (4)
  6) writes scan_report.json + CycloneDX sbom.json                (5)
  7) optionally explains the result locally  ai_explainer.py

Usage:
    python3 scanner.py examples/sample-requirements.txt
    python3 scanner.py reqs.txt --supply-chain      # add module 2 checks
    python3 scanner.py reqs.txt --offline           # no PyPI/OSV lookups
    python3 scanner.py reqs.txt --no-explain --json out.json

Exit codes (so this can gate CI):
    0  every package is ALLOW
    1  bad input / nothing to scan
    2  at least one package is BLOCK
"""

import argparse
import json
import re
import sys
from importlib.metadata import version as installed_version, PackageNotFoundError, metadata

from osv_client import query_vulnerabilities
from license_checker import classify_license, classify_license_detailed
from sbom_generator import build_final_sbom
from ai_explainer import explain_results
from score_engine import calculate_trust_score

try:
    from prettytable import PrettyTable
    HAS_PRETTYTABLE = True
except ImportError:
    HAS_PRETTYTABLE = False

# Modules 2 and 3 are optional at import time so a partial checkout, or a
# missing transitive dependency, degrades to the core scan instead of
# preventing the CLI from starting at all.
try:
    from recommendation import RecommendationEngine
    HAS_RECOMMENDATION = True
except ImportError:
    HAS_RECOMMENDATION = False

try:
    from repository_checker import check_repository
    HAS_REPOSITORY_CHECKER = True
except ImportError:
    HAS_REPOSITORY_CHECKER = False

try:
    from model_checker import check_model
    HAS_MODEL_CHECKER = True
except ImportError:
    HAS_MODEL_CHECKER = False


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


def _vulns_to_issues(vulns: list) -> list:
    """
    OSV 취약점 목록을 score_engine이 기대하는 issues 형식으로 변환.

    cvss_score is carried through deliberately: score_engine falls back to
    the CVSS base score when a severity label is missing, and dropping the
    field here would disable that path.
    """
    issues = []
    for v in vulns:
        sev = str(v.get("severity", "unknown")).lower()
        if sev not in ("critical", "high", "medium", "low"):
            sev = "unknown"
        issue = {
            "type": "cve",
            "id": v.get("id"),
            "severity": sev,
            "summary": v.get("summary") or v.get("detail"),
            "detail": v.get("detail") or v.get("summary"),
        }
        if v.get("cvss_score") is not None:
            issue["cvss_score"] = v["cvss_score"]
        if v.get("aliases"):
            issue["aliases"] = v["aliases"]
        issues.append(issue)
    return issues


def _build_check_result(
    license_status: str,
    issues: list,
    repository_info: dict | None = None,
    model_info: dict | None = None,
) -> dict:
    """
    score_engine.calculate_trust_score() 입력 스키마에 맞게 조립.

    `issues` is the merged list from every producer - OSV plus whatever
    module 3 found - already in the team Data Protocol shape. Module 2's
    full result goes into `repository_info`; score_engine reads its
    trust_score and folds in its issues.
    """
    return {
        "type": "library",
        "license_status": license_status,
        "issues": issues,
        "model_info": model_info,
        "repository_info": repository_info,
    }


def analyze_package_risks(engine, name: str, version: str, vulns: list) -> tuple[list, list]:
    """
    Run module 3 over one package and return (issues, alternatives).

    RecommendationEngine.analyze_package() merges the OSV findings we hand
    it into its own issue list, so its return value is the complete set -
    adding `vulns` again here would double-count every CVE.

    A failure downgrades to the OSV issues alone rather than aborting the
    scan; the caller records the reason.
    """
    if engine is None:
        return _vulns_to_issues(vulns), []
    try:
        result = engine.analyze_package(name, version, cve_issues=_vulns_to_issues(vulns))
    except Exception as exc:  # noqa: BLE001 - network/parse errors must not stop a scan
        print(f"  [WARNING] recommendation engine failed for {name}: {exc}")
        return _vulns_to_issues(vulns), []
    return result.get("issues") or [], result.get("alternatives") or []


def scan_model(model_ref: str, max_pickle_size_mb: int = 0) -> dict | None:
    """
    Run module 1 over one Hugging Face model and score it.

    Returns the model_checker report with the AIBOM-Guard verdict folded in,
    or None when the model could not be read at all.

    `max_pickle_size_mb` defaults to 0 (metadata only). Downloading weights
    to scan pickle contents is opt-in because a single model can be tens of
    gigabytes; --model-pickle-scan raises it.
    """
    if not HAS_MODEL_CHECKER:
        print("  [WARNING] model_checker.py unavailable - model scan skipped.")
        return None

    try:
        report = check_model(model_ref, max_pickle_size_mb=max_pickle_size_mb)
    except Exception as exc:  # noqa: BLE001 - a bad model must not end the run
        print(f"  [ERROR] could not read model '{model_ref}': {exc}")
        return None

    # Grade the declared license. This is the whole point of an AIBOM:
    # llama3.1, gemma and the RAIL family are not OSI-approved, and the
    # generic package path would never see them.
    license_text = report.get("license_name") or report.get("license")
    detail = classify_license_detailed(license_text)
    report["license_status"] = detail["status"]
    report["license_family"] = detail["family"]
    report["license_reason"] = detail["reason"]

    # score_engine also harvests issues out of `model_info`, so the raw
    # model_checker findings are removed from the copy handed to it - they
    # are already present, translated, in the top-level `issues` list.
    # Leaving both in counted every model finding twice.
    model_context = {k: v for k, v in report.items() if k != "issues"}

    score_result = calculate_trust_score({
        "type": "model",
        "license_status": detail["status"],
        "issues": _model_issues(report),
        "model_info": model_context,
        "repository_info": None,
    })
    report["risk_score"] = score_result["trust_score"]
    report["verdict"] = score_result["verdict"]
    report["hard_block"] = score_result["hard_block"]
    report["hard_block_reasons"] = score_result["hard_block_reasons"]
    report["score_breakdown"] = score_result["breakdown"]
    report["confidence"] = score_result["confidence"]
    return report


def _model_issues(report: dict) -> list:
    """
    Translate model_checker's findings into team Data Protocol issues.

    model_checker grades its own findings as HIGH/MEDIUM/LOW with its own
    issue types; score_engine works in the seven protocol categories. The
    mapping is explicit rather than implicit so an unmapped finding type
    shows up as `unrecognised` instead of vanishing.
    """
    type_map = {
        "malicious": "malicious",          # dangerous pickle global
        "suspicious": "malicious",
        "pickle_only": "provenance",
        "pickle_file": "provenance",
        "remote_code": "malicious",        # arbitrary code on from_pretrained
        "external_code": "provenance",
        "python_files": "provenance",
        "no_model_card": "provenance",
        "template_model_card": "provenance",
        "incomplete_model_card": "provenance",
        "no_license": "license",
        "gated": "license",
        "unverified": "provenance",
    }
    severity_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

    issues = []
    for issue in report.get("issues") or []:
        issues.append({
            "type": type_map.get(issue.get("type"), issue.get("type")),
            "id": issue.get("type"),
            "severity": severity_map.get(issue.get("severity"), "unknown"),
            "detail": issue.get("message"),
            "summary": issue.get("message"),
        })
    return issues


def check_supply_chain(name: str, version: str) -> dict | None:
    """
    Run module 2 over one package. Returns None when it could not run.

    Kept behind --supply-chain because it costs several network round trips
    per package (PyPI, GitHub, OpenSSF) and needs GITHUB_TOKEN to avoid
    rate limits.
    """
    if not HAS_REPOSITORY_CHECKER:
        return None
    try:
        return check_repository(f"{name}=={version}", target_type="pypi")
    except Exception as exc:  # noqa: BLE001
        print(f"  [WARNING] supply-chain check failed for {name}: {exc}")
        return None


def run_scan(
    requirements_path: str,
    supply_chain: bool = False,
    offline: bool = False,
    explain: bool = True,
    report_path: str = "scan_report.json",
    sbom_path: str = "sbom.json",
    models: list | None = None,
    model_pickle_size_mb: int = 0,
) -> list[dict]:
    """
    Scan every pinned package in `requirements_path`.

    Args:
        supply_chain: also run module 2 per package (slow; needs network
            and ideally GITHUB_TOKEN).
        offline: skip every network lookup - OSV, PyPI and supply chain.
            The license check still runs against installed metadata.
        explain: run the local Ollama explanation at the end.

    Returns the report list, so tests and other callers can assert on it
    without parsing stdout.
    """
    packages = parse_requirements(requirements_path)
    if not packages:
        print("No packages found to scan. Check your requirements.txt format.")
        return []

    engine = None
    if offline:
        print("[INFO] Offline mode: OSV, PyPI and supply-chain lookups are skipped.")
    elif not HAS_RECOMMENDATION:
        print("[WARNING] recommendation.py unavailable - typosquatting, "
              "hallucination and deprecation checks will NOT run.")
    else:
        engine = RecommendationEngine()

    if supply_chain and not HAS_REPOSITORY_CHECKER:
        print("[WARNING] repository_checker.py unavailable - supply-chain "
              "checks will NOT run.")

    report = []

    for name, version in packages:
        print(f"[Scanning] {name}=={version} ...")

        lic_raw = get_license_for_package(name)
        lic_status = classify_license(lic_raw)

        if offline:
            # None, not [] - the distinction matters. An empty list means
            # "we looked and found nothing"; None means "we never looked",
            # which score_engine turns into low confidence and a
            # CONDITIONAL verdict instead of a clean ALLOW.
            vulns, issues, alternatives = [], None, []
        else:
            vulns = query_vulnerabilities(name, version)
            issues, alternatives = analyze_package_risks(engine, name, version, vulns)

        repository_info = None
        if supply_chain and not offline:
            repository_info = check_supply_chain(name, version)

        score_result = calculate_trust_score(
            _build_check_result(lic_status, issues, repository_info)
        )

        entry = {
            "package": name,
            "version": version,
            "license_raw": lic_raw,
            "license_status": lic_status,
            "vulnerabilities": vulns,
            "issues": issues or [],
            "scanned": issues is not None,   # False = nothing was looked at
            "alternatives": alternatives,
            "trust_score": score_result["trust_score"],
            "verdict": score_result["verdict"],
            "hard_block": score_result["hard_block"],
            "hard_block_reasons": score_result["hard_block_reasons"],
            "score_breakdown": score_result["breakdown"],
            "confidence": score_result["confidence"],
        }
        if repository_info is not None:
            # Keep the summary, not the full 20-key payload, so scan_report
            # stays readable. The MCP check_repo_trust tool returns the rest.
            entry["supply_chain"] = {
                "trust_score": repository_info.get("trust_score"),
                "verdict": repository_info.get("verdict"),
                "openssf_score": repository_info.get("openssf_score"),
                "repository": repository_info.get("github_repository"),
                "github_star": repository_info.get("github_star"),
                "last_commit": repository_info.get("last_commit"),
                "signature": repository_info.get("signature"),
                "provenance": repository_info.get("provenance"),
                "issues": repository_info.get("issues") or [],
            }

        report.append(entry)

    # -- AI models (module 1) ------------------------------------------------
    model_reports = []
    for model_ref in (models or []):
        if offline:
            print(f"[INFO] Offline: skipping model {model_ref}")
            continue
        print(f"[Scanning model] {model_ref} ...")
        model_report = scan_model(model_ref, model_pickle_size_mb)
        if model_report:
            model_reports.append(model_report)

    print_report(report)
    if model_reports:
        print_model_report(model_reports)

    save_report(report, report_path, model_reports)
    build_final_sbom(requirements_path, report, sbom_path, model_reports)

    if explain:
        print("\n===== AI Explanation (local model via Ollama) =====\n")
        print(explain_results(report))

    # Models participate in the exit code: a BLOCK model must fail CI just
    # like a BLOCK package.
    report_with_models = list(report)
    for model_report in model_reports:
        report_with_models.append({
            "package": model_report.get("model_id"),
            "verdict": model_report.get("verdict", "CONDITIONAL"),
            "_is_model": True,
        })
    return report_with_models


def print_report(report: list[dict]):
    print("\n===== AIBOM-Guard Scan Results =====\n")

    # Only widen the table when supply-chain data was actually collected;
    # three empty columns on a normal scan is just noise.
    has_supply = any(item.get("supply_chain") for item in report)

    if HAS_PRETTYTABLE:
        table = PrettyTable()
        columns = ["Package", "Version", "License Status", "Vulns"]
        if has_supply:
            columns += ["OpenSSF", "Signed"]
        columns += ["Trust Score", "Verdict"]
        table.field_names = columns

        for item in report:
            row = [
                item["package"],
                item["version"],
                item["license_status"],
                len(item["vulnerabilities"]),
            ]
            if has_supply:
                supply = item.get("supply_chain") or {}
                openssf = supply.get("openssf_score")
                signed = supply.get("signature")
                row += [
                    openssf if openssf is not None else "-",
                    ("yes" if signed else "no") if signed is not None else "-",
                ]
            row += [item["trust_score"], item["verdict"]]
            table.add_row(row)
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
            print(f"- {item['package']}=={item['version']} "
                  f"({item['verdict']}, score {item['trust_score']})")

            for reason in item.get("hard_block_reasons") or []:
                print(f"    [HARD BLOCK] {reason}")

            if item["license_status"] in ("REVIEW", "BLOCKED", "UNKNOWN"):
                license_text = str(item["license_raw"])
                if len(license_text) > 80:      # full license texts are huge
                    license_text = license_text[:77].replace("\n", " ") + "..."
                print(f"    License: {license_text} -> {item['license_status']}")

            # Non-CVE findings first: a typosquat or a hallucinated package is
            # a different kind of problem from a known vulnerability, and it
            # is what module 3 exists to surface.
            for issue in item.get("issues") or []:
                if issue.get("type") == "cve":
                    continue
                print(f"    [{issue.get('type')}] {issue.get('detail') or issue.get('summary')}")

            for issue in item.get("issues") or []:
                if issue.get("type") != "cve":
                    continue
                extra = ""
                if issue.get("cvss_score") is not None:
                    extra = f", CVSS {issue['cvss_score']}"
                if issue.get("aliases"):
                    extra += f", aka {', '.join(issue['aliases'])}"
                print(f"    Vuln {issue.get('id')} "
                      f"(severity {issue.get('severity')}{extra}): "
                      f"{issue.get('summary') or issue.get('detail')}")

            supply = item.get("supply_chain")
            if supply:
                print(f"    Supply chain: {supply.get('verdict')} "
                      f"(trust {supply.get('trust_score')}, "
                      f"OpenSSF {supply.get('openssf_score')})")
                for issue in supply.get("issues") or []:
                    print(f"      - [{issue.get('severity')}] {issue.get('detail')}")

            for alt in item.get("alternatives") or []:
                print(f"    -> suggested: {alt.get('target')} "
                      f"({alt.get('confidence')}) - {alt.get('reason')}")


def print_model_report(model_reports: list[dict]):
    """Terminal summary for the AI models in this scan."""
    print("\n===== AI Models =====\n")

    if HAS_PRETTYTABLE:
        table = PrettyTable()
        table.field_names = ["Model", "License", "Family", "Weights",
                             "Remote code", "Card", "Score", "Verdict"]
        for model in model_reports:
            formats = model.get("file_formats") or {}
            weights = "safetensors" if formats.get("has_safetensors") else "-"
            if formats.get("pickle_only"):
                weights = "PICKLE ONLY"
            elif formats.get("pickle"):
                weights += " + pickle"
            table.add_row([
                model.get("model_id"),
                model.get("license") or "NOT DECLARED",
                model.get("license_family", "-"),
                weights,
                "YES" if model.get("trust_remote_code") else "no",
                f"{(model.get('model_card') or {}).get('completeness', 0)}/100",
                model.get("risk_score"),
                model.get("verdict"),
            ])
        print(table)
    else:
        for model in model_reports:
            print(f"{model.get('model_id')} | license:{model.get('license')} "
                  f"| score:{model.get('risk_score')} | {model.get('verdict')}")

    for model in model_reports:
        if model.get("verdict") == "ALLOW":
            continue
        print(f"\n- {model.get('model_id')} ({model.get('verdict')}, "
              f"score {model.get('risk_score')})")
        if model.get("license_family") in ("ai-community", "ai-behavioural"):
            print(f"    License: {model.get('license')} "
                  f"[{model['license_family']}] - {model.get('license_reason')}")
        for reason in model.get("hard_block_reasons") or []:
            print(f"    [HARD BLOCK] {reason}")
        for issue in model.get("issues") or []:
            # Hub errors arrive as multi-line HTTP dumps; keep the report
            # readable and leave the full text in scan_report.json.
            message = " ".join(str(issue.get("message") or "").split())
            if len(message) > 160:
                message = message[:157] + "..."
            print(f"    [{issue.get('severity')}] {issue.get('type')}: {message}")


def save_report(report: list[dict], out_path: str, model_reports: list | None = None):
    payload = {
        "packages": report,
        "models": model_reports or [],
    } if model_reports else report
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"\n[Saved] {out_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Scan a requirements.txt for vulnerability, license and "
                    "supply-chain risk, and emit a CycloneDX SBOM.",
    )
    parser.add_argument("requirements", help="path to a requirements.txt")
    parser.add_argument("--supply-chain", action="store_true",
                        help="also run repository/supply-chain trust checks "
                             "(module 2). Slow: several network calls per "
                             "package; set GITHUB_TOKEN to avoid rate limits.")
    parser.add_argument("--offline", action="store_true",
                        help="skip all network lookups (OSV, PyPI, GitHub)")
    parser.add_argument("--no-explain", action="store_true",
                        help="skip the local Ollama explanation")
    parser.add_argument("--json", dest="report_path", default="scan_report.json",
                        help="where to write the JSON report "
                             "(default: scan_report.json)")
    parser.add_argument("--sbom", dest="sbom_path", default="sbom.json",
                        help="where to write the CycloneDX SBOM "
                             "(default: sbom.json)")
    parser.add_argument("--model", dest="models", action="append", metavar="REF",
                        help="a Hugging Face model to include in the AIBOM "
                             "(URL or owner/name). Repeatable. The SBOM "
                             "becomes an ML-BOM when this is used.")
    parser.add_argument("--model-pickle-scan", type=int, default=0,
                        metavar="MB",
                        help="download and picklescan model weight files up "
                             "to this size in MB (default: 0 = metadata only)")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        report = run_scan(
            args.requirements,
            supply_chain=args.supply_chain,
            offline=args.offline,
            explain=not args.no_explain,
            report_path=args.report_path,
            sbom_path=args.sbom_path,
            models=args.models,
            model_pickle_size_mb=args.model_pickle_scan,
        )
    except FileNotFoundError:
        print(f"[ERROR] No such file: {args.requirements}", file=sys.stderr)
        return 1

    if not report:
        return 1
    return 2 if any(item["verdict"] == "BLOCK" for item in report) else 0


if __name__ == "__main__":
    sys.exit(main())
