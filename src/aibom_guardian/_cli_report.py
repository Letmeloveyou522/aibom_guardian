"""
Terminal and JSON report helpers for the AIBOM-Guardian CLI.

Kept separate from scanner.py so the scan orchestration stays readable;
behavior matches the former inlined implementations exactly.
"""

import json

try:
    from prettytable import PrettyTable
    HAS_PRETTYTABLE = True
except ImportError:
    HAS_PRETTYTABLE = False


# How many vulnerabilities to print per package before pointing at the JSON.
# Django 4.2.11 alone reports 36 and Pillow 15; a ten-package scan printed
# 17,805 characters, which is not a report anyone reads. The findings are all
# in scan_report.json - the terminal's job is to say what to act on.
_MAX_VULNS_SHOWN = 3
_VULN_SUMMARY_CHARS = 100

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                   "unknown": 4, None: 5}


def _vuln_count_label(vulns: list | None) -> str:
    if vulns is None:
        return "?"
    return str(len(vulns))


def _first_sentence(text: str, limit: int = _VULN_SUMMARY_CHARS) -> str:
    """One readable line: first sentence, or a hard truncation."""
    text = " ".join(str(text or "").split())
    if not text:
        return ""
    head = text.split(". ")[0]
    if len(head) > limit:
        head = head[:limit - 1].rstrip() + "…"
    return head


def _print_vulnerabilities(item: dict, verbose: bool = False) -> None:
    """
    Print a package's vulnerabilities worst-first, capped unless --verbose.

    Sorting by severity matters more than the cap: OSV returns them in
    identifier order, so the critical one that decides the verdict could
    previously be the thirtieth line.
    """
    vulns = [i for i in (item.get("issues") or []) if i.get("type") == "cve"]
    if not vulns:
        return

    vulns.sort(key=lambda i: (_SEVERITY_ORDER.get(i.get("severity"), 5),
                              -(i.get("cvss_score") or 0)))
    shown = vulns if verbose else vulns[:_MAX_VULNS_SHOWN]

    for issue in shown:
        extra = ""
        if issue.get("cvss_score") is not None:
            extra = f", CVSS {issue['cvss_score']}"
        if verbose and issue.get("aliases"):
            extra += f", aka {', '.join(issue['aliases'])}"
        summary = (issue.get("summary") or issue.get("detail")
                   if verbose else
                   _first_sentence(issue.get("summary") or issue.get("detail")))
        print(f"    [{issue.get('severity')}{extra}] {issue.get('id')}: {summary}")

    hidden = len(vulns) - len(shown)
    if hidden:
        print(f"    ... and {hidden} more (--verbose, or see the JSON report)")


def print_report(report: list[dict], verbose: bool = False):
    # Lazy: avoids a circular import with scanner (OSV_UNVERIFIED_ISSUE lives there).
    from .scanner import OSV_UNVERIFIED_ISSUE

    print("\n===== AIBOM-Guardian Scan Results =====\n")

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
                _vuln_count_label(item["vulnerabilities"]),
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
                  f"vulns:{_vuln_count_label(item['vulnerabilities'])} | "
                  f"score:{item['trust_score']} | {item['verdict']}")

    unverified = [i for i in report if i.get("osv_unverified")]
    if unverified:
        print("\n[OSV lookup failed — CVE status unverified]")
        for item in unverified:
            print(f"- {item['package']}=={item['version']}: "
                  f"OSV query failed; not treated as vulnerability-free")

    # Show details for anything that isn't a clean ALLOW
    risky = [i for i in report if i["verdict"] != "ALLOW"]
    if risky:
        print("\n[Packages needing attention]")
        for item in risky:
            print(f"- {item['package']}=={item['version']} "
                  f"({item['verdict']}, score {item['trust_score']})")

            for reason in item.get("hard_block_reasons") or []:
                print(f"    [HARD BLOCK] {reason}")

            if item.get("osv_unverified"):
                print(f"    [unverified] {OSV_UNVERIFIED_ISSUE['detail']}")

            if item["license_status"] in ("REVIEW", "BLOCKED", "UNKNOWN"):
                license_text = str(item["license_raw"])
                if len(license_text) > 80:      # full license texts are huge
                    license_text = license_text[:77].replace("\n", " ") + "..."
                print(f"    License: {license_text} -> {item['license_status']}")

            # Non-CVE findings first: a typosquat or a hallucinated package is
            # a different kind of problem from a known vulnerability, and it
            # is what recommendation exists to surface.
            for issue in item.get("issues") or []:
                if issue.get("type") == "cve":
                    continue
                print(f"    [{issue.get('type')}] {issue.get('detail') or issue.get('summary')}")

            _print_vulnerabilities(item, verbose=verbose)

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


def print_unscanned_lines(unscanned_lines: list[str]):
    """Report requirements.txt lines that were not in name==version format."""
    print("\n[Unscanned requirements lines]")
    for line in unscanned_lines:
        print(f"- {line}")


def save_report(report_document: dict, out_path: str):
    payload = {
        "packages": report_document.get("packages") or [],
        "models": report_document.get("models") or [],
        "unscanned": report_document.get("unscanned") or [],
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"\n[Saved] {out_path}")
