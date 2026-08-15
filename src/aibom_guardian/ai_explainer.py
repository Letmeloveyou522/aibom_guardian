"""
ai_explainer.py
-----------------------------------
Sends our scan results to a locally-running open-weight model (via
Ollama) and asks it to explain the risky findings in plain language.

Why a local model instead of calling Claude/OpenAI directly?
The competition rules (Article 9) require AI features to run on an
open-weight model that can be hosted locally/independently, not just
call a closed commercial API. Ollama runs models like Gemma 2 or
Llama 3 fully on your own machine.

Ollama exposes a simple local HTTP API at http://localhost:11434,
so this is just a normal HTTP request - no API key needed.
"""

from __future__ import annotations

import json

import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5:0.5b"  # lightweight model, good for limited-resource machines/VMs


def _normalize_scan_report(scan_report: list | dict) -> list[dict]:
    """
    Accept either the legacy list shape or the fixed document shape
    {"packages": [...], "models": [...], "unscanned": [...]}.
    """
    if isinstance(scan_report, dict):
        packages = scan_report.get("packages") or []
        models = scan_report.get("models") or []
        risky_models = [
            {
                "package": m.get("model_id") or m.get("model") or "unknown-model",
                "version": m.get("commit_sha") or "-",
                "verdict": m.get("verdict", "WARNING"),
                "license_status": m.get("license_status", "UNKNOWN"),
                "vulnerabilities": [],
                "issues": m.get("issues") or [],
                "alternatives": [],
                "_is_model": True,
            }
            for m in models
            if m.get("verdict") != "ALLOW"
        ]
        return list(packages) + risky_models
    if isinstance(scan_report, list):
        return scan_report
    return []


def _package_label(item: dict) -> str:
    if item.get("_is_model"):
        return str(item.get("package") or "unknown-model")
    return f"{item['package']}=={item['version']}"


def _cve_count(item: dict) -> int | None:
    """
    Number of known CVEs for this package entry.

    None means OSV lookup failed (unverified), not zero vulnerabilities.
    """
    vulns = item.get("vulnerabilities")
    if vulns is None:
        return None
    return len(vulns)


def _non_cve_issues(item: dict) -> list[dict]:
    return [
        issue for issue in (item.get("issues") or [])
        if issue.get("type") not in ("cve", None)
    ]


def _cve_issues(item: dict) -> list[dict]:
    return [issue for issue in (item.get("issues") or []) if issue.get("type") == "cve"]


def _primary_issue_line(item: dict) -> str | None:
    """One factual issue line for this package only — no cross-package data."""
    for issue in _non_cve_issues(item):
        detail = issue.get("detail") or issue.get("summary") or issue.get("message")
        return f"{issue.get('type')}: {detail}"

    cve_issues = _cve_issues(item)
    if cve_issues:
        first = cve_issues[0]
        summary = first.get("summary") or first.get("detail") or "known CVE"
        sev = first.get("severity") or "unknown"
        return f"cve ({sev}): {summary}"

    vulns = item.get("vulnerabilities") or []
    if vulns:
        first = vulns[0]
        summary = first.get("summary") or first.get("detail") or "known CVE"
        sev = first.get("severity") or "unknown"
        return f"cve ({sev}): {summary}"

    if item.get("osv_unverified"):
        return "unverified: OSV vulnerability lookup failed; CVE status unknown"

    if item.get("license_status") not in (None, "", "ALLOWED"):
        return f"license: status is {item['license_status']} (not a CVE finding)"

    return None


def _fix_line(item: dict) -> str | None:
    alternatives = item.get("alternatives") or []
    if not alternatives:
        return None
    alt = alternatives[0]
    target = alt.get("target")
    if not target:
        return None
    reason = alt.get("reason") or "recommended upgrade"
    confidence = alt.get("confidence") or "suggested"
    return f"Suggested fix for {_package_label(item)}: {target} ({confidence}) — {reason}"


def _package_fact_block(item: dict) -> str:
    """
    Self-contained facts for ONE package. Each block is built only from
    ``item`` — no shared list indices, no merging across packages.
    """
    label = _package_label(item)
    lines = [
        "---",
        f"Package: {label}",
        f"Verdict: {item.get('verdict', 'WARNING')}",
    ]

    count = _cve_count(item)
    if count is None:
        lines.append("Known CVE count: unknown (OSV lookup failed — not the same as zero CVEs)")
    elif count == 0:
        lines.append("Known CVE count: 0 (no published CVEs recorded for this pinned version)")
    else:
        lines.append(f"Known CVE count: {count}")

    issue_line = _primary_issue_line(item)
    if issue_line:
        lines.append(f"Primary issue: {issue_line}")
    else:
        lines.append("Primary issue: none beyond the verdict score")

    fix = _fix_line(item)
    if fix:
        lines.append(fix)
    else:
        lines.append(f"Suggested fix for {label}: none listed")

    supply = item.get("supply_chain") or {}
    supply_issues = supply.get("issues") or []
    if supply_issues:
        lines.append(f"Supply chain: {supply_issues[0].get('detail')}")
    elif supply.get("openssf_score") is not None:
        lines.append(f"Supply chain: OpenSSF score {supply['openssf_score']}")

    lines.append("---")
    return "\n".join(lines)


def build_prompt(scan_report: list | dict, *, item: dict | None = None) -> str | None:
    """
    Build an Ollama prompt.

    When ``item`` is given, the prompt covers that single package only so
    the model cannot attribute another package's CVE or upgrade target to
    the wrong name. When ``item`` is omitted, one block per risky package
    is still emitted with explicit ``---`` delimiters (used in tests).
    """
    if item is not None:
        targets = [item] if item.get("verdict") != "ALLOW" else []
    else:
        items = _normalize_scan_report(scan_report)
        targets = [entry for entry in items if entry.get("verdict") != "ALLOW"]

    if not targets:
        return None

    header = [
        "You explain dependency scan results for a non-expert developer.",
        "Rules:",
        "- Each --- block is exactly ONE package.",
        "- Use ONLY facts inside that block. Never mention other packages.",
        "- If Known CVE count is 0, do NOT describe any CVE or loader vulnerability.",
        "- If Suggested fix names another package/version, use it only for that block's package.",
        "- One or two short sentences per block, then the suggested fix line if present.",
        "",
    ]

    blocks = [_package_fact_block(entry) for entry in targets]
    return "\n".join(header + blocks)


def _deterministic_explanation(item: dict) -> str:
    """
    Template explanation derived only from this package's fields.
    Used when Ollama is unreachable or when the model mixes packages.
    """
    label = _package_label(item)
    count = _cve_count(item)
    parts: list[str] = []

    if count is None:
        parts.append(
            f"{label} could not be checked against OSV; treat CVE status as unverified."
        )
    elif count == 0:
        parts.append(
            f"{label} has no known published CVEs for the pinned version."
        )
    else:
        issue = _primary_issue_line(item) or "a known CVE"
        parts.append(f"{label} has {count} known CVE(s): {issue}.")

    if item.get("license_status") not in (None, "", "ALLOWED"):
        parts.append(
            f"License status is {item['license_status']} "
            f"(this is separate from CVE count)."
        )

    fix = _fix_line(item)
    if fix:
        parts.append(fix.replace(f"Suggested fix for {label}: ", "Fix: "))
    elif count == 0 and item.get("license_status") not in (None, "", "ALLOWED"):
        parts.append(
            "Fix: confirm the installed package license metadata; no CVE upgrade is required."
        )

    return " ".join(parts)


def _other_package_tokens(items: list[dict], current: dict) -> set[str]:
    """Names/versions from other packages — used to detect cross-talk."""
    current_name = str(current.get("package", "")).lower()
    tokens: set[str] = set()
    for entry in items:
        name = str(entry.get("package", "")).lower()
        if not name or name == current_name:
            continue
        tokens.add(name)
        version = str(entry.get("version", "")).lower()
        if version and version not in {"-", ""}:
            tokens.add(version)
            tokens.add(f"{name}=={version}")
    return tokens


def _response_mentions_other_package(text: str, forbidden: set[str]) -> bool:
    lowered = text.lower()
    for token in forbidden:
        if token and token in lowered:
            return True
    return False


def _llm_response_is_valid(item: dict, text: str, forbidden_tokens: set[str]) -> bool:
    """
    Reject model output that cites other packages or invent CVE/fixes for
    packages with zero known CVEs.
    """
    lowered = text.lower()
    if _response_mentions_other_package(text, forbidden_tokens):
        return False

    count = _cve_count(item)
    if count == 0:
        cve_phrases = (
            "cve", "vulnerability", "vulnerabilities", "full_load", "fullloader",
            "pyyaml", "yaml library", "arbitrary code execution",
        )
        if any(phrase in lowered for phrase in cve_phrases):
            return False
        if not _fix_line(item) and "upgrade" in lowered:
            return False

    return True


def _call_ollama(prompt: str) -> str:
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {"num_predict": 250},
    }
    response = requests.post(OLLAMA_URL, json=payload, timeout=300)
    response.raise_for_status()
    data = response.json()
    return data.get("response", "[No response text returned]").strip()


def explain_results(scan_report: list | dict) -> str:
    """
    Explain risky packages one at a time so CVE/fix lines cannot bleed
    across package boundaries in a small local model.
    """
    items = _normalize_scan_report(scan_report)
    risky = [entry for entry in items if entry.get("verdict") != "ALLOW"]

    if not risky:
        return "No risky packages found - nothing to explain."

    sections: list[str] = []
    ollama_error: str | None = None
    used_llm = False

    for item in risky:
        label = _package_label(item)
        deterministic = _deterministic_explanation(item)
        forbidden = _other_package_tokens(items, item)

        prompt = build_prompt(scan_report, item=item)
        explanation = deterministic
        try:
            if prompt:
                llm_text = _call_ollama(prompt)
                if llm_text and _llm_response_is_valid(item, llm_text, forbidden):
                    explanation = llm_text
                    used_llm = True
        except requests.exceptions.RequestException as exc:
            ollama_error = str(exc)

        sections.append(f"{label} ({item.get('verdict')}): {explanation}")

    body = "\n\n".join(sections)
    if ollama_error and not used_llm:
        body += (
            f"\n\n[WARNING] Could not reach local Ollama server: {ollama_error}\n"
            f"Showing deterministic explanations instead. "
            f"Make sure Ollama is running and '{MODEL_NAME}' is pulled."
        )
    return body


if __name__ == "__main__":
    # Manual test: reuse scan_report.json produced by scanner.py
    with open("scan_report.json", "r", encoding="utf-8") as f:
        report = json.load(f)

    explanation = explain_results(report)
    print("\n===== AI Explanation =====\n")
    print(explanation)
