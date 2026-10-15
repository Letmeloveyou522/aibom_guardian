"""Report provenance and conservative package vulnerability comparisons."""

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import re

from . import __version__

POLICY_VERSION = "guardian-default-3"


def project_summary(report):
    """Summarize package evidence without treating verdicts as clean scans."""
    rows = report.get("packages", [])
    verdicts = {key: sum(p.get("verdict") == key for p in rows)
                for key in ("ALLOW", "WARNING", "BLOCK")}
    attention = []
    for p in rows:
        vulnerabilities = p.get("vulnerabilities")
        unknown = (not isinstance(vulnerabilities, list)
                   or bool(p.get("osv_unverified")) or p.get("scanned") is False)
        if (p.get("verdict") != "ALLOW" or vulnerabilities or unknown
                or p.get("license_unverified") or p.get("license_status") != "ALLOWED"):
            attention.append({
                "package": p.get("package"), "version": p.get("version"),
                "verdict": p.get("verdict"), "trust_score": p.get("trust_score"),
                "advisory_count": None if unknown else len(vulnerabilities),
                "vulnerabilities_unverified": unknown,
                "license_status": p.get("license_status"),
                "license_unverified": bool(p.get("license_unverified")),
            })
    attention.sort(key=lambda p: {"BLOCK": 0, "WARNING": 1, "ALLOW": 2}.get(p["verdict"], 3))
    unscanned = report.get("unscanned", [])
    conflicts = sum(isinstance(item, str) and "(dependency conflict:" in item for item in unscanned)
    return {
        "package_count": len(rows),
        "direct_count": sum(p.get("direct") is True for p in rows),
        "transitive_count": sum(p.get("direct") is False for p in rows),
        "verdicts": verdicts,
        "packages_with_advisories": sum(bool(p.get("vulnerabilities")) for p in rows),
        "vulnerabilities_unverified_count": sum(
            not isinstance(p.get("vulnerabilities"), list) or bool(p.get("osv_unverified"))
            or p.get("scanned") is False for p in rows),
        "license_unverified_count": sum(bool(p.get("license_unverified")) for p in rows),
        "unscanned_entry_count": len(unscanned),
        "dependency_conflict_entry_count": conflicts,
        "scope": report.get("metadata", {}).get("scope"),
        "attention_packages": attention,
        "notes": [
            "ALLOW is a policy verdict, not an absence of advisories.",
            "Unscanned entries are requirements or errors, not a count of distinct omitted packages.",
            "Dependency conflicts describe selected candidates versus requirements; they do not prove the deployed environment is broken.",
        ],
    }


def set_scan_scope(metadata, *, lockfile=False):
    """Describe the source of the package list, not installation success."""
    options = metadata["options"]
    requested = options.get("transitive", False)
    offline = options.get("offline", False)
    basis = "lockfile" if lockfile else "registry_candidates" if requested and not offline else "manifest"
    scope = {
        "basis": basis,
        "transitive": "included" if requested and (lockfile or not offline)
                      else "skipped_offline" if requested else "not_requested",
        "installed_inventory": False,
        "installation_verified": False,
        "description": {
            "lockfile": "Versions recorded in the lockfile; installed files and platform exclusions are not verified.",
            "registry_candidates": "Dependency candidates from registry metadata; not an installed inventory or a resolver-validated installation plan.",
            "manifest": "Direct manifest requirements only; installed packages are not inventoried.",
        }[basis],
    }
    metadata["scope"] = scope
    return scope


def scope_message(metadata):
    env = metadata["environment"]
    scope = metadata["scope"]
    return (f"[SCOPE] Scanner: {env['os']} / Python {env['python']}. "
            f"{scope['description']} Transitive: {scope['transitive']}.")


def scan_metadata(input_path, options):
    path = Path(input_path)
    return {
        "schema_version": "1.1",
        "tool_version": __version__,
        "policy_version": POLICY_VERSION,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "input_name": path.name,
        "input_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "environment": {"os": platform.system(), "python": platform.python_version()},
        "options": options,
    }


def _key(row):
    ecosystem = row.get("ecosystem") or "unknown"
    name = str(row.get("package") or row.get("name") or "")
    if ecosystem.lower() == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    return (ecosystem, name, row.get("installation_path") or "", row.get("section") or "")


def _ids(row):
    result = set()
    for finding in row.get("vulnerabilities") or []:
        if not isinstance(finding, dict) or not finding.get("id"):
            return None
        result.add(str(finding["id"]))
    return result


def _verified(row):
    return (isinstance(row.get("vulnerabilities"), list)
            and not row.get("osv_unverified") and row.get("scanned") is not False)


def compare_reports(before, after):
    """Compare known advisory IDs, never infer resolution from missing evidence.

    Removed components are not classified as remediated. Alias-ID changes may
    appear as new/absent findings. Model and license remediation are not inferred.
    """
    for doc in (before, after):
        if not isinstance(doc, dict) or not isinstance(doc.get("packages"), list):
            raise ValueError("Expected a report object containing a packages array")
        if not isinstance(doc.get("metadata", {}), dict):
            raise ValueError("Report metadata must be an object")
        if any(not isinstance(row, dict) for row in doc["packages"]):
            raise ValueError("Package entries must be objects")
    groups = []
    for doc in (before, after):
        indexed = defaultdict(list)
        for row in doc["packages"]:
            indexed[_key(row)].append(row)
        groups.append(indexed)
    old, new = groups
    changed, added, removed, findings = [], [], [], []
    for key in sorted(set(old) | set(new)):
        label = {"ecosystem": key[0], "package": key[1], "installation_path": key[2], "section": key[3]}
        if key not in old:
            added.append({**label, "versions": [r.get("version") for r in new[key]]})
            continue
        if key not in new:
            removed.append({**label, "status": "unverified" if after.get("unscanned") else "absent_from_report"})
            continue
        if len(old[key]) != 1 or len(new[key]) != 1:
            findings.append({**label, "status": "unverified", "reason": "ambiguous component identity"})
            continue
        a, b = old[key][0], new[key][0]
        if a.get("version") != b.get("version"):
            changed.append({**label, "before": a.get("version"), "after": b.get("version")})
        if not (_verified(a) and _verified(b)) or before.get("unscanned") or after.get("unscanned"):
            findings.append({**label, "status": "unverified", "reason": "incomplete scan evidence"})
            continue
        a_ids, b_ids = _ids(a), _ids(b)
        if a_ids is None or b_ids is None:
            findings.append({**label, "status": "unverified", "reason": "advisory ID missing"})
            continue
        findings.append({**label, "status": "compared", "no_longer_reported": sorted(a_ids - b_ids),
                         "new": sorted(b_ids - a_ids), "remaining": sorted(a_ids & b_ids)})
    old_meta, new_meta = before.get("metadata") or {}, after.get("metadata") or {}
    return {
        "scope": "package advisory IDs only; absence is not proof of remediation or compatibility",
        "metadata_available": bool(old_meta and new_meta),
        "policy_changed": old_meta.get("policy_version") != new_meta.get("policy_version"),
        "options_changed": old_meta.get("options") != new_meta.get("options"),
        "environment_changed": old_meta.get("environment") != new_meta.get("environment"),
        "scope_changed": old_meta.get("scope") != new_meta.get("scope"),
        "changed": changed, "added": added, "removed": removed, "findings": findings,
        "unscanned": after.get("unscanned") or [],
        "models_compared": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before")
    parser.add_argument("after")
    args = parser.parse_args()
    try:
        docs = [json.loads(Path(p).read_text(encoding="utf-8-sig")) for p in (args.before, args.after)]
        print(json.dumps(compare_reports(*docs), ensure_ascii=False, indent=2))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Cannot compare reports: {exc}\n")


if __name__ == "__main__":
    main()
