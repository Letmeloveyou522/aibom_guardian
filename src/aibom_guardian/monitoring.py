"""Monitor a fixed scan inventory. SQLite history and local JSON alerts; no daemon setup."""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import time

from packaging.version import Version, InvalidVersion


SCHEMA = 1
MODEL_FIELDS = ("commit_sha", "license", "base_model", "datasets", "files", "file_hashes")


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _ids(value):
    if not isinstance(value, list):
        return None
    if any(not isinstance(v, dict) or not isinstance(v.get("id"), str) or not v["id"] for v in value):
        return None
    return sorted({v["id"] for v in value})


def _identity(row):
    eco = row.get("ecosystem", "PyPI")
    name, version = row.get("package"), row.get("version")
    if eco not in ("PyPI", "npm") or not isinstance(name, str) or not name.strip():
        raise ValueError("Only named PyPI/npm components can be monitored")
    if (not isinstance(version, str) or not re.match(r"v?\d", version)
            or re.search(r"[\s<>=~^*|/@]", version)):
        raise ValueError("Monitor requires exact component versions")
    if eco == 'PyPI':
        try:
            Version(version)
        except InvalidVersion:
            raise ValueError('Invalid PyPI version') from None
    elif not re.fullmatch(r'v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?', version):
        raise ValueError('Monitor requires a complete npm version')
    name = re.sub(r"[-_.]+", "-", name).lower() if eco == "PyPI" else name
    return eco, name, version


def initialize(database, report, *, track_model_refs=False):
    """Create a new inventory; never silently replace an existing baseline."""
    if not isinstance(report, dict) or not isinstance(report.get("packages"), list):
        raise ValueError("Expected a Guardian report with packages")
    if (not isinstance(report.get('models', []), list)
            or not isinstance(report.get('unscanned', []), list)
            or not isinstance(report.get('metadata', {}), dict)):
        raise ValueError('Invalid report collections')
    components = {}
    for row in report["packages"]:
        if not isinstance(row, dict):
            raise ValueError("Invalid package row")
        eco, name, version = _identity(row)
        key = _json([eco, name, version])
        ids = None if row.get("osv_unverified") or row.get("scanned") is False else _ids(row.get("vulnerabilities"))
        item = {"kind": "package", "ecosystem": eco, "name": name, "version": version,
                "origin": {k: row.get(k) for k in ("direct", "depth", "required_by", "installation_path")}}
        if key in components:
            # Preserve uncertainty in duplicate installation rows.
            previous = components[key][1]
            ids = sorted(set(previous) | set(ids)) if previous is not None and ids is not None else None
        components[key] = (item, ids)
    for row in report.get("models", []):
        if not isinstance(row, dict):
            raise ValueError('Invalid model row')
        name, sha = row.get("model_id"), row.get("commit_sha")
        if not isinstance(name, str) or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
            raise ValueError("Model monitoring requires an identified model with a resolved full commit SHA")
        revision = row.get("requested_revision") if track_model_refs else sha
        if not isinstance(revision, str) or not revision.strip():
            raise ValueError("Model reference tracking requires requested_revision")
        components[_json(["model", name, sha])] = (
            {"kind": "model", "name": name, "version": sha, "revision": revision,
             "track_mutable_ref": track_model_refs and not bool(re.fullmatch(r"[0-9a-fA-F]{40}", revision))},
            {k: row.get(k) for k in MODEL_FIELDS})
    if not components:
        raise ValueError("No monitorable components")
    path = Path(database)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise ValueError("Database already exists; choose a new baseline path")
    # Reserve the destination to avoid two initializers racing.
    with path.open("xb"):
        pass
    with closing(sqlite3.connect(path)) as db, db:
        db.executescript("""
            CREATE TABLE metadata (value TEXT NOT NULL);
            CREATE TABLE components (key TEXT PRIMARY KEY, target TEXT NOT NULL, evidence TEXT,
                                     unavailable INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE runs (id INTEGER PRIMARY KEY, at TEXT NOT NULL, result TEXT NOT NULL);
        """)
        metadata = {"schema_version": SCHEMA, "created_at": _now(),
                    "inventory_sha256": hashlib.sha256(_json(sorted(components)).encode()).hexdigest(),
                    "source_metadata": report.get("metadata", {}),
                    "baseline_unscanned": report.get("unscanned", []),
                    "scope": "Fixed reported versions; not proof of deployed inventory. OSV and model metadata only."}
        db.execute("INSERT INTO metadata VALUES (?)", (_json(metadata),))
        db.executemany("INSERT INTO components(key,target,evidence) VALUES (?,?,?)",
                       [(k, _json(item), None if evidence is None else _json(evidence))
                        for k, (item, evidence) in components.items()])
    return {"registered_components": len(components), **metadata}


def _connect(database):
    path = Path(database).resolve(strict=True)
    db = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=5)
    try:
        rows = db.execute("SELECT value FROM metadata").fetchall()
        if len(rows) != 1 or not isinstance(rows[0][0], str):
            raise ValueError('Monitor metadata missing or ambiguous')
        metadata = json.loads(rows[0][0])
        if (not isinstance(metadata, dict) or metadata.get('schema_version') != SCHEMA
                or not isinstance(metadata.get('baseline_unscanned'), list)
                or not isinstance(metadata.get('inventory_sha256'), str)
                or not isinstance(metadata.get('scope'), str)):
            raise ValueError('Invalid monitor metadata')
    except Exception:
        db.close()
        raise
    return db, metadata


def check_once(database, *, package_query=None, model_query=None):
    """Query pinned identities, retain last good evidence on failure, emit changes once."""
    if package_query is None:
        from .osv_client import query_vulnerabilities
        package_query = query_vulnerabilities
    if model_query is None:
        from .model_checker import check_model
        model_query = check_model
    db, metadata = _connect(database)
    try:
        with db:
            db.execute("BEGIN IMMEDIATE")
            events, failures = [], []
            targets = db.execute("SELECT key,target,evidence,unavailable FROM components ORDER BY key").fetchall()
            for key, encoded, old_encoded, unavailable in targets:
                target = json.loads(encoded)
                old = json.loads(old_encoded) if old_encoded is not None else None
                reason = None
                try:
                    if target["kind"] == "package":
                        current = _ids(package_query(target["name"], target["version"], ecosystem=target["ecosystem"]))
                    else:
                        value = model_query(target["name"] + "@" + target["revision"], max_pickle_size_mb=0)
                        current = ({k: value.get(k) for k in MODEL_FIELDS}
                                   if isinstance(value, dict)
                                   and isinstance(value.get("commit_sha"), str)
                                   and re.fullmatch(r"[0-9a-fA-F]{40}", value["commit_sha"])
                                   and (target["track_mutable_ref"] or value["commit_sha"].lower() == target["revision"].lower())
                                   else None)
                    if current is None:
                        reason = "lookup_unverified"
                except Exception as exc:
                    # Persist only the error class; URLs/exceptions can contain credentials.
                    current, reason = None, type(exc).__name__
                if current is None:
                    failures.append({"target": target, "reason": reason})
                    if not unavailable:
                        events.append({"type": "lookup_failed", "target": target, "reason": reason})
                    db.execute("UPDATE components SET unavailable=1 WHERE key=?", (key,))
                    continue
                if unavailable:
                    events.append({"type": "lookup_recovered", "target": target})
                if old is None:
                    events.append({"type": "baseline_verified", "target": target, "evidence": current})
                elif target["kind"] == "package":
                    added, absent = sorted(set(current) - set(old)), sorted(set(old) - set(current))
                    if added:
                        events.append({"type": "new_advisories", "target": target, "ids": added})
                    if absent:
                        events.append({"type": "no_longer_reported", "target": target, "ids": absent,
                                       "note": "Absence from this lookup is not proof of remediation."})
                else:
                    for field in MODEL_FIELDS:
                        if current[field] is None and old.get(field) is not None:
                            failures.append({"target": target, "reason": "model_field_unverified", "field": field})
                            current[field] = old[field]
                        elif current[field] != old.get(field):
                            events.append({"type": "model_metadata_changed", "target": target, "field": field,
                                           "before": old.get(field), "after": current[field],
                                           "note": "Review change; not a maliciousness determination."})
                db.execute("UPDATE components SET evidence=?,unavailable=0 WHERE key=?", (_json(current), key))
            result = {"checked_at": _now(), "inventory_sha256": metadata["inventory_sha256"],
                      "component_count": len(targets), "events": events, "lookup_failures": failures,
                      "baseline_unscanned": metadata["baseline_unscanned"],
                      "complete": not failures and not metadata["baseline_unscanned"],
                      "scope": metadata["scope"], "external_notifications_sent": False}
            db.execute("INSERT INTO runs(at,result) VALUES (?,?)", (result["checked_at"], _json(result)))
            db.execute("DELETE FROM runs WHERE id NOT IN (SELECT id FROM runs ORDER BY id DESC LIMIT 30)")
            return result
    finally:
        db.close()


def history(database, limit=5):
    if type(limit) is not int or not 1 <= limit <= 30:
        raise ValueError("History limit must be between 1 and 30")
    db, metadata = _connect(database)
    try:
        rows = db.execute("SELECT id,result FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return {"metadata": metadata, "runs": [{"run_id": row[0], **json.loads(row[1])} for row in rows]}
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Register a report's exact versions")
    init.add_argument("report")
    init.add_argument("--db", required=True)
    init.add_argument("--track-model-refs", action="store_true", help="Follow originally requested model branches/tags instead of pinning commits")
    check = commands.add_parser("check", help="Recheck once; JSON events on stdout")
    check.add_argument("--db", required=True)
    check.add_argument("--interval", type=int, default=0, help="Seconds between runs; 0 runs once, minimum 60")
    hist = commands.add_parser("history")
    hist.add_argument("--db", required=True)
    hist.add_argument("--limit", type=int, default=5)
    args = parser.parse_args()
    try:
        if args.command == "init":
            print(_json(initialize(args.db, json.loads(Path(args.report).read_text(encoding="utf-8-sig")),
                                   track_model_refs=args.track_model_refs)))
        elif args.command == "history":
            print(_json(history(args.db, args.limit)))
        else:
            if args.interval != 0 and args.interval < 60:
                raise ValueError("Interval must be 0 or at least 60 seconds")
            while True:
                result = check_once(args.db)
                print(_json(result), flush=True)
                if not args.interval:
                    return 3 if not result["complete"] or result["events"] else 0
                time.sleep(args.interval)
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(1, f"Monitor failed: {type(exc).__name__}\n")
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
