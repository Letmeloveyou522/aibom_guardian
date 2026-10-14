"""Validate CycloneDX 1.6 JSON and explicitly upload it to Dependency-Track."""

import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import requests
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator


def validate_bom(document):
    if not isinstance(document, dict) or document.get("specVersion") != "1.6":
        raise ValueError("Expected CycloneDX 1.6 JSON")
    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(document))
    if error:
        raise ValueError(f"Invalid CycloneDX BOM: {error}")


def upload_bom(document, server, project, api_key, *, session=None):
    """Upload to an existing project. Acceptance does not establish analysis success.

    No automatic retry: a timed-out POST may already have been accepted.
    Redirects are refused so an API key cannot follow a redirect to another host.
    """
    validate_bom(document)
    parsed = urlsplit(server)
    if (not parsed.hostname or parsed.username or parsed.password or parsed.query
            or parsed.fragment or parsed.scheme not in ("http", "https")):
        raise ValueError("Use a server base URL without credentials, query or fragment")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("HTTPS is required except for a local server")
    project = str(UUID(project))
    if not api_key or not api_key.strip():
        raise ValueError("Set DEPENDENCY_TRACK_API_KEY")
    payload = json.dumps(document, ensure_ascii=False).encode("utf-8")
    client = session or requests.Session()
    try:
        response = client.post(
            server.rstrip("/") + "/api/v1/bom",
            headers={"X-Api-Key": api_key}, data={"project": project},
            files={"bom": ("bom.json", payload, "application/json")},
            timeout=(10, 60), allow_redirects=False,
        )
        if response.status_code != 200:
            raise ValueError(f"Dependency-Track upload rejected: HTTP {response.status_code}")
        result = response.json()
        if not isinstance(result, dict) or not isinstance(result.get("token"), str):
            raise ValueError("Upload response did not contain a processing token")
        token = str(UUID(result["token"]))
        return {"status": "accepted", "processing_token": token,
                "analysis_verified": False, "project": project,
                "bom_sha256": hashlib.sha256(payload).hexdigest()}
    except requests.RequestException:
        raise ValueError("Upload could not be confirmed; check the server before retrying") from None
    finally:
        if session is None:
            client.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bom")
    parser.add_argument("--server", help="Explicitly upload to this Dependency-Track server")
    parser.add_argument("--project", help="Existing Dependency-Track project UUID")
    args = parser.parse_args(argv)
    try:
        document = json.loads(Path(args.bom).read_text(encoding="utf-8-sig"))
        validate_bom(document)
        if args.server:
            if not args.project:
                raise ValueError("--project is required with --server")
            result = upload_bom(document, args.server, args.project,
                                os.environ.get("DEPENDENCY_TRACK_API_KEY"))
        else:
            if args.project:
                raise ValueError("--project requires --server")
            result = {"schema_valid": True, "uploaded": False}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError) as exc:
        parser.exit(1, f"BOM operation failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
