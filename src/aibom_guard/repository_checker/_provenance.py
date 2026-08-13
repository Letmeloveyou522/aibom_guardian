"""
Local artifact provenance, as a mixin on RepositoryChecker: file hashes,
detached signatures, in-toto attestations, cosign verification.

This one reads the filesystem and shells out to cosign, so its failures are
missing files and a missing binary rather than HTTP errors.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from ._evidence import (
    _looks_like_signature,
    _normalize_sha256,
    _redact_sensitive,
    calculate_sha256,
)
from ._helpers import _classify_revision, _error, _issue
from ._scoring import evaluate_provenance


class ProvenanceMixin:
    """check_provenance, cosign verification and their helpers."""

    # -- Provenance ---------------------------------------------------------

    def check_provenance(
        self,
        *,
        revision: str | None = None,
        local_file: str | None = None,
        expected_sha256: str | None = None,
        artifact_filename: str | None = None,
        signature_file: str | None = None,
        signature_bundle: str | None = None,
        signature_key: str | None = None,
        certificate_identity: str | None = None,
        certificate_oidc_issuer: str | None = None,
        published_hashes: list | None = None,
        release_assets: list | None = None,
        version_pinned: bool = False,
        pypi_version: str | None = None,
    ) -> dict:
        issues: list[dict] = []
        errors: list[dict] = []
        published_hashes = list(published_hashes or [])
        release_assets = list(release_assets or [])

        rev_type, rev_pinned = _classify_revision(revision)
        if revision and not rev_pinned and rev_type in ("branch", "tag", "ref", "short_sha"):
            issues.append(_issue(
                "revision", "medium",
                "revision is not an immutable commit SHA",
                evidence=revision,
                recommendation="pin a full 40-character commit SHA",
            ))

        actual_hash = None
        hash_verified = None
        expected_hash = _normalize_sha256(expected_sha256) if expected_sha256 else None
        hash_source = None

        if expected_sha256 and expected_hash is None:
            issues.append(_issue(
                "hash", "high", "expected SHA-256 is not a valid 64-char hex digest",
                evidence=expected_sha256[:20] + "...",
            ))

        if local_file:
            try:
                actual_hash = calculate_sha256(local_file)
            except FileNotFoundError:
                errors.append(_error("hash", "not_found", "local file not found", False))
            except PermissionError:
                errors.append(_error("hash", "permission", "local file not readable", False))
            except ValueError as exc:
                errors.append(_error("hash", "invalid_file", str(exc), False))

        # Gather expected hashes from publications matching a concrete filename.
        # Different release assets naturally have different digests — that is
        # NOT a conflict unless the same filename (or source pair) disagrees.
        fname = artifact_filename or (Path(local_file).name if local_file else None)
        matching_published = []
        if fname:
            by_name_hashes: dict[str, set[str]] = {}
            by_name_items: dict[str, list[dict]] = {}
            for item in published_hashes:
                h = item.get("hash")
                name = item.get("name")
                if not h or not name:
                    continue
                by_name_hashes.setdefault(name, set()).add(h)
                by_name_items.setdefault(name, []).append(item)
                if name == fname:
                    matching_published.append(item)

            if fname in by_name_hashes and len(by_name_hashes[fname]) > 1:
                issues.append(_issue(
                    "hash", "critical",
                    "conflicting published SHA-256 digests from different sources",
                    evidence=list(by_name_hashes[fname]),
                ))
                hash_verified = False

        if expected_hash:
            hash_source = "user"
        elif matching_published:
            vals = {m["hash"] for m in matching_published}
            if len(vals) > 1:
                issues.append(_issue(
                    "hash", "critical",
                    "conflicting published SHA-256 digests",
                    evidence=list(vals),
                ))
                hash_verified = False
            elif len(vals) == 1:
                expected_hash = next(iter(vals))
                hash_source = matching_published[0].get("source")

        if actual_hash and expected_hash:
            if actual_hash.lower() == expected_hash.lower():
                hash_verified = True
            else:
                hash_verified = False
                issues.append(_issue(
                    "hash", "critical",
                    "local file SHA-256 does not match the published digest",
                    evidence={"expected": expected_hash, "actual": actual_hash},
                    recommendation="do not use this artifact; verify the download source",
                ))
        elif actual_hash and not expected_hash:
            hash_verified = None
            issues.append(_issue(
                "hash", "medium", "hash verification material is insufficient",
                recommendation="provide expected_sha256 or a matching published digest",
            ))

        # Signature detection / optional cosign verify
        sig_evidence = []
        signature_present = False

        def _note_sig(path_or_name: str, source: str) -> None:
            nonlocal signature_present
            signature_present = True
            sig_evidence.append({"name": path_or_name, "source": source})

        if signature_file:
            _note_sig(Path(signature_file).name, "user_signature_file")
        if signature_bundle:
            _note_sig(Path(signature_bundle).name, "user_signature_bundle")

        if local_file:
            parent = Path(local_file).resolve().parent
            base = Path(local_file).name
            # Listing the directory is best-effort: the artifact can sit
            # somewhere the process may read but not enumerate, and an
            # unhandled PermissionError here aborted the whole scan. Not being
            # able to look is recorded as unverified rather than swallowed -
            # "we found no signature" and "we could not check" are different
            # answers, and only one of them is evidence.
            try:
                siblings = list(parent.iterdir()) if parent.is_dir() else []
            except OSError as exc:
                siblings = []
                issues.append(_issue(
                    "unverified", "low",
                    f"Could not list {parent} to look for a signature file "
                    f"next to {base}: {exc}",
                    recommendation="Pass the signature explicitly with "
                                   "--signature-file / --signature-bundle.",
                ))
            for sibling in siblings:
                if sibling.name == base:
                    continue
                if _looks_like_signature(sibling.name) and (
                    sibling.name.startswith(base) or base in sibling.name
                    or sibling.suffix in {".sig", ".asc", ".bundle", ".sigstore"}
                ):
                    _note_sig(sibling.name, "local_adjacent")

        for asset in release_assets:
            name = asset.get("name") or ""
            if _looks_like_signature(name):
                _note_sig(name, "github_release")

        signature_status = "not_found"
        signature_verified = False

        if (certificate_identity and not certificate_oidc_issuer) or (
            certificate_oidc_issuer and not certificate_identity
        ):
            issues.append(_issue(
                "signature", "medium",
                "keyless verification requires both certificate_identity and certificate_oidc_issuer",
            ))

        # Enough material to attempt cryptographic verification with cosign
        has_blob_bundle = bool(local_file and signature_bundle)
        has_blob_key = bool(local_file and signature_file and signature_key)
        has_keyless = bool(
            local_file
            and certificate_identity
            and certificate_oidc_issuer
            and (signature_bundle or signature_file)
        )
        can_verify = has_blob_bundle or has_blob_key or has_keyless

        if can_verify:
            verified, status, detail = self._verify_cosign(
                local_file=local_file,
                signature_file=signature_file,
                signature_bundle=signature_bundle,
                signature_key=signature_key,
                certificate_identity=certificate_identity,
                certificate_oidc_issuer=certificate_oidc_issuer,
            )
            signature_status = status
            signature_verified = verified
            if status == "failed":
                issues.append(_issue(
                    "signature", "critical", "signature verification failed",
                    evidence=_redact_sensitive(detail or ""),
                ))
            elif status == "unavailable":
                # Materials exist but tooling is missing — still count as present evidence
                if signature_present:
                    signature_status = "present"
                issues.append(_issue(
                    "signature", "info",
                    detail or "cosign not available for cryptographic verification",
                ))
            elif status == "present":
                issues.append(_issue(
                    "signature", "medium",
                    "signature evidence present but not cryptographically verified",
                    recommendation="provide signature bundle/key and ensure cosign is installed",
                ))
        elif signature_present:
            signature_status = "present"
            signature_verified = False
            issues.append(_issue(
                "signature", "medium", "signature evidence present but not cryptographically verified",
                recommendation="provide signature bundle/key and ensure cosign is installed",
            ))
        else:
            signature_status = "not_found"
            issues.append(_issue(
                "signature", "medium", "no signature found",
                recommendation="verify a signed release or Sigstore bundle",
            ))

        provenance, prov_status = evaluate_provenance(
            revision_pinned=rev_pinned,
            hash_verified=hash_verified,
            signature_verified=signature_verified,
            signature_status=signature_status,
        )

        detail = {
            "status": prov_status,
            "requested_revision": revision,
            "resolved_revision": revision if rev_pinned else None,
            "revision_type": rev_type,
            "revision_pinned": rev_pinned,
            "version": pypi_version,
            "version_pinned": version_pinned,
            "hash_algorithm": "sha256",
            "expected_hash": expected_hash,
            "actual_hash": actual_hash,
            "hash_source": hash_source,
            "hash_verified": hash_verified,
            "local_file": Path(local_file).name if local_file else None,
            "signature_status": signature_status,
            "signature_evidence": sig_evidence,
        }

        return {
            "provenance": provenance,
            "signature": signature_present,
            "signature_verified": signature_verified,
            "provenance_detail": detail,
            "issues": issues,
            "errors": errors,
        }

    def _verify_cosign(
        self,
        *,
        local_file: str,
        signature_file: str | None,
        signature_bundle: str | None,
        signature_key: str | None,
        certificate_identity: str | None,
        certificate_oidc_issuer: str | None,
    ) -> tuple[bool, str, str | None]:
        cosign = shutil.which("cosign")
        if not cosign:
            return False, "unavailable", "cosign executable not found on PATH"

        cmd = [cosign, "verify-blob", local_file]
        if signature_bundle:
            cmd.extend(["--bundle", signature_bundle])
        elif signature_file and signature_key:
            cmd.extend(["--key", signature_key, "--signature", signature_file])
        elif certificate_identity and certificate_oidc_issuer and signature_bundle:
            cmd.extend([
                "--bundle", signature_bundle,
                "--certificate-identity", certificate_identity,
                "--certificate-oidc-issuer", certificate_oidc_issuer,
            ])
        elif certificate_identity and certificate_oidc_issuer and signature_file:
            cmd.extend([
                "--signature", signature_file,
                "--certificate-identity", certificate_identity,
                "--certificate-oidc-issuer", certificate_oidc_issuer,
            ])
        else:
            return False, "present", "insufficient material for cosign verify-blob"

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 5,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False, "failed", "cosign verification timed out"
        except OSError as exc:
            return False, "failed", f"cosign execution error: {type(exc).__name__}"

        stdout = _redact_sensitive(proc.stdout or "")
        stderr = _redact_sensitive(proc.stderr or "")
        combined = f"{stdout}\n{stderr}".lower()
        if proc.returncode == 0 and ("verified" in combined or "equality check passed" in combined or not stderr.strip()):
            return True, "verified", None
        return False, "failed", stderr or stdout or f"exit={proc.returncode}"
