"""check_repository() - the entry point everything outside this package uses."""

from __future__ import annotations

from ._checker import RepositoryChecker


def _resolve_target(
    target: str | None,
    target_type: str,
    *,
    package_name: str | None = None,
    version: str | None = None,
    owner: str | None = None,
    repo: str | None = None,
    dataset_id: str | None = None,
) -> tuple[str, str]:
    """
    Turn the named target arguments into (target, target_type).

    A positional target always wins, so existing callers are unaffected.
    Each named form also fixes the target type, which removes the
    owner/repo ambiguity between GitHub and Hugging Face.
    """
    if target:
        return target, target_type

    if package_name:
        pinned = f"{package_name}=={version}" if version else package_name
        return pinned, ("pypi" if target_type == "auto" else target_type)

    if owner and repo:
        return f"{owner}/{repo}", ("github" if target_type == "auto" else target_type)

    if dataset_id:
        return dataset_id, ("hf_dataset" if target_type == "auto" else target_type)

    raise ValueError(
        "check_repository needs a target: pass it positionally, or use "
        "package_name=, owner= and repo=, or dataset_id="
    )


def check_repository(
    target: str | None = None,
    *,
    package_name: str | None = None,
    version: str | None = None,
    owner: str | None = None,
    repo: str | None = None,
    dataset_id: str | None = None,
    target_type: str = "auto",
    revision: str | None = None,
    local_file: str | None = None,
    expected_sha256: str | None = None,
    artifact_filename: str | None = None,
    signature_file: str | None = None,
    signature_bundle: str | None = None,
    signature_key: str | None = None,
    certificate_identity: str | None = None,
    certificate_oidc_issuer: str | None = None,
    timeout: float = 10.0,
) -> dict:
    """
    Inspect a package, GitHub repository, or Hugging Face model/dataset
    for supply-chain trust signals.

    The target can be given either as one string or as named parts:

        check_repository("requests==2.28.0")
        check_repository(package_name="requests", version="2.28.0")
        check_repository("https://github.com/pallets/flask")
        check_repository(owner="pallets", repo="flask")
        check_repository(dataset_id="squad")

    The named forms exist because building the string by hand is easy to get
    wrong, and because "owner/repo" alone is ambiguous between GitHub and
    Hugging Face - naming the parts also settles the type, so the caller does
    not have to remember to pass target_type as well.

    Returns a JSON-serializable dict with trust_score and verdict.
    """
    target, target_type = _resolve_target(
        target, target_type,
        package_name=package_name, version=version,
        owner=owner, repo=repo, dataset_id=dataset_id,
    )

    checker = RepositoryChecker(timeout=timeout)
    return checker.check(
        target,
        target_type=target_type,
        revision=revision,
        local_file=local_file,
        expected_sha256=expected_sha256,
        artifact_filename=artifact_filename,
        signature_file=signature_file,
        signature_bundle=signature_bundle,
        signature_key=signature_key,
        certificate_identity=certificate_identity,
        certificate_oidc_issuer=certificate_oidc_issuer,
    )
