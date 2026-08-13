"""
Shared constants for the repository checker.

The allow-lists are security boundaries and validate_public_url reads them
directly, so there is deliberately only one copy of each.
"""

from __future__ import annotations

import re


ALLOWED_HOSTS = frozenset({
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "api.securityscorecards.dev",
    "huggingface.co",
    "pypi.org",
    "files.pythonhosted.org",
})

# None = no explicit port in the URL. Without this a redirect could walk an
# allow-listed hostname onto an unexpected service port.
ALLOWED_PORTS = frozenset({443, None})

# Added only when a caller passes allow_http=True, so relaxing the scheme
# cannot widen the https policy too.
ALLOWED_HTTP_PORTS = frozenset({80})

GITHUB_API = "https://api.github.com"
OPENSSF_API = "https://api.securityscorecards.dev"
HF_API = "https://huggingface.co"
PYPI_API = "https://pypi.org"

COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SHORT_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,39}$")
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
PYPI_SPEC_RE = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:==([A-Za-z0-9](?:[A-Za-z0-9._+-]*[A-Za-z0-9])?))?$"
)
GITHUB_OWNER_REPO_RE = re.compile(
    r"^(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?$"
)
CODEOWNERS_OWNER_RE = re.compile(r"@[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?")
GITHUB_URL_RE = re.compile(
    r"(?:https?://)?(?:www\.)?github\.com/"
    r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)

SIGNATURE_SUFFIXES = (
    ".sig", ".asc", ".sigstore", ".bundle", ".pem", ".crt", ".cosign",
    ".intoto.jsonl", ".intoto.json",
)
SIGNATURE_FILENAMES = frozenset({
    "provenance.json", "attestation.json",
})

BRANCH_LIKE = frozenset({
    "main", "master", "dev", "develop", "development", "trunk",
    "latest", "head", "default",
})

BOT_LOGINS = frozenset({
    "dependabot", "dependabot[bot]", "renovate", "renovate[bot]",
    "github-actions[bot]", "greenkeeper[bot]", "imgbot[bot]",
    "codecov[bot]", "snyk-bot",
})

INVALID_LICENSE_VALUES = frozenset({
    "", "unknown", "other", "none", "n/a", "na", "null",
})

MAX_HF_FILES_DETAIL = 30
MAX_EVIDENCE_CHARS = 200
WEAK_CHECK_THRESHOLD = 5
CONTRIBUTOR_MIN_COMMITS = 5
CONTRIBUTOR_MAX_MAINTAINERS = 10
REDIRECT_MAX = 5

USER_AGENT = "AIBOM-Guard"
