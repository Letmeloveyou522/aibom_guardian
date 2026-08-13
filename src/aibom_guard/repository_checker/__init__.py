"""
repository_checker
-----------------------------------
Checks the provenance and supply-chain trustworthiness of packages,
GitHub repositories, and Hugging Face models/datasets.

Public entry point:
    check_repository(target, ...) -> dict

Also usable as a CLI:
    python -m aibom_guard.repository_checker https://github.com/pallets/flask

Split by target ecosystem rather than by layer:

    _constants.py     allow-lists, API roots, regexes, thresholds
    _helpers.py       issue/error records, date and revision normalisation
    _http.py          SSRF guard + the client that enforces it
    _targets.py       works out what the caller pointed at
    _evidence.py      hashes, signatures, CODEOWNERS, GitHub URL extraction
    _datasets.py      dataset card section coverage (English + Korean)
    _scoring.py       repository trust score
    _github.py        GitHubMixin
    _huggingface.py   HuggingFaceMixin
    _pypi.py          PyPIMixin
    _provenance.py    ProvenanceMixin (local files, cosign)
    _checker.py       RepositoryChecker - composes the mixins, routes check()
    _api.py           check_repository()
    _cli.py           argument parsing for standalone use

The submodules are private; everything public is re-exported below, including
the stdlib names tests patch through this namespace
(``patch("aibom_guard.repository_checker.socket.getaddrinfo")``).
"""

from __future__ import annotations

# Re-exported so existing patch targets and callers keep resolving.
import argparse
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ._api import _resolve_target, check_repository
from ._checker import RepositoryChecker
from ._cli import _build_arg_parser, main
from ._constants import (
    ALLOWED_HOSTS,
    ALLOWED_HTTP_PORTS,
    ALLOWED_PORTS,
    BOT_LOGINS,
    BRANCH_LIKE,
    CODEOWNERS_OWNER_RE,
    COMMIT_SHA_RE,
    CONTRIBUTOR_MAX_MAINTAINERS,
    CONTRIBUTOR_MIN_COMMITS,
    GITHUB_API,
    GITHUB_OWNER_REPO_RE,
    GITHUB_URL_RE,
    HEX64_RE,
    HF_API,
    INVALID_LICENSE_VALUES,
    MAX_EVIDENCE_CHARS,
    MAX_HF_FILES_DETAIL,
    OPENSSF_API,
    PYPI_API,
    PYPI_SPEC_RE,
    REDIRECT_MAX,
    SHORT_SHA_RE,
    SIGNATURE_FILENAMES,
    SIGNATURE_SUFFIXES,
    USER_AGENT,
    WEAK_CHECK_THRESHOLD,
)
from ._datasets import (
    _extract_dataset_license,
    _extract_section,
    _section_documented,
    check_dataset_documentation,
)
from ._evidence import (
    _github_root_from_url,
    _looks_like_signature,
    _normalize_sha256,
    _redact_sensitive,
    calculate_sha256,
    estimate_maintainers_from_contributors,
    extract_github_candidates,
    parse_codeowners,
)
from ._helpers import (
    _classify_revision,
    _days_since,
    _error,
    _is_commit_sha,
    _issue,
    _normalize_date,
    _normalize_pypi_name,
    _parse_datetime,
    _safe_path_for_log,
)
from ._http import (
    _NAT64_WELL_KNOWN_PREFIX,
    _build_session,
    _embedded_ipv4,
    _is_blocked_ip,
    SafeHTTPClient,
    SSRFError,
    validate_public_url,
)
from ._scoring import calculate_trust_score, evaluate_provenance
from ._targets import _parse_pypi_target, detect_target_type

logger = logging.getLogger(__name__)

# What callers should actually use.
__all__ = [
    "RepositoryChecker",
    "SSRFError",
    "SafeHTTPClient",
    "calculate_sha256",
    "calculate_trust_score",
    "check_dataset_documentation",
    "check_repository",
    "detect_target_type",
    "estimate_maintainers_from_contributors",
    "evaluate_provenance",
    "extract_github_candidates",
    "main",
    "parse_codeowners",
    "validate_public_url",
]

# Everything else the flat module used to expose, listed so the split is
# invisible from the outside. Constants and private helpers were reachable
# here before, and the stdlib names matter because tests patch through this
# namespace - `patch("aibom_guard.repository_checker.shutil.which")` has to
# keep resolving. Nothing new is published; this only stops the move from
# quietly narrowing the surface.
__all__ += [
    # constants
    "ALLOWED_HOSTS", "ALLOWED_HTTP_PORTS", "ALLOWED_PORTS", "BOT_LOGINS",
    "BRANCH_LIKE",
    "CODEOWNERS_OWNER_RE", "COMMIT_SHA_RE", "CONTRIBUTOR_MAX_MAINTAINERS",
    "CONTRIBUTOR_MIN_COMMITS", "GITHUB_API", "GITHUB_OWNER_REPO_RE",
    "GITHUB_URL_RE", "HEX64_RE", "HF_API", "INVALID_LICENSE_VALUES",
    "MAX_EVIDENCE_CHARS", "MAX_HF_FILES_DETAIL", "OPENSSF_API", "PYPI_API",
    "PYPI_SPEC_RE", "REDIRECT_MAX", "SHORT_SHA_RE", "SIGNATURE_FILENAMES",
    "SIGNATURE_SUFFIXES", "USER_AGENT", "WEAK_CHECK_THRESHOLD",
    # internal helpers that were importable from the flat module
    "_NAT64_WELL_KNOWN_PREFIX", "_build_arg_parser", "_build_session",
    "_classify_revision", "_days_since", "_embedded_ipv4", "_error",
    "_extract_dataset_license", "_extract_section", "_github_root_from_url",
    "_is_blocked_ip", "_is_commit_sha", "_issue", "_looks_like_signature",
    "_normalize_date", "_normalize_pypi_name", "_normalize_sha256",
    "_parse_datetime", "_parse_pypi_target", "_redact_sensitive",
    "_resolve_target", "_safe_path_for_log", "_section_documented",
    # stdlib re-exports, kept for patch targets
    "Any", "HTTPAdapter", "Path", "Retry", "argparse", "datetime", "hashlib",
    "ipaddress", "json", "logging", "os", "re", "requests", "shutil",
    "socket", "subprocess", "timezone", "urljoin", "urlparse",
]
