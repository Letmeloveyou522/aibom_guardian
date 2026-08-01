"""
recommendation.py
-----------------------------------
③ 위험 탐지 및 대안 추천 모듈

역할 (팀 Data Protocol):
  - 위험 요소 탐지 + 현황 보고(JSON)만 수행
  - Trust Score / ALLOW|WARNING|BLOCK 최종 판정은 score_engine.py 전담
  - Hugging Face API 호출·라이선스 검사는 각각 ①·④ 모듈 전유물
    → 이 모듈은 그 결과를 *입력*으로만 받아 활용

출력 스키마:
  {
    "issues": [ { "type": "...", "detail": "...", ... } ],
    "alternatives": [
      { "target": "...", "confidence": "confirmed"|"suggested", "reason": "..." }
    ]
  }
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional
from urllib.parse import quote

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"
PYPI_TIMEOUT_SEC = 10

# Typosquatting: 편집거리 허용 범위 (1~2)
TYPO_DISTANCE_MIN = 1
TYPO_DISTANCE_MAX = 2

# Deprecated: 마지막 업로드 기준 (일)
STALE_DAYS_THRESHOLD = 365 * 3  # 3년

# 모델 가중치 파일 중 pickle 계열로 간주하는 확장자
UNSAFE_WEIGHT_SUFFIXES = (".pt", ".pth", ".pkl", ".pickle", ".bin")
SAFE_WEIGHT_SUFFIX = ".safetensors"

# PyPI Top popular 패키지 (하드코딩 상수 — Top ~200 급 대표 목록)
# 정식 등록명만 소문자로 보관. typosquatting 비교 시 normalize 후 사용.
POPULAR_PYPI_PACKAGES: tuple[str, ...] = (
    # web / http
    "requests", "urllib3", "httpx", "aiohttp", "beautifulsoup4", "flask",
    "django", "fastapi", "starlette", "uvicorn", "gunicorn", "werkzeug",
    "jinja2", "markupsafe", "itsdangerous", "click", "bottle", "tornado",
    "pyramid", "sanic", "quart", "httpcore", "h11", "h2", "socks",
    # data / science
    "numpy", "pandas", "scipy", "scikit-learn", "matplotlib", "seaborn",
    "plotly", "sympy", "statsmodels", "numba", "cython", "pillow", "opencv-python",
    "imageio", "networkx", "dask", "xarray", "polars", "pyarrow", "h5py",
    # ml / ai
    "torch", "tensorflow", "keras", "transformers", "datasets", "accelerate",
    "safetensors", "huggingface-hub", "tokenizers", "diffusers", "peft",
    "onnx", "onnxruntime", "xgboost", "lightgbm", "catboost", "optuna",
    "scikit-image", "timm", "sentencepiece", "spacy", "nltk", "gensim",
    # cloud / devops
    "boto3", "botocore", "azure-core", "google-cloud-storage", "kubernetes",
    "docker", "ansible", "paramiko", "fabric", "invoke",
    # build / packaging
    "setuptools", "pip", "wheel", "build", "twine", "poetry", "virtualenv",
    "pipenv", "tox", "nox", "hatch", "flit", "packaging", "pkginfo",
    # testing / quality
    "pytest", "pytest-cov", "coverage", "unittest2", "nose", "hypothesis",
    "faker", "mock", "responses", "freezegun", "black", "isort", "flake8",
    "pylint", "mypy", "ruff", "bandit", "pre-commit",
    # utils
    "pyyaml", "ruamel.yaml", "toml", "tomli", "jsonschema", "orjson",
    "ujson", "msgpack", "protobuf", "attrs", "pydantic", "dataclasses-json",
    "python-dateutil", "pytz", "arrow", "pendulum", "tenacity", "retry",
    "tqdm", "rich", "colorama", "tabulate", "prettytable", "loguru",
    "structlog", "sentry-sdk", "psutil", "pathlib2", "filelock", "watchdog",
    "cryptography", "pycryptodome", "pyjwt", "oauthlib", "authlib",
    "sqlalchemy", "alembic", "psycopg2-binary", "pymysql", "redis",
    "celery", "kombu", "amqp", "pymongo", "elasticsearch", "lxml",
    "html5lib", "chardet", "charset-normalizer", "idna", "certifi",
    "six", "future", "typing-extensions", "importlib-metadata",
    "zipp", "platformdirs", "appdirs", "dotenv", "python-dotenv",
    "click-plugins", "pluggy", "iniconfig", "py", "tomlkit",
    "markdown", "docutils", "sphinx", "mkdocs", "jupyter", "notebook",
    "ipython", "ipykernel", "jupyterlab", "nbformat", "nbconvert",
)


# ---------------------------------------------------------------------------
# 1) String distance
# ---------------------------------------------------------------------------

def levenshtein_distance(a: str, b: str) -> int:
    """
    Classic Wagner–Fischer Levenshtein distance (edit distance).

    Operations counted: insert / delete / substitute (each cost 1).
    Optimized to O(min(n,m)) memory via two rolling rows.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    # Ensure b is the shorter string to minimize memory
    if len(a) < len(b):
        a, b = b, a

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (0 if ca == cb else 1)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def normalize_package_name(name: str) -> str:
    """
    PEP 503 normalization: lowercase, replace runs of [-_.] with '-'.
    Comparison / popular-list matching should use this form.
    """
    import re

    normalized = name.strip().lower().replace("_", "-").replace(".", "-")
    return re.sub(r"-+", "-", normalized)


# ---------------------------------------------------------------------------
# 2) PyPI client (sync + async)
# ---------------------------------------------------------------------------

@dataclass
class PyPIPackageInfo:
    """Normalized subset of https://pypi.org/pypi/{pkg}/json."""

    name: str
    exists: bool
    latest_version: Optional[str] = None
    yanked_versions: dict[str, str] = field(default_factory=dict)  # ver -> reason
    last_upload: Optional[datetime] = None
    raw: Optional[dict[str, Any]] = None
    error: Optional[str] = None


class PyPIClient:
    """
    Thin wrapper around the PyPI JSON API.

    Sync methods use `requests` (same stack as osv_client.py).
    Async methods run sync calls in a thread pool so we can batch-check
    many packages without adding aiohttp as a hard dependency.
    """

    def __init__(
        self,
        session: Optional[requests.Session] = None,
        timeout: float = PYPI_TIMEOUT_SEC,
    ) -> None:
        self._session = session or requests.Session()
        self._owns_session = session is None
        self.timeout = timeout

    def close(self) -> None:
        if self._owns_session:
            self._session.close()

    def __enter__(self) -> "PyPIClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ---- sync -------------------------------------------------------------

    def get_package(self, package_name: str) -> PyPIPackageInfo:
        """
        GET /pypi/{package}/json

        - 200 → exists=True (+ metadata)
        - 404 → exists=False  (hallucination candidate)
        - other errors → exists=False with error message (caller may skip)
        """
        url = PYPI_JSON_URL.format(package=quote(package_name, safe=""))
        try:
            resp = self._session.get(url, timeout=self.timeout)
        except requests.exceptions.RequestException as exc:
            return PyPIPackageInfo(
                name=package_name, exists=False, error=f"network: {exc}"
            )

        if resp.status_code == 404:
            return PyPIPackageInfo(name=package_name, exists=False)

        if resp.status_code != 200:
            return PyPIPackageInfo(
                name=package_name,
                exists=False,
                error=f"http {resp.status_code}",
            )

        try:
            data = resp.json()
        except ValueError as exc:
            return PyPIPackageInfo(
                name=package_name, exists=False, error=f"invalid json: {exc}"
            )

        return self._parse_package_json(package_name, data)

    def get_packages(self, names: Iterable[str]) -> dict[str, PyPIPackageInfo]:
        """Sequential sync batch lookup."""
        return {name: self.get_package(name) for name in names}

    # ---- async ------------------------------------------------------------

    async def aget_package(self, package_name: str) -> PyPIPackageInfo:
        """Async wrapper — offloads blocking HTTP to a worker thread."""
        return await asyncio.to_thread(self.get_package, package_name)

    async def aget_packages(
        self, names: Iterable[str], concurrency: int = 8
    ) -> dict[str, PyPIPackageInfo]:
        """
        Concurrent async batch lookup with a simple semaphore throttle
        so we don't hammer pypi.org.
        """
        sem = asyncio.Semaphore(concurrency)
        results: dict[str, PyPIPackageInfo] = {}

        async def _one(name: str) -> None:
            async with sem:
                results[name] = await self.aget_package(name)

        await asyncio.gather(*(_one(n) for n in names))
        return results

    # ---- parsing ----------------------------------------------------------

    @staticmethod
    def _parse_package_json(package_name: str, data: dict[str, Any]) -> PyPIPackageInfo:
        info = data.get("info") or {}
        releases = data.get("releases") or {}

        latest = info.get("version")
        yanked: dict[str, str] = {}
        last_upload: Optional[datetime] = None

        for ver, files in releases.items():
            if not isinstance(files, list):
                continue
            for f in files:
                if not isinstance(f, dict):
                    continue
                if f.get("yanked"):
                    reason = f.get("yanked_reason") or "yanked"
                    yanked[ver] = str(reason)
                upload_raw = f.get("upload_time_iso_8601") or f.get("upload_time")
                if upload_raw:
                    dt = _parse_pypi_time(upload_raw)
                    if dt and (last_upload is None or dt > last_upload):
                        last_upload = dt

        return PyPIPackageInfo(
            name=info.get("name") or package_name,
            exists=True,
            latest_version=latest,
            yanked_versions=yanked,
            last_upload=last_upload,
            raw=data,
        )


def _parse_pypi_time(raw: str) -> Optional[datetime]:
    raw = raw.strip()
    # PyPI ISO: 2024-01-15T12:34:56.123456Z
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(raw.replace("+00:00", "Z"), fmt).replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            continue
    try:
        # Fallback: date-only from upload_time "2024-01-15T12:34:56"
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# 3) Issue detectors
# ---------------------------------------------------------------------------

def detect_typosquatting(
    package_name: str,
    popular: Iterable[str] = POPULAR_PYPI_PACKAGES,
    min_distance: int = TYPO_DISTANCE_MIN,
    max_distance: int = TYPO_DISTANCE_MAX,
    *,
    package_exists: Optional[bool] = None,
) -> list[dict[str, Any]]:
    """
    Flag names that are edit-distance 1~2 from a popular package,
    but are NOT themselves that popular package.

    If `package_exists` is False (hallucination), still report typo matches
    so the caller can recommend the official name.
    If `package_exists` is True and the name normalizes to a popular package,
    it is treated as the real package → no typo issue.
    """
    issues: list[dict[str, Any]] = []
    needle = normalize_package_name(package_name)
    popular_norm = {normalize_package_name(p): p for p in popular}

    # Exact match against the allowlist → legitimate popular package
    if needle in popular_norm:
        return issues

    # Optional early-exit: if caller already confirmed this is the real
    # PyPI project for that spelling, we still check near-matches
    # (typosquat packages often *do* exist on PyPI).

    matches: list[tuple[int, str]] = []
    for norm, original in popular_norm.items():
        # Length gate: edit distance > |len diff| is impossible; also skip
        # if length gap already exceeds max_distance.
        if abs(len(needle) - len(norm)) > max_distance:
            continue
        dist = levenshtein_distance(needle, norm)
        if min_distance <= dist <= max_distance:
            matches.append((dist, original))

    matches.sort(key=lambda x: (x[0], x[1]))
    # Deduplicate by official name; keep closest only per official pkg
    seen: set[str] = set()
    for dist, official in matches:
        key = normalize_package_name(official)
        if key in seen:
            continue
        seen.add(key)
        issues.append(
            {
                "type": "typosquatting",
                "detail": (
                    f"Package '{package_name}' is similar to official package "
                    f"'{official}' (edit distance={dist})"
                ),
                "official_package": official,
                "distance": dist,
            }
        )
    return issues


def detect_hallucination(package_info: PyPIPackageInfo) -> list[dict[str, Any]]:
    """HTTP 404 / non-existent package → AI-hallucinated dependency."""
    if package_info.exists:
        return []
    # Network / 5xx: do not claim hallucination — leave to caller logs
    if package_info.error:
        return [
            {
                "type": "hallucination",
                "detail": (
                    f"Could not verify package '{package_info.name}' on PyPI "
                    f"({package_info.error}); treat as unresolved."
                ),
                "verified": False,
            }
        ]
    return [
        {
            "type": "hallucination",
            "detail": (
                f"Package '{package_info.name}' does not exist on PyPI "
                f"(possible AI-hallucinated dependency)."
            ),
            "verified": True,
        }
    ]


def detect_deprecated(
    package_info: PyPIPackageInfo,
    version: Optional[str] = None,
    stale_days: int = STALE_DAYS_THRESHOLD,
) -> list[dict[str, Any]]:
    """
    Detect yanked versions and long-unmaintained packages.

    Uses issue type \"malicious\" is reserved for supply-chain malware;
    deprecated/yanked findings use a free-form detail with type hint
    via \"provenance\" (supply-chain hygiene) per team vocabulary.
    """
    issues: list[dict[str, Any]] = []
    if not package_info.exists:
        return issues

    if version and version in package_info.yanked_versions:
        reason = package_info.yanked_versions[version]
        issues.append(
            {
                "type": "provenance",
                "detail": (
                    f"Version '{version}' of '{package_info.name}' is yanked "
                    f"on PyPI ({reason})."
                ),
                "yanked": True,
            }
        )

    if package_info.last_upload is not None:
        age_days = (datetime.now(timezone.utc) - package_info.last_upload).days
        if age_days >= stale_days:
            issues.append(
                {
                    "type": "provenance",
                    "detail": (
                        f"Package '{package_info.name}' appears unmaintained "
                        f"(last upload {age_days} days ago)."
                    ),
                    "stale_days": age_days,
                }
            )
    return issues


# ---------------------------------------------------------------------------
# 4) Alternative recommenders
# ---------------------------------------------------------------------------

def recommend_package_alternatives(
    package_name: str,
    version: Optional[str],
    issues: list[dict[str, Any]],
    package_info: Optional[PyPIPackageInfo],
    *,
    has_cve: bool = False,
) -> list[dict[str, Any]]:
    """
    confidence=\"confirmed\" recommendations:
      - typosquat → official package name
      - CVE / yanked → latest non-yanked PyPI version
    """
    alts: list[dict[str, Any]] = []
    seen_targets: set[str] = set()

    def _add(target: str, reason: str) -> None:
        if target in seen_targets:
            return
        seen_targets.add(target)
        alts.append(
            {
                "target": target,
                "confidence": "confirmed",
                "reason": reason,
            }
        )

    for issue in issues:
        if issue.get("type") == "typosquatting" and issue.get("official_package"):
            official = issue["official_package"]
            _add(
                official,
                f"Correct typosquat '{package_name}' -> official '{official}'",
            )

    if package_info and package_info.exists and package_info.latest_version:
        latest = package_info.latest_version
        # Prefer latest that is not yanked
        if latest in package_info.yanked_versions:
            # walk releases by version string order is unreliable;
            # fall back to info.version only if not yanked — else skip
            latest = None
        if latest and (has_cve or (version and version != latest)):
            if has_cve:
                _add(
                    f"{package_info.name}=={latest}",
                    "Upgrade to latest safe release",
                )
            elif version and version in (package_info.yanked_versions or {}):
                _add(
                    f"{package_info.name}=={latest}",
                    "Replace yanked version with latest release",
                )

    return alts


def recommend_model_alternatives(
    model_check_result: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    confidence=\"suggested\" recommendations from ① model_checker output.

    Expected input keys (flexible / best-effort):
      - model_id / id: Hugging Face repo id
      - files / filenames: list of weight filenames
      - has_safetensors: bool (optional)
      - task / pipeline_tag: e.g. \"text-generation\"
      - issues: upstream issues (cve / malicious / license ...)
      - suggested_models: optional list from model_checker
    """
    alts: list[dict[str, Any]] = []
    model_id = (
        model_check_result.get("model_id")
        or model_check_result.get("id")
        or model_check_result.get("name")
        or "unknown-model"
    )
    files = (
        model_check_result.get("files")
        or model_check_result.get("filenames")
        or model_check_result.get("siblings")
        or []
    )
    # siblings may be list[dict]
    filenames: list[str] = []
    for f in files:
        if isinstance(f, str):
            filenames.append(f)
        elif isinstance(f, dict):
            filenames.append(str(f.get("rfilename") or f.get("filename") or ""))

    has_pickle = any(
        name.lower().endswith(UNSAFE_WEIGHT_SUFFIXES) for name in filenames if name
    )
    has_safetensors = bool(model_check_result.get("has_safetensors")) or any(
        name.lower().endswith(SAFE_WEIGHT_SUFFIX) for name in filenames if name
    )

    if has_pickle and not has_safetensors:
        alts.append(
            {
                "target": f"{model_id} (safetensors)",
                "confidence": "suggested",
                "reason": "Replace unsafe pickle format with safetensors release",
            }
        )
    elif has_pickle and has_safetensors:
        alts.append(
            {
                "target": f"{model_id} (safetensors)",
                "confidence": "suggested",
                "reason": "Prefer safetensors weights over pickle (.pt/.bin/.pkl)",
            }
        )

    upstream_issues = model_check_result.get("issues") or []
    critical = any(
        str(i.get("severity", "")).lower() == "critical"
        or i.get("type") in ("malicious", "cve")
        and str(i.get("severity", "")).lower() in ("critical", "high")
        for i in upstream_issues
        if isinstance(i, dict)
    )
    # Also honor explicit flags from model_checker
    if model_check_result.get("is_malicious") or model_check_result.get("license_blocked"):
        critical = True

    if critical:
        for cand in model_check_result.get("suggested_models") or []:
            if isinstance(cand, str):
                target = cand
                reason = "Safer alternative model for the same task"
            elif isinstance(cand, dict):
                target = cand.get("model_id") or cand.get("id") or str(cand)
                reason = cand.get("reason") or "Safer alternative model for the same task"
            else:
                continue
            if not str(target).lower().endswith("safetensors"):
                target = f"{target} (safetensors)"
            alts.append(
                {
                    "target": target,
                    "confidence": "suggested",
                    "reason": reason,
                }
            )
        # Generic fallback if ① didn't supply candidates
        if not model_check_result.get("suggested_models"):
            task = model_check_result.get("task") or model_check_result.get("pipeline_tag")
            task_hint = f" for task '{task}'" if task else ""
            alts.append(
                {
                    "target": f"<clean-safetensors alternative{task_hint}>",
                    "confidence": "suggested",
                    "reason": (
                        "Critical CVE / malicious / blocked-license model detected; "
                        "switch to a trusted safetensors model for the same task"
                    ),
                }
            )

    return alts


# ---------------------------------------------------------------------------
# 5) Orchestrator (public API)
# ---------------------------------------------------------------------------

@dataclass
class RecommendationResult:
    issues: list[dict[str, Any]] = field(default_factory=list)
    alternatives: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"issues": self.issues, "alternatives": self.alternatives}


class RecommendationEngine:
    """
    Entry point used by scanner / MCP / score_engine callers.

    Usage:
        engine = RecommendationEngine()
        result = engine.analyze_package("reqeusts", version=None)
        result = engine.analyze_package(
            "requests", version="2.28.0", cve_issues=[...]
        )
        result = engine.analyze_model(model_checker_output)
    """

    def __init__(
        self,
        pypi_client: Optional[PyPIClient] = None,
        popular_packages: Iterable[str] = POPULAR_PYPI_PACKAGES,
    ) -> None:
        self.pypi = pypi_client or PyPIClient()
        self.popular_packages = tuple(popular_packages)

    def analyze_package(
        self,
        package_name: str,
        version: Optional[str] = None,
        *,
        cve_issues: Optional[list[dict[str, Any]]] = None,
        skip_pypi: bool = False,
    ) -> dict[str, Any]:
        """
        Full package risk scan → {issues, alternatives}.

        `cve_issues`: optional pre-fetched OSV findings from osv_client
        (type=cve). Passed through into issues and used to trigger
        confirmed version-upgrade alternatives.
        """
        issues: list[dict[str, Any]] = []
        cve_issues = list(cve_issues or [])

        package_info: Optional[PyPIPackageInfo] = None
        if not skip_pypi:
            package_info = self.pypi.get_package(package_name)
            issues.extend(detect_hallucination(package_info))
            issues.extend(detect_deprecated(package_info, version=version))

        exists_flag = None if package_info is None else package_info.exists
        issues.extend(
            detect_typosquatting(
                package_name,
                popular=self.popular_packages,
                package_exists=exists_flag,
            )
        )

        # Merge upstream CVE issues (already team-standard from osv_client)
        for cve in cve_issues:
            item = dict(cve)
            item.setdefault("type", "cve")
            issues.append(item)

        has_cve = any(i.get("type") == "cve" for i in issues)
        alternatives = recommend_package_alternatives(
            package_name,
            version,
            issues,
            package_info,
            has_cve=has_cve,
        )

        return RecommendationResult(issues=issues, alternatives=alternatives).to_dict()

    async def aanalyze_packages(
        self,
        packages: list[tuple[str, Optional[str]]],
        *,
        concurrency: int = 8,
    ) -> dict[str, dict[str, Any]]:
        """
        Async batch helper.
        `packages`: list of (name, version).
        """
        names = [n for n, _ in packages]
        infos = await self.pypi.aget_packages(names, concurrency=concurrency)

        out: dict[str, dict[str, Any]] = {}
        for name, version in packages:
            info = infos[name]
            issues: list[dict[str, Any]] = []
            issues.extend(detect_hallucination(info))
            issues.extend(detect_deprecated(info, version=version))
            issues.extend(
                detect_typosquatting(
                    name,
                    popular=self.popular_packages,
                    package_exists=info.exists,
                )
            )
            alts = recommend_package_alternatives(
                name, version, issues, info, has_cve=False
            )
            out[name] = RecommendationResult(issues=issues, alternatives=alts).to_dict()
        return out

    def analyze_model(self, model_check_result: dict[str, Any]) -> dict[str, Any]:
        """
        Consume ① model_checker.py output. Does NOT call Hugging Face.
        Passes through any issues already found, appends suggested alts.
        """
        issues = list(model_check_result.get("issues") or [])
        alternatives = recommend_model_alternatives(model_check_result)
        return RecommendationResult(issues=issues, alternatives=alternatives).to_dict()


# ---------------------------------------------------------------------------
# CLI self-check
# ---------------------------------------------------------------------------

def _self_check() -> None:
    assert levenshtein_distance("requests", "requests") == 0
    assert levenshtein_distance("requests", "reqeusts") == 2  # eu ↔ ue transposition-ish
    assert levenshtein_distance("requests", "requets") == 1
    assert levenshtein_distance("", "abc") == 3

    typos = detect_typosquatting("reqeusts")
    assert any(i["type"] == "typosquatting" for i in typos), typos
    assert any(i.get("official_package") == "requests" for i in typos), typos

    # Exact popular name must NOT be flagged
    assert detect_typosquatting("requests") == []

    print("Levenshtein / typosquat self-check: OK")

    with PyPIClient() as client:
        t0 = time.time()
        real = client.get_package("requests")
        fake = client.get_package("this-package-definitely-does-not-exist-xyz-aibom")
        elapsed = time.time() - t0

    assert real.exists and real.latest_version
    assert not fake.exists and fake.error is None
    hallu = detect_hallucination(fake)
    assert hallu and hallu[0]["type"] == "hallucination"
    print(f"PyPI sync lookup self-check: OK ({elapsed:.2f}s)")
    print(f"  requests latest = {real.latest_version}")

    async def _async_smoke() -> None:
        with PyPIClient() as client:
            batch = await client.aget_packages(
                ["numpy", "pandas", "not-a-real-pkg-zzz-aibom"], concurrency=3
            )
        assert batch["numpy"].exists
        assert batch["pandas"].exists
        assert not batch["not-a-real-pkg-zzz-aibom"].exists
        print("PyPI async batch self-check: OK")

    asyncio.run(_async_smoke())

    engine = RecommendationEngine()
    report = engine.analyze_package("reqeusts")
    print("analyze_package('reqeusts') →")
    import json

    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    _self_check()
