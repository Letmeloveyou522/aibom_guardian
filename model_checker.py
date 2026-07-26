"""
Collect Hugging Face model metadata and inspect model security signals.

Usage:
    python model_checker.py https://huggingface.co/owner/model
    python model_checker.py owner/model
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any
from urllib.parse import urlparse

try:
    from huggingface_hub import HfApi, hf_hub_download
except ImportError:
    HfApi = None
    hf_hub_download = None

try:
    from picklescan.scanner import SafetyLevel, scan_file_path
except ImportError:
    SafetyLevel = None
    scan_file_path = None


PICKLE_EXTENSIONS = {".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt"}
SAFETENSORS_EXTENSION = ".safetensors"
MODEL_CARD_NAMES = {"readme.md", "modelcard.md", "model_card.md"}
FULL_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


def parse_model_id(value: str) -> str:
    """Return an owner/model ID from a Hugging Face URL or model ID."""
    text = value.strip().rstrip("/")
    if not text:
        raise ValueError("Hugging Face URL or model ID is required")

    if "://" not in text:
        parts = text.split("/")
        if len(parts) == 2 and all(parts):
            return text
        raise ValueError("model ID must have the form 'owner/model'")

    parsed = urlparse(text)
    if parsed.netloc.lower() not in {"huggingface.co", "www.huggingface.co"}:
        raise ValueError("URL must point to huggingface.co")

    parts = [part for part in parsed.path.split("/") if part]
    if parts and parts[0] in {"models", "datasets", "spaces"}:
        if parts[0] != "models":
            raise ValueError("URL must point to a Hugging Face model")
        parts = parts[1:]

    if len(parts) < 2:
        raise ValueError("Hugging Face model URL must include owner and model name")
    return f"{parts[0]}/{parts[1]}"


def _card_to_dict(card_data: Any) -> dict[str, Any]:
    if card_data is None:
        return {}
    if isinstance(card_data, dict):
        return card_data
    if hasattr(card_data, "to_dict"):
        return card_data.to_dict()
    return {
        key: value
        for key, value in vars(card_data).items()
        if not key.startswith("_")
    }


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _metadata_value(
    card: dict[str, Any],
    tags: list[str],
    key: str,
    tag_prefix: str,
) -> Any:
    value = card.get(key)
    if value not in (None, "", []):
        return value
    tagged = [
        tag.split(":", 1)[1]
        for tag in tags
        if isinstance(tag, str) and tag.startswith(tag_prefix)
    ]
    return tagged or None


def _file_names(info: Any) -> list[str]:
    return sorted(
        sibling.rfilename
        for sibling in (getattr(info, "siblings", None) or [])
        if getattr(sibling, "rfilename", None)
    )


def _file_size(info: Any, filename: str) -> int | None:
    for sibling in getattr(info, "siblings", None) or []:
        if getattr(sibling, "rfilename", None) != filename:
            continue
        size = getattr(sibling, "size", None)
        if size is not None:
            return int(size)
        lfs = getattr(sibling, "lfs", None)
        if isinstance(lfs, dict) and lfs.get("size") is not None:
            return int(lfs["size"])
        if getattr(lfs, "size", None) is not None:
            return int(lfs.size)
    return None


def _dangerous_globals(scan_result: Any) -> list[str]:
    dangerous = []
    for item in getattr(scan_result, "globals", None) or []:
        safety = getattr(item, "safety", None)
        is_dangerous = (
            SafetyLevel is not None
            and safety == getattr(SafetyLevel, "Dangerous", object())
        )
        if not is_dangerous and "dangerous" in str(safety).lower():
            is_dangerous = True
        if is_dangerous:
            module = getattr(item, "module", "")
            name = getattr(item, "name", "")
            dangerous.append(".".join(part for part in (module, name) if part))
    return dangerous


def scan_pickle_files(
    model_id: str,
    revision: str,
    info: Any,
    pickle_files: list[str],
    max_file_size: int,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Download pickle-based files and scan them with picklescan."""
    results = []
    issues = []

    if not pickle_files:
        return results, issues
    if scan_file_path is None or hf_hub_download is None:
        issues.append({
            "type": "scan",
            "detail": "picklescan or huggingface_hub is not installed",
        })
        return results, issues

    token = os.environ.get("HF_TOKEN")
    for filename in pickle_files:
        size = _file_size(info, filename)
        if size is not None and size > max_file_size:
            results.append({
                "file": filename,
                "scanned": False,
                "malicious": None,
                "detail": f"file exceeds scan limit ({size} bytes)",
            })
            issues.append({
                "type": "scan",
                "detail": f"pickle scan skipped for {filename}: file is too large",
            })
            continue

        try:
            local_path = hf_hub_download(
                repo_id=model_id,
                filename=filename,
                revision=revision,
                token=token,
            )
            scan_result = scan_file_path(local_path, strict=False)
            dangerous = _dangerous_globals(scan_result)
            malicious = bool(
                dangerous
                or getattr(scan_result, "malicious_found", False)
                or getattr(scan_result, "infected_files", 0)
            )
            scan_error = bool(getattr(scan_result, "scan_err", False))
            results.append({
                "file": filename,
                "scanned": not scan_error,
                "malicious": malicious,
                "dangerous_globals": dangerous,
            })
            if malicious:
                detail = f"pickle file with dangerous opcode: {filename}"
                if dangerous:
                    detail += f" ({', '.join(dangerous)})"
                issues.append({"type": "malicious", "detail": detail})
            elif scan_error:
                issues.append({
                    "type": "scan",
                    "detail": f"picklescan could not fully scan {filename}",
                })
        except Exception as exc:
            results.append({
                "file": filename,
                "scanned": False,
                "malicious": None,
                "detail": str(exc),
            })
            issues.append({
                "type": "scan",
                "detail": f"pickle scan failed for {filename}: {exc}",
            })

    return results, issues


def check_model(
    model_url: str,
    *,
    max_pickle_size_mb: int = 500,
) -> dict[str, Any]:
    """Collect AIBOM metadata and security findings for one HF model."""
    model_id = parse_model_id(model_url)
    issues: list[dict[str, str]] = []

    if HfApi is None or hf_hub_download is None:
        raise RuntimeError(
            "huggingface_hub is required; install it with "
            "'pip install huggingface_hub'"
        )

    api = HfApi(token=os.environ.get("HF_TOKEN"))
    info = api.model_info(model_id, files_metadata=True)
    card = _card_to_dict(getattr(info, "card_data", None))
    tags = list(getattr(info, "tags", None) or [])
    files = _file_names(info)
    commit_sha = getattr(info, "sha", None)

    license_value = _metadata_value(card, tags, "license", "license:")
    if isinstance(license_value, list) and len(license_value) == 1:
        license_value = license_value[0]

    base_models = _as_list(
        _metadata_value(card, tags, "base_model", "base_model:")
    )
    datasets = _as_list(
        _metadata_value(card, tags, "datasets", "dataset:")
    )
    pipeline = (
        getattr(info, "pipeline_tag", None)
        or card.get("pipeline_tag")
        or card.get("pipeline")
    )

    pickle_files = [
        name for name in files
        if os.path.splitext(name.lower())[1] in PICKLE_EXTENSIONS
    ]
    safetensors_files = [
        name for name in files if name.lower().endswith(SAFETENSORS_EXTENSION)
    ]

    model_card = any(
        os.path.basename(name).lower() in MODEL_CARD_NAMES for name in files
    )
    required_card_fields = {
        "license": license_value,
        "base_model": base_models,
        "datasets": datasets,
        "pipeline": pipeline,
    }
    missing_card_fields = [
        key for key, value in required_card_fields.items() if not value
    ]
    model_card_complete = model_card and not missing_card_fields

    if not model_card:
        issues.append({"type": "model_card", "detail": "model card not found"})
    elif missing_card_fields:
        issues.append({
            "type": "model_card",
            "detail": "missing required fields: "
            + ", ".join(missing_card_fields),
        })

    if not commit_sha or not FULL_COMMIT_RE.fullmatch(commit_sha):
        issues.append({
            "type": "revision",
            "detail": "model revision is not resolved to a full commit SHA",
        })

    trust_remote_code = False
    auto_map: Any = None
    if "config.json" in files:
        try:
            config_path = hf_hub_download(
                repo_id=model_id,
                filename="config.json",
                revision=commit_sha,
                token=os.environ.get("HF_TOKEN"),
            )
            with open(config_path, "r", encoding="utf-8") as file:
                config = json.load(file)
            trust_remote_code = bool(config.get("trust_remote_code", False))
            auto_map = config.get("auto_map")
            if trust_remote_code:
                issues.append({
                    "type": "remote_code",
                    "detail": "config.json enables trust_remote_code",
                })
            if auto_map:
                issues.append({
                    "type": "remote_code",
                    "detail": "config.json contains auto_map custom code mappings",
                })
        except (OSError, ValueError, TypeError) as exc:
            issues.append({
                "type": "config",
                "detail": f"could not inspect config.json: {exc}",
            })

    pickle_scan, scan_issues = scan_pickle_files(
        model_id=model_id,
        revision=commit_sha or "main",
        info=info,
        pickle_files=pickle_files,
        max_file_size=max_pickle_size_mb * 1024 * 1024,
    )
    issues.extend(scan_issues)

    return {
        "type": "model",
        "model_name": model_id.split("/", 1)[-1],
        "model_id": model_id,
        "author": getattr(info, "author", None) or model_id.split("/", 1)[0],
        "license": license_value,
        "base_model": base_models,
        "datasets": datasets,
        "pipeline": pipeline,
        "trust_remote_code": trust_remote_code,
        "auto_map": auto_map,
        "model_card": model_card,
        "model_card_complete": model_card_complete,
        "missing_model_card_fields": missing_card_fields,
        "commit_sha": commit_sha,
        "files": files,
        "file_formats": {
            "pickle": pickle_files,
            "safetensors": safetensors_files,
        },
        "pickle_scan": pickle_scan,
        "issues": issues,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect a Hugging Face model for AIBOM metadata and risks."
    )
    parser.add_argument("model", help="Hugging Face model URL or owner/model ID")
    parser.add_argument(
        "--max-pickle-size-mb",
        type=int,
        default=500,
        help="maximum pickle file size to download and scan (default: 500)",
    )
    args = parser.parse_args()

    try:
        result = check_model(
            args.model,
            max_pickle_size_mb=max(args.max_pickle_size_mb, 0),
        )
    except Exception as exc:
        print(json.dumps({
            "type": "model",
            "model_name": None,
            "issues": [{"type": "error", "detail": str(exc)}],
        }, ensure_ascii=False, indent=2))
        return 1

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
