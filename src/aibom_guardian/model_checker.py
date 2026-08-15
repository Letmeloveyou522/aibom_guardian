"""
model_checker.py
-----------------------------------
AIBOM-Guardian - AI model information collector (Hugging Face).

Takes a Hugging Face model URL (or `owner/model`) and collects everything
an AI Bill of Materials needs:

  1) Model name / author / license
  2) Base model / datasets / pipeline (task) / commit SHA
  3) File list -> pickle vs safetensors
  4) picklescan on the pickle files (dangerous opcodes / globals)
  5) config.json -> trust_remote_code, auto_map
  6) Model card presence + required fields

Usage:
    python -m aibom_guardian.model_checker https://huggingface.co/facebook/bart-base
    python -m aibom_guardian.model_checker facebook/bart-base --max-pickle-size-mb 0
    python -m aibom_guardian.model_checker org/model --revision v1.0 --json out.json

Exit codes (so this can gate a CI pipeline):
    0  collected, no blocking issue
    1  collection failed (bad URL / not found / no access / no network)
    2  collected, but a HIGH severity issue was found

Requires huggingface_hub and picklescan (see requirements.txt).

This collector is shared by the standalone CLI, ``aibom-guardian --model`` and
MCP ``check_model``. Scoring fields (verdict, license_status) are added later
by ``scanner.scan_model``.
"""

import argparse
import json
import logging
import os
import posixpath
import re
import sys
from urllib.parse import unquote, urlsplit

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HUB_HOSTS = {"huggingface.co", "www.huggingface.co", "hf.co"}

# First path segments on huggingface.co that are site features, not user
# namespaces. Without this, ".../datasets/squad" parses as the model
# "datasets/squad" and we would happily scan the wrong thing.
RESERVED_NAMESPACES = {
    "datasets", "spaces", "models", "docs", "blog", "papers", "posts",
    "collections", "organizations", "settings", "pricing", "join", "login",
    "search", "chat", "learn", "tasks", "api", "new", "notifications",
}

# Segments that introduce a revision inside a repo URL.
REVISION_MARKERS = {"tree", "blob", "resolve", "commit", "raw"}

# Pickle-based formats. Unpickling runs a small stack VM whose REDUCE
# opcode calls arbitrary callables, so torch.load() on an untrusted file
# in this list is remote code execution. This is the core reason the tool
# exists.
PICKLE_EXTENSIONS = {".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle",
                     ".joblib", ".dill"}

SAFETENSORS_EXTENSIONS = {".safetensors"}

# Other weight formats, with the risk of *loading* them.
OTHER_WEIGHT_EXTENSIONS = {
    ".gguf": "SAFE", ".ggml": "SAFE", ".msgpack": "SAFE",
    ".onnx": "LOW", ".ort": "LOW", ".tflite": "LOW", ".mlmodel": "LOW",
    ".h5": "MEDIUM", ".hdf5": "MEDIUM", ".keras": "MEDIUM", ".pb": "MEDIUM",
    ".npy": "MEDIUM", ".npz": "MEDIUM", ".ot": "MEDIUM",
}

# Model card YAML fields an AIBOM needs, and their weight in the score.
REQUIRED_CARD_FIELDS = (
    ("license", 30), ("pipeline_tag", 15), ("library_name", 10),
    ("base_model", 15), ("datasets", 15), ("language", 10), ("tags", 5),
)

# Placeholders in the Hugging Face "Create model card" template. A card
# full of these is not a filled-in card.
PLACEHOLDER_RE = re.compile(
    r"\[More Information Needed\]|\[optional\]|\{\{\s*[\w_]+\s*\}\}",
    re.IGNORECASE,
)

# Sharded checkpoints: "model-00002-of-00007.safetensors"
SHARD_RE = re.compile(r"-\d{5}-of-\d{5}$")

# Filenames a model card can have. Checking only README.md misses the repos
# that name it modelcard.md or model_card.md, and reports them as having no
# card at all.
MODEL_CARD_NAMES = ("README.md", "readme.md", "README.MD",
                    "modelcard.md", "ModelCard.md",
                    "model_card.md", "MODEL_CARD.md")

# The Hub should resolve a revision to a 40-hex commit SHA. Anything else
# means the report is pinned to something that can move under it.
FULL_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)

# Filename stems that mean the same checkpoint in different frameworks.
STEM_ALIASES = {"pytorch_model": "model", "tf_model": "model",
                "flax_model": "model", "model": "model"}

DEFAULT_MAX_PICKLE_MB = 512


# ---------------------------------------------------------------------------
# 1) Input: Hugging Face URL -> model id
# ---------------------------------------------------------------------------

def parse_model_id(raw):
    """
    Turn a Hugging Face URL or bare `owner/model` into (model_id, revision).

    Accepts:
        https://huggingface.co/facebook/bart-base
        https://huggingface.co/gpt2                     (canonical, no owner)
        https://hf.co/org/model/tree/v1.0
        https://huggingface.co/org/model/blob/main/config.json
        huggingface.co/org/model
        org/model@abc1234
        org/model
        gpt2

    Raises ValueError on dataset/Space/doc URLs and non-Hub hosts, so a
    wrong paste fails loudly here instead of as a confusing 404 later.
    """
    if raw is None or not str(raw).strip():
        raise ValueError("No model reference supplied.")

    raw = str(raw).strip()
    candidate = raw

    if "://" not in candidate and candidate.lower().startswith(
        tuple(h + "/" for h in HUB_HOSTS)
    ):
        candidate = "https://" + candidate

    if "://" in candidate:
        parts = urlsplit(candidate)
        if parts.scheme not in ("http", "https"):
            raise ValueError(f"Unsupported URL scheme in '{raw}'.")
        host = parts.netloc.split("@")[-1].split(":")[0].lower()
        if host not in HUB_HOSTS:
            raise ValueError(
                f"'{host}' is not a Hugging Face host. Only huggingface.co "
                f"model repositories are supported."
            )
        path = parts.path
    else:
        path = candidate

    path = path.split("?", 1)[0].split("#", 1)[0]
    segments = [unquote(s) for s in path.split("/") if s]
    if not segments:
        raise ValueError(f"'{raw}' contains no repository path.")

    # git-style pin: org/model@revision
    revision = None
    if segments[-1].count("@") == 1:
        head, _, tail = segments[-1].partition("@")
        if head and tail:
            segments[-1], revision = head, tail

    if segments[0].lower() in RESERVED_NAMESPACES:
        raise ValueError(
            f"'{raw}' is a Hugging Face site page (dataset / Space / docs), "
            f"not a model repository."
        )

    if len(segments) >= 2 and segments[1] not in REVISION_MARKERS:
        model_id, tail = f"{segments[0]}/{segments[1]}", segments[2:]
    else:
        model_id, tail = segments[0], segments[1:]

    # /tree/<rev>, /blob/<rev>/<file>, and the awkward refs/pr/3 form where
    # the revision itself contains slashes.
    if tail and tail[0] in REVISION_MARKERS and len(tail) > 1:
        rest = tail[1:]
        if rest[0] == "refs" and len(rest) >= 3:
            revision = revision or "/".join(rest[:3])
        else:
            revision = revision or rest[0]

    for part in model_id.split("/"):
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,94}[A-Za-z0-9]$|^[A-Za-z0-9]$",
                        part):
            raise ValueError(f"Invalid repository name '{part}' in '{raw}'.")

    return model_id, revision


# ---------------------------------------------------------------------------
# 2) Metadata helpers
# ---------------------------------------------------------------------------

def _as_list(value):
    """Normalise a str | list | None metadata field into a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if v is not None and str(v).strip()]
    return [str(value)]


def _card_dict(info):
    """
    Model card YAML frontmatter as a plain dict.

    huggingface_hub returns a ModelCardData object, NOT a Mapping -
    dict(card_data) raises KeyError. Use .to_dict() with fallbacks so this
    keeps working across hub versions.
    """
    card = getattr(info, "card_data", None) or getattr(info, "cardData", None)
    if card is None:
        return {}
    if isinstance(card, dict):
        return dict(card)
    if callable(getattr(card, "to_dict", None)):
        try:
            result = card.to_dict()
            if isinstance(result, dict):
                return result
        except Exception as exc:  # noqa: BLE001 - metadata shape must not break a scan
            logger.debug(
                "card_data.to_dict() failed (%s); falling back to vars()",
                type(exc).__name__,
            )
    return {k: v for k, v in vars(card).items() if not k.startswith("_")}


def _metadata_value(info, card, field, tag_prefix=None):
    """
    Read one metadata field, merging the card frontmatter with the tags.

    The Hub expresses the same fact in several ways depending on how old
    the repo is and which tool published it:

        license   -> cardData["license"]  OR  tag "license:apache-2.0"
        datasets  -> cardData["datasets"] OR  tags "dataset:squad"
        base_model-> cardData["base_model"] OR "base_model:quantized:org/m"

    Reading only one source loses data on a large share of real repos, so
    this merges both and de-duplicates, preserving order.
    """
    values = _as_list(card.get(field))

    if tag_prefix:
        for tag in _as_list(getattr(info, "tags", None)):
            if tag.lower().startswith(tag_prefix):
                remainder = tag[len(tag_prefix):].strip()
                if remainder:
                    values.append(remainder)

    seen, result = set(), []
    for value in values:
        if value.lower() not in seen:
            seen.add(value.lower())
            result.append(value)
    return result


def _base_models(info, card):
    """
    Declared parent models, with the relation when the Hub gives one.

    The tag family is `base_model:<relation>:<repo>` where relation is one
    of finetune / quantized / merge / adapter. It matters because a
    quantized child inherits the parent's license and training data.
    """
    relations = {"finetune", "quantized", "merge", "adapter", "preference"}
    results, seen = [], set()

    for repo_id in _as_list(card.get("base_model")):
        if repo_id.lower() not in seen:
            seen.add(repo_id.lower())
            results.append({"repo_id": repo_id,
                            "relation": card.get("base_model_relation")})

    for tag in _as_list(getattr(info, "tags", None)):
        if not tag.lower().startswith("base_model:"):
            continue
        remainder = tag[len("base_model:"):]
        head, sep, tail = remainder.partition(":")
        relation, repo_id = (head.lower(), tail) if sep and head.lower() in relations \
            else (None, remainder)
        repo_id = repo_id.strip()
        if repo_id and repo_id.lower() not in seen:
            seen.add(repo_id.lower())
            results.append({"repo_id": repo_id, "relation": relation})

    return results


# ---------------------------------------------------------------------------
# 3) File classification: pickle vs safetensors
# ---------------------------------------------------------------------------

def _normalise_stem(filename):
    """Reduce a weight filename to a shard-and-framework-agnostic key."""
    stem = posixpath.splitext(filename)[0]
    shard = ""
    match = SHARD_RE.search(stem)
    if match:
        shard, stem = match.group(0), stem[:match.start()]
    return STEM_ALIASES.get(stem, stem) + shard


def _safe_alternative(path, safetensors_paths):
    """
    Find a .safetensors file equivalent to `path`, if the repo ships one.

    Handles the single most common layout in the ecosystem:
    pytorch_model.bin next to model.safetensors, sharded or not. Only the
    same directory counts - a conversion under onnx/ is not a substitute
    for the root .bin.
    """
    directory = posixpath.dirname(path)
    key = _normalise_stem(posixpath.basename(path))
    for candidate in safetensors_paths:
        if posixpath.dirname(candidate) == directory and \
                _normalise_stem(posixpath.basename(candidate)) == key:
            return candidate
    return None


def _is_not_really_pickle(path, all_paths):
    """
    Recognise `.bin` files that are NOT pickles.

    Two widely used toolchains write plain tensor blobs with a .bin
    extension. Grading them as "PyTorch pickle / arbitrary code execution"
    is a false positive - it pushed bert-base-uncased to HIGH before this
    check existed:

      CoreML   *.mlpackage/Data/com.apple.CoreML/weights/*.bin
      OpenVINO openvino_model.bin, always paired with openvino_model.xml
    """
    if ".mlpackage/" in path.lower():
        return "Core ML weight blob (.mlpackage): raw tensor data, not a pickle"
    if posixpath.splitext(path)[0] + ".xml" in all_paths:
        return "OpenVINO IR weights (paired with .xml): raw tensor data, not a pickle"
    return None


def classify_files(file_list):
    """
    Split the repository file list into pickle / safetensors / other.

    Args:
        file_list: (path, size_bytes) pairs. size may be None.

    Returns a dict shaped for the JSON report.
    """
    all_paths = {path for path, _ in file_list}
    safetensors_paths = [p for p in all_paths
                         if posixpath.splitext(p)[1].lower() in SAFETENSORS_EXTENSIONS]

    pickle_files, safetensors_files, other_weights, python_files = [], [], [], []

    for path, size in file_list:
        extension = posixpath.splitext(path)[1].lower()

        if extension in SAFETENSORS_EXTENSIONS:
            safetensors_files.append({"path": path, "size_bytes": size})

        elif extension in PICKLE_EXTENSIONS:
            exemption = _is_not_really_pickle(path, all_paths) if extension == ".bin" else None
            if exemption:
                other_weights.append({"path": path, "size_bytes": size,
                                      "risk": "LOW", "note": exemption})
                continue
            alternative = _safe_alternative(path, safetensors_paths)
            pickle_files.append({
                "path": path,
                "size_bytes": size,
                # The unsafe file still exists, but a loader can be pointed at
                # the safe one, so this is a policy issue rather than an
                # unavoidable exposure.
                "risk": "MEDIUM" if alternative else "HIGH",
                "safetensors_alternative": alternative,
            })

        elif extension in OTHER_WEIGHT_EXTENSIONS:
            other_weights.append({"path": path, "size_bytes": size,
                                  "risk": OTHER_WEIGHT_EXTENSIONS[extension]})

        elif extension == ".py":
            python_files.append(path)

    return {
        "total_files": len(file_list),
        "pickle": pickle_files,
        "safetensors": safetensors_files,
        "other_weights": other_weights,
        "python_files": python_files,
        "has_safetensors": bool(safetensors_files),
        "pickle_only": bool(pickle_files) and not safetensors_files,
    }


# ---------------------------------------------------------------------------
# 4) picklescan
# ---------------------------------------------------------------------------

class _ParseFailureLog(logging.Handler):
    """
    Capture picklescan's "could not parse" warnings.

    Needed because of a real gap in picklescan 1.0.x: when a file cannot be
    parsed as a pickle at all, scan_pickle_bytes() returns
    `ScanResult([], scanned_files=1, scan_err=False)` - byte-identical to a
    genuinely clean result - and reports the failure only through its
    logger. Reproduce it with:

        python -c "import io; from picklescan.scanner import scan_bytes; \
                   r=scan_bytes(io.BytesIO(b'\\x80\\x04garbage'),'x','.pkl'); \
                   print(r.scan_err, r.globals)"      # -> False []

    That default is fine for picklescan (a .dat file that is not a pickle
    is not a finding). It is wrong for us: a .bin we could not parse is an
    UNVERIFIED file, and calling it clean is the exact failure mode this
    tool exists to prevent.

    The other warning picklescan emits ("Invalid PyTorch magic number ...
    Trying to scan as non-PyTorch file") is a harmless fallback notice
    after which the scan succeeds, so we match the parse failure narrowly.
    """

    def __init__(self):
        super().__init__(level=logging.WARNING)
        self.failures = []

    def emit(self, record):
        message = record.getMessage()
        if "could not parse" in message.lower():
            self.failures.append(message)


def _safety_label(safety) -> str:
    """
    Normalise picklescan's SafetyLevel into a plain string.

    Compares against the SafetyLevel enum when it is importable, and falls
    back to the string form otherwise. Matching on the string alone breaks
    if picklescan ever changes its repr; matching on the enum alone breaks
    if picklescan is absent or the member set changes.
    """
    try:
        from picklescan.scanner import SafetyLevel

        for member in SafetyLevel:
            if safety is member or safety == member:
                return str(member.value).lower()
    except Exception as exc:  # noqa: BLE001 - enum shape is not guaranteed
        logger.debug(
            "SafetyLevel enum normalisation failed (%s); using string form",
            type(exc).__name__,
        )

    text = str(getattr(safety, "value", safety) or "").lower()
    for level in ("dangerous", "suspicious", "innocuous"):
        if level in text:
            return level
    return "suspicious"      # unrecognised: grade it as worth a look


def scan_pickle_files(model_id, revision, pickle_entries, max_size_mb, token=None):
    """
    Download each pickle file and scan it for dangerous globals.

    Deliberately does NOT use picklescan's own scan_huggingface_model():
    that helper hardcodes `resolve/main` (so it would scan different bytes
    than the commit SHA this report documents), pulls every matching file
    fully into memory with no size cap, aborts the whole scan on one
    failure, and reports nothing about what it skipped.

    Args:
        max_size_mb: per-file cap. 0 disables downloading entirely, which
            is the fast path for a metadata-only run.

    Returns a report dict. Every file that was not inspected is listed in
    `skipped` with a reason - a scan that silently covered 3 of 40 files
    and said "clean" is worse than no scan at all.
    """
    report = {"status": "OK", "scanned": [], "skipped": [], "malicious": [],
              "suspicious": []}

    if not pickle_entries:
        report["status"] = "NOT_APPLICABLE"
        report["detail"] = "No pickle-format files in the repository."
        return report

    if max_size_mb <= 0:
        report["status"] = "SKIPPED"
        report["skipped"] = [{"path": e["path"], "reason": "pickle scanning disabled"}
                             for e in pickle_entries]
        report["detail"] = (f"Pickle scanning disabled; {len(pickle_entries)} "
                            f"file(s) not inspected.")
        return report

    try:
        from picklescan.scanner import scan_file_path
    except ImportError:
        report["status"] = "UNAVAILABLE"
        report["skipped"] = [{"path": e["path"], "reason": "picklescan not installed"}
                             for e in pickle_entries]
        report["detail"] = ("picklescan is not installed - pickle contents were "
                            "NOT inspected. Install with: pip install picklescan")
        return report

    from huggingface_hub import hf_hub_download

    max_bytes = max_size_mb * 1024 * 1024
    # Scan the files a loader is most likely to open first, so a truncated
    # run still covers what matters: no-alternative first, then smallest.
    ordered = sorted(pickle_entries,
                     key=lambda e: (e["safetensors_alternative"] is not None,
                                    e["size_bytes"] or 0))

    for entry in ordered:
        path, size = entry["path"], entry["size_bytes"]

        if size is not None and size > max_bytes:
            report["skipped"].append({
                "path": path,
                "reason": f"exceeds --max-pickle-size-mb {max_size_mb} "
                          f"({size / 1024 / 1024:.0f} MB)",
            })
            continue

        try:
            local_path = hf_hub_download(model_id, path, revision=revision, token=token)
        except Exception as exc:  # noqa: BLE001 - one bad file must not end the scan
            report["skipped"].append({"path": path,
                                      "reason": f"download failed: {exc}"})
            continue

        handler = _ParseFailureLog()
        logger = logging.getLogger("picklescan")
        logger.addHandler(handler)
        try:
            result = scan_file_path(local_path)
        except Exception as exc:  # noqa: BLE001 - picklescan raises many types
            report["skipped"].append({
                "path": path, "reason": f"picklescan failed: {type(exc).__name__}: {exc}"})
            continue
        finally:
            logger.removeHandler(handler)

        findings = []
        for global_ref in getattr(result, "globals", None) or []:
            safety = _safety_label(getattr(global_ref, "safety", None))
            if safety == "innocuous":
                continue
            findings.append({
                "file": path,
                "module": str(getattr(global_ref, "module", "?")),
                "name": str(getattr(global_ref, "name", "?")),
                "safety": safety,
            })

        if not findings and (getattr(result, "scan_err", False) or handler.failures):
            reason = handler.failures[0] if handler.failures else \
                "picklescan reported a scan error"
            report["skipped"].append({"path": path, "reason": reason})
            continue

        report["scanned"].append(path)
        for finding in findings:
            bucket = "malicious" if finding["safety"] == "dangerous" else "suspicious"
            report[bucket].append(finding)

        # picklescan also reports a count independently of the globals list.
        # If it flagged the file but we extracted no global, the file is
        # still infected - recording only the globals would lose that.
        infected = getattr(result, "infected_files", 0) or 0
        if infected and not findings:
            report["malicious"].append({
                "file": path, "module": "?", "name": "?",
                "safety": "dangerous",
                "detail": "picklescan reported the file as infected without "
                          "naming a global",
            })

    if report["skipped"] and not report["scanned"]:
        report["status"] = "ERROR"

    report["detail"] = (
        f"scanned {len(report['scanned'])} file(s); "
        f"{len(report['malicious'])} dangerous, {len(report['suspicious'])} suspicious; "
        f"{len(report['skipped'])} not inspected."
    )
    return report


# ---------------------------------------------------------------------------
# 5) config.json: trust_remote_code / auto_map
# ---------------------------------------------------------------------------

def _download_json(model_id, filename, revision, token):
    """Download a small JSON file; returns (data, error_message)."""
    from huggingface_hub import hf_hub_download

    try:
        local_path = hf_hub_download(model_id, filename, revision=revision, token=token)
    except Exception as exc:  # noqa: BLE001 - absent or unreachable, caller decides
        return None, f"{filename}: {exc}"
    try:
        with open(local_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, f"{filename} could not be parsed: {exc}"
    return (data if isinstance(data, dict) else None), None


def _string_map(value):
    """Coerce an auto_map value into {auto_class: target} of strings."""
    if not isinstance(value, dict):
        return {}
    result = {}
    for key, target in value.items():
        if isinstance(target, str):
            result[str(key)] = target
        elif isinstance(target, (list, tuple)):
            # Some repos map to [slow_class, fast_class]; keep both.
            joined = ", ".join(str(t) for t in target if t)
            if joined:
                result[str(key)] = joined
    return result


def _external_code_repos(*auto_maps):
    """
    auto_map targets that load code from a DIFFERENT repository.

    transformers supports an "owner/repo--module.Class" form, e.g.
        "AutoModel": "nomic-ai/nomic-bert-2048--modeling.NomicBertModel"

    which imports from another repo entirely. For an AIBOM this is a
    provenance split worth recording on its own: the executed code has a
    different owner, license and commit history than the weights, and
    pinning this model's revision does not pin the code's.
    """
    repos = []
    for auto_map in auto_maps:
        for target in auto_map.values():
            for part in str(target).split(","):
                prefix, separator, _ = part.strip().partition("--")
                if separator and "/" in prefix and prefix not in repos:
                    repos.append(prefix)
    return repos


# ---------------------------------------------------------------------------
# 6) Model card
# ---------------------------------------------------------------------------

def check_model_card(model_id, revision, file_names, card, token, resolved=None):
    """
    Model card presence AND completeness.

    Presence alone is a useless signal: clicking "Create model card" on the
    Hub pre-fills a template whose every section reads
    `[More Information Needed]`, and a large share of repos publish that
    untouched. So we also score how much of it is actually filled in.

    Args:
        resolved: values the Hub API already worked out (from tags, or
            inferred from config.json). A field that is resolvable still
            counts as declared - otherwise the report contradicts itself,
            printing "Pipeline: feature-extraction" and "missing:
            pipeline_tag" a few lines apart.
    """
    resolved = resolved or {}

    # A card is not always README.md - modelcard.md and model_card.md are
    # both in use, and treating those repos as "no model card" is a false
    # finding.
    names = set(file_names)
    card_name = next((n for n in MODEL_CARD_NAMES if n in names), None)

    result = {
        "present": card_name is not None,
        "card_file": card_name,
        "completeness": 0,
        "placeholder_count": 0,
        "is_unedited_template": False,
    }

    earned = total = 0
    missing = []
    for field, weight in REQUIRED_CARD_FIELDS:
        total += weight
        value = card.get(field)
        if value in (None, "", [], {}):
            value = resolved.get(field)
        if value in (None, "", [], {}):
            missing.append(field)
            continue
        earned += weight
        # "license: other" with no name or link identifies nothing.
        if field == "license" and str(value).strip().lower() == "other" and \
                not (card.get("license_name") or card.get("license_link")):
            earned -= weight - 5
            missing.append("license_name/license_link (license is 'other')")

    result["completeness"] = round(100 * earned / total) if total else 0

    if not result["present"]:
        result["detail"] = ("No model card: the repository ships no README.md, "
                            "modelcard.md or model_card.md.")
        return result, missing

    text, error = _download_text(model_id, card_name, revision, token)
    if error:
        result["detail"] = f"Model card could not be read: {error}"
        return result, missing

    body = re.sub(r"^---\s*\n.*?\n---\s*\n", "", text, count=1, flags=re.DOTALL)
    result["placeholder_count"] = len(PLACEHOLDER_RE.findall(body))
    # Discount template scaffolding before judging how much prose is there:
    # instructional HTML comments, placeholders, and bare "**Label:**"
    # bullets whose value was a placeholder.
    residue = re.sub(r"<!--.*?-->", " ", body, flags=re.DOTALL)
    residue = PLACEHOLDER_RE.sub(" ", residue)
    residue = re.sub(r"[*_]{1,3}", "", residue)
    kept = [line.strip() for line in residue.splitlines()
            if line.strip() and not line.strip().startswith("#")
            and not re.match(r"^[\s\-\+>]*[^:\n]{1,60}:\s*$", line.strip())]
    result["body_chars"] = len(" ".join(kept))
    result["is_unedited_template"] = (result["placeholder_count"] >= 5
                                      and result["body_chars"] < 400)

    result["detail"] = (
        f"Model card is the unedited Hugging Face template "
        f"({result['placeholder_count']} placeholders remain)."
        if result["is_unedited_template"]
        else f"Model card completeness {result['completeness']}/100."
    )
    return result, missing


def _download_text(model_id, filename, revision, token):
    from huggingface_hub import hf_hub_download

    try:
        local_path = hf_hub_download(model_id, filename, revision=revision, token=token)
        with open(local_path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(), None
    except Exception as exc:  # noqa: BLE001
        return "", str(exc)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def check_model(model_ref, revision=None, max_pickle_size_mb=DEFAULT_MAX_PICKLE_MB,
                token=None):
    """
    Collect the full AIBOM record for one Hugging Face model.

    Failure policy: only an unusable URL or an unreadable repository aborts.
    Everything after that degrades - each section reports its own status and
    the reason lands in `issues`, so a partial record still tells you which
    parts are unverified. A scan that silently reports "clean" for checks it
    never ran is the failure mode this policy exists to prevent.
    """
    from huggingface_hub import HfApi

    model_id, url_revision = parse_model_id(model_ref)
    revision = revision or url_revision
    token = token or os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN")

    api = HfApi(token=token)
    # files_metadata=True is what populates per-file sizes, which the pickle
    # scan needs for its size cap.
    info = api.model_info(model_id, revision=revision, files_metadata=True)

    card = _card_dict(info)
    resolved_id = getattr(info, "id", None) or model_id
    commit_sha = getattr(info, "sha", None)

    # Pin every subsequent download to the immutable SHA. A branch can move
    # between the metadata call and the file downloads; pinning means the
    # files scanned are provably the files this report describes.
    scan_revision = commit_sha or revision

    file_list = []
    file_hashes = {}
    for sibling in getattr(info, "siblings", None) or []:
        path = getattr(sibling, "rfilename", None)
        if not path:
            continue
        size = getattr(sibling, "size", None)
        lfs = getattr(sibling, "lfs", None)
        if size is None:
            # huggingface_hub returns lfs as an object on some versions and a
            # plain dict on others; the real size only lives there for
            # LFS-tracked files, which is every large weight file.
            size = getattr(lfs, "size", None) if lfs is not None else None
            if size is None and isinstance(lfs, dict):
                size = lfs.get("size")

        # The Hub already publishes the SHA-256 of every LFS-tracked file, and
        # weight files are all LFS-tracked. An SBOM that names a model without
        # a hash cannot be used to verify anyone received the same bytes, and
        # "model hash" is a named element in the G7 SBOM-for-AI minimum set.
        digest = getattr(lfs, "sha256", None) if lfs is not None else None
        if digest is None and isinstance(lfs, dict):
            digest = lfs.get("sha256")
        if digest:
            file_hashes[path] = str(digest)

        file_list.append((path, size))

    file_names = {path for path, _ in file_list}
    file_formats = classify_files(file_list)

    licenses = _metadata_value(info, card, "license", "license:")
    last_modified = getattr(info, "last_modified", None) or getattr(info, "lastModified", None)
    gated_raw = getattr(info, "gated", False)

    report = {
        "model_id": resolved_id,
        "url": f"https://huggingface.co/{resolved_id}",
        "requested_revision": revision or "main",
        "commit_sha": commit_sha,
        "model_name": resolved_id.split("/")[-1],
        "author": getattr(info, "author", None) or (
            resolved_id.split("/")[0] if "/" in resolved_id else None),
        "license": licenses[0] if licenses else None,
        "license_name": card.get("license_name"),
        "license_link": card.get("license_link"),
        "base_model": _base_models(info, card),
        "datasets": _metadata_value(info, card, "datasets", "dataset:"),
        "pipeline": getattr(info, "pipeline_tag", None),
        "library": getattr(info, "library_name", None) or card.get("library_name"),
        "languages": _metadata_value(info, card, "language"),
        "architectures": _as_list((getattr(info, "config", None) or {}).get("architectures")),
        "last_modified": last_modified if isinstance(last_modified, str)
                         else (last_modified.isoformat() if last_modified else None),
        "gated": bool(gated_raw) and gated_raw != "False",
        "private": bool(getattr(info, "private", False)),
        "file_formats": file_formats,
        # The complete file list, sorted. An AIBOM should record what the
        # repository actually contains, not only the files we classified.
        "files": sorted(file_names),
        # path -> SHA-256, for every LFS-tracked file the Hub publishes one
        # for. Lets a consumer verify they received the same weights.
        "file_hashes": file_hashes,
        "issues": [],
    }

    # --- 4) pickle contents ------------------------------------------------
    report["pickle_scan"] = scan_pickle_files(
        resolved_id, scan_revision, file_formats["pickle"], max_pickle_size_mb, token)

    # --- 5) trust_remote_code / auto_map -----------------------------------
    auto_map, tokenizer_auto_map, config_errors = {}, {}, []
    declared_trc, quantization, transformers_version = None, None, None

    if "config.json" in file_names:
        config, error = _download_json(resolved_id, "config.json", scan_revision, token)
        if error:
            config_errors.append(error)
        elif config:
            auto_map = _string_map(config.get("auto_map"))
            transformers_version = config.get("transformers_version")
            if isinstance(config.get("trust_remote_code"), bool):
                declared_trc = config["trust_remote_code"]
            quant = config.get("quantization_config")
            if isinstance(quant, dict):
                quantization = quant.get("quant_method") or "unspecified"

    if "tokenizer_config.json" in file_names:
        tokenizer_config, error = _download_json(
            resolved_id, "tokenizer_config.json", scan_revision, token)
        if error:
            config_errors.append(error)
        elif tokenizer_config:
            tokenizer_auto_map = _string_map(tokenizer_config.get("auto_map"))

    report["auto_map"] = auto_map
    report["tokenizer_auto_map"] = tokenizer_auto_map
    report["trust_remote_code"] = bool(auto_map or tokenizer_auto_map or declared_trc)
    report["external_code_repos"] = _external_code_repos(auto_map, tokenizer_auto_map)
    report["transformers_version"] = transformers_version
    report["quantization"] = quantization
    report["config_errors"] = config_errors

    # --- 6) model card -----------------------------------------------------
    report["model_card"], report["missing_model_card_fields"] = check_model_card(
        resolved_id, scan_revision, file_names, card, token,
        resolved={
            "license": report["license"],
            "pipeline_tag": report["pipeline"],
            "library_name": report["library"],
            "base_model": report["base_model"],
            "datasets": report["datasets"],
            "language": report["languages"],
            "tags": _as_list(getattr(info, "tags", None)),
        })

    report["issues"] = collect_issues(report)
    report["risk"] = (
        "HIGH" if any(i["severity"] == "HIGH" for i in report["issues"]) else
        "MEDIUM" if any(i["severity"] == "MEDIUM" for i in report["issues"]) else
        "LOW" if report["issues"] else "SAFE"
    )
    return report


def collect_issues(report):
    """
    Turn collected model facts into a flat, sorted list of findings.

    Severity is chosen for downstream mapping in ``scanner._model_issues``,
    not for final verdicts — score_engine owns ALLOW/WARNING/BLOCK. HIGH is
    reserved for execution paths (picklescan globals, ``trust_remote_code``,
    external repos); MEDIUM covers hygiene gaps (missing card, pickle-only
    repos); LOW covers informational signals (gated access, stray ``.py`` files).

    ``unverified`` findings are emitted whenever a check did not run (pickle scan
    skipped, config unreadable) because silence would read as "clean" — the
    failure mode this tool exists to prevent.
    """
    issues = []

    def add(severity, issue_type, message):
        issues.append({"severity": severity, "type": issue_type, "message": message})

    scan = report["pickle_scan"]
    for finding in scan["malicious"]:
        add("HIGH", "malicious",
            f"Dangerous global {finding['module']}.{finding['name']} in "
            f"{finding['file']} - loading this file executes it.")
    for finding in scan["suspicious"]:
        add("MEDIUM", "suspicious",
            f"Suspicious global {finding['module']}.{finding['name']} in "
            f"{finding['file']}.")

    if report["file_formats"]["pickle_only"]:
        add("HIGH", "pickle_only",
            "No safetensors weights: loading this model requires unpickling, "
            "which can execute arbitrary code.")
    else:
        for entry in report["file_formats"]["pickle"]:
            if entry["risk"] == "HIGH":
                add("MEDIUM", "pickle_file",
                    f"{entry['path']} is a pickle with no safetensors equivalent.")

    if report["trust_remote_code"]:
        targets = sorted(set(report["auto_map"].values()) |
                         set(report["tokenizer_auto_map"].values()))
        add("HIGH", "remote_code",
            "Model requires trust_remote_code=True; loading it executes "
            "repository code: " + ", ".join(targets[:4]))
    elif report["file_formats"]["python_files"]:
        add("LOW", "python_files",
            f"Repository ships Python files that no loader wires up: "
            f"{', '.join(report['file_formats']['python_files'][:5])}")

    if report["external_code_repos"]:
        add("HIGH", "external_code",
            "Code is loaded from another repository (" +
            ", ".join(report["external_code_repos"]) +
            "), which has its own owner, license and revision - none of them "
            "pinned by this report.")

    card = report["model_card"]
    if not card["present"]:
        add("MEDIUM", "no_model_card", "No README.md: the model has no model card.")
    elif card["is_unedited_template"]:
        add("MEDIUM", "template_model_card",
            f"Model card is the unedited Hugging Face template "
            f"({card['placeholder_count']} placeholders remain).")
    if report["missing_model_card_fields"]:
        add("LOW", "incomplete_model_card",
            "Model card is missing required fields: " +
            ", ".join(report["missing_model_card_fields"]))

    if not report["license"]:
        add("MEDIUM", "no_license", "No license declared on the Hub.")

    if report["gated"]:
        add("LOW", "gated",
            "Gated model: the license must be accepted on the Hub before use, "
            "and redistribution terms likely apply.")

    # A check that could not run is never a pass. Say so explicitly.
    if scan["status"] in ("UNAVAILABLE", "ERROR", "SKIPPED"):
        add("MEDIUM", "unverified", f"Pickle scan did not run: {scan['detail']}")
    elif scan["skipped"]:
        add("MEDIUM", "unverified",
            f"{len(scan['skipped'])} pickle file(s) were not inspected; "
            f"their contents are unverified.")
    if report["config_errors"]:
        add("MEDIUM", "unverified",
            "Config could not be read: " + "; ".join(report["config_errors"]))
    commit_sha = report["commit_sha"]
    if not commit_sha:
        add("LOW", "unverified",
            "The Hub returned no commit SHA; files were fetched from a moving "
            "reference and may not match this report.")
    elif not FULL_COMMIT_RE.fullmatch(str(commit_sha)):
        # A short or symbolic revision is not an immutable pin - whatever it
        # points at today can point somewhere else tomorrow.
        add("LOW", "unverified",
            f"Revision '{commit_sha}' is not a full 40-character commit SHA, "
            f"so this report is not pinned to immutable content.")

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return sorted(issues, key=lambda i: order[i["severity"]])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def render(report):
    """Human-readable summary. Kept separate from check_model() so the JSON
    output and the terminal output cannot drift apart."""
    lines = [f"AIBOM-Guardian model report: {report['model_id']}", f"  {report['url']}"]

    def section(title):
        lines.extend(["", f"=== {title} ==="])

    section("Identity & provenance")
    lines.append(f"  Model        : {report['model_name']}")
    lines.append(f"  Author       : {report['author'] or '-'}")
    lines.append(f"  Commit SHA   : {report['commit_sha'] or '(none returned)'}")
    lines.append(f"  Pipeline     : {report['pipeline'] or '-'}")
    lines.append(f"  Library      : {report['library'] or '-'}")
    lines.append(f"  Architecture : {', '.join(report['architectures']) or '-'}")

    license_text = report["license"] or "NOT DECLARED"
    if report["license_name"]:
        license_text += f" ({report['license_name']})"
    lines.append(f"  License      : {license_text}"
                 + ("   [GATED]" if report["gated"] else ""))

    base = report["base_model"]
    lines.append("  Base model   : " + (", ".join(
        b["repo_id"] + (f" ({b['relation']})" if b["relation"] else "") for b in base)
        if base else "not declared"))
    lines.append(f"  Datasets     : {', '.join(report['datasets']) or 'not declared'}")

    section("File formats")
    formats = report["file_formats"]
    lines.append(f"  {formats['total_files']} files | "
                 f"safetensors {len(formats['safetensors'])} | "
                 f"pickle {len(formats['pickle'])} | "
                 f"other weights {len(formats['other_weights'])}")
    if formats["pickle_only"]:
        lines.append("  [!] PICKLE ONLY - no safetensors alternative exists.")
    for entry in formats["pickle"]:
        alternative = entry["safetensors_alternative"]
        lines.append(f"    {entry['risk']:<6} {entry['path']}"
                     + (f"  -> use {alternative}" if alternative else "  (no alternative)"))

    section("Pickle scan")
    scan = report["pickle_scan"]
    lines.append(f"  status: {scan['status']} - {scan['detail']}")
    for finding in scan["malicious"] + scan["suspicious"]:
        lines.append(f"    [{finding['safety'].upper()}] "
                     f"{finding['module']}.{finding['name']}  ({finding['file']})")
    for skipped in scan["skipped"][:10]:
        lines.append(f"    [not scanned] {skipped['path']} - {skipped['reason']}")

    section("Remote code")
    lines.append(f"  trust_remote_code required: "
                 f"{'YES' if report['trust_remote_code'] else 'no'}")
    for auto_class, target in report["auto_map"].items():
        lines.append(f"    auto_map  {auto_class} -> {target}")
    for auto_class, target in report["tokenizer_auto_map"].items():
        lines.append(f"    tokenizer {auto_class} -> {target}")
    if report["external_code_repos"]:
        lines.append("  [!] code loaded from OTHER repositories: "
                     + ", ".join(report["external_code_repos"]))

    section("Model card")
    card = report["model_card"]
    lines.append(f"  present: {card['present']}  completeness: {card['completeness']}/100")
    if card.get("is_unedited_template"):
        lines.append(f"  [!] unedited template ({card['placeholder_count']} placeholders)")
    if report["missing_model_card_fields"]:
        lines.append(f"  missing fields: {', '.join(report['missing_model_card_fields'])}")

    section("Issues")
    if not report["issues"]:
        lines.append("  none")
    for issue in report["issues"]:
        lines.append(f"  [{issue['severity']:<6}] {issue['type']}: {issue['message']}")

    lines.extend(["", f"OVERALL RISK: {report['risk']}"])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="model_checker",
        description="Collect AIBOM data for a Hugging Face model.")
    parser.add_argument("model", help="Hugging Face model URL or owner/model")
    parser.add_argument("--revision", help="branch, tag or commit SHA to scan")
    parser.add_argument("--token", help="Hugging Face token (default: $HF_TOKEN)")
    parser.add_argument("--max-pickle-size-mb", type=int, default=DEFAULT_MAX_PICKLE_MB,
                        help="per-file download cap for the pickle scan; "
                             "0 skips pickle scanning entirely (default: 512)")
    parser.add_argument("--json", dest="json_path", metavar="PATH",
                        help="write the full report to a JSON file")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress the human-readable report")
    args = parser.parse_args(argv)

    try:
        report = check_model(args.model, revision=args.revision,
                             max_pickle_size_mb=args.max_pickle_size_mb,
                             token=args.token)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - hub errors are many and varied
        print(f"[ERROR] Could not read '{args.model}': {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(render(report))

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2)
        print(f"\n[Saved] {args.json_path}")

    return 2 if report["risk"] == "HIGH" else 0


if __name__ == "__main__":
    sys.exit(main())
