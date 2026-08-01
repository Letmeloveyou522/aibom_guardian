"""
test_model_checker.py
-----------------------------------
Unit tests for model_checker.py.

Runs entirely offline - the Hugging Face Hub is replaced by fakes, so the
suite is deterministic and finishes in under a second.

    python3 -m pytest test_model_checker.py -q

The "malicious" pickle fixture is built with pickle.dumps() on an object
whose __reduce__ names builtins.eval. Constructing the payload executes
nothing, and nothing here ever unpickles it - this is the standard way to
verify that a pickle scanner detects what it is supposed to detect.
"""

import json
import os
import pickle
import tempfile

import pytest

import model_checker as mc


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class _CallsEval:
    def __reduce__(self):
        return (eval, ("1 + 1",))


DANGEROUS_PICKLE = pickle.dumps(_CallsEval())
BENIGN_PICKLE = pickle.dumps({"weights": [1.0, 2.0], "name": "layer0"})


@pytest.fixture
def fake_downloads(monkeypatch):
    """
    Replace hf_hub_download with a dict-backed fake.

    Returns a dict you fill with {filename: str | bytes}. A filename that
    is absent raises, mirroring a 404 from the Hub.
    """
    files = {}
    tempdir = tempfile.mkdtemp(prefix="mc-test-")
    calls = []

    def fake_hf_hub_download(repo_id, filename, revision=None, token=None, **kwargs):
        calls.append((filename, revision))
        if filename not in files:
            raise FileNotFoundError(f"404: {filename}")
        content = files[filename]
        local_path = os.path.join(tempdir, filename.replace("/", "__"))
        if isinstance(content, bytes):
            with open(local_path, "wb") as handle:
                handle.write(content)
        else:
            with open(local_path, "w", encoding="utf-8") as handle:
                handle.write(content)
        return local_path

    monkeypatch.setattr("huggingface_hub.hf_hub_download", fake_hf_hub_download)
    files["__calls__"] = calls          # exposed for assertions
    return files


def _calls(fake_downloads):
    return fake_downloads["__calls__"]


class FakeCardData:
    """
    Mimics huggingface_hub.ModelCardData.

    Deliberately NOT a Mapping: the real class raises KeyError on dict(...),
    which is the trap _card_dict() exists to avoid. Keeping that behaviour
    means these tests would catch a regression to naive dict() conversion.
    """

    def __init__(self, **fields):
        self._fields = fields

    def to_dict(self):
        return dict(self._fields)


class FakeInfo:
    def __init__(self, tags=None, card_data=None, **kwargs):
        self.tags = tags or []
        self.card_data = card_data
        for key, value in kwargs.items():
            setattr(self, key, value)


# ---------------------------------------------------------------------------
# 1) parse_model_id
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,model_id,revision", [
    ("https://huggingface.co/facebook/bart-base", "facebook/bart-base", None),
    ("https://huggingface.co/gpt2", "gpt2", None),
    ("http://huggingface.co/org/model", "org/model", None),
    ("https://hf.co/org/model", "org/model", None),
    ("huggingface.co/org/model", "org/model", None),
    ("org/model", "org/model", None),
    ("gpt2", "gpt2", None),
    ("https://huggingface.co/org/model/", "org/model", None),
    ("https://huggingface.co/org/model?library=transformers", "org/model", None),
    ("https://huggingface.co/org/model#usage", "org/model", None),
    ("https://huggingface.co/org/model/tree/main", "org/model", "main"),
    ("https://huggingface.co/org/model/tree/v1.0", "org/model", "v1.0"),
    ("https://huggingface.co/org/model/blob/main/config.json", "org/model", "main"),
    ("https://huggingface.co/org/model/resolve/abc123/model.safetensors",
     "org/model", "abc123"),
    ("https://huggingface.co/org/model/commit/deadbeef", "org/model", "deadbeef"),
    ("https://huggingface.co/gpt2/tree/main", "gpt2", "main"),
    ("org/model@v2", "org/model", "v2"),
])
def test_parse_model_id_accepts_valid_references(raw, model_id, revision):
    assert mc.parse_model_id(raw) == (model_id, revision)


def test_parse_model_id_handles_refs_revisions_with_slashes():
    """`refs/pr/3` is one revision, not a revision plus two path segments."""
    assert mc.parse_model_id(
        "https://huggingface.co/org/model/tree/refs/pr/3") == ("org/model", "refs/pr/3")
    assert mc.parse_model_id(
        "https://huggingface.co/org/model/resolve/refs/heads/main/config.json"
    ) == ("org/model", "refs/heads/main")


def test_parse_model_id_decodes_percent_encoding():
    assert mc.parse_model_id(
        "https://huggingface.co/org/model/resolve/refs%2Fpr%2F3/model.safetensors"
    ) == ("org/model", "refs/pr/3")


@pytest.mark.parametrize("raw", [
    "https://huggingface.co/datasets/squad",
    "https://huggingface.co/spaces/org/demo",
    "https://huggingface.co/models?pipeline_tag=text-generation",
    "https://huggingface.co/docs/transformers/index",
])
def test_parse_model_id_rejects_non_model_hub_urls(raw):
    """A dataset URL must fail loudly, not be scanned as the model 'datasets/squad'."""
    with pytest.raises(ValueError):
        mc.parse_model_id(raw)


@pytest.mark.parametrize("raw", [
    "", "   ", None,
    "https://github.com/org/repo",
    "https://example.com/org/model",
    "ftp://huggingface.co/org/model",
    "https://huggingface.co/",
    "org/-badname",
    "org/badname-",
    "org/" + "x" * 200,
])
def test_parse_model_id_rejects_invalid_input(raw):
    with pytest.raises(ValueError):
        mc.parse_model_id(raw)


def test_parse_model_id_names_the_bad_host():
    with pytest.raises(ValueError, match="github.com"):
        mc.parse_model_id("https://github.com/org/repo")


# ---------------------------------------------------------------------------
# 2) metadata helpers
# ---------------------------------------------------------------------------

def test_card_dict_uses_to_dict_not_dict():
    """dict(ModelCardData) raises KeyError; _card_dict must not rely on it."""
    info = FakeInfo(card_data=FakeCardData(license="mit", datasets=["squad"]))
    assert mc._card_dict(info) == {"license": "mit", "datasets": ["squad"]}


def test_card_dict_tolerates_missing_card():
    assert mc._card_dict(FakeInfo()) == {}


def test_metadata_value_merges_card_and_tags():
    """
    The same fact is expressed two ways on the Hub. Reading only one source
    loses data on a large share of real repositories.
    """
    info = FakeInfo(tags=["dataset:wikipedia", "dataset:bookcorpus", "en"])
    card = {"datasets": ["squad"]}
    assert mc._metadata_value(info, card, "datasets", "dataset:") == [
        "squad", "wikipedia", "bookcorpus"]


def test_metadata_value_dedupes_case_insensitively():
    info = FakeInfo(tags=["dataset:SQuAD"])
    assert mc._metadata_value(info, {"datasets": ["squad"]}, "datasets",
                              "dataset:") == ["squad"]


def test_metadata_value_reads_license_from_tag_when_card_is_empty():
    info = FakeInfo(tags=["license:apache-2.0"])
    assert mc._metadata_value(info, {}, "license", "license:") == ["apache-2.0"]


def test_base_models_parse_relation_from_tags():
    """
    A quantized child inherits the parent's license and training data, so
    the relation is not decoration - it drives downstream analysis.
    """
    info = FakeInfo(tags=["base_model:quantized:meta-llama/Llama-3.1-8B"])
    assert mc._base_models(info, {}) == [
        {"repo_id": "meta-llama/Llama-3.1-8B", "relation": "quantized"}]


def test_base_models_from_card_without_relation():
    info = FakeInfo()
    assert mc._base_models(info, {"base_model": "org/parent"}) == [
        {"repo_id": "org/parent", "relation": None}]


def test_base_models_tag_without_relation_prefix():
    info = FakeInfo(tags=["base_model:org/parent"])
    assert mc._base_models(info, {}) == [{"repo_id": "org/parent", "relation": None}]


def test_as_list_normalises_scalars_and_none():
    assert mc._as_list(None) == []
    assert mc._as_list("mit") == ["mit"]
    assert mc._as_list(["a", "b"]) == ["a", "b"]
    assert mc._as_list("") == []


# ---------------------------------------------------------------------------
# 3) classify_files - pickle vs safetensors
# ---------------------------------------------------------------------------

def test_pickle_next_to_safetensors_is_downgraded():
    """
    The most common real-world layout: pytorch_model.bin beside
    model.safetensors. The pickle is avoidable, so MEDIUM not HIGH.
    """
    result = mc.classify_files([
        ("pytorch_model.bin", 440_000_000),
        ("model.safetensors", 440_000_000),
        ("config.json", 570),
    ])
    entry = result["pickle"][0]
    assert entry["safetensors_alternative"] == "model.safetensors"
    assert entry["risk"] == "MEDIUM"
    assert result["pickle_only"] is False
    assert result["has_safetensors"] is True


def test_sharded_checkpoints_match_shard_by_shard():
    result = mc.classify_files([
        ("pytorch_model-00001-of-00002.bin", 1),
        ("pytorch_model-00002-of-00002.bin", 1),
        ("model-00001-of-00002.safetensors", 1),
        ("model-00002-of-00002.safetensors", 1),
    ])
    assert all(e["safetensors_alternative"] for e in result["pickle"])
    assert all(e["risk"] == "MEDIUM" for e in result["pickle"])


def test_partially_converted_shards_stay_high():
    """Only one of two shards converted: the unconverted one is still HIGH."""
    result = mc.classify_files([
        ("pytorch_model-00001-of-00002.bin", 1),
        ("pytorch_model-00002-of-00002.bin", 1),
        ("model-00001-of-00002.safetensors", 1),
    ])
    risks = {e["path"]: e["risk"] for e in result["pickle"]}
    assert risks["pytorch_model-00001-of-00002.bin"] == "MEDIUM"
    assert risks["pytorch_model-00002-of-00002.bin"] == "HIGH"


def test_safetensors_in_another_directory_does_not_count():
    """An onnx/ conversion is not a substitute for the root .bin."""
    result = mc.classify_files([
        ("pytorch_model.bin", 1),
        ("onnx/model.safetensors", 1),
    ])
    assert result["pickle"][0]["safetensors_alternative"] is None
    assert result["pickle"][0]["risk"] == "HIGH"


def test_pickle_only_repository():
    result = mc.classify_files([("pytorch_model.bin", 500), ("config.json", 10)])
    assert result["pickle_only"] is True
    assert result["has_safetensors"] is False


def test_safetensors_only_repository_has_no_pickles():
    result = mc.classify_files([("model.safetensors", 500), ("config.json", 10)])
    assert result["pickle"] == []
    assert result["pickle_only"] is False


def test_coreml_weight_blob_is_not_treated_as_a_pickle():
    """
    coreml/.../weights/weight.bin is a raw tensor blob inside an .mlpackage
    bundle. Grading it as a PyTorch pickle is a false positive that pushed
    bert-base-uncased to HIGH before this exemption existed.
    """
    path = ("coreml/fill-mask/float32_model.mlpackage/Data/"
            "com.apple.CoreML/weights/weight.bin")
    result = mc.classify_files([(path, 400_000_000), ("model.safetensors", 1)])
    assert result["pickle"] == []
    assert any(e["path"] == path and e["risk"] == "LOW"
               for e in result["other_weights"])


def test_openvino_bin_paired_with_xml_is_not_a_pickle():
    result = mc.classify_files([
        ("openvino_model.bin", 400_000_000),
        ("openvino_model.xml", 200_000),
    ])
    assert result["pickle"] == []
    assert "OpenVINO" in result["other_weights"][0]["note"]


def test_a_lone_bin_without_xml_is_still_a_pickle():
    """The OpenVINO exemption must not weaken the default .bin verdict."""
    result = mc.classify_files([("openvino_model.bin", 100)])
    assert len(result["pickle"]) == 1
    assert result["pickle"][0]["risk"] == "HIGH"


def test_python_files_are_collected():
    result = mc.classify_files([("modeling_custom.py", 100), ("model.safetensors", 1)])
    assert result["python_files"] == ["modeling_custom.py"]


def test_other_weight_formats_are_graded():
    result = mc.classify_files([
        ("model.gguf", 1), ("model.onnx", 1), ("tf_model.h5", 1),
    ])
    risks = {os.path.basename(e["path"]): e["risk"] for e in result["other_weights"]}
    assert risks == {"model.gguf": "SAFE", "model.onnx": "LOW", "tf_model.h5": "MEDIUM"}


def test_empty_repository():
    result = mc.classify_files([])
    assert result["total_files"] == 0
    assert result["pickle"] == []


# ---------------------------------------------------------------------------
# 4) scan_pickle_files
# ---------------------------------------------------------------------------

def _pickle_entry(path, size, alternative=None):
    return {"path": path, "size_bytes": size, "risk": "HIGH",
            "safetensors_alternative": alternative}


def test_dangerous_global_is_reported(fake_downloads):
    fake_downloads["payload.pkl"] = DANGEROUS_PICKLE
    report = mc.scan_pickle_files(
        "org/m", "sha", [_pickle_entry("payload.pkl", len(DANGEROUS_PICKLE))], 512)

    assert report["status"] == "OK"
    assert len(report["malicious"]) == 1
    assert report["malicious"][0]["module"] == "builtins"
    assert report["malicious"][0]["name"] == "eval"


def test_benign_pickle_produces_no_findings(fake_downloads):
    fake_downloads["data.pkl"] = BENIGN_PICKLE
    report = mc.scan_pickle_files(
        "org/m", "sha", [_pickle_entry("data.pkl", len(BENIGN_PICKLE))], 512)
    assert report["malicious"] == [] and report["suspicious"] == []
    assert report["scanned"] == ["data.pkl"]


def test_no_pickles_is_not_applicable(fake_downloads):
    report = mc.scan_pickle_files("org/m", "sha", [], 512)
    assert report["status"] == "NOT_APPLICABLE"
    assert _calls(fake_downloads) == []


def test_max_size_zero_skips_without_downloading(fake_downloads):
    """--max-pickle-size-mb 0 must not touch the network."""
    report = mc.scan_pickle_files("org/m", "sha", [_pickle_entry("m.bin", 100)], 0)
    assert report["status"] == "SKIPPED"
    assert len(report["skipped"]) == 1
    assert _calls(fake_downloads) == []


def test_oversized_files_are_skipped_and_listed(fake_downloads):
    """A file we chose not to download must be reported, never assumed clean."""
    fake_downloads["huge.bin"] = BENIGN_PICKLE
    report = mc.scan_pickle_files(
        "org/m", "sha", [_pickle_entry("huge.bin", 900 * 1024 * 1024)], 100)
    assert report["scanned"] == []
    assert "exceeds" in report["skipped"][0]["reason"]
    assert _calls(fake_downloads) == []


def test_download_failure_does_not_abort_remaining_files(fake_downloads):
    fake_downloads["good.pkl"] = DANGEROUS_PICKLE   # "bad.pkl" deliberately absent
    report = mc.scan_pickle_files("org/m", "sha", [
        _pickle_entry("bad.pkl", 100), _pickle_entry("good.pkl", 100)], 512)
    assert report["scanned"] == ["good.pkl"]
    assert len(report["malicious"]) == 1
    assert any(s["path"] == "bad.pkl" for s in report["skipped"])


def test_unparseable_pickle_is_not_reported_as_clean(fake_downloads):
    """
    picklescan returns ScanResult([], scanned_files=1, scan_err=False) for a
    file it could not parse - identical to a clean result - and reports the
    failure only through its logger. It must land in `skipped`, not pass.
    """
    fake_downloads["broken.pkl"] = b"\x80\x04not-a-real-pickle"
    report = mc.scan_pickle_files("org/m", "sha", [_pickle_entry("broken.pkl", 20)], 512)
    assert report["scanned"] == []
    assert len(report["skipped"]) == 1


def test_files_are_downloaded_at_the_pinned_revision(fake_downloads):
    fake_downloads["m.pkl"] = BENIGN_PICKLE
    mc.scan_pickle_files("org/m", "c0ffee", [_pickle_entry("m.pkl", 100)], 512)
    assert _calls(fake_downloads) == [("m.pkl", "c0ffee")]


def test_unavoidable_pickles_are_scanned_first(fake_downloads):
    """A truncated run should still cover the files a loader will open."""
    fake_downloads["a.bin"] = BENIGN_PICKLE
    fake_downloads["b.bin"] = BENIGN_PICKLE
    mc.scan_pickle_files("org/m", "sha", [
        _pickle_entry("a.bin", 100, alternative="model.safetensors"),
        _pickle_entry("b.bin", 900),
    ], 512)
    assert [name for name, _ in _calls(fake_downloads)] == ["b.bin", "a.bin"]


# ---------------------------------------------------------------------------
# 5) auto_map / trust_remote_code
# ---------------------------------------------------------------------------

def test_external_code_repos_detects_cross_repository_targets():
    """
    "owner/repo--module.Class" loads code from a different repository.
    Pinning this model's revision does not pin that code.
    """
    auto_map = {
        "AutoConfig": "nomic-ai/nomic-bert-2048--configuration.NomicBertConfig",
        "AutoModel": "nomic-ai/nomic-bert-2048--modeling.NomicBertModel",
    }
    assert mc._external_code_repos(auto_map) == ["nomic-ai/nomic-bert-2048"]


def test_local_auto_map_has_no_external_repos():
    auto_map = {"AutoModel": "modeling_chatglm.ChatGLMForConditionalGeneration"}
    assert mc._external_code_repos(auto_map) == []


def test_string_map_flattens_list_targets():
    """Some repos map AutoTokenizer to [slow_class, fast_class]."""
    result = mc._string_map({"AutoTokenizer": ["tokenization_x.XTokenizer", None]})
    assert "tokenization_x.XTokenizer" in result["AutoTokenizer"]


def test_string_map_ignores_non_dicts():
    assert mc._string_map(None) == {}
    assert mc._string_map("nope") == {}


# ---------------------------------------------------------------------------
# 6) model card
# ---------------------------------------------------------------------------

UNEDITED_TEMPLATE = """---
library_name: transformers
---

# Model Card for Model ID

<!-- Provide a quick summary of what the model is/does. -->

## Model Details

### Model Description

[More Information Needed]

- **Developed by:** [More Information Needed]
- **License:** [More Information Needed]

## Uses

[More Information Needed]

## Bias, Risks, and Limitations

[More Information Needed]

## Training Details

[More Information Needed]
"""

GOOD_CARD = """---
license: apache-2.0
---

# Tiny Instruct 1B

## Model Description

A 1.1 billion parameter decoder-only transformer fine-tuned for
instruction following on a filtered subset of C4.

## Intended Use

Research use for English instruction following. Not for medical advice.
"""


def test_unedited_template_is_detected(monkeypatch):
    monkeypatch.setattr(mc, "_download_text", lambda *a: (UNEDITED_TEMPLATE, None))
    result, _ = mc.check_model_card(
        "org/m", "sha", {"README.md"}, {"library_name": "transformers"}, None)
    assert result["present"] is True
    assert result["is_unedited_template"] is True
    assert result["placeholder_count"] >= 5


def test_real_card_is_not_flagged_as_template(monkeypatch):
    monkeypatch.setattr(mc, "_download_text", lambda *a: (GOOD_CARD, None))
    result, _ = mc.check_model_card(
        "org/m", "sha", {"README.md"}, {"license": "apache-2.0"}, None)
    assert result["is_unedited_template"] is False
    assert result["body_chars"] > 100


def test_missing_readme_is_reported(monkeypatch):
    result, missing = mc.check_model_card("org/m", "sha", {"config.json"}, {}, None)
    assert result["present"] is False
    assert "license" in missing


def test_license_other_without_a_name_loses_credit(monkeypatch):
    monkeypatch.setattr(mc, "_download_text", lambda *a: (GOOD_CARD, None))
    named, _ = mc.check_model_card(
        "org/m", "sha", {"README.md"},
        {"license": "other", "license_name": "llama3.1"}, None)
    unnamed, missing = mc.check_model_card(
        "org/m", "sha", {"README.md"}, {"license": "other"}, None)
    assert unnamed["completeness"] < named["completeness"]
    assert any("license_name" in field for field in missing)


def test_api_resolved_fields_count_as_declared(monkeypatch):
    """
    A field the Hub resolved from tags still counts, otherwise the report
    contradicts itself - printing the pipeline and calling it missing.
    """
    monkeypatch.setattr(mc, "_download_text", lambda *a: (GOOD_CARD, None))
    _, missing = mc.check_model_card(
        "org/m", "sha", {"README.md"}, {}, None,
        resolved={"license": "mit", "pipeline_tag": "text-generation"})
    assert "license" not in missing
    assert "pipeline_tag" not in missing


def test_unreadable_card_is_not_scored_as_complete(monkeypatch):
    monkeypatch.setattr(mc, "_download_text", lambda *a: ("", "network down"))
    result, _ = mc.check_model_card("org/m", "sha", {"README.md"}, {}, None)
    assert "could not be read" in result["detail"]


# ---------------------------------------------------------------------------
# 7) collect_issues
# ---------------------------------------------------------------------------

def _report(**overrides):
    base = {
        "license": "apache-2.0",
        "gated": False,
        "trust_remote_code": False,
        "auto_map": {},
        "tokenizer_auto_map": {},
        "external_code_repos": [],
        "commit_sha": "a" * 40,
        "config_errors": [],
        "missing_model_card_fields": [],
        "model_card": {"present": True, "is_unedited_template": False,
                       "placeholder_count": 0},
        "file_formats": {"pickle": [], "pickle_only": False, "python_files": []},
        "pickle_scan": {"status": "NOT_APPLICABLE", "malicious": [], "suspicious": [],
                        "skipped": [], "detail": ""},
    }
    base.update(overrides)
    return base


def test_clean_model_has_no_issues():
    assert mc.collect_issues(_report()) == []


def test_malicious_pickle_is_high():
    issues = mc.collect_issues(_report(pickle_scan={
        "status": "OK", "skipped": [], "suspicious": [], "detail": "",
        "malicious": [{"file": "m.bin", "module": "posix", "name": "system"}],
    }))
    assert issues[0]["severity"] == "HIGH"
    assert issues[0]["type"] == "malicious"


def test_pickle_only_is_high():
    issues = mc.collect_issues(_report(file_formats={
        "pickle": [{"path": "m.bin", "risk": "HIGH"}],
        "pickle_only": True, "python_files": []}))
    assert any(i["type"] == "pickle_only" and i["severity"] == "HIGH" for i in issues)


def test_trust_remote_code_is_high():
    issues = mc.collect_issues(_report(
        trust_remote_code=True, auto_map={"AutoModel": "modeling_x.X"}))
    assert any(i["type"] == "remote_code" and i["severity"] == "HIGH" for i in issues)


def test_external_code_repo_is_its_own_issue():
    issues = mc.collect_issues(_report(
        trust_remote_code=True, auto_map={"AutoModel": "other/repo--modeling_x.X"},
        external_code_repos=["other/repo"]))
    assert any(i["type"] == "external_code" for i in issues)


def test_skipped_scan_is_reported_as_unverified():
    """A check that could not run must never read as a pass."""
    issues = mc.collect_issues(_report(pickle_scan={
        "status": "UNAVAILABLE", "malicious": [], "suspicious": [],
        "skipped": [{"path": "m.bin", "reason": "picklescan not installed"}],
        "detail": "picklescan is not installed"}))
    assert any(i["type"] == "unverified" for i in issues)


def test_missing_license_is_flagged():
    issues = mc.collect_issues(_report(license=None))
    assert any(i["type"] == "no_license" for i in issues)


def test_missing_commit_sha_is_flagged():
    issues = mc.collect_issues(_report(commit_sha=None))
    assert any(i["type"] == "unverified" and "commit SHA" in i["message"]
               for i in issues)


def test_issues_are_sorted_by_severity():
    issues = mc.collect_issues(_report(
        license=None,                                   # MEDIUM
        gated=True,                                     # LOW
        file_formats={"pickle": [], "pickle_only": True, "python_files": []},  # HIGH
    ))
    severities = [i["severity"] for i in issues]
    assert severities == sorted(severities, key=lambda s: {"HIGH": 0, "MEDIUM": 1,
                                                           "LOW": 2}[s])


# ---------------------------------------------------------------------------
# 8) render / CLI
# ---------------------------------------------------------------------------

def test_render_does_not_crash_on_a_minimal_report():
    report = _report()
    report.update({
        "model_id": "org/m", "url": "https://huggingface.co/org/m",
        "model_name": "m", "author": "org", "pipeline": None, "library": None,
        "architectures": [], "license_name": None, "base_model": [], "datasets": [],
        "model_card": {"present": True, "completeness": 80,
                       "is_unedited_template": False, "placeholder_count": 0},
        "file_formats": {"total_files": 1, "pickle": [], "safetensors": [],
                         "other_weights": [], "python_files": [],
                         "pickle_only": False, "has_safetensors": False},
        "pickle_scan": {"status": "NOT_APPLICABLE", "malicious": [], "suspicious": [],
                        "skipped": [], "detail": "none"},
        "issues": [], "risk": "SAFE",
    })
    output = mc.render(report)
    assert "OVERALL RISK: SAFE" in output
    assert "org/m" in output


def test_cli_rejects_a_dataset_url(capsys):
    assert mc.main(["https://huggingface.co/datasets/squad", "--quiet"]) == 1
    assert "ERROR" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Merged from the yelin0726 implementation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filename", [
    "README.md", "readme.md", "modelcard.md", "model_card.md", "MODEL_CARD.md",
])
def test_model_card_is_found_under_any_of_its_names(monkeypatch, filename):
    """
    Checking only README.md reports repos that name their card modelcard.md
    or model_card.md as having no card at all - a false finding.
    """
    monkeypatch.setattr(mc, "_download_text", lambda *a: (GOOD_CARD, None))
    result, _ = mc.check_model_card("org/m", "sha", {filename}, {}, None)
    assert result["present"] is True
    assert result["card_file"] == filename


def test_card_is_downloaded_under_the_name_it_actually_has(monkeypatch):
    requested = []

    def fake_download(model_id, name, revision, token):
        requested.append(name)
        return GOOD_CARD, None

    monkeypatch.setattr(mc, "_download_text", fake_download)
    mc.check_model_card("org/m", "sha", {"modelcard.md"}, {}, None)
    assert requested == ["modelcard.md"]


def test_repository_with_no_card_under_any_name():
    result, _ = mc.check_model_card("org/m", "sha", {"config.json"}, {}, None)
    assert result["present"] is False
    assert result["card_file"] is None
    assert "model card" in result["detail"].lower()


def test_short_revision_is_flagged_as_not_pinned():
    """
    A 7-character revision is not immutable - what it points at can change.
    Only a full 40-hex SHA pins the report to fixed content.
    """
    issues = mc.collect_issues(_report(commit_sha="133a221"))
    assert any(i["type"] == "unverified" and "40-character" in i["message"]
               for i in issues)


def test_full_sha_is_not_flagged():
    issues = mc.collect_issues(_report(commit_sha="a" * 40))
    assert not any("40-character" in i["message"] for i in issues)


def test_branch_name_as_revision_is_flagged():
    issues = mc.collect_issues(_report(commit_sha="main"))
    assert any("40-character" in i["message"] for i in issues)


@pytest.mark.parametrize("value,expected", [
    ("dangerous", "dangerous"),
    ("suspicious", "suspicious"),
    ("innocuous", "innocuous"),
    ("Dangerous", "dangerous"),
    (None, "suspicious"),
    ("something-new", "suspicious"),
])
def test_safety_label_normalisation(value, expected):
    """
    An unrecognised safety level must grade as worth a look, never as
    innocuous - that is how a finding silently disappears.
    """
    assert mc._safety_label(value) == expected


def test_safety_label_accepts_the_picklescan_enum():
    picklescan = pytest.importorskip("picklescan.scanner")
    assert mc._safety_label(picklescan.SafetyLevel.Dangerous) == "dangerous"
    assert mc._safety_label(picklescan.SafetyLevel.Innocuous) == "innocuous"


def test_infected_file_without_named_globals_is_still_reported(fake_downloads,
                                                               monkeypatch):
    """
    picklescan reports an infected-file count separately from the globals
    list. Reading only the globals loses a file it flagged.
    """
    class Result:
        globals = []
        scan_err = False
        infected_files = 1

    fake_downloads["m.pkl"] = BENIGN_PICKLE
    monkeypatch.setattr("picklescan.scanner.scan_file_path", lambda p: Result())

    report = mc.scan_pickle_files(
        "org/m", "sha", [_pickle_entry("m.pkl", 100)], 512)
    assert len(report["malicious"]) == 1
    assert "infected" in report["malicious"][0]["detail"]


def test_report_lists_every_file_in_the_repository():
    """An AIBOM records what the repo contains, not only classified files."""
    formats = mc.classify_files([("a.safetensors", 1), ("README.md", 2),
                                 ("weird.xyz", 3)])
    assert formats["total_files"] == 3
