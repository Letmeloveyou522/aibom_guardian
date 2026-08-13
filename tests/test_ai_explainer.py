"""
tests/test_ai_explainer.py
-----------------------------------
Unit tests for ai_explainer.build_prompt() and explain_results().
"""

from aibom_guard import ai_explainer


PACKAGE_WARNING = {
    "package": "requests",
    "version": "2.28.0",
    "verdict": "WARNING",
    "license_status": "ALLOWED",
    "vulnerabilities": [{"summary": "leak", "severity": "medium"}],
    "issues": [{"type": "cve", "summary": "leak", "severity": "medium"}],
    "alternatives": [{"target": "requests==2.34.2", "confidence": "confirmed"}],
}

PACKAGE_ALLOW = {
    "package": "numpy",
    "version": "1.24.0",
    "verdict": "ALLOW",
    "license_status": "ALLOWED",
    "vulnerabilities": [],
    "issues": [],
    "alternatives": [],
}

NUMPY_LICENSE_ONLY = {
    "package": "numpy",
    "version": "1.24.0",
    "verdict": "WARNING",
    "license_status": "UNKNOWN",
    "vulnerabilities": [],
    "issues": [],
    "alternatives": [],
}

PYYAML_BLOCK = {
    "package": "pyyaml",
    "version": "5.3.1",
    "verdict": "BLOCK",
    "license_status": "ALLOWED",
    "vulnerabilities": [{
        "summary": "PyYAML full_load arbitrary code execution before 5.4",
        "severity": "critical",
    }],
    "issues": [{
        "type": "cve",
        "summary": "PyYAML full_load arbitrary code execution before 5.4",
        "severity": "critical",
    }],
    "alternatives": [{"target": "PyYAML==6.0.3", "confidence": "confirmed"}],
}


def test_build_prompt_accepts_document_shape():
    doc = {
        "packages": [PACKAGE_ALLOW, PACKAGE_WARNING],
        "models": [],
        "unscanned": [],
    }
    prompt = ai_explainer.build_prompt(doc)
    assert prompt is not None
    assert "requests==2.28.0" in prompt
    assert "Known CVE count: 1" in prompt
    assert "requests==2.34.2" in prompt


def test_build_prompt_single_item_isolates_one_package():
    prompt = ai_explainer.build_prompt({}, item=NUMPY_LICENSE_ONLY)
    assert prompt is not None
    assert "numpy==1.24.0" in prompt
    assert "Known CVE count: 0" in prompt
    assert "license: status is UNKNOWN" in prompt
    assert "pyyaml" not in prompt.lower()
    assert "6.0.3" not in prompt
    assert "full_load" not in prompt.lower()


def test_build_prompt_numpy_block_does_not_include_pyyaml_fix():
    prompt = ai_explainer.build_prompt(
        {"packages": [NUMPY_LICENSE_ONLY, PYYAML_BLOCK], "models": [], "unscanned": []},
        item=NUMPY_LICENSE_ONLY,
    )
    assert "PyYAML==6.0.3" not in prompt
    assert "full_load" not in prompt.lower()


def test_build_prompt_returns_none_when_everything_is_allow():
    doc = {"packages": [PACKAGE_ALLOW], "models": [], "unscanned": []}
    assert ai_explainer.build_prompt(doc) is None


def test_deterministic_explanation_for_zero_cve_license_warning():
    text = ai_explainer._deterministic_explanation(NUMPY_LICENSE_ONLY)
    assert "published cves" in text.lower()
    assert "license status is unknown" in text.lower()
    assert "pyyaml" not in text.lower()
    assert "5.3.1" not in text
    assert "full_load" not in text.lower()


def test_explain_results_short_circuits_when_nothing_risky():
    doc = {"packages": [PACKAGE_ALLOW], "models": [], "unscanned": []}
    assert ai_explainer.explain_results(doc) == "No risky packages found - nothing to explain."


def test_explain_results_uses_one_call_per_package(monkeypatch):
    prompts = []

    def fake_post(url, json, timeout):
        prompts.append(json["prompt"])

        class Resp:
            def raise_for_status(self):
                return None

            def json(self):
                if "numpy==1.24.0" in json["prompt"]:
                    return {"response": "numpy has UNKNOWN license; 0 CVEs."}
                return {"response": "pyyaml has a critical YAML loader CVE."}

        return Resp()

    monkeypatch.setattr(ai_explainer.requests, "post", fake_post)

    doc = {"packages": [NUMPY_LICENSE_ONLY, PYYAML_BLOCK], "models": [], "unscanned": []}
    text = ai_explainer.explain_results(doc)

    assert len(prompts) == 2
    assert "numpy==1.24.0" in prompts[0]
    assert "pyyaml==5.3.1" in prompts[1]
    numpy_part = text.split("pyyaml==5.3.1")[0]
    assert "full_load" not in numpy_part.lower()
    assert "6.0.3" not in numpy_part


def test_explain_results_rejects_cross_package_llm_output(monkeypatch):
    def fake_post(url, json, timeout):
        class Resp:
            def raise_for_status(self):
                return None

            def json(self):
                return {"response": "Upgrade numpy to PyYAML 6.0.3 due to full_load CVE."}

        return Resp()

    monkeypatch.setattr(ai_explainer.requests, "post", fake_post)

    text = ai_explainer.explain_results(
        {"packages": [NUMPY_LICENSE_ONLY], "models": [], "unscanned": []})
    assert "published cves" in text.lower()
    assert "full_load" not in text.lower()
    assert "6.0.3" not in text


def test_explain_results_prefixes_package_label(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"response": "Upgrade requests."}

    monkeypatch.setattr(ai_explainer.requests, "post", lambda *a, **k: FakeResponse())
    text = ai_explainer.explain_results({"packages": [PACKAGE_WARNING], "models": [], "unscanned": []})
    assert text.startswith("requests==2.28.0 (WARNING): Upgrade requests.")
