"""
test_sbom_generator.py
-----------------------------------
Unit tests for the CycloneDX / ML-BOM writer.

    python3 -m pytest test_sbom_generator.py -q

sbom_generator.py had no tests, which is how the severity mapping stayed
backwards for as long as it did. No network and no cyclonedx-py CLI needed:
every test drives the pure functions over a hand-built base SBOM.
"""

import json

import pytest

from sbom_generator import (
    _map_severity,
    add_models_to_sbom,
    build_model_component,
    enrich_sbom_with_findings,
)


def base_sbom(*names):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"name": name, "bom-ref": f"requirements-L{i}", "type": "library",
             "version": "1.0"}
            for i, name in enumerate(names, start=1)
        ],
    }


def package(name="requests", **overrides):
    entry = {
        "package": name, "version": "2.28.0",
        "license_status": "ALLOWED", "trust_score": 75,
        "verdict": "CONDITIONAL", "vulnerabilities": [],
    }
    entry.update(overrides)
    return entry


MODEL = {
    "model_id": "CompVis/stable-diffusion-v1-4",
    "url": "https://huggingface.co/CompVis/stable-diffusion-v1-4",
    "commit_sha": "133a221b",
    "author": "CompVis",
    "pipeline": "text-to-image",
    "library": "diffusers",
    "architectures": ["UNet2DConditionModel"],
    "datasets": ["laion/laion2B-en"],
    "license": "creativeml-openrail-m",
    "license_status": "BLOCKED",
    "license_family": "ai-behavioural",
    "risk_score": 49,
    "verdict": "BLOCK",
    "trust_remote_code": False,
    "external_code_repos": [],
    "file_formats": {"safetensors": [{"path": "a.safetensors"}],
                     "pickle": [{"path": "b.bin"}],
                     "has_safetensors": True, "pickle_only": False},
    "model_card": {"present": True, "completeness": 60,
                   "is_unedited_template": False, "placeholder_count": 0},
    "pickle_scan": {"status": "SKIPPED"},
    "issues": [{"type": "pickle_file", "severity": "MEDIUM",
                "message": "b.bin has no safetensors equivalent"}],
}


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("critical", "critical"), ("high", "high"), ("medium", "medium"),
    ("low", "low"), ("unknown", "unknown"), ("none", "none"),
    ("HIGH", "high"), ("High severity", "high"),
    (None, "unknown"), ("", "unknown"), ("nonsense", "unknown"),
])
def test_severity_maps_to_the_cyclonedx_set(raw, expected):
    assert _map_severity(raw) == expected


def test_attack_complexity_high_is_not_severity_high():
    """
    The previous mapping returned "high" for anything containing "AC:H".
    In a CVSS vector AC:H means Attack Complexity High - the attack is
    *harder*, which lowers the score. CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/
    I:N/A:N has a base score of 5.3, which is medium.
    """
    assert _map_severity("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N") != "high"


# ---------------------------------------------------------------------------
# Package enrichment
# ---------------------------------------------------------------------------

def test_findings_are_attached_as_properties():
    sbom = enrich_sbom_with_findings(base_sbom("requests"), [package()])
    props = {p["name"]: p["value"] for p in sbom["components"][0]["properties"]}
    assert props["aibom-guard:verdict"] == "CONDITIONAL"
    assert props["aibom-guard:trust_score"] == "75"
    assert props["aibom-guard:license_status"] == "ALLOWED"


def test_vulnerabilities_become_a_top_level_array():
    report = [package(vulnerabilities=[
        {"id": "GHSA-x", "summary": "leak", "severity": "medium",
         "cvss_score": 5.3}])]
    sbom = enrich_sbom_with_findings(base_sbom("requests"), report)

    vuln = sbom["vulnerabilities"][0]
    assert vuln["id"] == "GHSA-x"
    assert vuln["affects"][0]["ref"] == "requirements-L1"
    assert vuln["ratings"][0]["severity"] == "medium"


def test_cvss_score_is_emitted_as_a_number_not_null():
    """osv_client parses the vector, so the rating can carry the real score."""
    report = [package(vulnerabilities=[
        {"id": "GHSA-x", "summary": "s", "severity": "high", "cvss_score": 8.1}])]
    rating = enrich_sbom_with_findings(
        base_sbom("requests"), report)["vulnerabilities"][0]["ratings"][0]
    assert rating["score"] == 8.1
    assert rating["method"] == "CVSSv31"


def test_missing_cvss_score_omits_the_number():
    report = [package(vulnerabilities=[
        {"id": "PYSEC-1", "summary": "s", "severity": "unknown"}])]
    rating = enrich_sbom_with_findings(
        base_sbom("requests"), report)["vulnerabilities"][0]["ratings"][0]
    assert "score" not in rating
    assert rating["method"] == "other"


def test_alias_ids_are_recorded_as_references():
    """A reader must be able to find the same flaw in another database."""
    report = [package(vulnerabilities=[
        {"id": "GHSA-x", "summary": "s", "severity": "high",
         "aliases": ["PYSEC-2026-1872", "CVE-2024-1"]}])]
    refs = enrich_sbom_with_findings(
        base_sbom("requests"), report)["vulnerabilities"][0]["references"]
    assert {r["id"] for r in refs} == {"PYSEC-2026-1872", "CVE-2024-1"}
    assert {r["source"]["name"] for r in refs} == {"PyPI Advisory Database", "NVD"}


def test_no_vulnerabilities_key_when_there_are_none():
    sbom = enrich_sbom_with_findings(base_sbom("requests"), [package()])
    assert "vulnerabilities" not in sbom


# ---------------------------------------------------------------------------
# ML-BOM
# ---------------------------------------------------------------------------

def test_model_becomes_a_machine_learning_model_component():
    """This is what makes the output an AI BOM rather than a plain SBOM."""
    component = build_model_component(MODEL)
    assert component["type"] == "machine-learning-model"
    assert component["name"] == "CompVis/stable-diffusion-v1-4"


def test_model_version_is_the_commit_sha():
    """A branch moves; the SHA is what makes the reference reproducible."""
    component = build_model_component(MODEL)
    assert component["version"] == "133a221b"
    assert component["purl"].endswith("@133a221b")


def test_model_purl_uses_the_huggingface_type():
    component = build_model_component(MODEL)
    assert component["purl"] == (
        "pkg:huggingface/CompVis/stable-diffusion-v1-4@133a221b")


def test_ai_license_goes_in_as_a_name_not_an_spdx_id():
    """
    creativeml-openrail-m, llama3.1 and gemma have no SPDX identifier, so
    the spec says to use license.name. Emitting them as license.id would
    produce a document that fails schema validation.
    """
    licenses = build_model_component(MODEL)["licenses"]
    assert licenses[0]["license"]["name"] == "creativeml-openrail-m"
    assert "id" not in licenses[0]["license"]


def test_model_card_carries_task_and_datasets():
    card = build_model_component(MODEL)["modelCard"]
    assert card["modelParameters"]["task"] == "text-to-image"
    assert card["modelParameters"]["datasets"] == [
        {"type": "dataset", "name": "laion/laion2B-en"}]


def test_missing_model_card_is_recorded_as_a_consideration():
    model = dict(MODEL, model_card={"present": False, "completeness": 0})
    card = build_model_component(model)["modelCard"]
    assert "No model card" in card["considerations"]["ethicalConsiderations"][0]["name"]


def test_unedited_template_is_recorded_as_a_consideration():
    model = dict(MODEL, model_card={"present": True, "completeness": 10,
                                    "is_unedited_template": True,
                                    "placeholder_count": 12})
    card = build_model_component(model)["modelCard"]
    text = card["considerations"]["ethicalConsiderations"][0]["mitigationStrategy"]
    assert "12" in text


def test_findings_are_exposed_as_properties():
    props = {p["name"]: p["value"]
             for p in build_model_component(MODEL)["properties"]}
    assert props["aibom-guard:verdict"] == "BLOCK"
    assert props["aibom-guard:license_family"] == "ai-behavioural"
    assert props["aibom-guard:weight_formats:pickle"] == "1"
    assert props["aibom-guard:pickle_only"] == "false"


def test_external_code_repos_are_listed():
    model = dict(MODEL, external_code_repos=["nomic-ai/nomic-bert-2048"])
    props = [p for p in build_model_component(model)["properties"]
             if p["name"] == "aibom-guard:external_code_repo"]
    assert props[0]["value"] == "nomic-ai/nomic-bert-2048"


def test_models_are_appended_alongside_packages():
    sbom = add_models_to_sbom(base_sbom("requests"), [MODEL])
    types = [c["type"] for c in sbom["components"]]
    assert types == ["library", "machine-learning-model"]


def test_model_issues_become_vulnerabilities():
    """One consumer reads package CVEs and model findings the same way."""
    sbom = add_models_to_sbom(base_sbom("requests"), [MODEL])
    vuln = sbom["vulnerabilities"][0]
    assert vuln["affects"][0]["ref"] == sbom["components"][1]["bom-ref"]
    assert vuln["ratings"][0]["severity"] == "medium"


def test_ml_bom_profile_is_declared():
    sbom = add_models_to_sbom(base_sbom("requests"), [MODEL])
    props = {p["name"]: p["value"] for p in sbom["metadata"]["properties"]}
    assert props["aibom-guard:profile"] == "ml-bom"


def test_no_models_leaves_the_sbom_untouched():
    original = base_sbom("requests")
    assert add_models_to_sbom(dict(original), []) == original


def test_output_is_json_serialisable():
    sbom = add_models_to_sbom(
        enrich_sbom_with_findings(base_sbom("requests"), [package()]), [MODEL])
    json.dumps(sbom)      # must not raise


def test_model_with_minimal_metadata_does_not_raise():
    """Gated or sparse repos return very little; the writer must cope."""
    component = build_model_component({"model_id": "org/sparse"})
    assert component["type"] == "machine-learning-model"
    assert component["version"] == "main"


# ---------------------------------------------------------------------------
# Supply-chain evidence in the SBOM (merged from yelin0726)
# ---------------------------------------------------------------------------

SUPPLY = {
    "trust_score": 65, "verdict": "CONDITIONAL", "openssf_score": 8.2,
    "repository": "psf/requests", "github_star": 54200,
    "last_commit": "2026-07-27", "signature": False, "provenance": False,
    "issues": [{"type": "signature", "severity": "medium",
                "detail": "no signature found"}],
}


def test_supply_chain_evidence_reaches_the_sbom():
    """
    scanner collects this under --supply-chain, but it never reached the
    document: the SBOM recorded the verdict while dropping the evidence
    behind it.
    """
    sbom = enrich_sbom_with_findings(
        base_sbom("requests"), [package(supply_chain=SUPPLY)])
    props = {p["name"]: p["value"] for p in sbom["components"][0]["properties"]}

    assert props["aibom-guard:openssf_score"] == "8.2"
    assert props["aibom-guard:repository"] == "psf/requests"
    assert props["aibom-guard:supply_chain_trust"] == "65"
    assert props["aibom-guard:github_star"] == "54200"
    assert props["aibom-guard:last_commit"] == "2026-07-27"


def test_boolean_supply_chain_fields_are_lowercased():
    """CycloneDX property values are strings; Python's True is not valid."""
    sbom = enrich_sbom_with_findings(
        base_sbom("requests"), [package(supply_chain=SUPPLY)])
    props = {p["name"]: p["value"] for p in sbom["components"][0]["properties"]}
    assert props["aibom-guard:signature"] == "false"
    assert props["aibom-guard:provenance"] == "false"


def test_no_supply_chain_adds_no_properties():
    sbom = enrich_sbom_with_findings(base_sbom("requests"), [package()])
    names = {p["name"] for p in sbom["components"][0]["properties"]}
    assert not any("openssf" in n for n in names)


def test_missing_supply_chain_fields_are_skipped_not_emitted_as_none():
    sbom = enrich_sbom_with_findings(base_sbom("requests"), [package(
        supply_chain={"trust_score": 50, "openssf_score": None})])
    values = [p["value"] for p in sbom["components"][0]["properties"]]
    assert "None" not in values
