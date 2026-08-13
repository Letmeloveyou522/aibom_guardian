"""
test_sbom_generator.py
-----------------------------------
Unit tests for the CycloneDX / ML-BOM writer.

sbom_generator.py had no tests, which is how the severity mapping stayed
backwards for as long as it did. No network and no cyclonedx-py CLI needed:
every test drives the pure functions over a hand-built base SBOM.
"""

import json

import pytest

from aibom_guard import sbom_generator
from aibom_guard.sbom_generator import (
    _map_severity,
    add_models_to_sbom,
    build_model_component,
    enrich_sbom_with_findings,
    ensure_cyclonedx_metadata,
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
        "verdict": "WARNING", "vulnerabilities": [],
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
    vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"
    assert _map_severity(vector) != "high"
    assert _map_severity(vector) == "medium"


# ---------------------------------------------------------------------------
# Package enrichment
# ---------------------------------------------------------------------------

def test_findings_are_attached_as_properties():
    sbom = enrich_sbom_with_findings(base_sbom("requests"), [package()])
    props = {p["name"]: p["value"] for p in sbom["components"][0]["properties"]}
    assert props["aibom-guard:verdict"] == "WARNING"
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
    "trust_score": 65, "verdict": "WARNING", "openssf_score": 8.2,
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


# ---------------------------------------------------------------------------
# G7 metadata + OSV None contract
# ---------------------------------------------------------------------------

def test_g7_metadata_includes_tools_timestamp_and_manufacturer():
    sbom = enrich_sbom_with_findings(base_sbom("requests"), [package()])
    meta = sbom["metadata"]
    assert "timestamp" in meta
    assert meta["manufacturer"]["name"] == "AIBOM-Guard"
    tools = meta["tools"]
    assert isinstance(tools, dict)
    names = [c["name"] for c in tools["components"]]
    assert "AIBOM-Guard" in names


def test_ensure_metadata_upgrades_profile_to_ml_bom():
    sbom = enrich_sbom_with_findings(base_sbom("requests"), [package()])
    assert {p["name"]: p["value"]
            for p in sbom["metadata"]["properties"]}["aibom-guard:profile"] == "sbom"
    sbom = add_models_to_sbom(sbom, [MODEL])
    props = {p["name"]: p["value"] for p in sbom["metadata"]["properties"]}
    assert props["aibom-guard:profile"] == "ml-bom"
    # Profile must appear once, not duplicated.
    assert sum(1 for p in sbom["metadata"]["properties"]
               if p["name"] == "aibom-guard:profile") == 1


def test_osv_none_vulnerabilities_do_not_raise_and_mark_unverified():
    """None means unverified — must not be iterated as an empty CVE list."""
    report = [package(vulnerabilities=None, osv_unverified=True)]
    sbom = enrich_sbom_with_findings(base_sbom("requests"), report)
    assert "vulnerabilities" not in sbom
    props = {p["name"]: p["value"] for p in sbom["components"][0]["properties"]}
    assert props["aibom-guard:osv_unverified"] == "true"


def test_model_component_always_has_model_card():
    """G7 / ML-BOM: every machine-learning-model carries a modelCard object."""
    component = build_model_component(MODEL)
    assert component["type"] == "machine-learning-model"
    assert "modelCard" in component
    assert "bom-ref" in component["modelCard"]


def test_ensure_cyclonedx_metadata_is_idempotent():
    sbom = base_sbom("requests")
    ensure_cyclonedx_metadata(sbom, profile="sbom")
    ensure_cyclonedx_metadata(sbom, profile="sbom")
    tools = sbom["metadata"]["tools"]["components"]
    assert sum(1 for c in tools if c["name"] == "AIBOM-Guard") == 1


# ---------------------------------------------------------------------------
# The resolved license has to reach the document, not just the report
# ---------------------------------------------------------------------------

def _component(name="requests", licenses=None):
    component = {"name": name, "bom-ref": f"ref-{name}", "type": "library"}
    if licenses is not None:
        component["licenses"] = licenses
    return component


def _scan_row(**overrides):
    row = {
        "package": "requests", "version": "2.32.3",
        "license_raw": "Apache-2.0", "license_status": "ALLOWED",
        "license_spdx_id": "Apache-2.0", "license_family": "permissive",
        "license_source": "pypi:license", "license_unverified": False,
        "license_obligations": ["Keep the copyright notice."],
        "trust_score": 100, "verdict": "ALLOW", "vulnerabilities": [],
    }
    row.update(overrides)
    return row


def test_resolved_licence_fills_the_standard_licenses_field():
    """
    cyclonedx-py reads installed metadata, so scanning a requirements file on
    a machine without those packages produced a document where every
    component had `licenses: null` - while the scan report held the SPDX id.
    The finding never reached the artifact that is supposed to carry it.
    """
    sbom = {"components": [_component()]}
    sbom_generator.enrich_sbom_with_findings(sbom, [_scan_row()])

    assert sbom["components"][0]["licenses"] == [{"license": {"id": "Apache-2.0"}}]


def test_obligations_and_provenance_ride_along():
    sbom = {"components": [_component()]}
    sbom_generator.enrich_sbom_with_findings(sbom, [_scan_row()])

    props = {p["name"]: p["value"] for p in sbom["components"][0]["properties"]}
    assert props["aibom-guard:license_spdx_id"] == "Apache-2.0"
    assert props["aibom-guard:license_source"] == "pypi:license"
    assert props["aibom-guard:license_obligation:0"].startswith("Keep the")


def test_a_real_spdx_expression_is_emitted_as_an_expression():
    sbom = {"components": [_component()]}
    sbom_generator.enrich_sbom_with_findings(
        sbom, [_scan_row(license_raw="Apache-2.0 OR BSD-3-Clause",
                         license_spdx_id="")])

    assert sbom["components"][0]["licenses"] == [
        {"expression": "Apache-2.0 OR BSD-3-Clause"}]


def test_prose_is_not_passed_off_as_an_spdx_expression():
    """
    psycopg2 declares "LGPL with exceptions". SPDX operators are uppercase, so
    lowercase "with" is a word here, not an operator - emitting it as an
    expression produces a document no validator accepts.
    """
    sbom = {"components": [_component()]}
    sbom_generator.enrich_sbom_with_findings(
        sbom, [_scan_row(license_raw="LGPL with exceptions", license_spdx_id="")])

    assert sbom["components"][0]["licenses"] == [
        {"license": {"name": "LGPL with exceptions"}}]


def test_an_unreadable_license_leaves_the_field_alone():
    sbom = {"components": [_component()]}
    sbom_generator.enrich_sbom_with_findings(
        sbom, [_scan_row(license_raw="NOT_INSTALLED", license_spdx_id="")])

    assert "licenses" not in sbom["components"][0]


def test_a_licence_the_generator_already_found_is_kept_visible():
    """Overwriting a declared license silently would hide the disagreement."""
    sbom = {"components": [_component(licenses=[{"license": {"id": "MIT"}}])]}
    sbom_generator.enrich_sbom_with_findings(sbom, [_scan_row()])

    component = sbom["components"][0]
    assert component["licenses"] == [{"license": {"id": "Apache-2.0"}}]
    props = {p["name"]: p["value"] for p in component["properties"]}
    assert "MIT" in props["aibom-guard:license_declared_by_generator"]


# ---------------------------------------------------------------------------
# G7: metadata cluster, model lineage and hashes
# ---------------------------------------------------------------------------

def test_metadata_names_the_author_and_the_lifecycle_phase():
    """
    G7 keeps "SBOM author" (who ran the tool) apart from "Producer" (who made
    the component), and asks for the generation context. Only the producer
    side was filled, so a reader could not tell whether the document
    described a build or a declared dependency list.
    """
    sbom = ensure_cyclonedx_metadata({}, subject="my-service")
    meta = sbom["metadata"]

    assert meta["authors"] == [{"name": "AIBOM-Guard"}]
    assert meta["lifecycles"] == [{"phase": "pre-build"}]
    assert meta["component"]["name"] == "my-service"


def test_metadata_never_overwrites_what_is_already_there():
    sbom = {"metadata": {"authors": [{"name": "Someone Else"}],
                         "lifecycles": [{"phase": "build"}]}}
    ensure_cyclonedx_metadata(sbom, subject="x")

    assert sbom["metadata"]["authors"] == [{"name": "Someone Else"}]
    assert sbom["metadata"]["lifecycles"] == [{"phase": "build"}]


def _model(**overrides):
    model = {
        "model_id": "org/tuned", "commit_sha": "abc123",
        "license": "apache-2.0", "last_modified": "2026-01-02T03:04:05+00:00",
        "base_model": [{"repo_id": "org/base", "relation": "finetune"}],
        "file_hashes": {"model.safetensors": "a" * 64,
                        "pytorch_model.bin": "b" * 64},
        "file_formats": {
            "safetensors": [{"path": "model.safetensors", "size_bytes": 900}],
            "pickle": [{"path": "pytorch_model.bin", "size_bytes": 800}],
        },
    }
    model.update(overrides)
    return model


def test_a_fine_tune_records_the_model_it_came_from():
    """
    model_checker parses the Hub's base_model metadata, relation included,
    but it never reached the document - an ML-BOM described a fine-tune as if
    it had been trained from nothing. G7 calls this the model's lineage.
    """
    component = build_model_component(_model())

    ancestors = component["pedigree"]["ancestors"]
    assert ancestors[0]["name"] == "org/base"
    assert ancestors[0]["purl"] == "pkg:huggingface/org/base"
    relation = {p["name"]: p["value"] for p in ancestors[0]["properties"]}
    assert relation["aibom-guard:base_model_relation"] == "finetune"


def test_the_primary_weight_file_is_hashed():
    """
    `hashes` describes one artifact under different algorithms, so the
    largest safetensors shard goes there and the rest become properties -
    nine same-algorithm digests in that array would misuse the field.
    """
    component = build_model_component(_model())

    assert component["hashes"] == [{"alg": "SHA-256", "content": "a" * 64}]
    props = {p["name"]: p["value"] for p in component["properties"]}
    assert props["aibom-guard:sha256:model.safetensors"] == "a" * 64
    assert props["aibom-guard:sha256:pytorch_model.bin"] == "b" * 64


def test_a_pickle_only_model_still_gets_a_hash():
    component = build_model_component(_model(
        file_formats={"pickle": [{"path": "pytorch_model.bin",
                                  "size_bytes": 800}]},
        file_hashes={"pytorch_model.bin": "c" * 64}))

    assert component["hashes"] == [{"alg": "SHA-256", "content": "c" * 64}]


def test_a_model_without_published_hashes_omits_the_field():
    component = build_model_component(_model(file_hashes={}))
    assert "hashes" not in component


def test_the_model_timestamp_is_recorded():
    props = {p["name"]: p["value"]
             for p in build_model_component(_model())["properties"]}
    assert props["aibom-guard:last_modified"] == "2026-01-02T03:04:05+00:00"
