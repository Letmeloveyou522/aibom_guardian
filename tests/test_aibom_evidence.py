from aibom_guardian.aibom_evidence import model_evidence
from aibom_guardian.repository_checker._datasets import check_dataset_documentation


def test_disclosure_is_not_integrity_or_compliance():
    result = model_evidence({"model_id": "org/model", "commit_sha": "a" * 40,
                             "requested_revision": "main", "file_hashes": {"x.bin": "b" * 64}})
    fields = {f["field"]: f for f in result["fields"]}
    assert result["conformance_claim"] is False and result["score_effect"] == "none"
    assert fields["resolved_revision"]["status"] == "present"
    assert fields["published_file_hashes"]["status"] == "present"
    assert fields["training_data_rights"]["status"] == "needs_review"
    assert fields["pickle_static_scan"]["status"] == "unverified"


def test_mismatch_and_unreadable_card_are_unverified():
    result = model_evidence({"commit_sha": "a" * 40, "requested_revision": "b" * 40,
                             "file_hashes": {"x": "bad"},
                             "model_card": {"present": True, "read_status": "unverified"}})
    fields = {f["field"]: f for f in result["fields"]}
    for field in ("resolved_revision", "published_file_hashes", "model_card"):
        assert fields[field]["status"] == "unverified"


def test_deep_dataset_heading_and_placeholder_do_not_cross_sections():
    result = check_dataset_documentation(
        "#### Data Sources:\nData collected from https://example.org/archive.\n"
        "#### Data Collection\n[More Information Needed]\n"
        "#### Other\n" + "Irrelevant text. " * 10)
    assert result["source_documented"] is True
    assert result["collection_method_documented"] is None
    assert result["field_status"]["collection_method"] == "unverified"
    assert result["confidence"]["processing_method"] == "low"


def test_ordinary_prose_does_not_prove_documentation_absent():
    result = check_dataset_documentation("The dataset is discussed in our paper.")
    assert result["field_status"]["source"] == "not_observed"
    assert result["confidence"]["source"] == "low"


def test_license_section_does_not_use_first_word_as_identifier():
    result = check_dataset_documentation("## License\nLicensed under MIT. See LICENSE.")
    assert result["license"] == "MIT"
    assert check_dataset_documentation("## License\nPlease contact the author.")["license"] is None
