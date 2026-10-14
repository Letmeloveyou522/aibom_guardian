from unittest.mock import Mock

import pytest
import requests

from aibom_guardian.bom_tools import upload_bom, validate_bom
from aibom_guardian.sbom_generator import (
    enrich_sbom_with_findings, add_models_to_sbom, ensure_cyclonedx_metadata,
)

PROJECT = "12345678-1234-4234-8234-123456789012"


def bom():
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [{"type": "library", "name": "demo", "version": "1",
                            "bom-ref": "pkg:pypi/demo@1", "purl": "pkg:pypi/demo@1"}]}


def test_generated_package_and_model_fields_pass_real_schema():
    document = enrich_sbom_with_findings(bom(), [{
        "package": "demo", "version": "1", "license_status": "ALLOWED",
        "trust_score": 100, "verdict": "ALLOW", "vulnerabilities": [],
    }])
    document = add_models_to_sbom(document, [{
        "model_id": "owner/model", "commit_sha": "a" * 40,
        "license": "mit", "license_status": "ALLOWED", "verdict": "WARNING",
        "risk_score": 90, "issues": [], "model_card": {"present": True},
    }])
    ensure_cyclonedx_metadata(document, profile="ml-bom", subject="test")
    validate_bom(document)


def test_invalid_bom_never_uploads():
    session = Mock()
    invalid = bom()
    invalid["components"][0]["type"] = "made-up"
    with pytest.raises(ValueError, match="Invalid CycloneDX"):
        upload_bom(invalid, "https://example.invalid", PROJECT, "secret", session=session)
    session.post.assert_not_called()


def test_upload_acceptance_is_not_analysis_success():
    session = Mock()
    session.post.return_value.status_code = 200
    session.post.return_value.json.return_value = {"token": PROJECT}
    result = upload_bom(bom(), "https://example.invalid", PROJECT, "secret", session=session)
    assert result["status"] == "accepted"
    assert result["analysis_verified"] is False
    kwargs = session.post.call_args.kwargs
    assert kwargs["allow_redirects"] is False
    assert kwargs["headers"]["X-Api-Key"] == "secret"
    assert "secret" not in str(result)
    assert len(result["bom_sha256"]) == 64


@pytest.mark.parametrize("url", ["http://example.invalid", "https://user:pass@example.invalid", "https://example.invalid?key=abc"])
def test_upload_rejects_unsafe_url(url):
    session = Mock()
    with pytest.raises(ValueError):
        upload_bom(bom(), url, PROJECT, "secret", session=session)
    session.post.assert_not_called()


@pytest.mark.parametrize("status", [302, 401, 403, 500])
def test_upload_rejects_http_failure(status):
    session = Mock()
    session.post.return_value.status_code = status
    with pytest.raises(ValueError, match=f"HTTP {status}"):
        upload_bom(bom(), "https://example.invalid", PROJECT, "secret", session=session)


def test_timeout_is_not_retried_and_does_not_leak_secret():
    session = Mock()
    session.post.side_effect = requests.Timeout("secret")
    with pytest.raises(ValueError) as error:
        upload_bom(bom(), "https://example.invalid", PROJECT, "secret", session=session)
    assert "secret" not in str(error.value)
    assert session.post.call_count == 1


def test_missing_token_is_not_success():
    session = Mock()
    session.post.return_value.status_code = 200
    session.post.return_value.json.return_value = {}
    with pytest.raises(ValueError, match="processing token"):
        upload_bom(bom(), "https://example.invalid", PROJECT, "secret", session=session)
