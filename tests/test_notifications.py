import json
from unittest.mock import Mock

import pytest
import requests

from aibom_guardian.notifications import (
    SLACK_WEBHOOK_ENV, send_slack, slack_payload, slack_webhook_url,
)


@pytest.mark.parametrize("url", [
    "http://hooks.slack.com/services/a/b/secret",
    "https://example.com/services/a/b/secret",
    "https://hooks.slack.com.evil.test/services/a/b/secret",
    "https://user:secret@hooks.slack.com/services/a/b/c",
    "https://hooks.slack.com:999/services/a/b/secret",
    "https://hooks.slack.com/services/a/b/secret?token=secret",
    "https://hooks.slack.com/services/a/b/secret#secret",
    "https://hooks.slack.com/wrong/secret",
    "https://[broken/secret",
])
def test_reject_invalid_urls_without_secret(monkeypatch, url):
    monkeypatch.setenv(SLACK_WEBHOOK_ENV, url)
    with pytest.raises(ValueError) as error:
        slack_webhook_url()
    assert "secret" not in str(error.value)


def test_optional_url_and_govslack(monkeypatch):
    monkeypatch.delenv(SLACK_WEBHOOK_ENV, raising=False)
    assert slack_webhook_url() is None
    url = "https://hooks.slack-gov.com/services/a/b/c"
    monkeypatch.setenv(SLACK_WEBHOOK_ENV, url)
    assert slack_webhook_url() == url


@pytest.mark.parametrize("code,body,status", [
    (200, "ok", "sent"), (200, "unexpected", "failed"),
    (200, "", "failed"), (302, "ok", "failed"),
    (400, "invalid_payload", "failed"), (429, "rate_limited", "failed"),
    (500, "secret error", "failed"),
])
def test_http_delivery(monkeypatch, code, body, status):
    response = Mock(status_code=code, text=body)
    post = Mock(return_value=response)
    monkeypatch.setattr("aibom_guardian.notifications.requests.post", post)
    payload = {"text": "summary"}
    result = send_slack("https://hooks.slack.com/services/a/b/secret", payload)
    assert result["status"] == status
    assert "secret" not in json.dumps(result)
    assert post.call_args.kwargs == {
        "json": payload, "timeout": (5, 10), "allow_redirects": False}
    response.close.assert_called_once()


def test_timeout_does_not_expose_webhook(monkeypatch):
    post = Mock(side_effect=requests.Timeout("https://hooks.slack.com/services/a/b/secret"))
    monkeypatch.setattr("aibom_guardian.notifications.requests.post", post)
    assert send_slack("unused", {}) == {"status": "failed", "error": "request_failed"}


def test_payload_bounds_plain_text_and_private_fields():
    events = [{"type": "new_advisories", "target": {
        "name": "<!channel>" + "x" * 200, "version": "1.0",
        "origin": {"installation_path": "private-directory"}},
        "ids": ["CVE-" + "y" * 100] * 20} for _ in range(50)]
    result = slack_payload({"events": events, "checked_at": "now",
                            "source_metadata": "private-metadata"}, "stable-id")
    encoded = json.dumps(result)
    assert "private-directory" not in encoded and "private-metadata" not in encoded
    assert result["blocks"][0]["text"]["type"] == "plain_text"
    assert len(result["blocks"][0]["text"]["text"]) <= 3000
    assert "stable-id" in encoded and "50 monitoring event(s)" in encoded
