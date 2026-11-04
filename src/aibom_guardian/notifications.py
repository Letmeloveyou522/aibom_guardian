"""Optional Slack incoming-webhook notifications for monitor events."""

import os
import re
from urllib.parse import urlsplit

import requests


SLACK_WEBHOOK_ENV = "AIBOM_GUARDIAN_SLACK_WEBHOOK_URL"


def slack_webhook_url() -> str | None:
    """Read opt-in configuration without exposing the webhook secret in errors."""
    value = os.environ.get(SLACK_WEBHOOK_ENV, "").strip()
    if not value:
        return None
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname in ("hooks.slack.com", "hooks.slack-gov.com")
            and parsed.port in (None, 443)
            and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment
            and re.fullmatch(r"/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+", parsed.path)
        )
    except ValueError:
        valid = False
    if not valid:
        raise ValueError(f"Invalid {SLACK_WEBHOOK_ENV}; expected a Slack HTTPS webhook")
    return value


def slack_payload(result: dict, notification_id: str) -> dict:
    """Summarize events without transmitting local paths or full scan evidence."""
    events = result["events"]
    lines = [f"AIBOM-Guardian: {len(events)} monitoring event(s)",
             f"Checked: {result['checked_at']}", f"Notification: {notification_id}"]
    for event in events[:10]:
        target = event["target"]
        # Bound individual untrusted fields before composing the Slack message.
        identity = str(target["name"])[:120] + "@" + str(target["version"])[:80]
        detail = ", ".join(str(v)[:80] for v in event.get("ids", [])[:5])
        if len(event.get("ids", [])) > 5:
            detail += ", ..."
        if event.get("field"):
            detail = str(event["field"])[:80]
        lines.append(f"{event['type']}: {identity}" + (f" ({detail})" if detail else ""))
    if len(events) > 10:
        lines.append(f"... and {len(events) - 10} more event(s).")
    lines.append("See local monitor history for full details.")
    message = "\n".join(lines)
    if len(message) > 2900:
        message = message[:2800] + "\n... See local monitor history for full details."
    return {
        "text": f"AIBOM-Guardian: {len(events)} monitoring event(s)",
        "blocks": [{"type": "section", "text": {
            "type": "plain_text", "text": message, "emoji": False}}],
        "unfurl_links": False, "unfurl_media": False,
    }


def send_slack(webhook_url: str, payload: dict) -> dict:
    """Attempt one delivery; return only sanitized status, never URL or body."""
    try:
        response = requests.post(webhook_url, json=payload, timeout=(5, 10),
                                 allow_redirects=False)
        try:
            if response.status_code == 200 and response.text.strip() == "ok":
                return {"status": "sent"}
            return {"status": "failed", "error": "slack_rejected",
                    "http_status": response.status_code}
        finally:
            response.close()
    except requests.RequestException:
        return {"status": "failed", "error": "request_failed"}
