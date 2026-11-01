# Monitoring and Slack notifications

[Back to README](../README.en.md) · [한국어](monitoring.md)

Run from the repository root after installing the project and generating `scan_report.json`.
Monitoring tracks the fixed inventory in that report; it does not discover the deployed inventory.

## Register a baseline and check periodically

Register an existing report with `python -m aibom_guardian.monitoring init scan_report.json --db .aibom-guardian/monitor.db`.
Run `python -m aibom_guardian.monitoring check --db .aibom-guardian/monitor.db --interval 3600` for periodic checks (Ctrl+C to stop).
Events are local JSON output; the database retains 30 runs. Slack delivery is opt-in; email is not supported.
Models default to fixed commits; `init --track-model-refs` opts into following the originally requested branches/tags.
Set server env `AIBOM_GUARDIAN_MONITOR_DB` to the database's absolute path for the MCP history/check tools.

## Slack delivery

To enable Slack, create an app, enable **Incoming Webhooks**, and use **Add New Webhook to Workspace**
to choose a channel ([Slack setup guide](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/)).
Set `AIBOM_GUARDIAN_SLACK_WEBHOOK_URL` to the issued HTTPS URL before running `monitoring check`.
For MCP, add the same variable to the server environment and restart it. Keep the URL secret and out of version control.
Only new change events are queued while configured; earlier history is not sent retroactively.
Summaries include component names, versions and advisory IDs, but exclude local paths and full reports.

Each check attempts the oldest queued notification once. Failures remain in SQLite for subsequent checks,
independently of the 30-run history limit. Retries retain the notification ID; a lost response after delivery
can still cause duplicates. Removing the variable pauses delivery; setting it again sends pending alerts
to the currently configured URL. JSON `notification` records delivery status and pending count;
a one-shot check exits with code `3` while notifications remain pending.

## Windows scheduled checks

Windows scheduled monitoring is available through `scripts/monitor-windows.ps1`.
Create `.aibom-guardian`, then securely prompt for the webhook and save its user-bound DPAPI ciphertext:

```powershell
New-Item -ItemType Directory -Force .aibom-guardian | Out-Null
$secureWebhook = Read-Host "Slack Webhook URL" -AsSecureString
$secureWebhook | ConvertFrom-SecureString | Set-Content .aibom-guardian/slack-webhook.dpapi
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/monitor-windows.ps1 -Action Install
```

Installation initializes `monitor.db` from the current `scan_report.json` only if no baseline exists.
It checks immediately, hourly, and at logon while the current Windows user is logged in.
Checks cannot run while the PC is off or asleep; missed checks resume when execution is possible.
The registered inventory stays fixed even if the report or installed packages change.
Use `-IntervalHours 2` during installation to change the interval, and `-Action Status`, `Disable`, or `Enable`
to manage the task. The task command contains no webhook secret. Latest results are saved in
`.aibom-guardian/last-run.json`; lookup or notification failures trigger up to three retries five minutes apart.
