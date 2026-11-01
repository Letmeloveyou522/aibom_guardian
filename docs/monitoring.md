# 모니터링과 Slack 알림

[README로 돌아가기](../README.md) · [English](monitoring.en.md)

저장소 루트에서 실행하며, 먼저 README의 설치와 예제 검사를 완료해 `scan_report.json`을 준비합니다.
등록하는 대상은 보고서의 고정 버전 목록입니다. 실제 배포 환경의 설치 목록을 자동으로 동기화하지 않습니다.

## 기준 등록과 주기적 검사

저장한 보고서의 버전을 계속 확인하려면 다음 명령을 사용합니다. 알림은 터미널 JSON으로 출력하며 최근 30회 결과를 보관합니다.

```powershell
python -m aibom_guardian.monitoring init scan_report.json --db .aibom-guardian/monitor.db
python -m aibom_guardian.monitoring check --db .aibom-guardian/monitor.db --interval 3600
```

중지는 `Ctrl+C`입니다. MCP 이력 도구는 서버 `env`의 `AIBOM_GUARDIAN_MONITOR_DB`에 DB 절대 경로를 지정합니다.
모델은 저장한 커밋을 검사하며, 최초 등록에 `--track-model-refs`를 추가하면 원래 브랜치·태그의 변경을 추적합니다.

## Slack 알림

Slack 알림은 선택 사항입니다. [Slack Incoming Webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/)에서
앱을 만들고 **Incoming Webhooks → Add New Webhook to Workspace**에서 수신 채널을 선택한 뒤,
발급받은 URL을 환경변수에 설정하세요.

```powershell
$env:AIBOM_GUARDIAN_SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/YOUR/CHANNEL/SECRET"
python -m aibom_guardian.monitoring check --db .aibom-guardian/monitor.db --interval 3600
```

신규 취약점, 모델 메타데이터 변경, 조회 실패·복구 등 변경 이벤트를 요약해 전송합니다.
패키지·모델 이름과 버전, 취약점 ID가 포함되며 로컬 경로나 전체 보고서는 전송하지 않습니다.
설정 전의 이력은 소급 발송하지 않습니다. MCP `check_monitor`에도 적용하려면 서버 `env`에 같은 변수를 추가하고 재시작하세요.
URL에는 비밀 값이 있으므로 저장소에 커밋하지 마세요. 미설정 시 기존 터미널 JSON 출력만 사용하며 이메일은 지원하지 않습니다.

전송 실패 시 알림을 SQLite 대기열에 보관하고 다음 `check`에서 가장 오래된 알림 하나를 재시도합니다.
대기열은 최근 30회 이력 보관 제한과 별개이며, 재전송에도 같은 알림 ID를 사용합니다.
수신 후 응답이 유실되면 중복 수신할 수 있습니다. 환경변수를 해제하면 전송을 멈추고,
다시 설정하면 현재 URL로 대기 중인 알림을 전송합니다.
결과 JSON의 `notification`에 전송 상태와 대기 건수가 기록되며, 미전송 알림이 남은 단발 검사는 종료 코드 `3`을 반환합니다.

## Windows 자동 실행

Windows에서 자동 실행하려면 아래와 같이 설정합니다. 웹훅은 현재 Windows 사용자에게 묶인 DPAPI 암호문으로
`.aibom-guardian/slack-webhook.dpapi`에 저장하며 이 폴더는 Git에서 제외합니다.

```powershell
New-Item -ItemType Directory -Force .aibom-guardian | Out-Null
$secureWebhook = Read-Host "Slack Webhook URL" -AsSecureString
$secureWebhook | ConvertFrom-SecureString | Set-Content .aibom-guardian/slack-webhook.dpapi
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/monitor-windows.ps1 -Action Install
```

현재 `scan_report.json`으로 처음 한 번 기준 DB를 만들며, 기존 DB가 있으면 유지합니다.
현재 사용자가 로그인한 동안 1시간 간격 및 로그인 시 검사하고, 설치 직후에도 한 번 실행합니다.
PC가 꺼져 있거나 절전 중이면 검사하지 못합니다. 이후 실행 가능한 시점에 다시 검사합니다.
보고서 파일이나 설치 패키지가 바뀌어도 등록한 고정 버전 목록이 자동 갱신되지는 않습니다.
`Install -IntervalHours 2`처럼 간격을 바꿀 수 있으며, 작업 스케줄러에는 웹훅 비밀 값을 넣지 않습니다.

```powershell
# 실행 상태 확인 / 자동 검사 중지 / 다시 시작
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/monitor-windows.ps1 -Action Status
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/monitor-windows.ps1 -Action Disable
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/monitor-windows.ps1 -Action Enable
```

최근 결과는 `.aibom-guardian/last-run.json`, 이력은 `.aibom-guardian/monitor.db`에 저장합니다.
조회 또는 알림 전송이 실패하면 작업 스케줄러가 5분 간격으로 최대 3회 재시도합니다.
Windows 예약 작업 설정은 [Microsoft 공식 문서](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger)를 참고하세요.
