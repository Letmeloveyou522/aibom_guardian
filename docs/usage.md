# 검사 범위와 상세 사용법

[README로 돌아가기](../README.md) · [English](usage.en.md)

## 검사 범위

### Python 패키지

- `requirements.txt`의 직접 의존성과 간접 의존성
- OSV에 등록된 취약점 조회와 같은 취약점의 중복 항목 병합
- SPDX와 Blue Oak 자료를 바탕으로 라이선스 분류와 준수 사항 확인
- 존재하지 않는 패키지, 타이포스쿼팅, yanked 릴리스, 릴리스 경과 기간
- 옵션으로 저장소, 서명, OpenSSF 검사 추가

`>=`, `~=` 같은 버전 범위는 PyPI에서 해당 조건에 맞는 버전을 찾습니다.
환경 마커와 요청한 extras를 반영하며, extras로 추가되는 의존성도 검사합니다.
요청한 옵션은 JSON의 `extras` 필드에 기록합니다.

include, URL, VCS 요구사항 등 처리하지 못한 입력은 `unscanned`에 남깁니다.
의존성 충돌이나 메타데이터 조회 실패, 탐색 깊이 제한으로 검사를 마치지 못한 경우도
여기에 기록합니다. 이 분석은 pip의 의존성 해결을 대체하지 않으며 설치 성공을 보장하지 않습니다.

### npm 패키지

입력 파일과 같은 폴더에 `package-lock.json` v2/v3가 있으면 고정된 버전과
설치 경로를 읽어 검사합니다. JSON의 `dependency_source`, `resolution_source`,
`installation_path`, `required_by_paths`에 출처와 경로를 기록합니다.
`node_modules`의 실제 파일이나 무결성을 확인하는 기능은 아닙니다.
`package.json`과 lockfile의 루트 의존성 선언이 다르면 오류로 종료합니다.
lockfile v1과 npm-shrinkwrap은 지원하지 않아 오류를 반환합니다.
로컬 링크, 별칭, 사설 registry 항목은 `unscanned`에 기록합니다.

lockfile이 없으면 `package.json`의 `dependencies`와 `devDependencies`를 읽고
npm registry에서 간접 의존성을 찾습니다. `^`, `~` 등 지원하는 버전 범위는
조건에 맞는 최신 버전을 선택합니다. 해석하지 못한 범위는 `unscanned`에 남깁니다.
이렇게 찾은 패키지의 라이선스와 알려진 취약점을 검사합니다.

### AI 모델

- Hugging Face 메타데이터, 리비전, 라이선스, gated 여부
- pickle과 safetensors 가중치 형식
- 파일 검사 옵션을 켰을 때 pickle의 위험 패턴
- `trust_remote_code`와 `auto_map` 등 원격 코드 설정
- 모델 카드의 누락 정보와 개인정보(PII) 패턴
- 확인 가능한 기반 모델과 학습 데이터셋 정보

모델 파일은 특정 커밋을 기준으로 검사합니다. 기본 설정에서는 pickle 파일을
다운로드해 검사하지 않습니다. 파일 내용까지 검사하려면 `--model-pickle-scan MB`로
검사할 파일의 최대 크기를 지정하세요.

## CLI 활용 예시

```bash
# Python 패키지 기본 검사
aibom-guardian examples/sample-requirements.txt

# npm 프로젝트 검사
aibom-guardian --npm examples/sample-package.json

# 합성 입력으로 판정 흐름 시연 (실제 악성 모델 다운로드 없음)
python examples/demo_scenarios.py

# AI 모델을 포함한 검사
aibom-guardian requirements.txt --model CompVis/stable-diffusion-v1-4

# 저장소와 공급망 검사
aibom-guardian requirements.txt --supply-chain

# SARIF 생성 및 CI 판정
aibom-guardian requirements.txt --no-explain --sarif out.sarif --fail-on warning

# 오프라인 검사
aibom-guardian requirements.txt --offline --fail-on never
```

## 주요 옵션

| 옵션 | 설명 |
|---|---|
| `--npm PATH` | npm `package.json` 검사 |
| `--model REF` | Hugging Face 모델 추가, 여러 번 지정 가능 |
| `--direct-only` | 간접 의존성 확장 생략 |
| `--min-release-age DAYS` | 최근 릴리스 경고, 기본값 0 |
| `--supply-chain` | 저장소와 출처 검사 활성화 |
| `--model-pickle-scan MB` | 지정한 크기 이하의 pickle 파일 검사 |
| `--sarif PATH` | SARIF 2.1.0 파일 생성 |
| `--json PATH` | JSON 경로, 기본값 `scan_report.json` |
| `--sbom PATH` | SBOM 경로, 기본값 `sbom.json` |
| `-j`, `--jobs N` | 패키지 병렬 작업 수, 기본값 8 |
| `--offline` | 네트워크 연결 없이 실행 |
| `--no-explain` | Ollama 설명 생략 |
| `--verbose` | 취약점 상세 결과 모두 출력 |
| `--fail-on POLICY` | `warning`, `block`, `never` 중 선택 |
| `--version` | 설치된 버전 출력 |

패키지 단위로 병렬 처리하며, 한 패키지의 세부 조회는 순서대로 진행합니다.
최종 보고서는 입력 순서를 유지합니다.

## 출력 파일과 종료 코드

저장소 전용 명령 `python -m aibom_guardian.repository_checker`도
`--fail-on warning|block|never`를 지원합니다. 기본값 `warning`에서는
WARNING 또는 보고서의 수집 오류가 있으면 3, BLOCK이면 2를 반환합니다.
판정과 수집 오류에 관계없이 보고서를 받고 종료 코드 0을 반환하려면 `--fail-on never`를 지정합니다.

| 파일 | 내용 |
|---|---|
| `scan_report.json` | 전체 결과, 발견 항목, 신뢰도, 점수 내역 |
| `sbom.json` | CycloneDX 1.6 SBOM 또는 ML-BOM |
| 선택한 `.sarif` 파일 | 코드 스캔 연동용 SARIF 2.1.0 결과 |

샘플은 [`examples/scan_report.sample.json`](../examples/scan_report.sample.json)과
[`examples/sbom.sample.json`](../examples/sbom.sample.json)에서 확인할 수 있습니다.

| 코드 | 의미 |
|---:|---|
| `0` | 모든 결과가 `ALLOW`이고 미검사 항목이 없음 |
| `1` | 입력 또는 인자 오류 |
| `2` | 하나 이상의 `BLOCK` 존재 |
| `3` | `BLOCK`은 없지만 `WARNING` 또는 미검사 항목 존재 |

`--fail-on block`은 차단 항목이 있을 때만 CI를 실패시키고,
`--fail-on never`는 결과만 기록합니다.


## 추가 설정

| 항목 | 용도 |
|---|---|
| `GITHUB_TOKEN` | 공급망 검사 시 GitHub API 한도 완화 |
| `HF_TOKEN` | 이용 조건에 동의한 gated 모델 접근 |
| Ollama | `qwen2.5:0.5b`를 이용한 로컬 결과 설명 |
| `cosign` | 서명 검증 |

위 항목이 없어도 기본 패키지 검사는 실행할 수 있습니다.

## MCP 서버

Claude Desktop, Cursor, VS Code에서 연결할 설정 파일을 만들 수 있습니다.
저장소 폴더에서 설치에 사용한 가상 환경의 Python으로 실행하세요.

```bash
python examples/mcp_setup.py --output mcp-client-configs --check
```

출력 폴더가 이미 있으면 다른 이름을 지정하세요. 이 명령은 설정 파일을 생성하며
앱의 기존 설정을 바꾸지는 않습니다.

| 클라이언트 | 생성 파일 | 적용 위치 |
|---|---|---|
| Claude Desktop | claude-desktop.json | Windows의 `%APPDATA%\Claude\claude_desktop_config.json` 아래 `mcpServers` |
| Cursor | cursor.json | 프로젝트 `.cursor/mcp.json` 아래 `mcpServers` |
| VS Code | vscode.json | 프로젝트 `.vscode/mcp.json` 아래 `servers` |

생성된 파일의 `aibom-guardian` 항목을 앱 설정에 추가하고 서버를 시작하세요.
Python 절대 경로를 사용하므로 가상 환경을 옮겼다면 설정을 다시 생성해야 합니다.
채팅의 도구 목록에서 서버를 활성화하고 `check_license`로 MIT를 검사해 연결을 확인할 수 있습니다.
`--check`는 MCP SDK로 서버를 시작하고 도구 목록과 호출 결과를 확인합니다.
앱에서의 연결과 권한 설정은 별도로 확인해야 합니다.

`aibom-guardian-mcp`는 stdio 방식으로 여덟 가지 도구를 제공합니다.

| 도구 | 용도 |
|---|---|
| `check_package` | PyPI 패키지 한 건 검사 |
| `check_license` | 라이선스 분류와 의무사항 반환 |
| `check_model` | Hugging Face 모델 한 건 검사 |
| `check_repo_trust` | 저장소와 출처 정보 검사 |
| `scan_project` | 허용한 프로젝트 폴더의 Python requirements 파일 검사 |
| `compare_package_candidate` | Python 패키지 두 버전 재검사와 취약점 비교 |
| `monitor_history` | 저장한 모니터링 이력 조회 |
| `check_monitor` | 등록한 버전 재조회와 변경 기록 |

MCP는 검사 결과를 JSON으로 반환합니다. 보고서 파일 생성과 Ollama 설명은 CLI에서 처리합니다.

CI용 요약은 `python -m aibom_guardian.ci_summary scan_report.json`으로 만들 수 있습니다.
이전 결과와 비교하려면 `--before before.json`을 추가합니다. 기존 CI에서는 오프라인 검사 요약과 원본 보고서를 남깁니다.

프로젝트 검사는 아래 `env`에 `"AIBOM_GUARDIAN_PROJECT_ROOT": "D:/projects/my-app"`을 추가하고
서버를 다시 시작하면 사용할 수 있습니다. 채팅에서 “requirements.txt를 scan_project로 검사해줘”라고 요청하세요.

모니터링 도구의 DB 경로와 Slack 설정은 [운영 안내](../docs/monitoring.md)를 참고하세요.

```json
{
  "mcpServers": {
    "aibom-guardian": {
      "command": "aibom-guardian-mcp",
      "env": { "GITHUB_TOKEN": "...", "HF_TOKEN": "..." }
    }
  }
}
```

실제 토큰은 저장소에 커밋하지 마세요.
