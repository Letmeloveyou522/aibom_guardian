# AIBOM Guardian

[![CI](https://github.com/Letmeloveyou522/aibom_guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/Letmeloveyou522/aibom_guardian/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.6-brightgreen)](https://cyclonedx.org/)

## 소프트웨어 의존성과 AI 모델을 검사하는 공급망 보안 도구

AIBOM Guardian은 Python 패키지, npm 패키지, Hugging Face 모델을 도입하기 전에
취약점과 라이선스, 모델 파일의 위험 요소를 확인하는 도구입니다.
터미널이나 CI에서 실행할 수 있고, MCP를 통해 AI 클라이언트에서도 사용할 수 있습니다.

검사 결과에는 Trust Score와 `ALLOW`, `WARNING`, `BLOCK` 판정이 표시됩니다.
JSON 보고서와 CycloneDX 1.6 형식의 SBOM 또는 ML-BOM으로 저장할 수 있습니다.
조회하지 못한 항목은 미검증으로 표시합니다.

[English README](README.en.md) | [기여 가이드](CONTRIBUTING.md) | [보안 정책](SECURITY.md) | [변경 이력](CHANGELOG.md)

## 빠른 시작

Python 3.10 이상이 필요합니다.

```bash
git clone https://github.com/Letmeloveyou522/aibom_guardian.git
cd aibom_guardian
python -m venv .venv
```

가상 환경을 활성화합니다. 사용하는 셸에 맞는 명령 하나를 실행하세요.

```bash
# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# Windows 명령 프롬프트(cmd)
.venv\Scripts\activate.bat

# macOS 또는 Linux
source .venv/bin/activate
```

프로젝트를 설치합니다. 저장소를 업데이트한 뒤에도 이 명령으로 설치본을 갱신하세요.

```bash
python -m pip install .
```

AIBOM Guardian은 의존성 파일의 메타데이터를 기반으로 취약점을 분석하므로, 검사 대상 패키지를 현재 가상환경에 미리 설치(`pip install`, `npm install`)할 필요가 없습니다.

> **주의 (시연용 예제 파일 관련)**  
> `examples/` 디렉터리에 포함된 파일들에는 취약점 탐지 시연을 위해 보안 취약점이 존재하는 구버전 패키지가 기재되어 있습니다.  
> 이 파일들은 AIBOM Guardian의 검사 입력용으로만 사용하시고, 절대 운영 환경에 직접 설치(`pip install -r ...`)하지 마세요.

### 1. 기본 제공 예제로 바로 실행해보기 (Quick Start)

저장소 루트 디렉터리에서 아래 명령어를 실행하여 도구 동작을 바로 확인할 수 있습니다.

```bash
# Python 의존성 취약점 검사 시연
aibom-guardian examples/sample-requirements.txt --no-explain

# npm 의존성 취약점 검사 시연
aibom-guardian --npm examples/npm-live-before.json --no-explain

# Python 의존성 + Hugging Face AI 모델 동시 진단 시연
aibom-guardian examples/sample-requirements.txt --model sshleifer/tiny-gpt2 --no-explain
```

### 2. 내 프로젝트에 적용하기 (Usage)

본인의 프로젝트를 검사할 때는 `<경로>` 부분을 실제 파일 위치로 변경하여 실행하세요.

- Python 프로젝트 검사(`requirements.txt`)

```bash
aibom-guardian <내_프로젝트_경로>/requirements.txt --no-explain
```

- Node.js/npm 프로젝트 검사(`package.json`)

```bash
aibom-guardian --npm <내_프로젝트_경로>/package.json --no-explain
```

- Python 의존성 및 Hugging Face 모델 동시 검사

```bash
aibom-guardian <내_프로젝트_경로>/requirements.txt --model <조직명/모델ID> --no-explain
```

**옵션 설명**
`--no-explain`: 상세한 판정 사유 및 해설 출력을 생략하고, 검사 결과 요약(테이블 및 종료 코드) 위주로 간결하게 표시합니다.
  

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

## 실행 결과 예시
<p align="center">
  <img width="413" height="244" alt="python 패키지 검사 결과" src="https://github.com/user-attachments/assets/04687cd8-a9d0-4e9a-ab9d-227aa1933746" />
  <img width="410" height="295" alt="ai 모델 검사 결과" src="https://github.com/user-attachments/assets/bb46e442-a08f-4857-99f2-758f0134d9b0" />
</p>

<p align="center">
  <sub>Python 패키지 검사 결과와 AI 모델 검사 결과</sub>
</p>

간접 의존성 여부는 JSON 보고서와 SBOM에 함께 기록됩니다. 상세 결과에는
심각도, 근거, 확인 가능한 대안이 포함됩니다.

## Trust Score

100점에서 시작해 발견한 문제에 따라 점수를 차감합니다. 항목별 가중치는 다음과 같습니다.

| 항목 | 가중치 |
|---|---:|
| 악성 코드 | 28 |
| 취약점 | 25 |
| 라이선스 | 15 |
| 타이포스쿼팅 | 12 |
| 존재하지 않는 패키지 또는 모델 | 10 |
| 출처 | 10 |

- `BLOCK`: hard block 조건에 해당하거나 50점 미만
- `ALLOW`: 80점 이상, 신뢰도 0.7 이상이며 높은 심각도의 문제가 없음
- `WARNING`: 나머지 경우와 검증이 충분하지 않은 경우

차단 대상 라이선스, 확인된 악성 코드, 치명적인 문제는 점수와 관계없이
`BLOCK`으로 판정합니다. CLI와 MCP는 같은 채점 엔진을 사용합니다.

### 검증 상태

| 필드 | 검사 완료, 발견 없음 | 미검증 |
|---|---|---|
| `vulnerabilities` | `[]` | `null` |
| `license_unverified` | `false` | `true` |
| `pii_scan_unverified` | `false` | `true` |

조회 실패로 확인하지 못한 항목은 신뢰도를 낮추며 일반적으로 `WARNING`으로 표시됩니다.
취약점 목록이 비어 있는 경우와 조회 자체가 실패한 경우를 구분해서 확인하세요.

## CLI 활용 예시

```bash
# Python 패키지 기본 검사
aibom-guardian examples/sample-requirements.txt

# npm 프로젝트 검사
aibom-guardian --npm examples/sample-package.json

# 데모 시나리오 실행
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

샘플은 [`examples/scan_report.sample.json`](examples/scan_report.sample.json)과
[`examples/sbom.sample.json`](examples/sbom.sample.json)에서 확인할 수 있습니다.

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

`aibom-guardian-mcp`는 stdio 방식으로 네 가지 도구를 제공합니다.

| 도구 | 용도 |
|---|---|
| `check_package` | PyPI 패키지 한 건 검사 |
| `check_license` | 라이선스 분류와 의무사항 반환 |
| `check_model` | Hugging Face 모델 한 건 검사 |
| `check_repo_trust` | 저장소와 출처 정보 검사 |

MCP 서버는 대상 한 건에 대한 JSON을 반환합니다. 의존성 파일 일괄 검사,
보고서 파일 생성, Ollama 설명은 CLI에서 처리합니다.

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

## 구조

<p align="center">
  <img
    src="https://github.com/user-attachments/assets/b395cf4d-fdc9-4a32-af0e-e93c23c2edef"
    width="520"
    alt="AIBOM-Guardian 시스템 구조"
  />
</p>

<p align="center">
  <sub>시스템 구조</sub>
</p>

수집한 검사 결과는 `_adapters.py`에서 채점에 필요한 형식으로 변환합니다.
CLI와 MCP는 `score_engine.py`에서 점수와 판정을 계산합니다.

| 모듈 | 역할 |
|---|---|
| `scanner.py` | CLI 실행과 전체 흐름 |
| `_requirements.py` | requirements 해석과 간접 의존성 확장 |
| `npm_checker.py` | npm 프로젝트 검사 |
| `osv_client.py` | OSV 조회와 CVSS 처리 |
| `license_checker.py` | 라이선스 분류와 의무사항 |
| `model_checker.py` | Hugging Face 모델 검사 |
| `repository_checker/` | 저장소와 출처 검사 |
| `_adapters.py` | 공통 채점 입력 생성 |
| `score_engine.py` | Trust Score와 최종 판정 |
| `sbom_generator.py` | CycloneDX SBOM과 ML-BOM 생성 |
| `mcp_server.py` | MCP 도구 |

## 제한 사항

- MCP `check_package`는 PyPI만 지원하며 npm은 CLI의 `--npm`을 사용합니다.
- 모델 카드 PII 검사는 정적 텍스트 검사이며 실행 중 마스킹 기능은 아닙니다.
- 버전 범위는 현재 registry 데이터를 기준으로 해석합니다.
- pickle 내부 검사는 기본 비활성화이며 알려진 위험 패턴만 탐지합니다.
- gated 모델은 이용 조건 동의와 `HF_TOKEN`이 필요합니다.
- 서명 검증은 로컬 `cosign` 실행 파일이 필요합니다.
- 네트워크 실패는 취약점 0건이 아니라 미검증으로 기록됩니다.

## 개발과 기여

```bash
pytest
pyflakes src/aibom_guardian tests examples
```

기여 절차는 [`CONTRIBUTING.md`](CONTRIBUTING.md), 보안 문제 신고는
[`SECURITY.md`](SECURITY.md)를 참고해 주세요. 사용 중인 라이브러리와
라이선스는 [`DEPENDENCIES.md`](DEPENDENCIES.md)에 정리되어 있습니다.

## 라이선스

Apache License 2.0으로 배포됩니다. 전문은 [`LICENSE`](LICENSE)에서 확인할
수 있습니다.
