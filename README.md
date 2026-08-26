# AIBOM-Guardian

[![CI](https://github.com/Letmeloveyou522/aibom_guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/Letmeloveyou522/aibom_guardian/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.6-brightgreen)](https://cyclonedx.org/)

## 소프트웨어 의존성과 AI 모델을 검사하는 공급망 보안 도구

AIBOM-Guardian은 Python과 npm 의존성을 검사하고, 필요한 경우 Hugging Face
모델까지 확인해 CycloneDX 1.6 SBOM 또는 ML-BOM으로 기록합니다. 로컬 개발
환경, CI, MCP 서버에서 사용할 수 있습니다.

각 구성요소에는 취약점, 라이선스, 위험 신호, 출처 정보를 바탕으로 Trust
Score와 `ALLOW`, `WARNING`, `BLOCK` 판정이 부여됩니다. 조회에 실패한
항목은 정상으로 처리하지 않고 미검증 상태로 남깁니다.

[English README](README.en.md) | [기여 가이드](CONTRIBUTING.md) | [보안 정책](SECURITY.md) | [변경 이력](CHANGELOG.md)

## 빠른 시작

Python 3.10 이상이 필요합니다.

```bash
git clone https://github.com/Letmeloveyou522/aibom_guardian.git
cd aibom_guardian
python -m venv .venv
```

가상 환경을 활성화하고 설치합니다.

```bash
# Windows
.venv\Scripts\activate

# macOS 또는 Linux
source .venv/bin/activate

pip install -e .
```

검사 실행:

```bash
aibom-guardian requirements.txt
aibom-guardian --npm package.json
aibom-guardian requirements.txt --model CompVis/stable-diffusion-v1-4
```

[`examples/`](examples/)의 입력 파일에는 시연을 위해 취약한 버전이 포함되어
있습니다. 운영 환경에 설치하지 마세요.

## 검사 범위

### Python 패키지

- `requirements.txt`의 직접 의존성과 간접 의존성
- OSV에 등록된 취약점과 중복 별칭 병합
- SPDX와 Blue Oak 자료를 이용한 라이선스 분류 및 의무사항
- 존재하지 않는 패키지, 타이포스쿼팅, yanked 릴리스, 릴리스 경과 기간
- 선택 사항인 저장소, 서명, OpenSSF 검사

`>=`, `~=` 같은 버전 범위는 PyPI 기준으로 해석합니다. extras와 환경
마커도 처리합니다. include, URL, VCS 요구사항과 해석하지 못한 줄은
`unscanned`에 기록합니다.

### npm 패키지

`package.json`의 `dependencies`와 `devDependencies`를 읽고 npm
registry를 통해 간접 의존성을 확장합니다. 각 패키지의 라이선스와 알려진
취약점을 검사합니다.

### AI 모델

- Hugging Face 메타데이터, 리비전, 라이선스, gated 여부
- pickle과 safetensors 가중치 형식
- 파일 검사를 활성화한 경우 pickle 위험 패턴
- `trust_remote_code`와 `auto_map` 등 원격 코드 설정
- 모델 카드 완성도와 정적 PII 신호
- 확인 가능한 기반 모델과 학습 데이터셋 정보

검사 중 모델 파일은 커밋 리비전에 고정합니다. 대용량 파일 다운로드를
피하기 위해 pickle 내부 검사는 기본적으로 비활성화되어 있습니다.
`--model-pickle-scan MB` 옵션으로 활성화할 수 있습니다.

## 실행 결과 예시

<img width="413" height="244" alt="image" src="https://github.com/user-attachments/assets/04687cd8-a9d0-4e9a-ab9d-227aa1933746" />
<img width="410" height="295" alt="image" src="https://github.com/user-attachments/assets/bb46e442-a08f-4857-99f2-758f0134d9b0" />


간접 의존성 여부는 JSON 보고서와 SBOM에 함께 기록됩니다. 상세 결과에는
심각도, 근거, 확인 가능한 대안이 포함됩니다.

## Trust Score

점수는 100점에서 시작하며 다음 여섯 항목에 따라 차감됩니다.

| 항목 | 가중치 |
|---|---:|
| 악성 코드 | 28 |
| 취약점 | 25 |
| 라이선스 | 15 |
| 타이포스쿼팅 | 12 |
| 존재하지 않는 패키지 또는 모델 | 10 |
| 출처 | 10 |

- `BLOCK`: hard block 조건에 해당하거나 50점 미만
- `ALLOW`: 80점 이상, 신뢰도 0.7 이상, 높은 등급의 발견 없음
- `WARNING`: 나머지 경우와 검증이 충분하지 않은 경우

차단 라이선스, 확인된 악성 코드, 치명 등급 발견은 점수와 관계없이
`BLOCK`으로 판정합니다. CLI와 MCP는 같은 채점 엔진을 사용합니다.

### 검증 상태

| 필드 | 검사 완료, 발견 없음 | 미검증 |
|---|---|---|
| `vulnerabilities` | `[]` | `null` |
| `license_unverified` | `false` | `true` |
| `pii_scan_unverified` | `false` | `true` |

미검증 항목은 신뢰도를 낮추며 일반적으로 `WARNING`으로 이어집니다.
네트워크나 메타데이터 조회 실패가 정상 결과로 표시되지 않도록 하기 위한
처리입니다.

## 실행 예시

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


## 선택 연동

| 항목 | 용도 |
|---|---|
| `GITHUB_TOKEN` | 공급망 검사 시 GitHub API 한도 완화 |
| `HF_TOKEN` | 이용 조건에 동의한 gated 모델 접근 |
| Ollama | `qwen2.5:0.5b`를 이용한 로컬 결과 설명 |
| `cosign` | 서명 검증 |

위 항목이 없어도 기본 패키지 검사는 실행할 수 있습니다.

## MCP 서버

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

<img width="461" height="533" alt="image" src="https://github.com/user-attachments/assets/b395cf4d-fdc9-4a32-af0e-e93c23c2edef" />

수집 모듈은 검사 근거를 만들고 최종 판정은 하지 않습니다. CLI와 MCP는
`_adapters.py`에서 결과를 같은 형식으로 바꾼 뒤 `score_engine.py`로
전달합니다.

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
