# AIBOM Guardian

[![CI](https://github.com/Letmeloveyou522/aibom_guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/Letmeloveyou522/aibom_guardian/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.6-brightgreen)](https://cyclonedx.org/)

## 패키지와 AI 모델의 공급망 위험을 함께 확인합니다

AIBOM Guardian은 **Python·npm 의존성과 Hugging Face 모델**의 취약점, 라이선스,
모델 파일 위험 요소를 검사하고 판단 근거와 미검증 상태를 제공하는 개발 도구입니다.
CLI·CI·MCP에서 검사하고, 결과를 CycloneDX 1.6 SBOM/ML-BOM으로 기록하며,
등록한 구성요소의 변화를 추적해 Slack으로 알립니다.

[시연](#대표-시연) · [검증 결과](#검증-결과) · [빠른 시작](#빠른-시작) · [상세 사용법](docs/usage.md) · [모니터링 설정](docs/monitoring.md) · [English](README.en.md)

## 해결하려는 문제

AI 애플리케이션을 도입할 때는 소프트웨어 패키지뿐 아니라 모델의 라이선스,
가중치 파일 형식, 원격 코드 설정과 출처도 검토해야 합니다.
검사 결과가 여러 도구와 형식으로 나뉘면 개발자가 근거를 모으고 검토 순서를 정하기 어렵습니다.
조회에 실패한 항목을 놓치거나, 도입 후 새로 알려진 취약점을 계속 확인해야 하는 문제도 있습니다.

AIBOM Guardian은 개발자가 **도입 전 검사 → 근거에 따른 검토 → BOM 기록 → 변경 추적**을
하나의 작업 흐름으로 수행하도록 돕습니다. `ALLOW`, `WARNING`, `BLOCK`은 검토와 CI 정책에
사용하는 판정이며, 모든 위험의 부재나 실행 환경의 안전성을 보증하지 않습니다.

## 직접 구현한 부분

| 구현 | 개발자가 얻는 결과 | 코드 |
|---|---|---|
| 의존성 해석과 검사 결과 통합 | Python 간접 의존성과 extras, npm lockfile의 고정 버전·경로를 추적하고 미처리 입력을 기록 | [`_requirements.py`](src/aibom_guardian/_requirements.py), [`npm_checker.py`](src/aibom_guardian/npm_checker.py) |
| 근거와 판정을 분리한 공통 엔진 | CLI와 MCP가 같은 정책으로 점수·판정·신뢰도를 계산하고 조회 실패를 미검증으로 유지 | [`_adapters.py`](src/aibom_guardian/_adapters.py), [`score_engine.py`](src/aibom_guardian/score_engine.py) |
| 패키지·모델 정보를 BOM으로 연결 | 모델 커밋, 파일 형식, 라이선스와 확인 가능한 기반 모델·데이터셋 정보를 검사 결과와 함께 기록 | [`model_checker.py`](src/aibom_guardian/model_checker.py), [`sbom_generator.py`](src/aibom_guardian/sbom_generator.py) |
| 검사 이후의 변경 추적과 알림 | 고정 버전 재조회, 신규 관측 취약점·모델 메타데이터 변경 감지, SQLite 이력과 Slack 재전송 대기열 | [`monitoring.py`](src/aibom_guardian/monitoring.py), [`notifications.py`](src/aibom_guardian/notifications.py) |

취약점 원천 데이터는 **OSV**, 패키지·모델 메타데이터는 **PyPI·npm·Hugging Face**,
라이선스 분류 자료는 **SPDX·Blue Oak**를 활용합니다. pickle 검사는 **picklescan**,
선택적 공급망 검사는 **OpenSSF Scorecard·cosign** 등과 연동합니다.
이 프로젝트의 기여는 이들 근거의 수집·정규화·정책 판정과 개발 작업 흐름의 연결에 있습니다.
[사용 라이브러리와 라이선스](DEPENDENCIES.md)

## 대표 시연

<p align="center">
  <img width="413" height="244" alt="python 패키지 검사 결과" src="https://github.com/user-attachments/assets/04687cd8-a9d0-4e9a-ab9d-227aa1933746" />
  <img width="410" height="295" alt="ai 모델 검사 결과" src="https://github.com/user-attachments/assets/bb46e442-a08f-4857-99f2-758f0134d9b0" />
</p>

<p align="center">
  <sub>Python 패키지 검사 결과와 AI 모델 검사 결과</sub>
</p>


위 화면은 예시 실행 결과입니다. 온라인 데이터가 갱신되므로 취약점 수와 판정은 실행 시점에 따라 달라질 수 있습니다.

| 입력 | 확인할 결과 | 다음 행동 |
|---|---|---|
| [`sample-requirements.txt`](examples/sample-requirements.txt) | 의도적으로 지정한 구버전과 간접 의존성의 취약점·라이선스·판정 근거 | 수정 버전 후보를 재검사하고 애플리케이션 테스트 |
| 같은 입력 + `--model sshleifer/tiny-gpt2` | 패키지와 모델의 라이선스, 파일 형식, 커밋 등 검사 결과 | 모델별 근거와 미검증 항목 검토; 필요 시 pickle 내용 검사 |
| 저장한 보고서로 모니터링 시작 | 신규 관측 취약점·모델 정보 변경·조회 실패/복구 이벤트 | Slack 요약과 이력에서 변경 원인 확인 |

설치 후 아래 명령으로 패키지와 모델을 함께 검사할 수 있습니다.

```bash
aibom-guardian examples/sample-requirements.txt --model sshleifer/tiny-gpt2 --no-explain
```

결과는 터미널, `scan_report.json`, `sbom.json`에 남습니다.
[JSON 예시](examples/scan_report.sample.json) · [BOM 예시](examples/sbom.sample.json)

네트워크 없이 판정 흐름을 시연하려면 `python examples/demo_scenarios.py --compact`를 사용하세요.
이 명령의 기본 모드는 **합성 모델 보고서와 모의 PyPI 응답**을 사용합니다. 실제 악성 모델 탐지 실험과 구분합니다.

## 검증 결과

검증 기준은 **2026-11-01, 기준 커밋 `4fec520`에 시연 명령 수정·회귀 테스트를 적용한 작업본**입니다.
재현 명령, 환경, 결과와 검증 범위는 [검증 기록](docs/validation.md)에 정리했습니다.

| 검증 종류 | 확인 내용 | 근거 |
|---|---|---|
| 자동 테스트 | 전체 1,052개 통과, 그중 모니터링·Slack 관련 44개 통과 | [결과 요약](docs/evidence/verification-2026-11-01.json), [테스트 코드](tests/) |
| 실제 Slack 연동 | 테스트용 가상 변경 1건을 실제 웹훅으로 전송, 성공 응답·이력 저장·다음 검사에서 중복 발송 없음 확인 | [연동 기록](docs/evidence/verification-2026-11-01.json) |
| Windows 예약 실행 | 기존 보고서의 패키지 7개·모델 1개 재조회 성공, 조회 실패 0건, 최근 작업 종료 코드 0 확인 | [운영 검증 범위](docs/validation.md#실제-연동-확인) |
| CI 구성 | Python 3.10–3.13 테스트, 정적 검사, 패키징, 오프라인 CLI 실행을 검사하도록 구성 | [워크플로](.github/workflows/ci.yml), [실행 기록](https://github.com/Letmeloveyou522/aibom_guardian/actions/workflows/ci.yml) |

자동 테스트 통과는 구현 동작에 대한 검증입니다. **실환경 탐지 정확도나 Trust Score의 외부 타당성을 뜻하지 않습니다.**
재부팅 후 자동 실행, 장기 연속 운영, 외부 정답 데이터셋을 이용한 평가는 별도 검증 과제입니다.

## 빠른 시작

Python 3.10 이상이 필요합니다.

```bash
git clone https://github.com/Letmeloveyou522/aibom_guardian.git
cd aibom_guardian
python -m venv .venv
```

사용하는 셸에 맞는 명령 하나로 가상 환경을 활성화합니다.

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# macOS / Linux
source .venv/bin/activate
# Windows cmd에서는 .venv\Scripts\activate.bat 사용
```

프로젝트를 설치하고 예제를 검사합니다. 저장소 업데이트 후에도 설치 명령을 다시 실행하세요.

```bash
python -m pip install .
aibom-guardian examples/sample-requirements.txt --no-explain
```

검사 대상 패키지를 설치할 필요는 없습니다. 예제에는 취약점 시연용 구버전이 포함돼 있으므로
**검사 입력으로만 사용**하고 운영 환경에 설치하지 마세요.
취약점이나 미검증 항목이 발견되면 종료 코드 **2(BLOCK) 또는 3(WARNING)**가 나올 수 있습니다.
이는 판정 결과를 전달하는 정상 동작입니다. 입력·인자 오류는 코드 1로 구분합니다.

`--no-explain`은 **Ollama의 추가 설명 생성만 생략**합니다. 검사 결과, 판정 근거와 보고서 저장은 유지됩니다.
기본 검사는 Ollama나 GitHub/Hugging Face 토큰 없이 실행할 수 있습니다.

```bash
# npm 예제
aibom-guardian --npm examples/npm-live-before.json --no-explain
# 내 Python 프로젝트
aibom-guardian ../my-project/requirements.txt --no-explain
# 내 npm 프로젝트
aibom-guardian --npm ../my-project/package.json --no-explain
```

## 판정 방식과 검증 상태

Trust Score는 100점에서 발견한 문제에 따라 감점하는 **프로젝트 자체의 정책 점수**입니다.
국제 표준이 가중치를 지정하거나 인증한 점수가 아닙니다.
Confidence는 확보한 증거의 충분성을 나타내며 안전할 확률을 의미하지 않습니다.

| 항목 | 카테고리별 최대 감점 |
|---|---:|
| 악성 코드 | 28 |
| 취약점 | 25 |
| 라이선스 | 15 |
| 타이포스쿼팅 | 12 |
| 존재하지 않는 패키지 또는 모델 | 10 |
| 출처 | 10 |

판정은 다음 우선순위를 따릅니다.

1. 정책상 강제 차단 조건이 있으면 `BLOCK`.
2. 강제 차단이 없고 신뢰도가 0.5 미만이면 `WARNING`.
3. 위 조건에 해당하지 않고 점수가 50점 미만이면 `BLOCK`.
4. 점수 80점 이상, 신뢰도 0.7 이상이며 확인된 High 문제와 검토가 필요한 suspicious 이슈가 없으면 `ALLOW`.
5. 나머지는 `WARNING`.

취약점 조회 완료 후 발견이 없으면 `vulnerabilities: []`, 조회하지 못했으면 `null`로 구분합니다.
라이선스와 모델 카드 검사도 미검증 상태를 별도 필드에 기록합니다.
[점수 산식·정책·평가 방법](docs/trust_score_methodology.md)

## 활용과 상세 문서

| 목적 | 제공 기능 | 안내 |
|---|---|---|
| 도입 전 검사 | Python·npm·AI 모델 검사와 JSON/BOM 출력 | [검사 범위·CLI 옵션](docs/usage.md) |
| CI 검토 | 종료 코드 기반 정책 적용, SARIF, 검사 요약 | [출력과 종료 코드](docs/usage.md#출력-파일과-종료-코드) |
| AI 클라이언트 연결 | 패키지·모델 검사, 프로젝트 검사, 버전 비교, 모니터링 이력 등 MCP 도구 8개 | [MCP 설정](docs/usage.md#mcp-서버) |
| 도입 이후 추적 | 고정 버전 재조회, Slack 알림, Windows 예약 실행 | [모니터링과 알림](docs/monitoring.md) |

보고서를 만든 뒤 아래 명령으로 모니터링을 시작할 수 있습니다.

```bash
python -m aibom_guardian.monitoring init scan_report.json --db .aibom-guardian/monitor.db
python -m aibom_guardian.monitoring check --db .aibom-guardian/monitor.db --interval 3600
```

기본은 터미널 JSON 출력이며, Slack은 웹훅을 설정해야 발송됩니다.
등록한 버전 목록은 고정되며 설치 환경을 자동으로 동기화하지 않습니다.

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
| `monitoring.py`, `notifications.py` | 변경 감지, 이력, Slack 전송 |


## 제한 사항

- 알려진 취약점과 수집 가능한 근거를 검사합니다. 모델의 행동, 백도어 또는 모든 악성 코드를 탐지하는 도구는 아닙니다.
- pickle 내용 검사는 기본 비활성화입니다. `--model-pickle-scan MB`를 켜도 알려진 위험 패턴을 검사하는 범위입니다.
- 모델 카드 PII 검사는 정적 텍스트 검사이며 실행 중 마스킹 기능은 아닙니다.
- 범위로 지정한 버전은 현재 registry 데이터로 해석합니다. 실제 설치 성공이나 애플리케이션 호환성은 별도 확인해야 합니다.
- MCP `check_package`는 PyPI만 지원합니다. npm은 CLI의 `--npm`을 사용합니다. 검사 범위가 다르면 같은 채점 엔진을 사용해도 결과가 다를 수 있습니다.
- gated 모델에는 이용 조건 동의와 `HF_TOKEN`, 서명 검증에는 로컬 `cosign`이 필요합니다.
- Windows 예약 검사는 PC가 켜져 있고 해당 사용자가 로그인한 상태에서 실행됩니다. Slack 응답이 유실된 경우 재시도로 중복 수신할 수 있습니다.

## 개발과 기여

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m pyflakes src/aibom_guardian tests examples
```

[기여 가이드](CONTRIBUTING.md) · [보안 정책](SECURITY.md) · [변경 이력](CHANGELOG.md) · [의존성·라이선스](DEPENDENCIES.md)

## 라이선스

[Apache License 2.0](LICENSE)으로 배포됩니다.
