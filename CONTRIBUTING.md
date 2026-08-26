# 기여 가이드

AIBOM-Guardian에 관심을 가져 주셔서 감사합니다. 이 문서는 개발 환경 설정,
코드 작성 기준, 테스트와 Pull Request 절차를 설명합니다.

일반적인 버그와 기능 제안은
[GitHub Issues](https://github.com/Letmeloveyou522/aibom_guardian/issues)에
등록해 주세요. 보안 취약점은 공개 이슈 대신 [SECURITY.md](SECURITY.md)의
신고 절차를 이용해 주세요.

## 개발 환경 설정

Python 3.10 이상이 필요합니다.

```bash
git clone https://github.com/Letmeloveyou522/aibom_guardian.git
cd aibom_guardian
python -m venv .venv
```

가상 환경을 활성화한 뒤 개발 의존성을 설치합니다.

```bash
# Windows
.venv\Scripts\activate

# macOS 또는 Linux
source .venv/bin/activate

pip install -e ".[dev]"
pytest
```

테스트는 외부 네트워크를 사용하지 않습니다.

## 구현 원칙

### 미검증 상태 유지

조회 실패와 위험 요소가 발견되지 않은 상태를 구분합니다.

```python
[]      # 조회가 완료되었으며 알려진 취약점이 없음
None    # 조회를 완료하지 못함
```

`None`을 빈 목록으로 변환하면 실행되지 않은 검사가 정상 결과로 기록될 수
있습니다. 같은 원칙이 라이선스와 모델 카드 검사에도 적용됩니다.

- 라이선스를 확인하지 못한 경우: `UNKNOWN`과 `license_unverified` 기록
- 모델 카드 PII 검사를 완료하지 못한 경우: `pii_scan_unverified: true` 기록

관련 입력 형식은
[`src/aibom_guardian/_adapters.py`](src/aibom_guardian/_adapters.py)의 모듈
설명을 참고해 주세요.

### 공통 채점 경로

`model_checker`, `repository_checker`, `recommendation`은 검사 결과를
수집하고, 최종 Trust Score와 `ALLOW`, `WARNING`, `BLOCK` 판정은
`score_engine.py`에서 처리합니다.

CLI와 MCP의 채점 입력은
[`_adapters.py`](src/aibom_guardian/_adapters.py)에서 공통으로 생성합니다.
두 경로의 판정 기준이 달라지지 않도록 별도의 변환 로직을 추가하지 말고
기존 어댑터를 사용해 주세요. CLI와 MCP가 같은 어댑터를 사용하는지는
테스트에서 확인합니다.

### 가중치와 판정 기준

가중치와 판정 경계는 `tests/test_score_engine.py`에서 검증합니다. 값을
변경하는 PR에는 다음 내용을 포함해 주세요.

- 변경 근거
- 기존 결과에 미치는 영향
- 수정된 테스트

가중치 변경은 기존 검사 결과와의 비교에 영향을 주므로 코드와 테스트를
함께 수정해 주세요.

### 네트워크 없는 테스트

테스트가 외부 서비스 상태에 영향을 받지 않도록 모든 네트워크 요청을
mock으로 대체합니다. `tests/conftest.py`는 `AIBOM_GUARDIAN_CACHE`를
`tests/fixtures`로 지정해 SPDX와 Blue Oak 데이터를 내려받지 않도록
설정합니다.

새로운 API 연동을 추가할 때는 성공, 실패, 응답 누락 상황을 각각 테스트해
주세요.

### 라이선스 목록 관리

SPDX와 Blue Oak 목록은 저장소에 포함하지 않고 실행 시 내려받아 캐시합니다.
다운로드 및 캐시 방식을 변경하는 경우 오프라인 동작과 라이선스 데이터의
배포 조건을 함께 확인해 주세요.

오프라인 환경이나 조회 실패 상황에서는 확인되지 않은 라이선스를
`ALLOWED`로 처리하지 않아야 합니다.

### 의존성 변경

런타임 의존성을 추가하거나 버전을 변경하면 다음 파일을 함께 수정합니다.

| 파일 | 수정 내용 |
|---|---|
| `pyproject.toml` | `[project].dependencies` 항목 |
| `requirements.txt` | 같은 의존성과 사용 목적 |
| `DEPENDENCIES.md` | 이름, 용도, 사용 모듈, 저장소, 라이선스 |

`pyproject.toml`과 `requirements.txt`의 일치 여부는
`tests/test_packaging.py`에서 확인합니다.

`mcp`는 현재 `1.28.1`로 고정되어 있습니다. 다른 버전으로 변경하려면 MCP
서버 호환성을 먼저 확인하고 관련 테스트를 함께 수정해 주세요.

### 종료 코드

| 코드 | 의미 |
|---:|---|
| `0` | 모든 결과가 `ALLOW`이고 미검사 항목이 없음 |
| `1` | 입력 또는 인자 오류 |
| `2` | 하나 이상의 `BLOCK` 존재 |
| `3` | `BLOCK`은 없지만 `WARNING` 또는 미검사 항목 존재 |

종료 코드는 CI 연동 규격의 일부입니다. 값을 변경할 경우 CLI 테스트,
GitHub Action 동작, 문서를 함께 검토해 주세요.

## 코드 작성 기준

별도의 자동 포매터를 강제하지 않으며 기존 코드의 형식을 따릅니다.

- 들여쓰기 4칸
- 한 줄은 가급적 79자에서 88자 이내
- 타입 힌트 사용
- 공개 함수에 docstring 작성
- 패키지 내부 import는 상대 경로 사용

주석과 docstring은 영어로 작성합니다. 코드만으로 알기 어려운 설계 이유,
예외 처리 기준, 외부 규격을 설명하는 데 주석을 사용해 주세요. 긴 설명은
함수 또는 모듈 docstring에 작성하고, 작업 번호처럼 저장소 밖에서만 통하는
용어는 피합니다.

## 테스트와 정적 검사

전체 테스트:

```bash
pytest
```

특정 파일 또는 키워드만 실행:

```bash
pytest tests/test_scanner.py -v
pytest -k license
```

정적 검사:

```bash
pyflakes src/aibom_guardian tests examples
```

`pyflakes`는 정의되지 않은 이름과 사용되지 않는 import 등을 확인하며 CI에서도
실행됩니다. 동작을 변경하거나 버그를 수정한 경우 해당 상황을 재현하는
테스트를 추가해 주세요.

## Pull Request 절차

1. `dev` 브랜치에서 작업 브랜치를 생성합니다.
2. 브랜치 이름은 `feat/`, `fix/`, `docs/`, `test/`, `refactor/` 중 변경
   성격에 맞는 접두사로 시작합니다.
3. 커밋 메시지는 `타입: 요약` 형식으로 작성합니다.
4. `pytest`와 `pyflakes src/aibom_guardian tests examples`를 실행합니다.
5. `dev` 브랜치를 대상으로 Pull Request를 엽니다.

커밋 메시지 예시:

```text
feat: requirements 범위와 환경 마커 파싱 추가
fix: 취약점 별칭 병합 시 제목 유지
docs: 라이선스 캐시 동작 설명 보완
```

Pull Request 본문에는 변경 목적, 주요 구현 내용, 검증 방법을 적어 주세요.
판정 로직이나 외부 데이터 처리 방식을 변경했다면 선택한 기준과 영향을 함께
설명해 주세요.

CI에서 지원 Python 버전별 테스트, 패키지 빌드, CLI 실행 검사가 모두
통과해야 병합할 수 있습니다.

## 프로젝트 구조

```text
src/aibom_guardian/
    scanner.py              CLI 실행과 전체 검사 흐름
    _requirements.py        requirements 파싱과 간접 의존성 확장
    _scanner_license.py     PyPI와 npm 릴리스 라이선스 조회
    _scanner_collect.py     OSV, 위험 신호, 공급망 정보 수집
    _scanner_models.py      모델 검사 결과 변환
    _cli_report.py          터미널 출력과 JSON 저장
    npm_checker.py          package.json 검사
    security_classifiers.py 모델 카드 PII 검사
    mcp_server.py           MCP 서버와 도구 4종
    _adapters.py            공통 채점 입력 생성
    score_engine.py         Trust Score와 최종 판정
    model_checker.py        Hugging Face 모델 검사
    osv_client.py           OSV 조회와 CVSS 처리
    recommendation.py       위험 탐지와 대안 제시
    license_checker.py      라이선스 분류
    sbom_generator.py       CycloneDX SBOM과 ML-BOM 생성
    ai_explainer.py         Ollama 기반 로컬 설명
    repository_checker/     저장소와 출처 검사
examples/                   예제 입력과 출력
tests/                      단위 테스트
```

`repository_checker/`는 검사 대상별로 나뉩니다. GitHub 관련 코드는
`_github.py`, Hugging Face 관련 코드는 `_huggingface.py`에서 확인할 수
있습니다. 공통 HTTP 처리와 SSRF 방어는 `_http.py`, 결과 조립은
`_checker.py`에서 담당합니다.

## 라이선스

기여한 코드는 프로젝트와 동일한
[Apache License 2.0](LICENSE)으로 배포됩니다.
