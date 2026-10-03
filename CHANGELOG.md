# 변경 이력

이 프로젝트의 주요 변경 사항을 기록합니다.
형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르고,
버전은 [유의적 버전](https://semver.org/lang/ko/)을 따릅니다.

버전 번호의 단일 출처는 [`src/aibom_guardian/__init__.py`](src/aibom_guardian/__init__.py)의
`__version__`입니다. `pyproject.toml`이 여기서 읽어 가고, 릴리스 워크플로가
태그와 일치하는지 검사합니다.

---

## [Unreleased]

### Added

- npm 검사에서 같은 폴더의 `package-lock.json` v2/v3를 자동으로 읽습니다.
  고정 버전과 중첩 설치 경로, 의존성 연결을 보존하며 registry 버전으로 재선택하지 않습니다.
  루트 선언 불일치·미지원 형식은 오류로, 미지원 소스는 `unscanned`로 처리합니다.

### Fixed

- MCP 서버 생성 전에 FastMCP Settings의 lifespan 타입 참조를 재구성해 시작 경고를 해결합니다.
  경고 필터나 의존성 버전 변경은 사용하지 않습니다.
- pickle 경고와 CLI 표시를 실제 조건인 pickle 존재·safetensors 부재로 한정합니다.
  다른 가중치 형식이 있어도 모든 로딩에 unpickling이 필수라고 표현하던 문구를 수정합니다.
  기존 pickle_only 필드·이슈 ID와 점수 규칙은 유지합니다.

- Hugging Face 저장소 검사의 revision을 전용 API 경로로 요청하고 응답 SHA를 검증합니다.
  기본 브랜치로 잘못 조회한 뒤 존재하지 않는 SHA를 고정으로 인정하던 문제를 수정했습니다.
  README 조회와 출처 요약도 확인된 커밋에 맞추며 조회 실패 시 고정 점수를 주지 않습니다.

- GitHub revision을 해당 저장소의 커밋 API로 확인한 뒤 고정 여부를 판정합니다.
  형식만 맞는 존재하지 않는 SHA에 고정 점수를 주던 문제를 수정했습니다.
  `revision_verified`와 실제 `resolved_revision`을 기록하며 브랜치 조회 성공과 불변 고정을 구분합니다.

- 저장소 전용 CLI의 종료 코드를 기본 CLI와 같은 정책으로 판정합니다.
  기본값에서 WARNING·수집 오류는 3, BLOCK은 2입니다. 이전의 무조건 0 반환을
  변경했으며, 보고서 출력만 필요한 경우 `--fail-on never`로 기존 동작을 선택할 수 있습니다.

- Hugging Face 모델 메타데이터 조회의 연결·타임아웃 오류를 최대 2회 재시도합니다.
  요청별 timeout은 20초이며 HTTP 권한·미발견 오류는 재시도하지 않습니다.

- 모델 검사 실패·오프라인 생략을 `unscanned`에 기록해 기본 정책에서 정상 통과하지 않도록 했습니다.
  Python 패키지 목록이 비어 있어도 `--model` 검사를 수행합니다.

- Python extras를 직접 입력에서 보존하고 전이 의존성으로 전달합니다.
  동일 패키지의 extras 요청을 병합하고 나중에 추가된 옵션도 다시 확장합니다.
  JSON 보고서에 `extras`를 기록합니다.

- Python 전이 의존성에서 선택된 버전과 요구 범위의 충돌, 메타데이터 조회 실패,
  깊이 제한 및 미지원 전이 요구사항을 `unscanned`에 기록합니다.
  충돌 시 사용자가 지정한 버전을 임의로 교체하지 않습니다.

- npm 직접 의존성의 지원 버전 범위를 registry에서 해석한 뒤 검사합니다.
  범위 시작 버전을 대신 검사하던 동작을 제거하고, 해석 실패·오프라인은
  `unscanned`로 남깁니다. 결과의 `resolution_source`로 선택 근거를 표시합니다.
- npm 전이 의존성의 이름이 같아도 버전이 다르면 검사에 포함하고,
  JSON의 `required_by`에 부모를 기록합니다. 개발/운영 의존성 유입을
  구분하며, 조회 실패 및 깊이 제한으로 남은 항목을 `unscanned`에 기록합니다.
- SPDX 기본 주소 다운로드 실패 시 공식 SPDX GitHub JSON을 조회하는 대체
  경로를 추가했습니다. 기존 캐시 및 오프라인 정책은 유지합니다.

---

## [1.0.0] - 2026-08-27

오픈소스 개발자대회 제출을 위한 첫 정식 릴리스입니다.

### Changed

- 한국어와 영어 README의 구성과 내용을 통일하고 설치, 검사 범위, 출력,
  제한 사항을 실제 구현에 맞게 정리했습니다.
- 기여 가이드, 보안 정책, 이슈 양식, PR 템플릿을 외부 기여자가 사용하기
  쉬운 형태로 정리했습니다.
- npm 검사에서 공유하던 세션 상태를 제거해 실행 간 영향을 받지 않도록
  수정했습니다.
- `--fail-on never`가 발견된 문제를 보고하되 종료 코드 0을 반환하도록
  동작을 명확히 했습니다.

### Fixed

- 정적 검사에서 발견된 사용하지 않는 import와 모듈 참조를 정리했습니다.
- GitHub Action의 지원 범위와 종료 정책 설명을 실제 동작에 맞췄습니다.

---

## [0.1.0] - 2026-08-22

**AIBOM-Guardian** 첫 공개 후보 릴리스입니다. PyPI, npm, Hugging Face를
검사하고 CycloneDX SBOM 또는 ML-BOM과 Trust Score를 생성합니다.

### Added

**패키지 검사**

- PyPI `requirements.txt` 스캔: OSV CVE, SPDX/Blue Oak 라이선스, 환각 및
  타이포스쿼팅, yanked 릴리스, 쿨다운, 전이 의존성(`_requirements.expand_transitive`).
- npm `package.json` 검사: `dependencies`와 `devDependencies` 파싱, npm
  registry 기반 간접 의존성 확장, OSV 취약점 조회, 라이선스 판정.
- `examples/sample-package.json` npm 데모 입력.

**AI 모델**

- Hugging Face 모델 검사: pickle과 safetensors 형식, picklescan,
  `trust_remote_code`, `auto_map`, 모델 카드 완성도.
- 모델 카드 PII 탐지: 이메일, 한국 휴대폰 번호, Luhn 검증 신용카드 번호.
  카드를 읽지 못하면 `pii_scan_unverified: true`로 기록.

**판정과 출력**

- Trust Score 6카테고리(malicious 28, cve 25, license 15, typosquatting 12,
  hallucination 10, provenance 10).
- CycloneDX **1.6** SBOM / ML-BOM, SARIF 2.1.0, `scan_report.json`.
- MCP 도구 4종: `check_package`, `check_license`,
  `check_repo_trust`, `check_model`.
- GitHub Composite Action (`action.yml`), CI 게이트(`--fail-on`).
- Ollama 로컬 설명(선택), `examples/demo_recommendation.py`,
  `examples/demo_scenarios.py`(정상 모델 / 악성 pickle / 타이포 / 환각 시연).

**공급망과 인프라**

- `repository_checker/`: OpenSSF Scorecard, cosign, SSRF 방어.
- `pip install` 패키징과 `aibom-guardian`, `aibom-guardian-mcp` 실행 명령.
- 네트워크를 사용하지 않는 단위 테스트와 `tests/test_packaging.py` 의존성
  동기화 검사.

### Changed

- 프로젝트명과 패키지명을 **AIBOM-Guardian**, CLI를 `aibom-guardian`과
  `aibom-guardian-mcp`, 모듈을 `aibom_guardian`으로 통일.
- `scanner.py` 기능 분리: `_requirements.py`, `_cli_report.py`,
  `_scanner_license.py`, `_scanner_collect.py`, `_scanner_models.py`.
- CLI와 MCP의 공통 이슈 스키마를 `_adapters.py`로 통합.
- `score_engine`에서 사용하지 않는 `pii` 가중치 항목 제거. 기존
  `type: pii`는 provenance 항목으로 처리.
- README와 CONTRIBUTING의 가중치표를 코드와 일치(6카테고리 / 100점 합).

### Fixed

- OSV와 `license_unverified`: `None`을 `[]`로 변환하지 않고 미검증 상태의
  신뢰도를 낮춰 `WARNING`으로 판정.
- MCP `check_package` PyPI 전용 처리와 `unsupported_ecosystem` 응답 추가.
- MCP stdout의 JSON-RPC 외 출력 제거(`test_mcp_stdout_is_clean.py`).
- `check_model`과 `scan_report.json`의 `models[]` 스키마 통일.
- `check_license` 응답을 구조화된 객체로 변경.
- 잘못된 SSRF 포트를 오류 없이 거부하도록 수정.
- OSV alias 병합과 CVSS 파싱, SBOM tool 버전 `__version__` 연동.

### Security

- SSRF 방어를 위해 허용 호스트와 포트를 제한하고 DNS를 재검증.
- pickle 내부 검사는 기본적으로 비활성화하며 미검사 항목은 `unverified`로 기록.

[Unreleased]: https://github.com/Letmeloveyou522/aibom_guardian/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Letmeloveyou522/aibom_guardian/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/Letmeloveyou522/aibom_guardian/releases/tag/v0.1.0
