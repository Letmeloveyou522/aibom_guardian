# 변경 이력

이 프로젝트의 주요 변경 사항을 기록합니다.
형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르고,
버전은 [유의적 버전](https://semver.org/lang/ko/)을 따릅니다.

버전 번호의 단일 출처는 [`src/aibom_guardian/__init__.py`](src/aibom_guardian/__init__.py)의
`__version__`입니다. `pyproject.toml`이 여기서 읽어 가고, 릴리스 워크플로가
태그와 일치하는지 검사합니다.

---

## [Unreleased]

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
