# 변경 이력

이 프로젝트의 주요 변경 사항을 기록합니다.
형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르고,
버전은 [유의적 버전](https://semver.org/lang/ko/)을 따릅니다.

버전 번호의 단일 출처는 [`src/aibom_guardian/__init__.py`](src/aibom_guardian/__init__.py)의
`__version__`입니다. `pyproject.toml`이 여기서 읽어 가고, 릴리스 워크플로가
태그와 일치하는지 검사합니다.

---

## [Unreleased]

(아직 태그되지 않은 변경은 여기에 적습니다.)

---

## [0.1.0] - 2026-08-22

**AIBOM-Guardian** 첫 공개 후보 릴리스. PyPI·npm·Hugging Face를 한 파이프라인으로
검사하고 CycloneDX SBOM/ML-BOM과 Trust Score를 남깁니다. (Git 태그·PyPI 업로드는
아직 — 코드·휠 버전만 `0.1.0`.)

### Added

**패키지 · npm**

- PyPI `requirements.txt` 스캔 — OSV CVE, SPDX/Blue Oak 라이선스, 환각·타이포,
  yanked·쿨다운, 전이 의존성(`_requirements.expand_transitive`).
- **npm 생태계** — `aibom-guardian --npm package.json`. `dependencies` /
  `devDependencies` 파싱, npm registry 기반 전이 트리(`expand_npm_transitive`,
  최대 깊이 12), OSV `ecosystem=npm`, registry 라이선스 필드 → `license_checker`.
- `examples/sample-package.json` npm 데모 입력.

**AI 모델**

- Hugging Face 모델 스캔 — pickle/safetensors, picklescan, `trust_remote_code` /
  `auto_map`, Model Card 완성도.
- **모델 카드 PII 탐지** (`security_classifiers.scan_text_for_pii`) — 이메일,
  한국 휴대폰(010 등), Luhn 검증 신용카드 PAN. `type: pii` → `score_engine`
  provenance 가중치. 카드를 읽지 못하면 `pii_scan_unverified: true`.

**판정 · 출력**

- Trust Score 6카테고리(malicious 28, cve 25, license 15, typosquatting 12,
  hallucination 10, provenance 10).
- CycloneDX **1.6** SBOM / ML-BOM, SARIF 2.1.0, `scan_report.json`.
- MCP 도구 4종 — `check_package`, `check_license`(dict envelope),
  `check_repo_trust`, `check_model`.
- GitHub Composite Action (`action.yml`), CI 게이트(`--fail-on`).
- Ollama 로컬 설명(선택), `examples/demo_recommendation.py`,
  `examples/demo_scenarios.py`(정상 모델 / 악성 pickle / 타이포 / 환각 시연).

**공급망 · 인프라**

- `repository_checker/` — OpenSSF Scorecard, cosign, SSRF 방어.
- `pip install` 패키징 — `aibom-guardian`, `aibom-guardian-mcp` console scripts.
- ~840 오프라인 단위 테스트, `tests/test_packaging.py` 의존성 동기화 검사.

### Changed

- 프로젝트·패키지명 **AIBOM-Guardian** / CLI **`aibom-guardian`** /
  **`aibom-guardian-mcp`** / 모듈 **`aibom_guardian`** 으로 통일.
- `scanner.py` 오케스트레이터 분할 — `_requirements.py`, `_cli_report.py`,
  `_scanner_license.py`, `_scanner_collect.py`, `_scanner_models.py`.
- CLI/MCP 공통 이슈 스키마를 `_adapters.py` 단일 사본으로 통합.
- `score_engine`에서 미사용 `pii` 가중치 슬롯 제거(legacy `type: pii`는
  provenance alias).
- README·CONTRIBUTING 가중치표를 코드와 일치(6카테고리 / 100점 합).

### Fixed (P0–P2)

- **P0** — OSV/`license_unverified`: `None`을 `[]`로 coalesce하지 않음.
  미검증은 confidence↓ + `WARNING`.
- **P0** — MCP `check_package` PyPI 전용, non-PyPI → `unsupported_ecosystem`.
- **P1** — MCP stdout JSON-RPC 오염 제거(`test_mcp_stdout_is_clean.py`).
- **P1** — `check_model` ↔ `scan_report.json` `models[]` 스키마 정합.
- **P2** — `check_license` str → `{success, tool, status, spdx_id, family, …}`.
- **P2** — SSRF 잘못된 포트가 크래시 대신 거부.
- OSV alias 병합·CVSS 파싱, SBOM tool 버전 `__version__` 연동.

### Security

- SSRF: 허용 호스트·포트, DNS 재검증(`repository_checker/_http.py`).
- pickle 검사 기본 비활성 — 미검사는 `unverified`로 보고.

[Unreleased]: https://github.com/Letmeloveyou522/aibom_guardian/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Letmeloveyou522/aibom_guardian/releases/tag/v0.1.0
