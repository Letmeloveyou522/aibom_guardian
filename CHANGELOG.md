# 변경 이력

이 프로젝트의 주요 변경 사항을 기록합니다.
형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르고,
버전은 [유의적 버전](https://semver.org/lang/ko/)을 따릅니다.

버전 번호의 단일 출처는 [`src/aibom_guard/__init__.py`](src/aibom_guard/__init__.py)의
`__version__`입니다. `pyproject.toml`이 여기서 읽어 가고, 릴리스 워크플로가
태그와 일치하는지 검사합니다.

---

## [Unreleased]

### Added

- **전이 의존성 검사.** 파일에 적힌 것만이 아니라 실제로 설치될 것 전부를
  검사합니다. PyPI `requires_dist`를 고정 버전마다 읽어 아무것도 설치하지 않고
  트리를 만듭니다. 예제 파일 기준 3개 → 7개, 취약점 5건 → 10건
  (`requests`가 끌어오는 `urllib3`에만 CVE 5건). 리포트와 SBOM 모두
  `direct`/`transitive`를 구분합니다. `--direct-only`로 끕니다.
- **동시 조회.** 조회는 네트워크 대기가 대부분이라 스레드로 병렬화했습니다.
  20줄 파일(전이 포함 53개) 기준 36.4초 → 7.9초. `--jobs N`, 기본 8.
  `jobs=1`과 `jobs=8`의 리포트는 순서까지 동일합니다.
- **릴리스 쿨다운** (`--min-release-age DAYS`). 그보다 최근에 올라온 버전을
  경고합니다. 공격받은 릴리스는 대개 몇 시간 안에 내려가므로, 하루만 기다려도
  그 창을 대부분 피합니다. 기본 0(끔).
- **SARIF 2.1.0 출력** (`--sarif PATH`). GitHub code scanning이 읽어 PR에
  인라인 주석으로 붙습니다. 발견을 requirements 파일의 해당 줄에 연결하며,
  fingerprint에 버전이 들어가 업그레이드 후 같은 알림이 남지 않습니다.
- **GitHub Action** (`action.yml`). `uses:` 한 줄로 남의 CI에 넣을 수 있습니다.
- **패키징**: `pip install`로 설치되는 배포물이 됩니다. 콘솔 명령
  `aibom-guard`(스캐너)와 `aibom-guard-mcp`(MCP 서버)가 등록되고,
  `python -m aibom_guard`로도 실행됩니다.
- **CI 빌드 검증**: 매 푸시마다 휠과 sdist를 만들고 `twine check`합니다.
  릴리스 워크플로는 태그를 달 때만 도는데, 그때 처음 실패를 발견하는 상황을
  막기 위한 것입니다.
- **릴리스 안전장치**: 태그(`v0.2.0`)와 패키지 버전(`__version__`)이 다르면
  릴리스를 중단합니다.
- `tests/test_packaging.py` — `pyproject.toml`과 `requirements.txt`의
  의존성 목록이 갈라지면 실패합니다. 진입점과 버전 단일화도 검사합니다.
- `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, 이슈·PR 템플릿.

### Changed

- `requests.Session`을 스레드-로컬로 분리하고 워커마다 자체
  `RecommendationEngine`을 만듭니다. 병렬 조회에서 세션을 공유하면 안 됩니다.
- README 가중치표가 코드와 달랐습니다(`30/25/15/10/8/7/5` → 실제
  `28/25/15/12/10/8/2`). 문서를 코드에 맞췄습니다.
- **구조**: 최상위에 흩어져 있던 모듈 10개를 `src/aibom_guard/` 패키지로
  옮겼습니다. 최상위 모듈이 여러 개인 flat 레이아웃은 setuptools가 배포물로
  만들 수 없어, 이전 릴리스 워크플로는 실행되면 반드시 실패하는 상태였습니다.
- **실행 방법**: `python scanner.py <파일>` → `aibom-guard <파일>`.
  개별 모듈은 `python -m aibom_guard.<모듈>`로 실행합니다.
- **MCP 설정**: Claude Desktop에 `mcp_server.py` 경로를 넘기던 방식이
  동작하지 않습니다. `aibom-guard-mcp` 또는
  `python -m aibom_guard.mcp_server`를 쓰십시오.
- `_vulns_to_issues`와 `_build_check_result`가 `scanner.py`와
  `mcp_server.py`에 복사되어 있던 것을 `_adapters.py` 한 곳으로 합쳤습니다.
  두 사본은 이미 갈라져 있었고(MCP 쪽만 `None`을 처리), CLI와 MCP가 같은
  판정을 낸다는 보장이 사람 손에 달려 있었습니다.
- `examples/demo_module3.py` → `examples/demo_recommendation.py`.

### Fixed

- **CI가 테스트를 실행하지 않던 문제.** 이전 워크플로는 의존성을 설치한 뒤
  성공 메시지를 출력하기만 했습니다. 테스트 600여 개가 한 번도 돌지
  않았습니다. 이제 Python 3.10 / 3.11 / 3.12 / 3.13에서 전부 실행하고,
  CLI를 오프라인으로 돌려 종료 코드 3과 산출물 형식까지 확인합니다.
- **릴리스 워크플로의 권한 누락.** `permissions: contents: write`가 없어
  기본 설정 저장소에서는 마지막 릴리스 생성 단계가 403으로 실패합니다.
- **MCP 프로토콜 오염.** `check_package`와 `check_model`이 실패 경로에서
  stdout에 경고를 출력했습니다. stdio MCP에서 stdout은 JSON-RPC 전송
  채널이라 클라이언트가 파싱 중인 메시지 안에 섞여 들어갑니다. 해당 경고는
  logging으로 옮겼고, CLI는 stderr 핸들러를 붙여 사람이 그대로 볼 수
  있습니다. `tests/test_mcp_stdout_is_clean.py`가 회귀를 막습니다.
- **잘못된 포트가 SSRF 차단이 아니라 크래시를 냈습니다.**
  `https://github.com:99999/...`처럼 범위를 벗어난 포트는 `urlparse`가
  평범한 `ValueError`를 던지는데, `SSRFError`가 그 하위 클래스라 호출자의
  `except SSRFError`를 그대로 통과해 스캔이 중단됐습니다. 이제 거부됩니다.
- **포트 정책이 두 곳에 있었습니다.** `ALLOWED_PORTS` 상수와
  `validate_public_url` 안의 인라인 검사가 각각 존재했고, 안쪽 분기 하나는
  도달 불가능한 죽은 코드였습니다. 상수 하나로 통일하고 테스트가 둘의
  일치를 검사합니다.
- SBOM이 자기 버전을 하드코딩된 `"0.1.0"`으로 기록하던 문제. 릴리스를
  올려도 모든 SBOM이 계속 0.1.0이라고 주장했을 것입니다.
- **문장 끝 마침표가 저장소 이름에 붙던 문제.** README에
  `See https://github.com/org/repo.` 라고 쓰여 있으면 저장소 이름을
  `repo.` 로 읽어 GitHub API가 404를 냈고, 결과적으로 "소스 저장소를 찾을
  수 없음"이라는 **출처 오판**이 났습니다. 정규화가 메타데이터 경로에만
  적용되고 README 경로는 자체 키를 만들고 있었던 것이 원인이라, 두 경로가
  같은 함수를 쓰도록 합쳤습니다. 점이 들어간 정상 이름
  (`requests/requests.oauthlib`)은 그대로 보존됩니다.

### Tests

- `_huggingface` 8% → 95%, `_pypi` 9% → 91%, 전체 71% → 78%.
  Hub와 PyPI의 JSON 응답을 파싱하는 경로는 외부가 정하는 모양을 다루면서도
  검증이 거의 없었습니다. 추가한 테스트는 정상 응답뿐 아니라 리스트로 오는
  `license`, dict가 아닌 `cardData`, digest 없는 파일, 401/403/404 같은
  **형태가 어긋나는 응답**을 함께 다룹니다.

---

## [0.1.0] - 미출시

첫 기능 완성 시점의 내용입니다. 아직 태그를 달지 않았습니다.

### Added

**패키지 검사**

- OSV 조회, CVSS 벡터 파싱, GHSA·PYSEC·CVE 별칭 중복 제거
- `requirements.txt`의 `>=`, `~=`, `<`, extras, 환경 마커 파싱.
  범위는 PyPI에서 실제로 설치될 버전으로 좁혀 검사하고, 파일이 정한
  버전인지 스캐너가 고른 버전인지 리포트에 남깁니다
- 검사할 수 없는 줄(`-r`, `-c`, URL/VCS 요구사항)을 `unscanned`로 보고
- 타이포스쿼팅(편집 거리), 환각 패키지(PyPI 미등록), 폐기(yanked, 장기 미관리)
- 안전한 상위 버전·오타 교정 등 대안 추천

**라이선스**

- SPDX License List(식별자 727개)와 Blue Oak Council List(관대함 등급 225개)
  두 공인 목록 기반 판정. 키워드 추측을 쓰지 않습니다
- `isOsiApproved` 단독 판정을 쓰지 않습니다 — 그것은 "제한적인가"가 아니라
  "OSI에 신청했는가"라는 절차적 사실이라, 관대하지만 미신청인 161개가
  통째로 차단됩니다
- SPDX 표현식의 `AND`/`OR` 결합 우선순위와 괄호 처리. `WITH`는 분해하지
  않습니다(`Apache-2.0 WITH Commons Clause`가 Apache로 통과하는 것을 방지)
- 라이선스를 PyPI의 **고정 버전 릴리스**에서 읽습니다. 릴리스마다 라이선스가
  바뀌기 때문입니다(`chardet` 5.2.0은 LGPL-2.1, 7.5.1은 0BSD)
- 버전 없는 표기(`"LGPL"`)는 계열만 보고하고 버전은 미해결로 둡니다
- 의무사항(카피레프트 범위, 고지 의무) 안내와 근거 링크
- 목록은 저장소에 넣지 않고 첫 실행에 받아 캐시합니다(30일 갱신, 실패 시
  기존 캐시 사용). 재배포 조건을 확인할 수 없는 파일이기 때문입니다

**AI 모델**

- Hugging Face 모델 스캔. 모든 파일을 commit SHA로 고정해 받습니다
- 가중치 형식 판정(pickle 대 safetensors, 샤드 단위 대체 파일 대조)
- `picklescan`으로 pickle 내부 위험 global 탐지 (기본 비활성)
- 원격 코드 실행 경로 탐지(`trust_remote_code`, `auto_map`)
- 모델 라이선스 계열 분류(OpenRAIL → BLOCKED, Llama·Gemma → REVIEW)
- Model Card 완성도 평가(HF 기본 템플릿 감지 포함)
- 출처 정보(commit SHA, base model, 학습 데이터셋, gated 여부)

**공급망**

- GitHub 활동·관리 상태, OpenSSF Scorecard, 서명·provenance 검증
- SSRF 방어: 허용 호스트/포트 목록, DNS 리바인딩 대응

**판정과 출력**

- Trust Score — 7개 항목 가중 감점(malicious 30, cve 25, license 15,
  typosquatting 10, hallucination 8, provenance 7, pii 5)
- 증거 부족 시 confidence를 낮춰 `WARNING`으로 보냅니다. 미검사 항목을
  통과 처리하지 않습니다
- 점수와 무관한 하드 블록 3종(critical 취약점, 악성코드, 차단 라이선스)
- CycloneDX 1.6 SBOM / ML-BOM 생성. 모델 가중치 SHA-256, 파생 계보,
  최종 수정일 포함. G7 「SBOM for AI」 50개 항목 중 28개 커버,
  Models 클러스터 13/13
- CI 게이트용 종료 코드 0/1/2/3과 `--fail-on` 옵션
- MCP 도구 4종: `check_package`, `check_license`, `check_repo_trust`,
  `check_model`
- Ollama 로컬 모델을 통한 결과 설명 (선택)

### Fixed

- OSV 조회 실패를 취약점 0건으로 보고하던 문제. `vulnerabilities`는 `null`,
  판정은 `WARNING`입니다 — 미검증과 검증된 안전은 다릅니다
- 별칭 병합 시 요약 대신 본문 문단이 남던 문제
- 나열할 수 없는 디렉터리에서 `check_provenance`가 크래시하던 문제
- 라이선스 오탐 및 hallucination 판정 로직 분리

[Unreleased]: https://github.com/Letmeloveyou522/aibom_guard/compare/main...dev
