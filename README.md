# AIBOM-Guardian

[CI](https://github.com/Letmeloveyou522/aibom_guardian/actions/workflows/ci.yml)
[Python](pyproject.toml)
[License](LICENSE)
[CycloneDX](https://cyclonedx.org/)
[MCP](src/aibom_guardian/mcp_server.py)

> **Vibe Coding 시대, 개발자를 위한 AI 공급망 메인테이너 에이전트**

LLM이 추천하고, 문서에서 복사하고, `pip install` / `npm install` 한 줄로
들어오는 의존성 — 그 안에 **없는 패키지**, **쓸 수 없는 라이선스**,
**실행되는 pickle 가중치**, **모델 카드에 남은 PII**가 섞여 있습니다.
AIBOM-Guardian는 **PyPI · npm · Hugging Face**를 한 파이프라인으로 검사해
두 가지를 남깁니다.


| 산출물                                                            | 의미         |
| -------------------------------------------------------------- | ---------- |
| **CycloneDX 1.6 SBOM / ML-BOM** (`sbom.json`)                  | 무엇이 들어 있는가 |
| **Trust Score + ALLOW / WARNING / BLOCK** (`scan_report.json`) | 그것을 써도 되는가 |


검사하지 못한 것을 통과시키지 않습니다. 아래 **데이터 계약**을 CLI·MCP·
`score_engine`이 공유합니다.


| 필드 / 이슈               | `[]` 또는 `false`             | `null` 또는 `true`             |
| --------------------- | --------------------------- | ---------------------------- |
| `vulnerabilities`     | OSV 응답, 알려진 CVE 없음          | OSV/네트워크 실패 → `WARNING`      |
| `license_unverified`  | 고정 버전 PyPI/npm 메타에서 라이선스 확인 | 설치 사본 폴백 등 → confidence↓     |
| `pii_scan_unverified` | 모델 카드 텍스트 PII 스캔 완료         | 카드 미읽기/빈 본문 → provenance 미검증 |


English: [README.en.md](README.en.md) ·
기여: [CONTRIBUTING.md](CONTRIBUTING.md) ·
보안: [SECURITY.md](SECURITY.md) ·
변경 이력: [CHANGELOG.md](CHANGELOG.md)

---

## 핵심 아키텍처

에이전트(판단)와 MCP 도구(실행)를 나누고, 점수는 `score_engine` 한곳에서만
매깁니다. CLI와 MCP가 같은 답을 내는 근거입니다.

<img width="795" height="891" alt="image" src="https://github.com/user-attachments/assets/ca58ee8f-e1e9-4eb1-88af-1dc6ffc5da66" />


MCP 도구 4종: `check_package` · `check_license` · `check_repo_trust` ·
`check_model`. 에이전트는 도구를 호출하고, 배치 CI·SBOM 파일 출력은
`aibom-guardian` CLI가 담당합니다.

> **범위 안내:** 취약점 소스는 **OSV**, 공급망 점수는 **OpenSSF Scorecard**,
> 서명 검증은 **cosign(Sigstore CLI)**, 모델 직렬화는 **picklescan**입니다.
> 컨테이너/IaC용 Trivy·Semgrep 엔진은 포함하지 않습니다. 그 영역은
> 기존 도구와 병행하는 것을 권장합니다.

---

## 주요 기능

### 모델 직렬화 검사 (Pickle vs Safetensors)

`.bin` / `.pkl`은 pickle입니다. `torch.load()`가 그 안의 코드를 실행할 수
있습니다. safetensors 대안 존재 여부, pickle-only 저장소, picklescan
위험 전역을 이슈로 올립니다. 기본은 메타데이터만 보고,
`--model-pickle-scan MB`로 다운로드 검사를 켭니다.

### 원격 코드 실행 신호 (`trust_remote_code`)

`config.json`의 `auto_map` / `trust_remote_code`와 외부 코드 저장소 참조를
수집해 `malicious`·`provenance` 이슈로 점수에 반영합니다.
(정적 메타데이터 기반 — 임의 Python AST 전수 분석기는 아닙니다.)

### npm 생태계 (`--npm`)

`package.json`의 `dependencies` / `devDependencies`를 스캔합니다.
npm registry에서 릴리스별 `dependencies` 체인을 전개(최대 깊이 12)하고,
OSV `ecosystem=npm`·registry 라이선스 필드를 PyPI와 같은 `license_checker`
게이트로 판정합니다. 대형 manifest(예: `express`) live 스캔 시 **170+**
전이 패키지까지 추적할 수 있습니다.

```bash
aibom-guardian --npm examples/sample-package.json
aibom-guardian --npm package.json --direct-only --offline
```

### 환각 패키지 · 타이포스쿼팅

PyPI/npm에 없는 이름, 인기 패키지와 편집 거리가 가까운 이름, yanked 릴리스,
너무 젊은 릴리스(쿨다운)를 탐지하고 대안을 제안합니다.

### 라이선스 — 패키지와 모델 동일 게이트

SPDX License List + Blue Oak Council로 식별하고, OpenRAIL / Llama / Gemma
등 SPDX id가 없는 **AI 모델 라이선스**도 `BLOCKED` / `REVIEW`로 분류합니다.
`Apache-2.0 WITH Commons Clause`처럼 `WITH` 예외는 나누지 않고 함께 판정합니다.

### 모델 카드 PII (provenance)

Model Card/README 본문에서 **이메일**, **한국 휴대폰 번호**, **Luhn 검증
신용카드 PAN**을 찾습니다(`security_classifiers`). 발견은 `type: pii` 이슈로
올라가 `score_engine` provenance 카테고리에 반영됩니다. 카드를 읽지 못하면
`pii_scan_unverified: true` — **“PII 없음”이 아닙니다.**

### GitHub Actions 보안 게이트

```yaml
- uses: Letmeloveyou522/aibom_guardian@v1
  with:
    requirements: requirements.txt
    fail-on: warning   # block | warning | never
```

Composite Action이 SBOM·SARIF·JSON 리포트를 남기고, 종료 코드로 CI를
막을 수 있습니다. (`action.yml`)

---

## 실행 결과 예시
```text
$ aibom-guardian examples/sample-requirements.txt
```

<img width="1151" height="750" alt="image" src="https://github.com/user-attachments/assets/efae65e0-afce-4652-832d-f6afe71ca9ef" />


`urllib3`은 requirements에 없어도 `requests`의 **전이 의존성**으로 잡힙니다.

```text
$ aibom-guardian requirements.txt --model CompVis/stable-diffusion-v1-4
```
<img width="1452" height="295" alt="image" src="https://github.com/user-attachments/assets/7e714399-0f2f-4014-9f27-d4a1e084cef7" />


### 종료 코드


| 코드  | 의미                                              |
| --- | ----------------------------------------------- |
| `0` | 전부 ALLOW, 미검사 줄 없음                              |
| `1` | 입력 오류                                           |
| `2` | BLOCK 존재                                        |
| `3` | WARNING 또는 unscanned 줄 (`--fail-on warning` 기본) |


BLOCK만 막으려면 `--fail-on block`을 사용하십시오.

---

## 디렉터리 구조

```text
aibom_guardian/
├── src/aibom_guardian/
│   ├── scanner.py              # CLI 오케스트레이터 (run_scan / main)
│   ├── _requirements.py        # requirements 파싱 · PyPI 전이 의존성
│   ├── _scanner_license.py     # PyPI/npm 릴리스 라이선스 해석
│   ├── _scanner_collect.py     # 병렬 OSV · recommendation · supply chain
│   ├── _scanner_models.py      # HF 모델 스캔 · 이슈 번역
│   ├── _cli_report.py          # 터미널 리포트 · save_report
│   ├── npm_checker.py          # package.json · npm 전이 · run_npm_scan
│   ├── security_classifiers.py # 모델 카드 PII (이메일·휴대폰·카드)
│   ├── mcp_server.py           # MCP 서버 (도구 4종)
│   ├── score_engine.py         # Trust Score / 판정 (유일 채점기)
│   ├── _adapters.py            # CLI↔MCP 공통 이슈 스키마
│   ├── osv_client.py           # OSV + CVSS + alias 병합
│   ├── license_checker.py      # SPDX / Blue Oak / AI 라이선스
│   ├── recommendation.py       # 환각·타이포·대안
│   ├── model_checker.py        # HF 모델 · picklescan
│   ├── repository_checker/     # OpenSSF · cosign · SSRF 방어
│   ├── sbom_generator.py       # CycloneDX 1.6 / ML-BOM
│   ├── sarif.py                # GitHub Code Scanning용 SARIF
│   └── ai_explainer.py         # 로컬 Ollama 설명 (선택)
├── tests/                      # ~840 오프라인 단위 테스트
├── examples/                   # sample-requirements · sample-package.json
│                               # demo_scenarios · demo_recommendation
├── .github/workflows/          # ci.yml · cd.yml
├── action.yml                  # GitHub Marketplace composite action
├── CONTRIBUTING.md · SECURITY.md · CODE_OF_CONDUCT.md
├── DEPENDENCIES.md             # 런타임 의존성 · 라이선스 목록
└── pyproject.toml
```

수집(①②③)과 판정(④)이 분리되어 있습니다.

```text
① model_checker ──┐
② repository_checker ┼──▶ ④ score_engine ──▶ ⑤ sbom / sarif / mcp
③ recommendation ──┘         ▲
                             └── _adapters (스키마 단일화)
```

---

## 설치 및 빠른 시작

### 요구 사항

- Python **3.10+**
- (선택) `GITHUB_TOKEN` — `--supply-chain` rate limit
- (선택) `HF_TOKEN` — gated 모델
- (선택) `cosign` — 서명 검증
- (선택) Ollama — 로컬 설명 (`--no-explain`으로 생략)

### 설치

```bash
git clone https://github.com/Letmeloveyou522/aibom_guardian.git
cd aibom_guardian

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
pytest                             # 네트워크 없이 수 초 내 통과해야 정상
```

### CLI

```bash
# PyPI — 기본 스캔 (전이 의존성 포함) + SBOM
aibom-guardian examples/sample-requirements.txt

# npm — package.json (전이 + OSV npm + registry 라이선스)
aibom-guardian --npm examples/sample-package.json

# 시연 — 정상 모델 / 악성 pickle / 타이포 / 환각 (오프라인)
python examples/demo_scenarios.py

# AI 모델 포함 → ML-BOM
aibom-guardian requirements.txt --model CompVis/stable-diffusion-v1-4

# 공급망 · 서명 · OpenSSF
aibom-guardian requirements.txt --supply-chain

# CI 친화: 설명 생략, SARIF, fail 정책
aibom-guardian requirements.txt --no-explain --sarif out.sarif --fail-on warning

# 오프라인 (라이선스 캐시·설치 사본만)
aibom-guardian requirements.txt --offline --fail-on never
```

또는 `python -m aibom_guardian requirements.txt`.

### MCP (에이전트 연동)

```bash
aibom-guardian-mcp
# 또는: python -m aibom_guardian.mcp_server
```

Claude Desktop / Cursor 예시:

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


| 도구                 | 역할                                                |
| ------------------ | ------------------------------------------------- |
| `check_package`    | OSV CVE + 라이선스 + Trust Score (단건)                 |
| `check_license`    | 라이선스 문자열 → `{status, spdx_id, family, ...}`       |
| `check_repo_trust` | OpenSSF · provenance · cosign · HF 데이터셋 문서        |
| `check_model`      | HF 모델 스캔 — `scan_report.json`의 `models[]`와 동일 스키마 |


`scan_report.json` 스키마:

```json
{
  "packages": [ { "package", "version", "license_status", "vulnerabilities", "verdict", "trust_score", "..." } ],
  "models":   [ { "model_id", "license_status", "verdict", "risk_score", "issues", "model_card", "..." } ],
  "unscanned": [ "검사하지 못한 requirements 줄" ]
}
```

### Trust Score (요약)


| 카테고리          | 가중치 |
| ------------- | --- |
| malicious     | 28  |
| cve           | 25  |
| license       | 15  |
| typosquatting | 12  |
| hallucination | 10  |
| provenance    | 10  |


- **≥ 80** + 충분한 confidence → `ALLOW`
- **< 50** 또는 hard block → `BLOCK`
- 그 사이이거나 증거 부족 → `WARNING`

상세 의무사항·판정 규칙은 본 문서 하단 “라이선스 판정”과
[CONTRIBUTING.md](CONTRIBUTING.md)를 참고하십시오.

---

## CI / CD


| 워크플로                       | 트리거                    | 내용                                                          |
| -------------------------- | ---------------------- | ----------------------------------------------------------- |
| `.github/workflows/ci.yml` | `main` / `dev` push·PR | Python 3.10–3.13 `pytest`, pyflakes, wheel 빌드, 오프라인·라이브 스모크 |
| `.github/workflows/cd.yml` | `v*.*.*` 태그            | 검증 후 GitHub Release (wheel/sdist + 데모 SBOM)                 |


로컬에서 CI와 같게 확인:

```bash
pytest -q
python -m pyflakes src/aibom_guardian tests examples
python -m build
```

---

## 다른 도구와의 차이


|                   | pip-audit | safety | syft · trivy | **AIBOM-Guardian**     |
| ----------------- | --------- | ------ | ------------ | ---------------------- |
| 취약점 (OSV 등)       | ✅         | ✅      | ✅            | ✅                      |
| PyPI + **npm**    | PyPI      | ❌      | ✅            | ✅                      |
| 전이 의존성            | ✅         | ✅      | ✅            | ✅                      |
| CycloneDX SBOM    | ❌         | ❌      | ✅            | ✅ 1.6                  |
| **AI 모델 라이선스**    | ❌         | ❌      | ❌            | ✅ OpenRAIL·Llama       |
| **모델 가중치 안전성**    | ❌         | ❌      | ❌            | ✅ pickle / safetensors |
| ML-BOM            | ❌         | ❌      | 부분           | ✅                      |
| 릴리스 쿨다운           | ❌         | ❌      | ❌            | ✅                      |
| SARIF             | ✅         | ✅      | ✅            | ✅                      |
| **미검증을 통과시키지 않음** | ❌         | ❌      | ❌            | ✅                      |
| 모델 카드 PII 신호      | ❌         | ❌      | ❌            | ✅                      |
| LLM 에이전트 (MCP)    | ❌         | ❌      | ❌            | ✅ 도구 4종                |


패키지 CVE만 필요하면 `pip-audit`이 더 가볍습니다. **모델까지 같은
기준으로 판정하고 하나의 AIBOM에 담을 때** 이 도구의 자리입니다.

---

## 라이선스 판정 (요약)

식별 근거: **SPDX License List** + **Blue Oak Council**. AI 전용 규칙은
별도 패턴(OpenRAIL → `BLOCKED`, Llama/Gemma → `REVIEW`).


| 조건                                   | 결과                |
| ------------------------------------ | ----------------- |
| 비상업 · Commons Clause · BUSL · SSPL 등 | `BLOCKED`         |
| OpenRAIL 계열                          | `BLOCKED`         |
| Llama · Gemma 등 커뮤니티 라이선스            | `REVIEW`          |
| 카피레프트 (GPL/AGPL/MPL…)                | `REVIEW` + 의무 안내  |
| Blue Oak / OSI 승인 관대 라이선스            | `ALLOWED`         |
| 식별 실패                                | `UNKNOWN` (통과 아님) |


캐시: `~/.cache/aibom-guardian/registries` (`AIBOM_GUARDIAN_CACHE`로 변경 가능).
`--offline`이고 캐시가 없으면 내장 규칙만 남으며, 이 경우 **ALLOWED로
무너지지 않습니다.**

고정 버전의 PyPI 메타데이터를 우선 읽고, 설치 사본은 폴백입니다.
폴백 시 `license_unverified: true`가 붙습니다.

---

## 기여 가이드 & 라이선스

### Contributing

1. [CONTRIBUTING.md](CONTRIBUTING.md)의 **None ≠ []** · `license_unverified` ·
  `pii_scan_unverified` 계약을 지키십시오.
2. 점수는 `score_engine`만, CLI/MCP 입력은 `_adapters`만 사용하십시오.
3. `pytest`는 네트워크를 쓰지 않습니다. 새 테스트도 mock 하십시오.
4. PR 전에 `pytest` + `pyflakes`가 통과해야 합니다.

보안 취약점 제보: [SECURITY.md](SECURITY.md) (공개 이슈 금지).  
행동 강령: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

### License

본 프로젝트는 **[Apache License 2.0](LICENSE)** 입니다.

런타임 의존성과 그 라이선스는 [DEPENDENCIES.md](DEPENDENCIES.md)에
정리되어 있습니다.

---

**AIBOM-Guardian** — ship AI dependencies you can still explain tomorrow.
