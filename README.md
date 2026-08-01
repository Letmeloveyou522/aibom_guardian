# AIBOM-Guard

Python/AI 의존성의 **보안·라이선스·공급망 위험**을 검사하고,
CycloneDX SBOM 및 MCP로 결과를 제공하는 도구입니다.

현재 ③ **위험 탐지 및 대안 추천** 모듈이 추가되어,
OSV CVE 조회 + Typosquatting/Hallucination 탐지 + 대안 추천을
팀 표준 JSON(`issues` / `alternatives`)으로 반환합니다.

## What it does

1. `requirements.txt`의 패키지·버전을 읽음
2. 라이선스 분류 + [OSV](https://osv.dev) CVE 조회 (CVSS v3/v3.1 벡터 파싱)
3. Typosquatting / Hallucination / Deprecated(yanked·미관리) 탐지 및 대안 추천
4. Trust Score / 판정 (`ALLOW` / `CONDITIONAL` / `BLOCK`) — CLI 기준
5. `scan_report.json` + CycloneDX `sbom.json` 생성
6. (옵션) Ollama 로컬 모델 설명, MCP 서버로 에이전트 연동

## Project structure

```
aibom_guard/
├─ scanner.py                 # CLI 메인 파이프라인
├─ license_checker.py         # 라이선스 분류 (ALLOWED / REVIEW / BLOCKED)
├─ osv_client.py              # OSV CVE 조회 + CVSS severity 파싱        ← ③
├─ recommendation.py          # 위험 탐지 + 대안 추천 엔진               ← ③
├─ repository_checker.py      # GitHub / HF / PyPI 공급망 신뢰도 검사    ← ②
├─ score_engine.py            # Trust Score / 최종 판정                  ← ④
├─ sbom_generator.py          # CycloneDX SBOM 생성                      ← ⑤
├─ mcp_server.py              # MCP 서버 (check_package / check_repo_trust)
├─ ai_explainer.py            # Ollama 로컬 모델 설명
├─ requirements.txt           # 예시 스캔 입력
├─ DEPENDENCIES.md            # 본 프로젝트 사용 OSS 목록
├─ test_module3.py            # ③ 모듈 통합 테스트
├─ test_score_engine.py       # ④ score_engine 단위 테스트
├─ tests/                     # ② repository_checker 단위 테스트 (네트워크 mock)
└─ scan_report.json / sbom.json   # 실제 실행 예시 출력
```

팀 확장 아키텍처 (진행 중):

```
① model_checker ──┐
② repository_checker ┼──> ④ score_engine ──> ⑤ AIBOM / MCP
③ recommendation ──┘     (Trust Score)      (sbom / scanner)
```

## Module ③ — 위험 탐지 & 대안 추천

### 연동 방법 (④ / ⑤에서 호출)

```python
from osv_client import query_vulnerabilities
from recommendation import RecommendationEngine

engine = RecommendationEngine()

# 패키지
cve_issues = query_vulnerabilities("requests", "2.28.0")
result = engine.analyze_package("requests", "2.28.0", cve_issues=cve_issues)

# 모델 (① model_checker 결과 dict 전달)
model_result = engine.analyze_model(model_info_dict)
```

### 반환 JSON (팀 Data Protocol)

```json
{
  "issues": [
    {
      "type": "cve",
      "id": "GHSA-xxxx",
      "severity": "high",
      "cvss_score": 8.1,
      "detail": "..."
    },
    {
      "type": "typosquatting",
      "detail": "Package 'reqeusts' is similar to official package 'requests'"
    }
  ],
  "alternatives": [
    {
      "target": "requests==2.34.2",
      "confidence": "confirmed",
      "reason": "Upgrade to latest safe release"
    }
  ]
}
```

- `issues[].type`: `cve` | `hallucination` | `typosquatting` | `malicious` | `pii` | `license` | `provenance`
- `alternatives[].confidence`: `confirmed` (버전업·오타교정) | `suggested` (대체 모델 등)
- **점수/최종 판정은 하지 않음** — ④ `score_engine` 전담

### 통합 테스트

```bash
pip install requests
python test_module3.py
# 또는 개별 케이스
python test_module3.py requests==2.28.0 reqeusts==1.0.0 nonexistent-ai-pkg==0.1.0
```

검증 케이스: CVE 업그레이드 추천 / typosquat 교정 / hallucination 탐지.

## How to run (CLI 전체 스캔)

```bash
pip install requests prettytable cyclonedx-bom
python scanner.py requirements.txt
```

Example output:

```
+----------+---------+----------------+-------+-------------+---------+
| Package  | Version | License Status | Vulns | Trust Score | Verdict |
+----------+---------+----------------+-------+-------------+---------+
| requests |  2.28.0 |    ALLOWED     |   8   |      20     |  BLOCK  |
|  numpy   |  1.24.0 |    ALLOWED     |   0   |     100     |  ALLOW  |
|  pyyaml  |  5.3.1  |    ALLOWED     |   2   |      80     |  ALLOW  |
+----------+---------+----------------+-------+-------------+---------+
```

## MCP server (Claude Desktop / Cursor)

`mcp_server.py` exposes AIBOM-Guard tools over stdio MCP.

### Tools

| Tool | Role |
|---|---|
| `check_package` | CVE/advisory lookup (OSV) + installed-package license status |
| `check_license` | Classify a license string (ALLOWED / REVIEW / BLOCKED / UNKNOWN) |
| `check_repo_trust` | Supply-chain trust: GitHub activity, OpenSSF Scorecard, revision pinning, SHA-256, signatures/provenance, HF dataset docs |

Use `check_package` when you only need vulnerabilities for a package version.
Use `check_repo_trust` for repository / provenance / integrity questions.

### Install the MCP SDK (once)

```bash
pip install mcp
```

Optional tokens (never commit real values):

```text
GITHUB_TOKEN
GITHUB_API_VERSION
HF_TOKEN
HUGGINGFACE_TOKEN
```

### Claude Desktop config example

Keep your existing `command` / `args` paths. Only add env vars if needed:

```json
{
  "mcpServers": {
    "aibom-guard": {
      "command": "python",
      "args": ["C:/path/to/aibom_guard/mcp_server.py"],
      "env": {
        "GITHUB_TOKEN": "<your-token>",
        "HF_TOKEN": "<your-token>"
      }
    }
  }
}
```

Start the server manually to confirm imports:

```bash
python mcp_server.py
```

stdio MCP servers wait for client input — that idle state is normal.

### Manual Claude Desktop prompts

```text
Flask GitHub 저장소의 신뢰도를 분석해줘.
OpenSSF 점수, 최근 커밋, revision 고정 여부,
서명과 provenance 상태를 함께 알려줘.
```

```text
requests==2.31.0의 공급망 신뢰도를 검사해줘.
CVE뿐 아니라 PyPI 공개 해시, GitHub 저장소,
OpenSSF 점수, 버전 고정 여부도 확인해줘.
```

```text
https://huggingface.co/datasets/namespace/name
데이터셋의 라이선스, 출처, 수집 방법 기재 여부를 검사해줘.
```

```text
target_type을 github로 지정해서 pallets/flask를 검사해줘.
```

`owner/repo` shorthand can mean either GitHub or Hugging Face.
Say the platform explicitly (or set `target_type`) so the tool is not ambiguous.

`local_file` paths are resolved on the machine running the MCP server,
not on a remote chat client's filesystem.

### Repository trust CLI (without MCP)

```bash
python repository_checker.py https://github.com/pallets/flask --json
python repository_checker.py requests==2.31.0
```

## Trust Score (④ `score_engine.py`)

`score_engine.calculate_trust_score()` is the single place that turns evidence
into a number. Modules ①-③ collect findings; only ④ scores them, so
`check_package` and `check_repo_trust` cannot drift apart.

Seven weighted categories, matching the `issues[].type` values of the team
Data Protocol:

| Category | Weight | |
|---|---|---|
| `malicious` | 30 | confirmed malicious code |
| `cve` | 25 | published vulnerabilities |
| `license` | 15 | legal blocker (Article 8) |
| `typosquatting` | 10 | name-confusion attack |
| `hallucination` | 8 | package/model does not exist |
| `provenance` | 7 | origin unverifiable |
| `pii` | 5 | sensitive data exposure |

Verdict thresholds mirror `repository_checker.calculate_trust_score()`:
`>= 80` ALLOW, `< 50` BLOCK, otherwise CONDITIONAL. A `critical` finding,
confirmed malicious code, or a `BLOCKED` license is a **hard block** regardless
of the score. A low `confidence` (evidence missing) yields CONDITIONAL rather
than a guess in either direction.

```bash
python score_engine.py                       # smoke test with sample inputs
python -m pytest test_score_engine.py -q     # 34 unit tests
```

## Current status / limitations

- Only supports `package==version` pinned entries in `requirements.txt`
- License check reads the license of the *currently installed* version,
  which may not exactly match the version pinned in `requirements.txt`
- `score_engine` weights and thresholds are a team calibration, not a
  standard; `test_score_engine.py` pins them so a change is visible in review
- AI explanations via Ollama are optional and require a local model
- Cosign verification in `repository_checker.py` needs a local `cosign` binary
- ① `model_checker.py` (AI model collection) is not yet merged, so
  `model_info` reaches `score_engine` as `None`

## Roadmap

- [x] Ollama 로컬 모델로 결과 설명 (`ai_explainer.py`)
- [x] MCP 서버 노출 (`mcp_server.py`)
- [x] ② 저장소·공급망 검증 (`repository_checker.py`)
- [x] ③ 위험 탐지·대안 추천 (`recommendation.py` + CVSS 파싱 수정)
- [x] ④ Trust Score 엔진 (`score_engine.py`) — scanner·MCP 통합 완료
- [ ] ① AI 모델 정보 수집 (`model_checker.py`)
- [ ] ⑤ AIBOM / ML-BOM 생성 (`sbom_generator.py` 확장)
