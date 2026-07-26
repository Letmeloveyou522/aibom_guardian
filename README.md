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
├─ scanner.py            # CLI 메인 파이프라인
├─ osv_client.py         # OSV CVE 조회 + CVSS severity 파싱  ← ③
├─ recommendation.py     # 위험 탐지 + 대안 추천 엔진        ← ③
├─ test_module3.py       # ③ 모듈 통합 테스트                 ← ③
├─ license_checker.py    # 라이선스 분류
├─ sbom_generator.py     # CycloneDX SBOM 생성
├─ ai_explainer.py       # Ollama 로컬 모델 설명
├─ mcp_server.py         # MCP 서버 (check_package 등)
├─ requirements.txt      # 예시 스캔 입력
├─ DEPENDENCIES.md       # 본 프로젝트 사용 OSS 목록
└─ scan_report.json / sbom.json / _base_sbom.json
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

## MCP server

```bash
pip install mcp
python mcp_server.py
```

## Current status / limitations

- `requirements.txt`는 `package==version` 형식만 지원
- 라이선스 검사는 *설치된* 패키지 메타데이터 기준일 수 있음
- Trust Score는 CLI placeholder (④ `score_engine`으로 이관 예정)
- AI 모델/데이터셋 스캐너(①·②) 및 score_engine(④)은 팀 연동 대기

## Roadmap

- [x] Ollama 로컬 모델로 결과 설명 (`ai_explainer.py`)
- [x] MCP 서버 노출 (`mcp_server.py`)
- [x] ③ 위험 탐지·대안 추천 (`recommendation.py` + CVSS 수정)
- [ ] ① AI 모델 정보 수집 (`model_checker.py`)
- [ ] ② 저장소·공급망 검증 (`repository_checker.py`)
- [ ] ④ Trust Score 엔진 (`score_engine.py`)
- [ ] ⑤ AIBOM 생성 / scanner·MCP 통합
