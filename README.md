# AIBOM-Guard

Python 패키지와 Hugging Face 모델의 보안·라이선스·공급망 위험을 검사하고
결과를 CycloneDX SBOM으로 출력합니다.

---

## 설치

Python 3.10 이상이 필요합니다.

```bash
git clone https://github.com/Letmeloveyou522/aibom_guard.git
cd aibom_guard
git checkout dev

python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux

pip install -r requirements.txt
```

설치 확인:

```bash
pytest
```

`pytest`가 전부 통과하면 정상입니다. 이 테스트는 네트워크를 쓰지 않습니다.

### 선택 사항

| 항목 | 필요한 경우 |
|---|---|
| `GITHUB_TOKEN` | `--supply-chain` 사용 시. 없으면 GitHub API rate limit에 걸립니다 |
| `HF_TOKEN` | Llama처럼 gated 모델을 검사할 때. Hub에서 라이선스 동의도 필요합니다 |
| Ollama | 결과를 로컬 LLM으로 설명받을 때. 없으면 경고만 뜨고 스캔은 정상 종료됩니다 |
| `cosign` | 서명 검증까지 할 때 |

---

## 실행

```bash
python scanner.py examples/sample-requirements.txt
```

`examples/sample-requirements.txt`는 검사 대상 예시이며 취약한 버전이
고정되어 있습니다. `pip install -r` 대상이 아닙니다. 자기 프로젝트를
검사하려면 그 프로젝트의 `requirements.txt` 경로를 넘기면 됩니다.

AI 모델까지 함께 검사:

```bash
python scanner.py examples/sample-requirements.txt \
    --model CompVis/stable-diffusion-v1-4
```

| 옵션 | 설명 |
|---|---|
| `--model REF` | HF 모델 포함. 반복 지정 가능. SBOM이 ML-BOM이 됩니다 |
| `--supply-chain` | 저장소 신뢰도 검사. 패키지마다 네트워크 왕복이 있어 느립니다 |
| `--model-pickle-scan MB` | 모델 pickle 내부 검사. 기본 0(미실행) |
| `--offline` | 네트워크 미사용. 라이선스만 검사합니다 |
| `--no-explain` | Ollama 설명 생략 |
| `--json PATH` / `--sbom PATH` | 출력 경로 지정 |

종료 코드는 `0` 전부 ALLOW, `1` 입력 오류, `2` BLOCK 존재입니다. CI에서
`python scanner.py requirements.txt` 한 줄로 게이트를 걸 수 있습니다.

---

## 출력 읽는 법

### 패키지 요약표

```
+----------+---------+----------------+-------+-------------+---------+
| Package  | Version | License Status | Vulns | Trust Score | Verdict |
+----------+---------+----------------+-------+-------------+---------+
| requests |  2.28.0 |    ALLOWED     |   4   |      75     | WARNING |
|  numpy   |  1.24.0 |    ALLOWED     |   0   |     100     |  ALLOW  |
|  pyyaml  |  5.3.1  |    ALLOWED     |   1   |      49     |  BLOCK  |
+----------+---------+----------------+-------+-------------+---------+
```

| 열 | 의미 |
|---|---|
| License Status | `ALLOWED` OSI 승인 / `REVIEW` 카피레프트·조건부 / `BLOCKED` 사용 제한 / `UNKNOWN` 식별 실패 |
| Vulns | OSV 취약점 수. GHSA·PYSEC·CVE 별칭은 하나로 합산 |
| Trust Score | 0~100. 100에서 항목별 가중 감점 |
| Verdict | `ALLOW` / `WARNING` / `BLOCK` |

`UNKNOWN`은 "안전"이 아니라 "식별하지 못함"입니다. 감점 대상입니다.

### 상세

```
- requests==2.28.0 (WARNING, score 75)
    Vuln GHSA-9hjg-9r4m-mvj7 (severity medium, CVSS 5.3, aka PYSEC-2026-1872):
        Requests vulnerable to .netrc credentials leak via malicious URLs
    -> suggested: requests==2.34.2 (confirmed) - Upgrade to latest safe release

- pyyaml==5.3.1 (BLOCK, score 49)
    [HARD BLOCK] Critical severity cve finding: GHSA-8q59-q68h-6hv4
```

- `aka PYSEC-...` — 같은 취약점의 다른 데이터베이스 ID. 중복 계산하지 않습니다.
- `-> suggested` — 권장 조치. `confirmed`는 확실한 조치(버전 상향, 오타 교정),
  `suggested`는 검토가 필요한 대안입니다.
- `[HARD BLOCK]` — 점수와 무관하게 차단. critical 취약점, 악성코드, 차단
  라이선스 세 가지입니다.
- `[unverified]` — 검사하지 못한 항목. 크기 제한으로 건너뛴 pickle, 네트워크
  실패, gated 모델 접근 불가 등이 여기 들어갑니다.

### AI 모델

```
| Model                         | License               | Family         | Weights              | Remote code | Card   | Score | Verdict |
| CompVis/stable-diffusion-v1-4 | creativeml-openrail-m | ai-behavioural | safetensors + pickle | no          | 60/100 | 49    | BLOCK   |
```

| 열 | 의미 |
|---|---|
| Family | `permissive` OSI 승인 / `copyleft` GPL 계열 / `ai-community` Llama·Gemma 등 조건부 / `ai-behavioural` OpenRAIL 등 용도 제한 |
| Weights | `safetensors` 안전 / `safetensors + pickle` 둘 다 존재 / `PICKLE ONLY` pickle만 존재 |
| Remote code | `YES`면 로딩 시 저장소의 파이썬 코드가 실행됩니다 |
| Card | Model Card 완성도 0~100 |

`ai-behavioural`은 특정 용도를 금지하는 조항이 있어 OSI 오픈소스가 아닙니다.
`BLOCKED`으로 판정됩니다. `ai-community`는 사용 가능하지만 조건이 붙으므로
`REVIEW`입니다.

`PICKLE ONLY`는 `.safetensors` 대체 파일이 없다는 뜻입니다. pickle은
`torch.load()`가 내부 코드를 실행하므로 모델을 불러오는 것만으로 임의 코드
실행이 됩니다. 같은 디렉터리에 대체 파일이 있으면 로더를 그쪽으로 돌릴 수
있으므로 위험도를 낮춥니다.

### 판정 기준

점수는 7개 항목 가중 감점입니다.

| 항목 | 가중치 | |
|---|---|---|
| malicious | 30 | 악성 코드 확인 |
| cve | 25 | 공표된 취약점 |
| license | 15 | 법적 차단 사유 |
| typosquatting | 10 | 이름 혼동 공격 |
| hallucination | 8 | 존재하지 않는 패키지·모델 |
| provenance | 7 | 출처 검증 불가 |
| pii | 5 | 민감정보 노출 |

80 이상 `ALLOW`, 50 미만 `BLOCK`, 나머지 `WARNING`입니다.

**검사하지 못한 항목은 통과 처리하지 않습니다.** 증거가 부족하면 confidence가
낮아져 `ALLOW`도 `BLOCK`도 아닌 `WARNING`이 됩니다. 무엇을 못 봤는지는
`unverified` 이슈로 기록됩니다.

가중치와 임계값은 팀 기준값이며 `tests/test_score_engine.py`가 고정합니다.

### 생성 파일

| 파일 | 내용 |
|---|---|
| `scan_report.json` | 전체 결과. 점수 내역(`score_breakdown`)과 confidence 포함 |
| `sbom.json` | CycloneDX SBOM. `--model` 사용 시 ML-BOM |

둘 다 실행할 때마다 새로 생성되므로 git에 추적하지 않습니다. 고정 사본이
[examples/scan_report.sample.json](examples/scan_report.sample.json)과
[examples/sbom.sample.json](examples/sbom.sample.json)에 있습니다.

---

## 검사 항목

### 패키지

| 항목 | 내용 |
|---|---|
| 취약점 | OSV 조회, CVSS 벡터 파싱, 별칭 중복 제거 |
| 라이선스 | OSI 승인 여부 분류. 라이선스 전문과 PyPI 분류자 문자열 모두 지원 |
| 타이포스쿼팅 | 유명 패키지와의 편집 거리 비교 |
| 환각 패키지 | PyPI에 없는 이름. 미등록 이름은 제3자가 선점 가능 |
| 폐기 | yanked 릴리스, 장기 미관리 |
| 대안 추천 | 안전한 상위 버전, 오타 교정 |

### AI 모델

| 항목 | 내용 |
|---|---|
| 가중치 형식 | pickle 대 safetensors. 샤드 단위로 대체 파일 대조 |
| pickle 내부 | picklescan으로 위험 global 탐지 |
| 원격 코드 | `trust_remote_code`, `auto_map`. `owner/repo--module.Class`는 외부 저장소 코드 로드 |
| 라이선스 | OpenRAIL 계열 `BLOCKED`, Llama·Gemma 등 `REVIEW` |
| Model Card | 존재 여부 + 완성도. HF 기본 템플릿(`[More Information Needed]`) 감지 |
| 출처 | commit SHA, base model, 학습 데이터셋, gated 여부 |

모든 모델 파일은 commit SHA로 고정해 받습니다. 브랜치는 검사 도중에도 움직일
수 있으므로, 보고서가 기술하는 파일과 실제 검사한 파일이 같아야 합니다.

---

## 구조

```
① model_checker ──┐
② repository_checker ┼──> ④ score_engine ──> ⑤ sbom_generator / mcp_server
③ recommendation ──┘
```

①②③은 증거만 수집하고 점수를 매기지 않습니다. 판정은 ④가 전담하므로
CLI와 MCP의 결과가 일치합니다.

```
scanner.py              CLI 진입점
mcp_server.py           MCP 진입점
model_checker.py        HF 모델 정보 수집                    ①
repository_checker.py   GitHub / HF / PyPI 공급망 신뢰도      ②
osv_client.py           OSV CVE 조회 + CVSS 파싱             ③
recommendation.py       위험 탐지 + 대안 추천                 ③
score_engine.py         Trust Score / 최종 판정              ④
sbom_generator.py       CycloneDX SBOM / ML-BOM              ⑤
license_checker.py      라이선스 분류
ai_explainer.py         Ollama 로컬 모델 설명
examples/               예시 입력, 데모, 출력 샘플
tests/                  단위 테스트
```

개별 모듈만 실행할 수도 있습니다.

```bash
python model_checker.py https://huggingface.co/google-bert/bert-base-uncased
python repository_checker.py https://github.com/pallets/flask --json
python license_checker.py
python score_engine.py
python examples/demo_module3.py reqeusts==1.0.0
```

`model_checker.py`를 단독 실행하면 512MB 이하의 pickle 파일을 **내려받아
검사합니다**. 모델 크기에 따라 수 분이 걸립니다. 메타데이터만 보려면
`--max-pickle-size-mb 0`을 붙입니다. `scanner.py --model`은 반대로 기본이
0이며, `--model-pickle-scan MB`로 켭니다.

---

## MCP

`mcp_server.py`는 stdio MCP로 **네 가지** 도구를 노출합니다. CLI
`scanner.py`와 달리 requirements.txt 일괄 스캔·`scan_report.json` /
`sbom.json` 파일 출력·Ollama 설명은 하지 않습니다. 한 건씩 JSON으로
돌려줍니다.

| 도구 | 역할 | CLI 대응 |
|---|---|---|
| `check_package` | OSV CVE + 라이선스 + Trust Score. OSV 실패 시 `vulnerabilities: null`, `osv_unverified: true`, WARNING | `scanner.py` 패키지 행 |
| `check_license` | 라이선스 문자열 분류 (ALLOWED/REVIEW/BLOCKED/UNKNOWN) | `license_checker` |
| `check_repo_trust` | GitHub 활동, OpenSSF, 서명, provenance, HF 데이터셋 문서 | `--supply-chain` |
| `check_model` | HF 모델 스캔. 반환값은 `scan_report.json`의 `models[]` 항목과 동일 스키마 | `--model REF` |

### CLI vs MCP 스코프

| | `scanner.py` (CLI) | `mcp_server.py` (MCP) |
|---|---|---|
| 입력 | `requirements.txt` + `--model` 반복 | 도구별 단일 대상 |
| 출력 | 터미널 + `scan_report.json` + CycloneDX/`ML-BOM` | 도구 반환 JSON만 |
| OSV 실패 | `vulnerabilities: null`, confidence↓, WARNING | `check_package`와 동일 계약 |
| 모델 | `--model` → `models[]` + SBOM `machine-learning-model` | `check_model` → 동일 `models[]` 필드 |

`scan_report.json` 스키마:

```json
{
  "packages": [ { "package", "version", "license_status", "vulnerabilities", "verdict", "..." } ],
  "models":   [ { "model_id", "license_status", "verdict", "risk_score", "issues", "model_card", "..." } ],
  "unscanned": [ "name>=1.0 처럼 == 가 아닌 줄" ]
}
```

Claude Desktop 설정:

```json
{
  "mcpServers": {
    "aibom-guard": {
      "command": "python",
      "args": ["C:/path/to/aibom_guard/mcp_server.py"],
      "env": { "GITHUB_TOKEN": "...", "HF_TOKEN": "..." }
    }
  }
}
```

토큰은 선택 사항입니다. 실제 값은 커밋하지 마십시오. 서버를 직접 실행하면
입력 대기 상태로 유지되는데, stdio MCP의 정상 동작입니다.

---

## 테스트

```bash
pytest                            # 전체 단위 테스트
pytest tests/test_scanner.py -v   # 파일 단위, 테스트 이름까지 출력
pytest -k license                 # 이름으로 필터
```

네트워크 없이 3초 내에 끝납니다. `pyproject.toml`이 경로를 설정하므로 저장소
어디에서 실행해도 동작합니다.

---

## 현재 상태

구현 완료: 패키지 CVE·라이선스·타이포스쿼팅·환각 탐지, AI 모델 스캔,
공급망 검사, Trust Score, SBOM / ML-BOM 생성, MCP 도구 4종
(`check_package`, `check_license`, `check_repo_trust`, `check_model`),
Ollama 설명.

미완 및 제약:

- **`LICENSE` 파일 없음.** 제출 전 추가 필요. 팀 합의 대기.
- 라이선스 판정은 설치된 버전의 메타데이터 기준이므로 `requirements.txt`에
  고정한 버전과 다를 수 있음.
- `requirements.txt`는 `package==version` 형식만 지원. 그 외 줄은
  `unscanned`에 기록됩니다.
- 모델 pickle 내부 검사는 기본 비활성. 미검사 파일은 `unverified`로 보고.
- picklescan은 알려진 위험 패턴만 탐지. 탐지 없음이 안전을 보장하지 않음.
- gated 모델은 `HF_TOKEN`과 Hub 라이선스 동의 필요.
- cosign 검증은 로컬 `cosign` 바이너리 필요.
- OSV/네트워크 실패 시 CVE를 0건으로 보지 않습니다. `vulnerabilities`는
  `null`이고 verdict는 WARNING입니다.

---

## 의존성

`requests`, `prettytable`, `cyclonedx-bom`, `mcp`, `huggingface_hub`,
`picklescan`. 전체 목록과 라이선스는 [DEPENDENCIES.md](DEPENDENCIES.md).

`mcp`는 `==1.28.1` 고정입니다. 2.x에서 `mcp.server.fastmcp`가 제거되어 최신
버전 설치 시 서버가 기동하지 않습니다.
