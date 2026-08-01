# AIBOM-Guard

**Python 패키지와 AI 모델의 보안·라이선스·공급망 위험을 한 번에 검사하고,
CycloneDX SBOM / ML-BOM으로 문서화하는 도구입니다.**

```bash
pip install -r requirements.txt
python scanner.py examples/sample-requirements.txt --model meta-llama/Llama-3.1-8B
```

---

## 왜 필요한가

요즘 소프트웨어는 오픈소스 패키지 **위에** AI 모델까지 얹어서 만듭니다.
그런데 이 둘은 위험의 성격이 다릅니다.

**패키지 쪽에서 생기는 문제**

- 알려진 취약점(CVE)이 있는 옛 버전을 그대로 쓰고 있음
- LLM이 지어낸 **존재하지 않는 패키지명**을 그대로 설치 — 그 이름은 아직
  아무도 선점하지 않았으므로, 누구나 등록해서 코드를 실행시킬 수 있습니다
- `requests`를 `reqeusts`로 쓴 **오타 패키지(typosquatting)**
- 상업적 사용을 제한하는 라이선스

**AI 모델 쪽에서 생기는 문제**

- **가중치 파일 형식.** `.bin`/`.pt`/`.ckpt`는 파이썬 pickle이고,
  `torch.load()`는 그 안의 코드를 **그대로 실행**합니다. 모델을 불러오는 것만으로
  임의 코드 실행이 됩니다
- **`trust_remote_code=True`.** `from_pretrained()`가 저장소에 들어있는
  파이썬 파일을 import합니다. 가중치를 읽기도 전에 코드가 돕니다
- **라이선스.** 오픈웨이트 모델 라이선스는 대부분 **OSI 승인이 아닙니다.**
  Llama·Gemma는 조건부이고, OpenRAIL 계열은 특정 용도를 아예 금지합니다.
  일반 패키지 검사 도구는 이런 라이선스를 본 적이 없어 그냥 통과시킵니다
- **출처.** 어떤 데이터로 학습했는지, 어떤 모델에서 파생됐는지 기록이 없음

AIBOM-Guard는 이 둘을 **하나의 파이프라인**에서 검사하고, 결과를 표준
포맷(CycloneDX)으로 남깁니다.

---

## 5분 안에 돌려보기

```bash
# 1. 설치
pip install -r requirements.txt

# 2. 패키지 스캔
python scanner.py examples/sample-requirements.txt
```

```
+----------+---------+----------------+-------+-------------+-------------+
| Package  | Version | License Status | Vulns | Trust Score |   Verdict   |
+----------+---------+----------------+-------+-------------+-------------+
| requests |  2.28.0 |    ALLOWED     |   4   |      75     | CONDITIONAL |
|  numpy   |  1.24.0 |    ALLOWED     |   0   |     100     |    ALLOW    |
|  pyyaml  |  5.3.1  |    ALLOWED     |   1   |      49     |    BLOCK    |
+----------+---------+----------------+-------+-------------+-------------+

[Packages needing attention]
- pyyaml==5.3.1 (BLOCK, score 49)
    [HARD BLOCK] Critical severity cve finding: GHSA-8q59-q68h-6hv4
    Vuln GHSA-8q59-q68h-6hv4 (severity critical, CVSS 9.8, aka PYSEC-2021-142):
        Improper Input Validation in PyYAML
    -> suggested: PyYAML==6.0.3 (confirmed) - Upgrade to latest safe release
```

```bash
# 3. AI 모델까지 포함 (SBOM이 ML-BOM이 됩니다)
python scanner.py examples/sample-requirements.txt \
    --model CompVis/stable-diffusion-v1-4 \
    --model TinyLlama/TinyLlama-1.1B-Chat-v1.0
```

```
===== AI Models =====
+------------------------------------+-----------------------+----------------+----------------------+-------------+--------+-------+---------+
|               Model                |        License        |     Family     |       Weights        | Remote code |  Card  | Score | Verdict |
+------------------------------------+-----------------------+----------------+----------------------+-------------+--------+-------+---------+
|   CompVis/stable-diffusion-v1-4    | creativeml-openrail-m | ai-behavioural | safetensors + pickle |      no     | 60/100 |   49  |  BLOCK  |
| TinyLlama/TinyLlama-1.1B-Chat-v1.0 |       apache-2.0      |   permissive   |     safetensors      |      no     | 85/100 |   99  |  ALLOW  |
+------------------------------------+-----------------------+----------------+----------------------+-------------+--------+-------+---------+
```

> `examples/sample-requirements.txt`는 **스캔 대상 예시**입니다. 일부러 취약한
> 버전을 고정해 둔 파일이니 `pip install -r` 하지 마세요. 프로젝트 자체
> 의존성은 `requirements.txt`에 있습니다.

### CLI 옵션

| 옵션 | 설명 |
|---|---|
| `--model REF` | Hugging Face 모델을 AIBOM에 포함 (반복 가능) |
| `--supply-chain` | 저장소·공급망 신뢰도까지 검사 (느림, `GITHUB_TOKEN` 권장) |
| `--model-pickle-scan MB` | 모델 가중치를 내려받아 pickle 내부까지 검사 (기본 0 = 안 함) |
| `--offline` | 네트워크 없이 실행 |
| `--no-explain` | Ollama 설명 생략 |
| `--json PATH` / `--sbom PATH` | 출력 경로 지정 |

**종료 코드:** `0` 전부 ALLOW · `1` 입력 오류 · `2` BLOCK 존재
→ CI 파이프라인 게이트로 그대로 쓸 수 있습니다.

---

## 판정 읽는 법

| 판정 | 뜻 |
|---|---|
| `ALLOW` | 문제 없음 |
| `CONDITIONAL` | 쓸 수는 있지만 사람이 확인해야 함. **검사를 못 한 경우도 여기** |
| `BLOCK` | 쓰면 안 됨 |

**중요한 설계 원칙 하나:** *검사하지 못한 것을 통과로 만들지 않습니다.*

pickle 파일이 너무 커서 건너뛰었거나, 네트워크가 끊겼거나, gated 모델이라
접근을 못 했다면 결과는 `ALLOW`가 아니라 `CONDITIONAL`이고, 무엇을 못 봤는지
`unverified` 항목으로 명시됩니다. "발견된 문제가 없다"와 "보지 못했다"는
전혀 다른 이야기이기 때문입니다.

---

## 구조

```
① model_checker ──┐
② repository_checker ┼──> ④ score_engine ──> ⑤ sbom_generator / mcp_server
③ recommendation ──┘     (Trust Score)         (SBOM · ML-BOM · MCP)
```

①②③은 **증거를 수집만** 합니다. 점수와 판정은 ④ `score_engine`이 전담하므로,
CLI와 MCP가 서로 다른 답을 내놓을 수 없습니다.

```
aibom_guard/
├─ README.md
├─ DEPENDENCIES.md            # 사용 OSS 목록 (Article 8)
├─ requirements.txt           # 이 프로젝트의 의존성 (pip install -r)
├─ pyproject.toml             # 프로젝트 메타 + pytest 설정
│
├─ scanner.py                 # CLI 진입점 (패키지 + AI 모델)
├─ mcp_server.py              # MCP 진입점 (Claude Desktop / Cursor)
│
├─ model_checker.py           # Hugging Face AI 모델 정보 수집      ← ①
├─ repository_checker.py      # GitHub / HF / PyPI 공급망 신뢰도    ← ②
├─ osv_client.py              # OSV CVE 조회 + CVSS 파싱            ← ③
├─ recommendation.py          # 위험 탐지 + 대안 추천               ← ③
├─ score_engine.py            # Trust Score / 최종 판정             ← ④
├─ sbom_generator.py          # CycloneDX SBOM / ML-BOM 생성        ← ⑤
├─ license_checker.py         # 라이선스 분류 (SW + AI 모델)
├─ ai_explainer.py            # Ollama 로컬 모델 설명
│
├─ examples/
│  ├─ sample-requirements.txt      # 스캔 예시 입력 (설치 금지)
│  ├─ demo_module3.py              # ③ 데모 CLI
│  ├─ scan_report.sample.json      # 실행 결과 예시
│  └─ sbom.sample.json             # 생성된 SBOM 예시
│
└─ tests/                     # 단위 테스트 379개
```

> 스캔 결과물(`scan_report.json` / `sbom.json`)은 실행할 때마다 새로 생기므로
> `.gitignore` 대상입니다. 문서용 고정 사본이 `examples/*.sample.json` 입니다.

---

## ① AI 모델 검사 — `model_checker.py`

```bash
python model_checker.py https://huggingface.co/google-bert/bert-base-uncased
python model_checker.py org/model --max-pickle-size-mb 512   # pickle 내부까지
```

무엇을 보는가:

- **가중치 포맷** — safetensors vs pickle. 같은 이름의 safetensors가 **함께
  있으면** 위험도를 낮춥니다(로더를 안전한 쪽으로 돌리면 되므로). 샤드 단위로
  매칭하며, 일부만 변환된 저장소는 변환 안 된 샤드를 HIGH로 남깁니다.
  safetensors가 아예 없으면 `PICKLE ONLY`
- **pickle 내부 opcode** — `picklescan`으로 위험한 global(`os.system`, `eval` 등) 탐지
- **`trust_remote_code` / `auto_map`** — 로딩 시 저장소 코드가 실행되는지.
  `owner/repo--module.Class` 형태면 **다른 저장소**에서 코드를 가져오는 것이라
  따로 표시합니다 (출처·라이선스·리비전이 전부 다름)
- **Model Card 완성도** — 존재 여부가 아니라 0~100점. HF에서 카드를 만들면
  전 항목이 `[More Information Needed]`인 템플릿이 자동 생성되는데, 그걸 그대로
  올린 저장소가 많아서 "카드 있음"은 신호가 되지 못합니다
- **출처** — commit SHA, base model(+파생 관계), 학습 데이터셋, gated 여부

모든 파일은 **commit SHA로 고정**해서 받습니다. 브랜치는 스캔 도중에도 움직일 수
있으므로, 그래야 보고서가 설명하는 파일과 실제로 검사한 파일이 같습니다.

### AI 라이선스 판정 (Article 8)

| 계열 | 예시 | 판정 | 이유 |
|---|---|---|---|
| `ai-behavioural` | OpenRAIL-M, CreativeML, BLOOM RAIL | **BLOCKED** | 특정 용도를 금지 → OSI 오픈소스가 아님 |
| `ai-community` | Llama 3.x, Gemma, Qwen, DeepSeek | **REVIEW** | 사용 가능하나 조건부(MAU 상한·명시 의무·별도 AUP) |
| `permissive` | Apache-2.0 / MIT 모델 | `ALLOWED` | OSI 승인 |
| `copyleft` | GPL, LGPL, MPL | `REVIEW` | 파생물 의무 확인 필요 |

같은 `REVIEW`라도 **왜**인지 구분됩니다. "GPL이라서"와 "Llama 커뮤니티
라이선스라서"는 리뷰어에게 완전히 다른 이야기이기 때문입니다.

---

## ② 공급망 신뢰도 — `repository_checker.py`

GitHub 활동 이력, OpenSSF Scorecard, revision 고정 여부, 아티팩트 SHA-256,
서명·provenance, Hugging Face 데이터셋 문서화 여부를 검사합니다.

```bash
python repository_checker.py https://github.com/pallets/flask --json
python repository_checker.py requests==2.31.0
python scanner.py reqs.txt --supply-chain     # 스캔에 통합
```

---

## ③ 위험 탐지 & 대안 추천 — `recommendation.py`

CVE 외에 **오타 패키지·환각 패키지·방치된 패키지**를 탐지하고 대안을 제시합니다.

```
- reqeusts==2.28.0 (CONDITIONAL, score 81)
    [hallucination] Package 'reqeusts' does not exist on PyPI
    [typosquatting] Package 'reqeusts' is similar to official package 'requests'
    -> suggested: requests (confirmed) - Correct typosquat 'reqeusts' -> 'requests'
```

### 팀 Data Protocol

①②③이 ④에 넘기는 공통 형식입니다.

```json
{
  "issues": [
    {"type": "cve", "id": "GHSA-xxxx", "severity": "high",
     "cvss_score": 8.1, "detail": "..."},
    {"type": "typosquatting", "detail": "'reqeusts' is similar to 'requests'"}
  ],
  "alternatives": [
    {"target": "requests==2.34.2", "confidence": "confirmed",
     "reason": "Upgrade to latest safe release"}
  ]
}
```

- `issues[].type` — `cve` · `hallucination` · `typosquatting` · `malicious` ·
  `pii` · `license` · `provenance` (7종)
- `alternatives[].confidence` — `confirmed`(버전업·오타교정) / `suggested`(대체 모델 등)

```bash
python examples/demo_module3.py                    # 데모
python examples/demo_module3.py reqeusts==1.0.0    # 개별 케이스
```

---

## ④ Trust Score — `score_engine.py`

증거를 점수로 바꾸는 **유일한** 지점입니다.

7개 카테고리 가중 감점(합계 100), 위 Data Protocol의 `issues[].type`과 1:1 대응:

| 카테고리 | 가중치 | |
|---|---|---|
| `malicious` | 30 | 악성 코드 확인 |
| `cve` | 25 | 공표된 취약점 |
| `license` | 15 | 법적 차단 사유 |
| `typosquatting` | 10 | 이름 혼동 공격 |
| `hallucination` | 8 | 존재하지 않는 패키지/모델 |
| `provenance` | 7 | 출처 검증 불가 |
| `pii` | 5 | 민감정보 노출 |

**판정 기준:** `80 이상` ALLOW · `50 미만` BLOCK · 나머지 CONDITIONAL

**즉시 차단(hard block):** critical 심각도 · 악성 코드 · BLOCKED 라이선스 —
점수와 무관하게 BLOCK입니다.

**confidence:** 증거가 부족하면 어느 쪽으로도 단정하지 않고 CONDITIONAL을
냅니다. 임계값은 `repository_checker`의 기존 판정 로직과 일치시켰으므로,
패키지 점수와 저장소 점수를 직접 비교할 수 있습니다.

```bash
python score_engine.py            # 샘플 입력 스모크 테스트
pytest tests/test_score_engine.py # 44개 단위 테스트
```

---

## ⑤ SBOM / ML-BOM — `sbom_generator.py`

`--model`을 쓰면 SBOM이 **ML-BOM**이 됩니다. CycloneDX 1.6의
`type: "machine-learning-model"` 컴포넌트와 `modelCard` 객체를 사용하므로,
CycloneDX를 이미 읽는 도구가 모델 인벤토리를 그대로 소비할 수 있습니다.

```json
{
  "type": "machine-learning-model",
  "bom-ref": "model:CompVis/stable-diffusion-v1-4@133a221b...",
  "purl": "pkg:huggingface/CompVis/stable-diffusion-v1-4@133a221b...",
  "licenses": [{"license": {"name": "creativeml-openrail-m"}}],
  "modelCard": {
    "modelParameters": {"task": "text-to-image", "architectureFamily": "diffusers"}
  },
  "properties": [
    {"name": "aibom-guard:verdict", "value": "BLOCK"},
    {"name": "aibom-guard:license_family", "value": "ai-behavioural"},
    {"name": "aibom-guard:pickle_only", "value": "false"}
  ]
}
```

> 모델 라이선스는 SPDX 식별자가 없으므로 `license.name`으로 넣습니다.
> `license.id`로 넣으면 스키마 검증에 실패합니다.

실제 출력 예시: [`examples/sbom.sample.json`](examples/sbom.sample.json)

---

## MCP 서버 (Claude Desktop / Cursor)

`mcp_server.py`가 stdio MCP로 도구를 노출합니다. AI 에이전트가 직접
"이 패키지 써도 돼?" 라고 물어볼 수 있습니다.

| 도구 | 역할 |
|---|---|
| `check_package` | OSV CVE 조회 + 라이선스 + Trust Score |
| `check_license` | 라이선스 문자열 분류 (ALLOWED / REVIEW / BLOCKED / UNKNOWN) |
| `check_repo_trust` | 공급망 신뢰도 (GitHub 활동, OpenSSF, 서명, provenance, HF 데이터셋 문서) |

취약점만 궁금하면 `check_package`, 저장소·출처·무결성 질문이면
`check_repo_trust`를 씁니다.

### 설정

```bash
pip install -r requirements.txt   # mcp==1.28.1 고정 설치
python mcp_server.py              # import 확인용. 입력 대기 상태가 정상입니다
```

Claude Desktop 설정 예시:

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

토큰은 선택 사항이며 **실제 값을 커밋하지 마세요.** 인식하는 환경변수:
`GITHUB_TOKEN` · `GITHUB_API_VERSION` · `HF_TOKEN` · `HUGGINGFACE_TOKEN`

### 프롬프트 예시

```text
Flask GitHub 저장소의 신뢰도를 분석해줘.
OpenSSF 점수, 최근 커밋, revision 고정 여부, 서명과 provenance 상태도 알려줘.
```

```text
requests==2.31.0의 공급망 신뢰도를 검사해줘.
CVE뿐 아니라 PyPI 공개 해시, GitHub 저장소, OpenSSF 점수, 버전 고정 여부도.
```

```text
https://huggingface.co/datasets/namespace/name
데이터셋의 라이선스, 출처, 수집 방법 기재 여부를 검사해줘.
```

> `owner/repo`만 쓰면 GitHub인지 Hugging Face인지 모호합니다. 플랫폼을
> 명시하거나 `target_type`을 지정하세요.
> `local_file` 경로는 **MCP 서버가 도는 machine** 기준으로 해석됩니다.

---

## 테스트

```bash
pip install -r requirements.txt
pytest                                # 379개 전부, 네트워크 불필요, 약 3초
pytest tests/test_scanner.py -v       # 특정 모듈만, 이름까지 출력
pytest -k "license"                   # 이름에 license 가 들어간 것만
```

`pyproject.toml`이 `testpaths`와 `pythonpath`를 설정하므로 저장소 어디에서
실행해도 동작합니다.

| 대상 | 테스트 |
|---|---|
| `license_checker.py` | 95 |
| `model_checker.py` | 85 |
| `repository_checker.py` + MCP | 56 |
| `score_engine.py` | 44 |
| `sbom_generator.py` | 33 |
| `scanner.py` | 28 |
| `recommendation.py` | 20 |
| `osv_client.py` | 18 |

---

## 알려진 한계

- `requirements.txt`는 `package==version` 형식만 지원합니다
- 패키지 라이선스는 **설치된 버전**의 메타데이터를 읽으므로, 핀으로 지정한
  버전과 다를 수 있습니다
- 모델 pickle 내부 검사는 기본 off입니다(`--model-pickle-scan MB`).
  가중치를 내려받아야 해서 대형 모델에서는 비쌉니다. 건너뛴 파일은 전부
  `unverified`로 보고됩니다
- gated 모델은 `HF_TOKEN`과 Hub에서의 라이선스 동의가 필요합니다.
  없으면 메타데이터는 대개 읽히지만 파일 검사는 못 합니다
- `score_engine`의 가중치·임계값은 **팀이 정한 값**이지 업계 표준이 아닙니다.
  `tests/test_score_engine.py`가 현재 값을 고정하고 있어 변경 시 리뷰에 드러납니다
- picklescan은 **알려진** 위험 global을 탐지합니다. 깨끗한 결과는 근거이지
  증명이 아닙니다
- `repository_checker.py`의 cosign 검증은 로컬에 `cosign` 바이너리가 필요합니다
- **이 저장소에는 아직 `LICENSE` 파일이 없습니다** (팀 합의 대기)
- MCP는 아직 모델 검사 도구를 노출하지 않습니다 (CLI만 지원)

---

## 로드맵

- [x] ① AI 모델 정보 수집 (`model_checker.py`) — scanner 통합 완료
- [x] ② 저장소·공급망 검증 (`repository_checker.py`)
- [x] ③ 위험 탐지·대안 추천 (`recommendation.py` + CVSS 파싱)
- [x] ④ Trust Score 엔진 (`score_engine.py`) — scanner·MCP 통합 완료
- [x] ⑤ ML-BOM 생성 (CycloneDX `machine-learning-model` + `modelCard`)
- [x] AI 라이선스 판정 (OpenRAIL / Llama / Gemma 계열)
- [x] MCP 서버 노출 (`mcp_server.py`)
- [x] Ollama 로컬 모델로 결과 설명 (`ai_explainer.py`)
- [ ] `LICENSE` 파일 추가 (팀 합의 대기)
- [ ] MCP에 모델 검사 도구 노출 (`check_model`)

---

## 사용한 오픈소스

`requests` · `prettytable` · `cyclonedx-bom` · `mcp` · `huggingface_hub` ·
`picklescan` — 전체 목록과 라이선스는 [DEPENDENCIES.md](DEPENDENCIES.md)에
있습니다.

> `mcp`는 `==1.28.1`로 고정되어 있습니다. mcp 2.x가
> `mcp.server.fastmcp`를 제거해서 `pip install mcp`로 최신 버전을 받으면
> MCP 서버가 뜨지 않습니다.
