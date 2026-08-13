# AIBOM-Guard

[![CI](https://github.com/Letmeloveyou522/aibom_guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Letmeloveyou522/aibom_guard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.6-brightgreen)](https://cyclonedx.org/)

Python 패키지와 Hugging Face 모델의 보안·라이선스·공급망 위험을 검사하고
결과를 CycloneDX SBOM으로 출력합니다.

English: [README.en.md](README.en.md) ·
기여: [CONTRIBUTING.md](CONTRIBUTING.md) ·
보안 제보: [SECURITY.md](SECURITY.md) ·
변경 이력: [CHANGELOG.md](CHANGELOG.md)

---

## 설치

Python 3.10 이상이 필요합니다.

```bash
git clone https://github.com/Letmeloveyou522/aibom_guard.git
cd aibom_guard

python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux

pip install -e .
```

`pip install -e .`가 의존성 설치와 `aibom-guard` 명령 등록을 함께 합니다.
소스를 수정할 생각이 없으면 `pip install .`이면 됩니다.

설치 확인:

```bash
pytest
```

`pytest`가 전부 통과하면 정상입니다. 이 테스트는 네트워크를 쓰지 않고
3초 안에 끝나며, 설치하지 않은 상태에서도 동작합니다
(`pyproject.toml`이 `src/`를 경로에 넣습니다).

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
aibom-guard examples/sample-requirements.txt
```

설치하지 않고 클론에서 바로 쓰려면 `python -m aibom_guard`도 같습니다.

`examples/sample-requirements.txt`는 검사 대상 예시이며 취약한 버전이
고정되어 있습니다. `pip install -r` 대상이 아닙니다. 자기 프로젝트를
검사하려면 그 프로젝트의 `requirements.txt` 경로를 넘기면 됩니다.

AI 모델까지 함께 검사:

```bash
aibom-guard examples/sample-requirements.txt \
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
| `--verbose` | 취약점을 전부 출력. 기본은 패키지당 심각도 상위 3건 |
| `--fail-on` | 종료 코드 기준. `warning`(기본) / `block` / `never` |

### 입력 형식

`==` 고정뿐 아니라 `>=`, `~=`, `<`, extras, 환경 마커를 읽습니다. 범위는
PyPI에서 **실제로 설치될 버전**으로 좁혀 검사하고, 리포트에 그 버전을 파일이
정했는지(`version_resolved: false`) 여기서 골랐는지(`true`) 기록합니다.

```
[INFO] Resolved requests>=2.32 -> requests==2.34.2
[Scanning] requests==2.34.2 ...  (resolved from >=2.32)
```

`-r`·`-c` 포함, URL/VCS 요구사항처럼 검사할 수 없는 줄은 `unscanned`에
남기고 보고합니다. 조용히 넘어가지 않습니다. `--offline`이면 범위를 좁힐 수
없으므로 그 줄도 `unscanned`가 됩니다.

### 종료 코드

| 코드 | 의미 |
|---|---|
| `0` | 전부 ALLOW이고 모든 줄을 검사함 |
| `1` | 입력 오류 (파일 없음, 인자 오류, 검사할 것 없음) |
| `2` | BLOCK 존재 |
| `3` | BLOCK은 없지만 WARNING이 있거나 검사 못 한 줄이 있음 |

인자 오류도 `1`입니다. argparse 기본값은 `2`인데 그러면 CI가 오타와 차단된
의존성을 구분할 수 없습니다.

`3`이 있는 이유가 있습니다. 이전에는 BLOCK만 실패로 봐서, OSV 조회 실패·
존재하지 않는 패키지·읽을 수 없는 라이선스·파싱 못 한 여섯 줄이 전부 `0`으로
통과했습니다. 아무것도 검사하지 않고 성공을 보고하는 게이트가 게이트 없는
것보다 나쁩니다.

BLOCK만으로 게이트를 걸려면 `--fail-on block`을 쓰면 됩니다.

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
| License Status | `ALLOWED` 관대 / `REVIEW` 의무가 따름 / `BLOCKED` 사용 제한 / `UNKNOWN` 식별 실패 |
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
| `sbom.json` | CycloneDX 1.6 SBOM. `--model` 사용 시 ML-BOM |

SBOM에는 해석한 SPDX 식별자가 표준 `licenses` 필드로 들어가고, 의무사항·
판정 근거는 `aibom-guard:` 프로퍼티로 붙습니다. 모델 컴포넌트는 가중치 파일의
SHA-256(`hashes`), 파생 관계(`pedigree.ancestors`), 최종 수정일을 함께 싣습니다.

G7 「SBOM for AI — Minimum Elements」 50개 항목 기준 커버리지는 **28개**이며,
Models 클러스터는 13/13입니다. 나머지는 Datasets·KPI·System Level처럼
모델 제작자만 알 수 있는 값이라 스캐너가 원리상 채울 수 없습니다.

둘 다 실행할 때마다 새로 생성되므로 git에 추적하지 않습니다. 고정 사본이
[examples/scan_report.sample.json](examples/scan_report.sample.json)과
[examples/sbom.sample.json](examples/sbom.sample.json)에 있습니다.

---

## 검사 항목

### 패키지

| 항목 | 내용 |
|---|---|
| 취약점 | OSV 조회, CVSS 벡터 파싱, 별칭 중복 제거 |
| 라이선스 | SPDX 식별 + 의무사항 안내. 아래 [라이선스 판정](#라이선스-판정) 참고 |
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

## 라이선스 판정

키워드로 추측하지 않고 두 공인 목록으로 식별합니다. 결과에 어느 목록이
근거였는지 함께 나옵니다.

| 목록 | 쓰임 |
|---|---|
| SPDX License List | 식별자 727개, `isOsiApproved` |
| Blue Oak Council License List | 관대함 등급 225개 |

`isOsiApproved` 하나로는 부족합니다. 이건 "제한적인가"가 아니라 "OSI에
신청해서 승인받았는가"라는 절차적 사실입니다. `CC0-1.0`, `BSD-Source-Code`,
`MIT-Festival`은 `false`이면서 관대합니다 — 아무도 신청하지 않았을 뿐입니다.
이 플래그만으로 차단하면 그런 161개가 통째로 막힙니다. Blue Oak이 그 부분을
채웁니다.

판정 순서:

| 조건 | 결과 |
|---|---|
| 문서화된 용도 제한 (비상업, Commons Clause, BUSL, SSPL) | `BLOCKED` |
| OpenRAIL 계열 / Llama·Gemma 계열 | `BLOCKED` / `REVIEW` |
| 카피레프트 | `REVIEW` |
| Blue Oak 등재 또는 OSI 승인 | `ALLOWED` |
| SPDX에 있으나 둘 다 아님 | `REVIEW` |
| 어디에도 없음 | `UNKNOWN` |

마지막 두 줄이 중요합니다. 증거가 없다는 이유로 차단하지 않습니다.

### 목록은 받아서 캐시합니다

첫 실행에 내려받아 `~/.cache/aibom-guard/registries`(Windows는
`%LOCALAPPDATA%\aibom-guard\registries`)에 둡니다. 이후에는 캐시를 쓰고,
30일이 지나면 갱신을 시도하되 실패하면 오래된 캐시를 그대로 씁니다.
`AIBOM_GUARD_CACHE`로 위치를 바꿀 수 있습니다.

저장소에 넣지 않았습니다. Blue Oak 약관은 JSON 파일에 자동으로 접근하는
것만 허용하고 재배포는 언급하지 않으며, SPDX 데이터 저장소도 목록 자체의
라이선스를 선언하지 않습니다. 남의 라이선스를 판정하는 도구가 조건을 말할
수 없는 파일을 담고 있을 수는 없습니다.

캐시가 없는 상태로 `--offline`이면 내장 규칙만 남습니다. 용도 제한과
카피레프트 계열은 그대로 잡히고 나머지는 `UNKNOWN`이 됩니다. 이 방향으로만
무너지며 `ALLOWED`가 되는 일은 없습니다.

### 의무를 함께 안내합니다

`REVIEW` 한 단어로는 할 일을 알 수 없고, AGPL과 MPL의 의무는 다릅니다.

```
mysqlclient==2.2.4   REVIEW   GPL-2.0-only
  why : GNU General Public License v2.0 only (GPL-2.0-only) is a copyleft license.
  todo: Strong copyleft. Distributing a work that links or embeds this requires
        releasing the complete corresponding source of the whole work under the
        GPL. Internal use without distribution triggers nothing.
  ref : https://spdx.org/licenses/GPL-2.0-only.html
```

### 버전은 지어내지 않습니다

`paramiko`는 `"LGPL"`이라고만 선언하지만 실제로는 LGPL-2.1입니다. 이걸
`LGPL-3.0-only`로 단정하면 틀린 의무를 안내하게 됩니다. 버전 없는 표기는
계열만 보고하고 버전은 미해결로 남깁니다.

```
LGPL   -> REVIEW  spdx=(unresolved)  "LGPL 계열이나 정확한 버전을 확정하지 못함"
LGPL-2.1 -> REVIEW  spdx=LGPL-2.1-only
```

### SPDX 표현식

`AND`가 `OR`보다 강하게 결합하고 괄호가 우선한다는 SPDX 규칙을 따릅니다.
`WITH`는 나누지 않습니다 — 예외를 왼쪽 라이선스와 함께 판정해야
`Apache-2.0 WITH Commons Clause`가 Apache로 통과하지 않습니다.

### 어느 버전의 라이선스를 읽는가

라이선스는 버전마다 바뀝니다. `chardet` 5.2.0은 LGPL-2.1, 7.5.1은 0BSD입니다.
설치된 사본을 읽으면 고정한 버전과 다른 조건을 보고하게 되고, 카피레프트
의무를 통째로 놓칩니다.

그래서 PyPI의 고정 버전 릴리스(`/pypi/<pkg>/<version>/json`)가 기준입니다.
설치 사본은 폴백이고, 폴백을 쓰면 표시합니다.

| `license_source` | 의미 |
|---|---|
| `pypi:license_expression` | PEP 639 SPDX 표현식 |
| `pypi:license` / `pypi:classifier` | 고정 버전의 메타데이터 |
| `installed:*` | 설치 사본. 버전이 다르면 `license_unverified: true` |
| `none` | 어디서도 못 읽음 |

`license_unverified`가 `true`면 `unverified` 이슈가 기록되고 confidence가
낮아집니다 — OSV 실패와 같은 계약입니다. 설치 사본은 버전이 고정 버전과
일치할 때만 검증된 것으로 봅니다.

필드가 여러 개면 순서대로 고르지 않고 SPDX id로 해석되는 쪽을 씁니다.
`psycopg2`는 `license`에 `"LGPL with exceptions"`, 분류자에 `"...v3 (LGPLv3)"`를
넣는데, 고정된 순서로 읽으면 해석 가능한 쪽을 버리게 됩니다.

`--offline`이면 PyPI를 조회하지 않고 설치 사본만 씁니다.

### 한계

Commons Clause는 SPDX 목록에도 예외 84개에도 없고, OpenRAIL·Llama 등 모델
라이선스도 SPDX id가 없습니다. 이 영역은 규칙 목록으로 처리하며 항목마다
제한 내용을 적었습니다.

---

## 구조

```
model_checker ──────┐
repository_checker ─┼──> score_engine ──> sbom_generator / mcp_server
recommendation ─────┘
```

수집 모듈은 증거만 모으고 점수를 매기지 않습니다. 판정은 `score_engine`이
전담하며, 두 진입점 모두 `_adapters.py` 한 곳을 거쳐 입력을 만들기 때문에
CLI와 MCP의 결과가 일치합니다. 그 동일성은 테스트가 고정합니다.

```
src/aibom_guard/
    scanner.py              CLI 진입점 (aibom-guard)
    mcp_server.py           MCP 진입점 (aibom-guard-mcp)
    _adapters.py            두 진입점 → score_engine 입력 (단일 사본)
    score_engine.py         Trust Score / 최종 판정   ← 유일한 채점자
    model_checker.py        HF 모델 정보 수집
    osv_client.py           OSV CVE 조회 + CVSS 파싱
    recommendation.py       위험 탐지 + 대안 추천
    license_checker.py      라이선스 분류
    sbom_generator.py       CycloneDX SBOM / ML-BOM
    ai_explainer.py         Ollama 로컬 모델 설명
    repository_checker/     공급망 신뢰도 — 대상별로 분할
        _constants.py         허용 호스트, API 루트, 임계값
        _http.py              SSRF 방어 + 이를 강제하는 클라이언트
        _targets.py           입력이 무엇을 가리키는지 판별
        _evidence.py          해시·서명·CODEOWNERS·GitHub URL 추출
        _datasets.py          데이터셋 카드 항목 충족도
        _scoring.py           저장소 신뢰 점수
        _github.py            GitHub 검사
        _huggingface.py       Hugging Face 검사
        _pypi.py              PyPI 검사
        _provenance.py        로컬 파일·서명·cosign
        _checker.py           RepositoryChecker (위 검사들을 조합)
        _api.py               check_repository()
examples/                   예시 입력, 데모, 출력 샘플
tests/                      단위 테스트
```

`repository_checker`는 원래 2,828줄짜리 단일 파일이었습니다. **계층이 아니라
검사 대상별로** 나눴는데, 실제로 일이 그렇게 갈리기 때문입니다 — GitHub
관리자 수를 세는 방식을 바꾸는 일은 Hugging Face나 PyPI 경로와 아무 상관이
없습니다. 바깥에서 보는 import 경로는 이전과 완전히 동일합니다.

개별 모듈만 실행할 수도 있습니다.

```bash
python -m aibom_guard.model_checker https://huggingface.co/google-bert/bert-base-uncased
python -m aibom_guard.repository_checker https://github.com/pallets/flask --json
python -m aibom_guard.license_checker
python -m aibom_guard.score_engine
python examples/demo_recommendation.py reqeusts==1.0.0
```

`model_checker`를 단독 실행하면 512MB 이하의 pickle 파일을 **내려받아
검사합니다**. 모델 크기에 따라 수 분이 걸립니다. 메타데이터만 보려면
`--max-pickle-size-mb 0`을 붙입니다. `aibom-guard --model`은 반대로 기본이
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
      "command": "aibom-guard-mcp",
      "env": { "GITHUB_TOKEN": "...", "HF_TOKEN": "..." }
    }
  }
}
```

`aibom-guard-mcp`가 PATH에 없으면(가상환경 안에만 설치한 경우 등) 인터프리터를
직접 지정합니다.

```json
{
  "command": "C:/path/to/.venv/Scripts/python.exe",
  "args": ["-m", "aibom_guard.mcp_server"]
}
```

`mcp_server.py` 파일 경로를 직접 넘기는 방식은 더 이상 동작하지 않습니다.
패키지 내부 모듈이라 상대 import를 쓰기 때문에 `-m`으로 실행해야 합니다.

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

- 라이선스는 PyPI의 고정 버전 릴리스에서 읽습니다. 조회 실패·오프라인 시
  설치 사본으로 폴백하며 `license_unverified`로 표시됩니다.
- 버전 범위는 오늘 PyPI에 있는 최신 버전으로 좁혀 검사합니다. 실제 설치
  시점이 다르면 다른 버전이 될 수 있고, 리포트의 `version_resolved`가 그
  구분을 남깁니다.
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

라이선스 판정에 쓰는 SPDX·Blue Oak 목록은 저장소에 넣지 않고 첫 실행에
받아서 캐시합니다. [라이선스 판정](#목록은-받아서-캐시합니다) 참고.

---

## 라이선스

Apache License 2.0. 전문은 [LICENSE](LICENSE).
