# 기여 가이드

AIBOM-Guardian에 기여해 주셔서 감사합니다. 이 문서는 개발 환경 준비부터
PR이 병합되기까지 필요한 것을 담고 있습니다.

버그 제보나 질문만 하실 거라면 [이슈](https://github.com/Letmeloveyou522/aibom_guardian/issues)를
열어 주시면 됩니다. 보안 취약점은 이슈가 아니라 [SECURITY.md](SECURITY.md)의
절차를 따라 주십시오.

---

## 개발 환경

Python 3.10 이상이 필요합니다.

```bash
git clone https://github.com/Letmeloveyou522/aibom_guardian.git
cd aibom_guardian

python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
```

확인:

```bash
pytest
```

전부 통과해야 정상입니다. 3초 안에 끝나고 **네트워크를 쓰지 않습니다.**

---

## 반드시 지켜야 할 것

프로젝트에는 깨면 도구의 존재 이유가 사라지는 규칙이 몇 개 있습니다.
대부분 테스트가 지키고 있지만, 왜 그런지 알고 계시는 편이 좋습니다.

### 1. 검사하지 못한 것을 통과시키지 않습니다

이 프로젝트에서 가장 중요한 규칙입니다.

```python
[]      # OSV가 응답했고, 알려진 취약점이 없음   → 검증된 안전
None    # OSV가 응답하지 않음                    → 알 수 없음
```

`None`을 `[]`로 바꾸는 코드는 **"아무도 검사하지 않은 패키지를 안전하다고
보고"**하게 만듭니다. [`src/aibom_guardian/_adapters.py`](src/aibom_guardian/_adapters.py)의
모듈 docstring에 OSV·라이선스 계약이 적혀 있습니다.

같은 이유로:

- 라이선스를 읽지 못했을 때 → `UNKNOWN` + `license_unverified`
- 모델 카드 PII 스캔이 돌지 않았을 때 → `pii_scan_unverified: true`
  (`security_classifiers.scan_text_for_pii`가 `None`을 반환)

`[]`/`false`는 “검사했고 깨끗함”, `null`/`None`/`true`는 “모름”입니다.

### 2. 점수는 `score_engine.py`만 매깁니다

`model_checker`, `repository_checker`, `recommendation`은 **증거만 수집**하고
판정하지 않습니다. 최종 점수와 ALLOW/WARNING/BLOCK은 `score_engine`이
전담합니다. CLI와 MCP가 같은 답을 내놓는 근거가 이것입니다.

두 진입점이 `score_engine`에 넘기는 입력은
[`_adapters.py`](src/aibom_guardian/_adapters.py) 한 곳에서 만듭니다. 복사해서
쓰지 마십시오 — 이전에 그렇게 했다가 두 사본이 갈라졌고, 지금은 테스트가
동일 객체인지 검사합니다.

### 3. 가중치와 임계값은 합의된 값입니다

6개 항목 가중치(malicious 28, cve 25, license 15, typosquatting 12, ...)와 판정 경계
(80 이상 ALLOW, 50 미만 BLOCK)는 `tests/test_score_engine.py`가 고정합니다.
바꾸려면 **테스트를 함께 고치고 PR에 근거를 적어 주십시오.** 숫자만 조용히
바뀌면 지난 리포트와 비교가 불가능해집니다.

### 4. 테스트는 네트워크를 쓰지 않습니다

`tests/conftest.py`가 `AIBOM_GUARDIAN_CACHE`를 `tests/fixtures`로 돌려 SPDX·
Blue Oak 목록을 받지 않게 합니다. 새 테스트가 외부 API를 호출한다면
`unittest.mock.patch`로 막아 주십시오.

네트워크를 타는 테스트는 남의 서버 상태에 따라 실패하고, 결국 아무도
믿지 않는 CI가 됩니다.

### 5. SPDX / Blue Oak 목록을 저장소에 넣지 않습니다

Blue Oak 약관은 JSON에 자동 접근하는 것만 허용하고 재배포는 언급하지
않으며, SPDX 데이터 저장소도 목록 자체의 라이선스를 선언하지 않습니다.
남의 라이선스를 판정하는 도구가 조건을 확인할 수 없는 파일을 담고 있을 수
없습니다. 첫 실행에 받아서 캐시하는 현재 방식을 유지해 주십시오.

### 6. 의존성을 추가하면 세 곳을 함께 고칩니다

| 파일 | 무엇을 |
|---|---|
| `pyproject.toml` | `[project].dependencies` — 정본 |
| `requirements.txt` | 같은 항목 + 왜 필요한지 주석 |
| `DEPENDENCIES.md` | 이름 / 용도 / 사용 모듈 / GitHub / 라이선스 |

앞의 두 개가 어긋나면 `tests/test_packaging.py`가 실패합니다.
`DEPENDENCIES.md`는 대회 제출 요건(제8조)이기도 하니 빠뜨리지 마십시오.

`mcp`는 `==1.28.1` 고정입니다. 2.x에서 `mcp.server.fastmcp`가 제거되어
서버가 기동하지 않습니다. 풀려면 서버를 먼저 이식해야 합니다.

### 7. 종료 코드는 계약입니다

| 코드 | 의미 |
|---|---|
| `0` | 전부 ALLOW이고 모든 줄을 검사함 |
| `1` | 입력 오류 |
| `2` | BLOCK 존재 |
| `3` | BLOCK은 없지만 WARNING이 있거나 검사 못 한 줄이 있음 |

CI가 이 값으로 게이트를 겁니다. 바꾸면 남의 파이프라인이 조용히 깨집니다.
`3`이 `0`이 되는 변경은 특히 위험합니다 — 아무것도 검사하지 않고 성공을
보고하는 게이트가 됩니다.

---

## 코드 스타일

특별한 포매터를 강제하지 않습니다. 주변 코드와 같아 보이면 됩니다.

- 들여쓰기 4칸, 한 줄 79~88자
- 타입 힌트를 답니다 (`from __future__ import annotations` 사용)
- 공개 함수에는 docstring을 답니다
- 모듈 안 import는 상대 경로 (`from .osv_client import ...`)

### 주석

**무엇을 하는지가 아니라 왜 그런지를 씁니다.** 코드를 읽으면 아는 것은
쓰지 않습니다. 대신 판단이 개입한 곳에는 근거를 남깁니다.

```python
# 좋음 - 왜 이 선택인지, 안 그러면 뭐가 깨지는지
# chardet 5.2.0은 LGPL-2.1인데 7.5.1은 0BSD입니다. 설치된 사본을 읽으면
# 고정한 버전과 다른 조건을 보고하게 되고 카피레프트 의무를 놓칩니다.

# 나쁨 - 코드가 이미 말하는 것
# 라이선스를 가져온다
```

함수 안 주석은 한두 줄이면 충분합니다. 긴 설명은 모듈이나 함수의
docstring으로 올려 주십시오.

**영어로 씁니다.** 외부 기여자가 읽을 수 있어야 합니다. 문서(README,
이 파일 등)는 한국어이고 `README.en.md`가 번역입니다.

팀 내부 용어(`module 3`, `P0-4` 같은 것)는 쓰지 마십시오. 대신 모듈
이름을 그대로 적으면 주석이 혼자서도 읽힙니다.

---

## PR 절차

1. `dev`에서 브랜치를 땁니다. 이름은 `feat/`, `fix/`, `docs/`, `test/`,
   `refactor/` 중 하나로 시작해 주십시오.
2. 커밋 메시지는 `타입: 요약` 형태로 씁니다.

   ```
   feat: requirements 범위·extras·마커 파싱
   fix: 별칭 병합 시 본문 문단 대신 제목을 유지
   docs: 라이선스 목록 캐시 동작과 미벤더링 사유 기록
   ```

3. **`pytest`가 전부 통과해야 합니다.** 동작을 바꿨다면 테스트를 함께
   추가해 주십시오.
4. `dev`로 PR을 엽니다. CI(테스트 4개 버전 + 빌드 + CLI 스모크)가
   초록이어야 병합됩니다.

리뷰에서 가장 자주 나오는 요청은 "이 판단의 근거를 주석이나 PR 본문에
남겨 달라"입니다. 나중에 그 코드를 만질 사람은 맥락이 없습니다.

---

## 프로젝트 구조

```
src/aibom_guardian/
    scanner.py              CLI 진입점 (aibom-guardian) — 오케스트레이션만
    _requirements.py        requirements 파싱 · PyPI 전이 의존성
    _scanner_license.py     고정 릴리스 라이선스 (PyPI / npm registry)
    _scanner_collect.py     병렬 OSV · recommendation · supply chain
    _scanner_models.py      HF 모델 스캔 · score_engine 이슈 번역
    _cli_report.py          터미널 표 · JSON 저장
    npm_checker.py          package.json · npm 전이 · run_npm_scan
    security_classifiers.py 모델 카드 PII (이메일 · 휴대폰 · 카드 PAN)
    mcp_server.py           MCP 진입점 (aibom-guardian-mcp)
    _adapters.py            두 진입점 → score_engine 입력 변환 (단일 사본)
    score_engine.py         Trust Score / 최종 판정  ← 유일한 채점자
    model_checker.py        Hugging Face 모델 정보 수집
    osv_client.py           OSV CVE 조회 + CVSS 파싱
    recommendation.py       위험 탐지 + 대안 추천
    license_checker.py      라이선스 분류
    sbom_generator.py       CycloneDX SBOM / ML-BOM
    ai_explainer.py         Ollama 로컬 모델 설명
    repository_checker/     공급망 신뢰도 (대상별 분할)
examples/                   예시 입력, demo_scenarios, 출력 샘플
tests/                      단위 테스트 (~840, 네트워크 미사용)
```

`repository_checker/`는 검사 대상별로 나뉘어 있습니다. GitHub 관련 수정은
`_github.py`, Hugging Face는 `_huggingface.py`처럼 해당 파일만 보면 됩니다.
공통 상수는 `_constants.py`, SSRF 방어는 `_http.py`에 있고, 새 검사를
추가한다면 결과 조립은 `_checker.py`의 `check()`를 거칩니다.

### lint

```bash
pyflakes src/aibom_guardian tests examples
```

CI가 이걸 돌립니다. 스타일 검사가 아니라 **해석되지 않는 이름**을 잡는
용도입니다. 커버리지가 71%라 테스트가 안 타는 경로의 오타나 빠진 import는
여기서만 걸립니다. 실제로 `repository_checker`를 분할할 때 34개가 걸렸고,
테스트는 그중 일부만 잡았을 것입니다.

---

## 라이선스

기여하신 코드는 프로젝트와 같은 [Apache License 2.0](LICENSE)으로
배포됩니다.
