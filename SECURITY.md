# 보안 정책 / Security Policy

**English:** Please report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/Letmeloveyou522/aibom_guardian/security/advisories/new),
not through public issues. Details below are in Korean; reports in English
are welcome.

---

## 지원 버전

| 버전 | 지원 |
|---|---|
| 1.0.x | 지원 |
| 0.1.x 이하 | 지원 종료 |

보안 수정은 최신 릴리스와 `main` 브랜치를 기준으로 진행합니다.

## 취약점 제보

취약점 세부 내용은 공개 이슈에 작성하지 마세요. 수정 전에 내용이 공개되면
사용자가 영향을 받을 수 있습니다.

[GitHub Security Advisories](https://github.com/Letmeloveyou522/aibom_guardian/security/advisories/new)로
비공개 제보해 주십시오. 저장소 소유자에게만 보입니다.

다음 내용을 포함하면 확인에 도움이 됩니다.

- 어떤 입력이 문제를 일으키는지 (재현 가능한 최소 예시)
- 관련 모듈과 함수
- 무엇을 할 수 있게 되는지 (임의 코드 실행, 내부망 접근, 정보 유출 등)
- 확인한 버전 또는 커밋

**대응 기준**

| 단계 | 목표 |
|---|---|
| 접수 확인 | 3일 이내 |
| 유효성 판단 및 회신 | 14일 이내 |
| 수정 배포 | 심각도에 따라 협의 |

기한 내 회신을 받지 못한 경우 공개 이슈에는 취약점 내용을 제외하고
Security Advisory 확인 요청만 남겨 주세요.

## 주요 보안 영역

### 외부에서 받은 URL로 요청을 보냅니다 (SSRF)

`repository_checker`는 사용자가 지정한 대상을 조회합니다. 허용 호스트
목록(`ALLOWED_HOSTS`), 포트 제한(`ALLOWED_PORTS`), 사설 및 루프백 주소 거부,
리다이렉트 홉마다 재검증이 들어 있고 `tests/test_repository_ssrf.py`가
회귀를 확인합니다. 이 검증을 우회하는 입력은 보안 취약점으로 분류합니다.

`npm_checker`는 `registry.npmjs.org`만 호출합니다(사용자 `package.json` 경로는
로컬 파일 읽기만).

알려진 한계: 검증과 실제 연결 사이에 `requests`가 DNS를 다시 조회하므로
TOCTOU 창이 남아 있습니다. 이를 닫으려면 검증한 주소로 연결을 고정하는
커스텀 어댑터가 필요하며 아직 구현하지 않았습니다. 다만 이 창에 도달하려면
`github.com`, `pypi.org`, `huggingface.co` 등 고정된 7개 호스트의 DNS를 이미
장악해야 합니다. 자세한 내용은 `_http.py`의 모듈 docstring에 있습니다.

### pickle 파일을 다룹니다

`model_checker.py`는 Hugging Face 모델 가중치를 내려받아 `picklescan`으로
검사합니다. 검사 과정에서 pickle이 역직렬화되는 경로는 임의 코드 실행으로
이어질 수 있으므로 비공개로 제보해 주세요.

pickle 검사는 기본 비활성(`--model-pickle-scan 0`)이며, picklescan은
알려진 패턴만 탐지합니다. 탐지 없음이 안전을 보장하지 않습니다.

### 외부 프로세스를 실행합니다

`cosign`(서명 검증)과 `cyclonedx-py`(SBOM 생성)를 하위 프로세스로
호출합니다. 사용자 입력이 검증 없이 명령 인자로 전달되는 경로는 명령 주입
가능성이 있습니다.

### 잘못된 안전 판정

위험한 대상을 안전하다고 판정하게 만드는 입력은 보안 문제로 취급합니다.
예시는 다음과 같습니다.

- 라이선스 제한 조항을 우회해 `ALLOWED`가 나오게 하는 문자열
- CVE가 있는데 `vulnerabilities: []`(검증된 안전)로 보고되는 경우
- 모델 카드 PII가 있는데 `pii_scan_unverified: false`로 보고되는 경우
- 타이포스쿼팅 탐지를 빠져나가는 이름

`None`(미검증)이 `[]`(검사 완료)로 바뀌는 경로도 여기에 해당합니다.
`_adapters._vulns_to_issues`와 `attach_license_unverified`를 변경할 때는
관련 회귀 테스트를 실행해 주세요.

## 범위 밖

- 이 도구가 **검사 대상 패키지에서 찾아낸** 취약점 — 정상 동작입니다.
  해당 패키지 관리자에게 제보하실 내용입니다.
- 토큰(`GITHUB_TOKEN`, `HF_TOKEN`) 없이 rate limit에 걸리는 것
- Ollama와 cosign 등 선택 도구가 없을 때의 기능 축소
- 외부 API(OSV, PyPI, GitHub, Hugging Face) 자체의 문제
