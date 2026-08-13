# 보안 정책 / Security Policy

**English:** Please report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/Letmeloveyou522/aibom_guard/security/advisories/new),
not through public issues. Details below are in Korean; reports in English
are welcome.

---

## 지원 버전

| 버전 | 지원 |
|---|---|
| 0.1.x | ✅ |

배포 전 단계라 최신 `dev` 브랜치를 기준으로 대응합니다.

## 취약점 제보

**공개 이슈로 올리지 말아 주십시오.** 수정본이 나오기 전에 공개되면
이 도구를 쓰는 쪽이 그대로 노출됩니다.

[GitHub Security Advisories](https://github.com/Letmeloveyou522/aibom_guard/security/advisories/new)로
비공개 제보해 주십시오. 저장소 소유자에게만 보입니다.

제보에 아래가 있으면 확인이 빠릅니다.

- 어떤 입력이 문제를 일으키는지 (재현 가능한 최소 예시)
- 어느 모듈·함수인지
- 무엇을 할 수 있게 되는지 (임의 코드 실행, 내부망 접근, 정보 유출 등)
- 확인한 버전 또는 커밋

**대응 기준**

| 단계 | 목표 |
|---|---|
| 접수 확인 | 3일 이내 |
| 유효성 판단 및 회신 | 14일 이내 |
| 수정 배포 | 심각도에 따라 협의 |

학생 팀이 운영하는 프로젝트라 상시 대기는 어렵습니다. 회신이 늦어지면
이슈에 "advisory 확인 부탁드립니다" 정도로만 남겨 주십시오 — 내용은
적지 말아 주십시오.

## 이 프로젝트에서 특히 민감한 부분

제보 시 참고하시라고 적어 둡니다.

### 외부에서 받은 URL로 요청을 보냅니다 (SSRF)

`repository_checker`는 사용자가 넘긴 대상을 조회합니다. 허용 호스트
목록(`ALLOWED_HOSTS`), 포트 제한(`ALLOWED_PORTS`), 사설·루프백 주소 거부,
리다이렉트 홉마다 재검증이 들어 있고 `tests/test_repository_ssrf.py`가
회귀를 막습니다. **이 방어를 우회하는 입력**은 높은 심각도로 봅니다.

알려진 한계: 검증과 실제 연결 사이에 `requests`가 DNS를 다시 조회하므로
TOCTOU 창이 남아 있습니다. 이를 닫으려면 검증한 주소로 연결을 고정하는
커스텀 어댑터가 필요하며 아직 구현하지 않았습니다. 다만 이 창에 도달하려면
`github.com`·`pypi.org`·`huggingface.co` 등 고정된 7개 호스트의 DNS를 이미
장악해야 합니다. 자세한 내용은 `_http.py`의 모듈 docstring에 있습니다.

### pickle 파일을 다룹니다

`model_checker.py`는 Hugging Face 모델 가중치를 내려받아 `picklescan`으로
검사합니다. **검사 과정 자체가 pickle을 역직렬화하게 만드는 경로**가
있다면 임의 코드 실행입니다. 즉시 알려 주십시오.

pickle 검사는 기본 비활성(`--model-pickle-scan 0`)이며, picklescan은
알려진 패턴만 탐지합니다. 탐지 없음이 안전을 보장하지 않습니다.

### 외부 프로세스를 실행합니다

`cosign`(서명 검증)과 `cyclonedx-py`(SBOM 생성)를 하위 프로세스로
호출합니다. **인자에 사용자 입력이 그대로 흘러드는 경로**가 있으면
명령 주입입니다.

### 판정을 잘못 내리는 것도 취약점입니다

이 도구의 결과로 의존성 도입 여부를 결정합니다. 따라서
**"위험한 것을 안전하다고 보고하게 만드는 입력"**은 기능 버그가 아니라
보안 문제로 취급합니다. 예를 들어

- 라이선스 제한 조항을 우회해 `ALLOWED`가 나오게 하는 문자열
- CVE가 있는데 `vulnerabilities: []`(검증된 안전)로 보고되는 경우
- 타이포스쿼팅 탐지를 빠져나가는 이름

`None`(미검증)이 `[]`(검증된 안전)로 바뀌는 모든 경로가 여기 해당합니다.

## 범위 밖

- 이 도구가 **검사 대상 패키지에서 찾아낸** 취약점 — 정상 동작입니다.
  해당 패키지 관리자에게 제보하실 내용입니다.
- 토큰(`GITHUB_TOKEN`, `HF_TOKEN`) 없이 rate limit에 걸리는 것
- Ollama·cosign 등 선택 도구가 없을 때의 기능 축소
- 외부 API(OSV, PyPI, GitHub, Hugging Face) 자체의 문제
