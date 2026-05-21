# 🎯 Modular Web Scanner
### **Python 비동기 I/O 아키텍처**를 기반으로 개발된 **모듈형 웹 취약점 스캐너 CLI 및 웹 UI 솔루션**

대상 웹 애플리케이션을 자동으로 크롤링하여 파라미터와 폼 등 공격 표면(Attack Surface)을 수집하고 다종의 보안 취약점을 병렬로 정밀 진단합니다. 

사용자가 터미널 환경의 **CLI**뿐만 아니라 **FastAPI 기반의 간단한 웹 UI**를 통해 편리하게 스캔을 트리거하고 결과를 조회할 수 있는 고성능 실전형 퍼징 엔진입니다.

> **법적·윤리적 고지**  
> 본 도구는 **본인이 소유하거나 명시적 서면 허가를 받은 시스템**에서만 사용하세요. 무단 스캔은 불법일 수 있습니다. 교육·연구·침투 테스트 계약 범위 내에서만 사용하시기 바랍니다.

---

## 👥 팀원 소개 

| 이름 | 역할 |
| :---: | :---: |
| **김진우(팀장)** | PM / 퍼저 엔진 / 공격 모듈 개발 담당 | 
| **강제윤** | 크롤러 / 파서 / 공격 모듈 개발 담당 | 
| **이시은** | 파서 / 공격 모듈 개발 담당 | 
| **허윤** | 공격 모듈 개발 담당 | 

---

## 🛠️ 기술 스택

| 분류 | 기술 스택 | 설명 |
| :---: | :--- | :--- |
| **Language** | ![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white) | 프로젝트 핵심 개발 언어 |
| **Web** | ![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white) | FastAPI 기반 웹 UI 대시보드 및 스캔 트리거 API 구현 |
| **Asynchronous** | ![asyncio](https://img.shields.io/badge/asyncio-3776AB?style=flat-square&logo=python&logoColor=white) | 비동기 이벤트 루프 기반의 동시성 제어 (병목 최소화) |
| **Network** | ![aiohttp](https://img.shields.io/badge/aiohttp-2C5BB4?style=flat-square&logo=python&logoColor=white) | 수많은 공격 페이로드를 동시에 전송하는 비동기 통신 |
| **Parsing** | ![BeautifulSoup4](https://img.shields.io/badge/BeautifulSoup4-4B8BBE?style=flat-square&logo=python&logoColor=white) | 크롤링한 HTML 원문에서 폼(Form), 파라미터 등 숨겨진 공격 표면(Attack Surface) 추출 |
| **Parsing** | ![Regex](https://img.shields.io/badge/Regex-4B8BBE?style=flat-square) | 응답 데이터(Response)에서 SQL 에러 시그니처, 취약점 징후 등을 빠르고 정밀하게 탐지 |
| **Package** | ![PyPI](https://img.shields.io/badge/PyPI-3775A9?style=flat-square&logo=pypi&logoColor=white) | 외부 패키지 및 의존성 관리 |
| **VCS** | ![Git](https://img.shields.io/badge/Git-F05032?style=flat-square&logo=git&logoColor=white) | 코드 형상 관리 및 브랜치(이슈) 기반 협업 |
---

## ⚙️ 주요 기능

| 영역 | 설명 |
| :---: | --- |
| **크롤러** | `CrawlerEngine`이 시작 URL부터 링크를 따라가며 `QueueManager`에 페이지를 넣고, 깊이·URL 수·지연·타임아웃·워커 수 등 `CrawlConfig`로 조절합니다. |
| **파서 / 공격 표면** | `SurfaceBuilder`가 큐에서 HTML을 소비해 `AttackSurface` 목록을 생성합니다. 결과는 `--surfaces-output`(기본 attack_surfaces.json)으로보낼 수 있습니다. |
| **URL 필터** | `URLFilter`로 크롤링 대상을 제한하고, `--exclude-urls`로 정규식 패턴 목록을 넘기면 크롤러·세션에 주입됩니다. |
| **인증** | `--login-url`, `--username`, `--password` 및 폼 필드명(`--username-field`, `--password-field`, `--csrf-field`, `--submit-field`)으로 로그인 후 크롤링할 수 있습니다. `-c` / `--cookie`로 세션 쿠키를 직접 줄 수도 있습니다. |
| **퍼저** | ``FuzzerEngine`이 모듈별 페이로드를 큐에 넣고 `aiohttp`로 요청을 보냅니다. RPS(`-r`), 워커 수(`-w`, 0이면 자동), 세션 풀(`--session-pool-size`)로 부하를 조절합니다. |
| **진단 모듈** | **SQLi**, **브루트포스**, **LFI**, **파일 업로드**, **OSCI**, **XSS(Stored,Reflected)**, **SSRF** (`fuzzer/setup.py` 기준). `-t all`은 브루트포스를 제외한 나머지를 순차 실행합니다. |
| **리포트** | 콘솔 요약 + JSON (`-o`, 기본 `scan_report.json`). 중복 제거·정렬 등은 `reporter` 패키지에서 처리합니다. |
| **웹 UI** | `webapp/main.py`를 통해 FastAPI 엔진과 정적 `index.html` 기반의 대시보드를 구동합니다. 웹 화면을 통해 쉽게 스캔 시작(트리거), 진행 상태 모니터링, 결과 JSON 조회 API를 이용할 수 있습니다. |

---

## 🧩 설치 방법 

#### 요구 사항 
- **Python 3.10+** 권장 
  *(Windows 환경에서 Python 3.13+ 사용 시 발생할 수 있는 asyncio 관련 경고 억제 코드가 `main.py`에 포함되어 있습니다.)*

#### 주요 서드파티 패키지(코드 기준): **`aiohttp`**, **`beautifulsoup4`**, **`fastapi`**, **`pydantic`**, **`uvicorn`**(웹 서버 실행용)

저장소에 requirements.txt / pyproject.toml이 없을 수 있으므로, 아래는 참고용 한 줄 예시입니다.
```bash
pip install aiohttp beautifulsoup4 lxml fastapi pydantic uvicorn
```

---

## 🚀 사용 방법

본 프로그램은 **CLI모드**와 **웹 UI 모드** 두 가지 방식으로 실행할 수 있습니다.

### 1. CLI 스캔 모드
 
```bash
# 저장소 루트에서 
python main.py -u http://127.0.0.1/DVWA -t all
```

### 2. 웹 UI

```bash
uvicorn webapp.main:app --reload --host 127.0.0.1 --port 8000
```

브라우저에서 `http://127.0.0.1:8000/` 로 접속합니다. (API 경로는 `webapp/main.py`의 FastAPI 라우트 정의를 참고하세요.)


### CLI 옵션 요약

#### 공통

| 옵션 | 설명 |
|------|------|
| `-u`, `--url` | **필수.** 스캔 대상 베이스 URL (예: DVWA 루트). |
| `-t`, `--type` | `sqli` \| `osci` \| `bruteforce` \| `lfi` \| `file_upload` \| `ssrf` \| `stored_xss` \| `reflected_xss` \| `all` (기본: `all`). `all`은 **브루트포스를 제외**한 나머지 모듈을 순차 실행. |
| `-r`, `--rps` | 초당 요청 상한 (기본 100). |
| `-w`, `--workers` | 큐 워커 수 (0이면 RPS 기반 자동). |
| `-c`, `--cookie` | 쿠키 헤더 문자열 (예: `PHPSESSID=...; security=low`). |
| `-o`, `--output` | 스캔 리포트 JSON 경로 (기본 `scan_report.json`). |
| `--surfaces-output` | 크롤링된 공격 표면 JSON (기본 `attack_surfaces.json`). |
| `--session-pool-size` | 병렬 HTTP 세션 수 (기본 3). |
| `--level N` | SQLi·OSCi·LFI·SSRF 회피 레벨을 한 번에 `N`(0–3)으로 설정. SSRF는 최대 2. 설정 시 개별 `--*-evasion-level`을 덮어씀. 브루트포스·XSS에는 적용되지 않음. |
| `--exclude-urls` | 크롤·공격에서 제외할 URL **정규식** 패턴 (공백으로 여러 개). |

#### 인증 (크롤 전 로그인)

| 옵션 | 설명 |
|------|------|
| `--login-url` | 로그인 페이지 URL (예: `http://target/login.php`). |
| `--username`, `--password` | 로그인 계정. |
| `--username-field`, `--password-field` | 폼 필드명 (기본 `username` / `password`). |
| `--csrf-field` | CSRF 토큰 필드명 (기본 `user_token`). |
| `--submit-field` | 제출 필드명 (기본 `Login`). |

#### 모듈별 옵션

| 모듈 | 옵션 | 설명 |
|------|------|------|
| **SQLi** | `--sqli-evasion-level` | 회피 강도 0–3 (기본 0). |
| | `--sqli-time-based` | time/stacked 페이로드 포함 (느림). |
| | `--sqli-time-max` | time 페이로드 상한 (0=전체). |
| **OSCi** | `--osci-evasion-level` | 회피 강도 0–3 (기본 0). |
| | `--osci-time-based` | time-based 지연 페이로드 포함. |
| | `--osci-time-max` | time 페이로드 상한 (0=전체). |
| | `--target-os` | `linux` \| `windows` \| `all` (기본 `linux`). |
| **LFI** | `--lfi-evasion-level` | 변형 레벨 0–3 (기본 1). |
| **SSRF** | `--ssrf-evasion-level` | 변형 레벨 0–2 (기본 1). |
| | `--ssrf-oob` | OOB/템플릿 페이로드 추가. |
| **Stored XSS** | `--sxss-evasion-level` | 변형 레벨 0–3 (기본 1). |
| **Reflected XSS** | `--rxss-evasion-level` | 변형 레벨 0–3 (기본 1). |
| **파일 업로드** | — | 모듈 전용 CLI 플래그 없음 (`-t file_upload`). |

#### 브루트포스

| 옵션 | 설명 |
|------|------|
| `--bf-wordlist` | 워드리스트 경로 (기본 `config/payloads/bruteforce/common_passwords.txt`). |
| `--bf-disable-mutation` | 사전 모드에서 비밀번호 돌연변이 비활성화. |
| `--bf-mutation-level` | 돌연변이 강도 0–3 (기본 1). |
| `--bf-true-random` | true-random 전용 모드 (사전 비활성화). |
| `--bf-charset` | true-random 문자 집합. |
| `--bf-min-length`, `--bf-max-length` | true-random 길이 범위. |
| `--bf-length` | 길이 또는 범위 (`8` → 1~8, `2~8`). `--bf-max-length`보다 우선. |
| `--bf-max-dictionary`, `--bf-max-true-random` | 페이로드 상한 (0=전체). |
| `--bf-stop-on-first-hit` / `--no-bf-stop-on-first-hit` | 첫 자격 증명 성공 시 중단 (기본: 활성). |
| `--bf-target-url` | 단일 대상 URL. |
| `--bf-method` | `GET` \| `POST` (기본 `GET`). |
| `--bf-fuzz-param` | FUZZ로 치환할 파라미터 (기본 `password`). |
| `--bf-target-param` | 대상 파라미터 강제 지정 (생략 시 자동 선택). |
| `--bf-username-param`, `--bf-username` | 사용자명 파라미터·값 (기본 `username` / `admin`). |
| `--bf-extra-params` | 고정 파라미터 `KEY=VALUE` (여러 개). |

`--bf-target-url`을 생략하면 `-u`로 크롤한 표면에서 `BruteforceModule` 휴리스틱으로 대상을 고릅니다.

전체 옵션은 다음으로 확인할 수 있습니다.

```bash
python main.py -h
```

---


## 📂 디렉터리 구조

```
├── main.py                  # CLI 진입점 (asyncio)
├── cli/                     # 인자 파싱, 서피스 해석, 실행·출력
├── core/                    # AttackSurface 등 공통 모델, 큐
├── crawler/                 # 크롤러 엔진, 세션, URL 필터
├── parsers/                 # HTML 파싱, 링크·폼 추출, SurfaceBuilder
├── fuzzer/                  # FuzzerEngine, 요청 빌더
├── modules/                 # 취약점 진단 공격 모듈
├── config/payloads/         # 모듈별 페이로드·워드리스트
├── reporter/                # 리포트 생성·중복 제거
├── webapp/                  # FastAPI + static UI
└── utils/                   # 로거, 뮤테이터 등
```



## 📚 참고 자료 

* **SQL Injection Module**
    * [sqlmap](https://github.com/sqlmapproject/sqlmap)
* **Login Brute Force Module**
    * [SecLists - Pwdb top 1000](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/Pwdb_top-1000.txt)
* **LFI Module**
    * [SecLists - LFI-LFISuite-pathtotest](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt)