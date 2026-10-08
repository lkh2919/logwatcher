# LogWatcher

nginx·HAProxy 로그를 올리면 **위협 IP를 위험도(높음·중간·낮음)순으로 정리하고, 이상이 있는지 없는지** 한눈에 알려주는 Windows용 경량 도구입니다.
사내 LogWatch v1.0의 탐지 방식을 벤치마킹해 nginx·HAProxy 전용으로 줄였습니다.

- **PC 안에서만 처리**: 127.0.0.1에서만 열리는 로컬 화면이며 로그는 외부로 전송되지 않습니다.
- **가벼움**: exe 하나(Python 표준 라이브러리만 사용), 인터넷·DB 불필요. 로그를 메모리에 쌓지 않고 IP별로 집계해 큰 파일도 처리합니다(100만 줄 ≈ 10초, 메모리 수십 MB).
- **근거 제시**: 탐지 항목마다 근거 로그, 추정 원인, 조치 가이드, 오탐 가능성을 보여줍니다. 공격 요청이 2xx 응답을 받으면 `⚠ 정상 응답` 경고를 붙입니다.

## 사용법

1. [Actions](../../actions) → 최신 실행의 **LogWatcher-windows** 아티팩트에서 `LogWatcher.exe`를 받습니다. (또는 `build.bat`으로 직접 빌드, Python 설치 시 `run_with_python.bat`로 바로 실행)
2. `LogWatcher.exe`를 더블클릭하면 콘솔 창이 뜨고 브라우저에 화면이 열립니다. (닫으려면 콘솔 창을 닫거나 Ctrl+C)
3. nginx `access.log`·`error.log` 또는 HAProxy 로그(여러 개, `.gz` 가능)를 화면에 끌어다 놓습니다.
4. 맨 위 판정을 확인합니다: **✔ 이상 없음** / **⚠ 이상 징후 N IP 발견**. 행을 누르면 근거와 조치 가이드가 펼쳐집니다.
5. `결과 CSV 저장`으로 보고용 파일(엑셀에서 한글 정상)을 받습니다.

## 지원 로그

파일 형식은 내용을 보고 자동으로 판별합니다(`.gz` 압축 가능). 여러 파일을 한 번에 올려도 됩니다.

| 로그 | 형식 | 비고 |
|---|---|---|
| nginx access.log | combined(기본) 및 뒤에 필드가 붙은 `log_format`, 대괄호형(`[request "..."] [status N] [body_bytes_sent N]`), JSON 한 줄 | 마지막에 `"$http_x_forwarded_for"`가 있으면 함께 읽음 |
| nginx error.log | `2026/10/08 10:12:01 [error] ...` | 보안 신호는 위협 IP 판정에 반영, 서버 오류는 "서버 상태"로 분리 |
| HAProxy | `option httplog` 형식(syslog 접두 유무 모두) | **실제 접속자 IP가 바로 기록됨**. `Server ... is DOWN`, `no server available`, TLS 핸드셰이크 실패 줄도 읽음 |

HAProxy TCP 모드 로그(`option tcplog`)는 요청 URL이 없어 분석할 수 없습니다(올리면 안내 메시지가 나옵니다).

## LB/프록시 뒤의 로그 (IP 구분)

| 로그 상태 | 동작 |
|---|---|
| 직접 접속 로그 | IP별로 판정합니다. |
| LB 뒤 + `X-Forwarded-For` 기록 | LB가 사설 IP이거나 `trusted_proxies`에 있으면 XFF의 실제 접속자 IP를 씁니다. **LB가 공인 IP여도** 요청 20건 이상 · 90% 이상에 XFF가 붙고 값이 3종류 이상이면 LB로 자동 판단하며, 화면 맨 위에 그 IP를 표시합니다(`auto_proxy`로 끌 수 있음). 그 외 공인 IP가 보낸 XFF는 위조될 수 있어 무시합니다. LB를 거치지 않은 직접 접속 요청은 원래 IP로 판정합니다. |
| LB 뒤 + XFF 없음 (모든 요청이 한 IP) | **IP 구분을 제외하고 요청 단위로 판정**합니다. URL 공격 패턴·스캐너·비정상 Method만 검사하고, IP별 집계가 필요한 규칙(과다 접속, 에러 다수, 로그인 시도 등)은 적용하지 않습니다. |

기본값은 자동 판별이며(요청의 80% 이상이 한 IP이거나 IP가 3개 이하 등), 화면의 **IP 구분** 선택으로 수동 전환할 수 있습니다.

**HAProxy가 앞에 있는 경우:** HAProxy 로그를 분석하면 별도 설정 없이 실제 접속자 IP로 판정할 수 있어 가장 정확합니다. nginx 로그를 분석하려면 HAProxy에 `option forwardfor`를 켜고 nginx `log_format`에 `"$http_x_forwarded_for"`를 남기세요.
HAProxy 로그와 nginx 접근 로그를 **함께** 올리면 같은 요청이 두 번 집계될 수 있어(과다 접속 등이 부풀려짐) 화면에 경고가 나옵니다. 한쪽만 올리세요. nginx error.log는 함께 올려도 됩니다.

## 탐지 항목

| 등급 | 항목 | 기준(기본값) |
|---|---|---|
| 높음 | SQL Injection / XSS / 경로 조작 / 명령어 삽입 | 디코딩한 URL에 공격 구문, Log4Shell(`${jndi:`) 포함 |
| 중간 | 취약점·관리페이지 탐색 | `.env`, `.git`, `wp-login`, `phpmyadmin`, `.php` 등 |
| 중간 | 스캐너 도구 | User-Agent가 sqlmap, nikto, nmap, Censys 등 |
| 중간 | 비정상 Method | GET/POST/HEAD/OPTIONS 이외(CONNECT, TRACE 등). PUT/DELETE/PATCH도 `.jsp`·`.php` 같은 실행 파일 경로면 해당 |
| 중간 | 과다 접속 | 60초에 300건 이상(정적 파일 제외) |
| 중간 | 에러 다수 | 4xx·5xx(499 제외) 20건 이상이고 50% 이상 |
| 중간 | 없는 경로 탐색 | 서로 다른 404 경로 10종 이상 |
| 중간 | 로그인 실패 반복 / 시도 과다 | 로그인 URL에서 인증 실패(400·401·403·422·429) 5건 / 10분에 POST 20건. 서버 오류(5xx)는 장애일 수 있어 세지 않음 |
| 중간·낮음 | 에러로그 의심 요청 | 요청 제한(limit_req) 초과·접근 거부·인증 실패·에러 난 요청 URL의 공격 패턴(중간), 잘못된 Method·TLS 실패(낮음) |
| 낮음 | REST Method(PUT/DELETE/PATCH) | REST API에서는 정상일 수 있음. 정상 서비스면 `allowed_methods`에 추가 |
| 낮음 | 순간 집중 접속 / 스크립트·도구 접근 | 1초 30건 / curl·python 등 |
| 낮음 | 깨진·바이너리 요청 | HTTP가 아닌 데이터. 어떤 프로토콜(JDWP, Java RMI, SMB, Redis, MongoDB, TLS 등)을 노렸는지 함께 표시 |

판정: 높음·중간이 하나라도 있으면 **이상 징후**, 없으면 **이상 없음**(낮음은 참고). IP 위험도는 걸린 항목 중 가장 높은 등급입니다. 목록은 기본으로 높음·중간만 보여주고 `낮음도 보기`로 펼칩니다.

### 서버 상태 (error.log · HAProxy 상태 줄)
위협 IP 판정(이상 유무)에는 포함하지 않고 **운영 참고**로 따로 보여줍니다: 파일 열기 실패(권한), 업스트림 오류, 서버 자원 부족, HAProxy 백엔드 서버 다운/복구·재시작 등. 연결 종료 같은 정상 범주 로그는 건수만 셉니다.

## 설정 (`config.json`)

처음 실행하면 exe 옆에 `config.json`이 만들어집니다. 메모장으로 수정하고 다시 실행하면 적용됩니다.
삭제하면 기본값으로 돌아갑니다.

| 키 | 설명 |
|---|---|
| `allow_ips` | 모든 탐지에서 제외할 IP/대역(CIDR 가능). 사내 사용자, 점검 서버, 모니터링·대시보드 폴링 등 정상 대량 접속 |
| `probe_ignore_paths` | 취약경로 탐색 규칙에서 제외할 경로 정규식. 예: `["^/graphql", "^/swagger"]` (SQLi 등 다른 공격은 계속 탐지) |
| `trusted_proxies` | X-Forwarded-For를 신뢰할 프록시/CDN 대역(사설 IP는 자동 신뢰) |
| `auto_proxy` | 공인 IP의 LB를 XFF 사용 패턴으로 자동 판단 (기본 true) |
| `rest_methods` | 비정상 Method(중간) 대신 낮음으로 보는 Method (기본 PUT, DELETE, PATCH) |
| `error_log_utc_offset_hours`, `haproxy_log_utc_offset_hours` | 시간대 표기가 없는 error.log·HAProxy 접속 시각의 기록 시간대(기본 9=KST) |
| `ip_mode` | `auto` / `ip` / `none` |
| `allowed_methods`, `static_extensions` | 정상 Method, 접속량 계산 제외 확장자 |
| `rate_*`, `burst_max`, `error_*`, `notfound_distinct`, `login_*` | 각 규칙의 기준값 |
| `display_utc_offset_hours` | 화면 표시 시간대(기본 9, KST) |

## 한계

- 로그 내용(URL, User-Agent, 응답코드) 기반 패턴 탐지입니다. **요청 본문(POST 데이터)에 숨은 공격은 보이지 않습니다.**
- 탐지 결과는 판단 보조 자료입니다. 차단·신고 전에 근거 로그와 응답 코드를 확인하세요. 탐지 누락과 오탐이 있을 수 있습니다.
- 해외 접속 판별(IP→국가)은 포함하지 않았습니다.
- 인터넷에 노출된 서버는 스캐너 IP가 매우 많아 "이상 징후"가 늘 나올 수 있습니다. 높음과 `⚠ 정상 응답` 표시부터 확인하세요.
- 사내 사용자의 정상 대량 접속(대시보드 자동 새로고침 등)은 `과다 접속`으로 나올 수 있으니 `allow_ips`로 제외하세요.
- 로그·CSV에는 IP·사용자 ID 등 개인정보가 포함될 수 있으니 사내 지침에 따라 관리하세요.

## 개발

```
python -m unittest discover -s tests -t . -v   # 테스트
python tools/make_samples.py                    # 샘플 로그 재생성 (samples/)
python run.py                                   # 실행 (--no-browser: 브라우저 자동 열기 끔)
```

`.github/workflows/build-exe.yml`이 push마다 테스트(Python 3.8·3.13)를 돌리고 Windows exe를 빌드해 아티팩트로 올립니다. `v*` 태그를 push하면 Release에 exe가 첨부됩니다.
