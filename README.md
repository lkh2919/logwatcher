# LogWatcher

nginx 접근 로그를 올리면 **위협 IP를 위험도(높음·중간·낮음)순으로 정리하고, 이상이 있는지 없는지** 한눈에 알려주는 Windows용 경량 도구입니다.
사내 LogWatch v1.0의 탐지 방식을 벤치마킹해 nginx 전용으로 줄였습니다.

- **PC 안에서만 처리**: 127.0.0.1에서만 열리는 로컬 화면이며 로그는 외부로 전송되지 않습니다.
- **가벼움**: exe 하나(Python 표준 라이브러리만 사용), 인터넷·DB 불필요. 로그를 메모리에 쌓지 않고 IP별로 집계해 큰 파일도 처리합니다(100만 줄 ≈ 10초, 메모리 수십 MB).
- **근거 제시**: 탐지 항목마다 근거 로그, 추정 원인, 조치 가이드, 오탐 가능성을 보여줍니다. 공격 요청이 2xx 응답을 받으면 `⚠ 정상 응답` 경고를 붙입니다.

## 사용법

1. [Actions](../../actions) → 최신 실행의 **LogWatcher-windows** 아티팩트에서 `LogWatcher.exe`를 받습니다. (또는 `build.bat`으로 직접 빌드, Python 설치 시 `run_with_python.bat`로 바로 실행)
2. `LogWatcher.exe`를 더블클릭하면 콘솔 창이 뜨고 브라우저에 화면이 열립니다. (닫으려면 콘솔 창을 닫거나 Ctrl+C)
3. nginx `access.log`(여러 개, `.gz` 가능)를 화면에 끌어다 놓습니다.
4. 맨 위 판정을 확인합니다: **✔ 이상 없음** / **⚠ 이상 징후 N IP 발견**. 행을 누르면 근거와 조치 가이드가 펼쳐집니다.
5. `결과 CSV 저장`으로 보고용 파일(엑셀에서 한글 정상)을 받습니다.

## 지원 로그

| 형식 | 예 |
|---|---|
| nginx combined(기본) 및 뒤에 필드가 붙은 사용자 정의 `log_format` | `1.2.3.4 - - [08/Oct/2026:10:12:01 +0900] "GET / HTTP/1.1" 200 512 "-" "ua"` |
| 위 형식 끝에 `"$http_x_forwarded_for"`가 붙은 로그 | `... "ua" "203.0.113.7"` |
| JSON 한 줄 로그 | `{"remote_addr":"1.2.3.4","request":"GET / HTTP/1.1","status":200,"time_iso8601":"..."}` |

`error.log`는 아직 지원하지 않습니다(올리면 안내 메시지가 나옵니다).

## LB 뒤에 있는 nginx (IP 구분)

| 로그 상태 | 동작 |
|---|---|
| 직접 접속 로그 | IP별로 판정합니다. |
| LB 뒤 + `X-Forwarded-For` 기록 | 사설 IP(10.x, 172.16.x, 192.168.x 등)나 `trusted_proxies`에서 온 요청에 한해 XFF의 실제 접속자 IP를 사용합니다. 공인 IP가 보낸 XFF는 위조될 수 있어 무시합니다. |
| LB 뒤 + XFF 없음 (모든 요청이 한 IP) | **IP 구분을 제외하고 요청 단위로 판정**합니다. URL 공격 패턴·스캐너·비정상 Method만 검사하고, IP별 집계가 필요한 규칙(과다 접속, 에러 다수, 로그인 시도 등)은 적용하지 않습니다. |

기본값은 자동 판별이며(요청의 80% 이상이 한 IP이거나 IP가 3개 이하 등), 화면 오른쪽 위 **IP 구분** 선택으로 수동 전환할 수 있습니다.
XFF를 남기려면 nginx에 `log_format main '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"';`를 사용하세요.

## 탐지 항목

| 등급 | 항목 | 기준(기본값) |
|---|---|---|
| 높음 | SQL Injection / XSS / 경로 조작 / 명령어 삽입 | 디코딩한 URL에 공격 구문, Log4Shell(`${jndi:`) 포함 |
| 중간 | 취약점·관리페이지 탐색 | `.env`, `.git`, `wp-login`, `phpmyadmin`, `.php` 등 |
| 중간 | 스캐너 도구 | User-Agent가 sqlmap, nikto, nmap, Censys 등 |
| 중간 | 비정상 Method | GET/POST/HEAD/OPTIONS 이외 |
| 중간 | 과다 접속 | 60초에 300건 이상(정적 파일 제외) |
| 중간 | 에러 다수 | 4xx·5xx(499 제외) 20건 이상이고 50% 이상 |
| 중간 | 없는 경로 탐색 | 서로 다른 404 경로 10종 이상 |
| 중간 | 로그인 실패 반복 / 시도 과다 | 로그인 URL 에러 5건 / 10분에 POST 20건 |
| 낮음 | 순간 집중 접속 / 스크립트·도구 접근 / 깨진·바이너리 요청 | 1초 30건 / curl·python 등 / HTTP 포트로 온 TLS 등 |

판정: 높음·중간이 하나라도 있으면 **이상 징후**, 없으면 **이상 없음**(낮음은 참고). IP 위험도는 걸린 항목 중 가장 높은 등급입니다.

## 설정 (`config.json`)

처음 실행하면 exe 옆에 `config.json`이 만들어집니다. 메모장으로 수정하고 다시 실행하면 적용됩니다.
삭제하면 기본값으로 돌아갑니다.

| 키 | 설명 |
|---|---|
| `allow_ips` | 모든 탐지에서 제외할 IP/대역(CIDR 가능). 내부 점검 서버·모니터링 등 |
| `probe_ignore_paths` | 취약경로 탐색 규칙에서 제외할 경로 정규식. 예: `["^/graphql", "^/swagger"]` (SQLi 등 다른 공격은 계속 탐지) |
| `trusted_proxies` | X-Forwarded-For를 신뢰할 프록시/CDN 대역(사설 IP는 자동 신뢰) |
| `ip_mode` | `auto` / `ip` / `none` |
| `allowed_methods`, `static_extensions` | 정상 Method, 접속량 계산 제외 확장자 |
| `rate_*`, `burst_max`, `error_*`, `notfound_distinct`, `login_*` | 각 규칙의 기준값 |
| `display_utc_offset_hours` | 화면 표시 시간대(기본 9, KST) |

## 한계

- 로그 내용(URL, User-Agent, 응답코드) 기반 패턴 탐지입니다. **요청 본문(POST 데이터)에 숨은 공격은 보이지 않습니다.**
- 탐지 결과는 판단 보조 자료입니다. 차단·신고 전에 근거 로그와 응답 코드를 확인하세요. 탐지 누락과 오탐이 있을 수 있습니다.
- 해외 접속 판별(IP→국가)은 포함하지 않았습니다.
- 로그·CSV에는 IP·사용자 ID 등 개인정보가 포함될 수 있으니 사내 지침에 따라 관리하세요.

## 개발

```
python -m unittest discover -s tests -t . -v   # 테스트
python tools/make_samples.py                    # 샘플 로그 재생성 (samples/)
python run.py                                   # 실행 (--no-browser: 브라우저 자동 열기 끔)
```

`.github/workflows/build-exe.yml`이 push마다 테스트(Python 3.8·3.13)를 돌리고 Windows exe를 빌드해 아티팩트로 올립니다. `v*` 태그를 push하면 Release에 exe가 첨부됩니다.
