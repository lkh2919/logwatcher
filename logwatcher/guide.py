"""위험도 기준과 탐지 규칙별 설명 · 추정 원인 · 조치 가이드 (화면 표시용)."""

LEVEL_GUIDE = [
    {"level": 3, "label": "높음", "when": "즉시 확인",
     "summary": "실제 공격 시도로 보이는 요청이 있음",
     "detail": ["URL에 SQL Injection, XSS, 경로 조작, 명령어 삽입 같은 공격 구문이 들어 있는 경우"]},
    {"level": 2, "label": "중간", "when": "당일 확인",
     "summary": "공격 전 정보 수집이나 비정상 행위로 의심됨",
     "detail": ["스캐너 도구, 취약 경로·관리 페이지 탐색, 허용되지 않은 Method",
                "로그인 실패 반복·시도 과다, 과다 접속, 에러 다수, 존재하지 않는 경로 탐색"]},
    {"level": 1, "label": "낮음", "when": "참고",
     "summary": "단독으로는 정상일 수 있는 항목",
     "detail": ["1초 순간 집중 접속, curl·python 같은 프로그램 접근",
                "깨진/바이너리 요청(HTTP 포트로 HTTPS 전송 등)", "다른 항목과 함께 나타날 때 의미가 커짐"]},
]

LEVEL_NOTES = [
    "IP의 위험도는 탐지된 항목 중 가장 높은 등급을 따릅니다.",
    "판정: 높음·중간이 하나라도 있으면 '이상 징후', 없으면 '이상 없음'입니다(낮음은 참고).",
    "공격 요청이 2xx(정상) 응답을 받은 경우 '정상 응답 경고'가 붙습니다. 서버가 요청을 처리했다는 뜻이라 우선 확인하세요.",
    "로그에는 요청 본문(POST 데이터)이 없어, 본문에 숨은 공격은 보이지 않습니다.",
]

# 정상 응답(2xx)을 받으면 실제 영향이 있을 수 있는 규칙
SUCCESS_WARN_KEYS = ["sqli", "xss", "traversal", "cmdi", "probe"]

# IP를 구분할 수 없을 때(요청 단위 판정)에도 쓸 수 있는 규칙 (나머지는 IP별 집계가 필요)
REQUEST_LEVEL_KEYS = ["sqli", "xss", "traversal", "cmdi", "probe", "scanner", "method", "malformed"]

RULES = {
    "sqli": {
        "label": "SQL Injection", "level": 3,
        "what": "URL(파라미터 포함)에 SQL 구문을 끼워 넣은 흔적이 있습니다. 예: ' OR 1=1, UNION SELECT, SLEEP().",
        "causes": ["공격자나 자동 도구(sqlmap 등)가 DB 내용을 빼내거나 조작하려는 시도", "취약점 스캐너의 자동 점검"],
        "actions": ["근거 요청의 응답코드와 크기를 확인하세요. 200 응답이면서 크기가 평소와 다르면 공격이 통했을 수 있어 개발·DB 담당자 확인이 필요합니다.",
                    "해당 IP를 방화벽 또는 WAF에서 차단하세요.",
                    "해당 URL·파라미터가 입력값 검증/PreparedStatement를 쓰는지 점검을 요청하세요."],
        "false_positive": "검색창에 SQL 문장을 그대로 입력한 정상 사용자일 수 있지만 드뭅니다.",
    },
    "xss": {
        "label": "XSS(스크립트 삽입)", "level": 3,
        "what": "URL에 브라우저에서 실행되는 스크립트를 넣은 흔적이 있습니다. 예: <script>, onerror=, javascript:.",
        "causes": ["다른 사용자의 쿠키·세션을 빼내거나 피싱 화면을 띄우려는 시도", "취약점 스캐너의 자동 점검"],
        "actions": ["응답코드를 확인하고, 입력값이 화면에 그대로 출력되는 페이지인지 개발 담당자에게 확인하세요.",
                    "반복되면 해당 IP를 차단하세요."],
        "false_positive": "게시판 글쓰기 등에서 정상 사용자가 꺾쇠(<>)를 입력한 경우.",
    },
    "traversal": {
        "label": "경로 조작/파일 접근", "level": 3,
        "what": "URL에 ../, /etc/passwd 같은 상위 경로·시스템 파일 접근 구문이 있습니다.",
        "causes": ["서버 내부 파일(설정, 계정 정보)을 읽으려는 시도", "자동 스캐너의 점검"],
        "actions": ["200 응답이면 실제 파일이 노출됐을 수 있으니 즉시 확인하세요.",
                    "다운로드·파일 조회 기능의 경로 검증을 점검하고 해당 IP를 차단하세요."],
        "false_positive": "상대 경로를 쓰는 오래된 링크가 그대로 요청된 경우(드묾).",
    },
    "cmdi": {
        "label": "명령어 삽입", "level": 3,
        "what": "URL에 쉘 명령어·원격 코드 실행 구문이 있습니다. 예: ;cat /etc/passwd, ${jndi:ldap://...} (Log4Shell).",
        "causes": ["서버에서 명령을 실행시키려는 시도(RCE)", "알려진 취약점(Log4Shell, Spring4Shell 등) 자동 공격"],
        "actions": ["응답코드와 이후 같은 IP의 행동을 확인하세요.",
                    "사용 중인 프레임워크·라이브러리의 취약점 패치 여부를 확인하고 해당 IP를 차단하세요."],
        "false_positive": "거의 없음. 정상 서비스 URL에 쉘 구문이 들어가는 경우는 드뭅니다.",
    },
    "probe": {
        "label": "취약점/관리페이지 탐색", "level": 2,
        "what": "흔히 알려진 취약 파일·관리 페이지 경로를 요청했습니다. 예: /.env, /.git, /wp-login.php, /phpmyadmin.",
        "causes": ["자동 스캐너·봇이 인터넷의 서버를 무작위로 훑으며 노출된 파일을 찾는 행위(가장 흔함)"],
        "actions": ["대부분 404면 실제 피해는 없습니다. 반복되면 IP를 차단하세요.",
                    "200 응답이 있는 경로는 실제로 존재하는 파일이라는 뜻입니다. 외부에 노출되면 안 되는 것이면 즉시 삭제하거나 접근을 막으세요."],
        "false_positive": "서비스가 실제로 /graphql, swagger, .php 등을 쓰는 경우. config.json의 probe_ignore_paths에 등록하세요.",
    },
    "scanner": {
        "label": "스캐너 도구", "level": 2,
        "what": "User-Agent가 sqlmap, nikto, nmap, Censys 등 알려진 점검·스캔 도구입니다.",
        "causes": ["공격 전 정보 수집", "외부 보안 연구/노출 점검 서비스의 스캔"],
        "actions": ["같은 IP의 다른 탐지 항목(SQLi 등)이 함께 있는지 확인하세요.", "의도하지 않은 점검이면 IP를 차단하세요."],
        "false_positive": "사내 취약점 점검·승인된 모의해킹이면 정상입니다. 해당 IP를 allow_ips에 등록하세요.",
    },
    "method": {
        "label": "비정상 Method", "level": 2,
        "what": "허용 목록(GET/POST/HEAD/OPTIONS)에 없는 HTTP Method를 사용했습니다. 예: PUT, DELETE, CONNECT, PROPFIND.",
        "causes": ["프록시 악용(CONNECT), 파일 업로드(PUT) 시도 등 점검", "일부 스캐너의 확인 요청"],
        "actions": ["응답코드가 2xx인지 확인하세요. nginx가 해당 Method를 막고 있는지 설정을 점검하세요."],
        "false_positive": "REST API가 PUT/DELETE/PATCH를 정상 사용하는 경우. config.json의 allowed_methods에 추가하세요.",
    },
    "malformed": {
        "label": "깨진/바이너리 요청", "level": 1,
        "what": "HTTP 형식이 아닌 데이터가 들어왔습니다. 예: HTTP 포트(80)로 HTTPS(TLS) 연결 시도.",
        "causes": ["포트 스캔·프로토콜 탐지", "잘못 설정된 클라이언트"],
        "actions": ["단독이면 참고만 하세요. 반복되면 해당 IP를 확인하세요."],
        "false_positive": "HTTP/HTTPS 포트를 혼동한 정상 클라이언트.",
    },
    "rate": {
        "label": "과다 접속", "level": 2,
        "what": "짧은 시간에 정적 파일을 제외한 요청이 기준 이상 들어왔습니다. (기본: 60초에 300건)",
        "causes": ["크롤러·스크래핑, 서비스 거부(DoS) 시도, 무차별 대입 공격"],
        "actions": ["요청한 URL을 확인하세요. 같은 URL 반복이면 공격/크롤링일 가능성이 높습니다.",
                    "반복되면 IP 차단 또는 nginx limit_req 적용을 검토하세요."],
        "false_positive": "내부 시스템·모니터링 도구의 정상 호출. allow_ips에 등록하세요.",
    },
    "burst": {
        "label": "순간 집중 접속", "level": 1,
        "what": "1초에 정적 파일 제외 요청이 기준 이상 들어왔습니다. (기본: 1초에 30건)",
        "causes": ["자동화 도구, 크롤러", "정상 페이지 로딩 중 API 다수 호출"],
        "actions": ["단독이면 참고만 하세요."],
        "false_positive": "API를 한꺼번에 호출하는 정상 화면.",
    },
    "errors": {
        "label": "에러 다수", "level": 2,
        "what": "한 IP의 요청 중 4xx/5xx 에러 응답이 기준 이상이며 비율도 높습니다. (기본: 20건 이상, 50% 이상)",
        "causes": ["스캐너·무차별 대입 공격(대부분 실패)", "고장 난 클라이언트의 반복 호출"],
        "actions": ["어떤 에러(404/401/403/500)가 많은지 확인하세요. 404는 탐색, 401/403은 인증 공격, 500은 공격에 의한 서버 오류 가능성입니다."],
        "false_positive": "깨진 링크를 계속 재시도하는 정상 클라이언트.",
    },
    "notfound": {
        "label": "없는 경로 탐색", "level": 2,
        "what": "존재하지 않는 서로 다른 경로를 여러 개(기본 10종) 요청했습니다.",
        "causes": ["디렉터리 스캐닝, 취약 경로 사전 대입"],
        "actions": ["요청한 경로 목록을 확인하세요. 대부분 피해는 없으나 반복되면 IP를 차단하세요."],
        "false_positive": "사이트 개편 후 옛 URL을 한꺼번에 따라가는 검색엔진/사용자.",
    },
    "login_fail": {
        "label": "로그인 실패/오류 반복", "level": 2,
        "what": "로그인 관련 URL에서 에러 응답(4xx/5xx)이 반복됐습니다. (기본: 5건 이상)",
        "causes": ["비밀번호 무차별 대입, 계정 정보 대입(Credential Stuffing)"],
        "actions": ["애플리케이션 로그에서 해당 시간대의 로그인 실패 계정을 확인하세요.", "계정 잠금·CAPTCHA 적용 여부를 점검하고 IP를 차단하세요."],
        "false_positive": "사용자가 비밀번호를 여러 번 틀린 경우.",
    },
    "login_burst": {
        "label": "로그인 시도 과다", "level": 2,
        "what": "짧은 시간에 로그인 URL로 POST가 기준 이상 들어왔습니다. (기본: 10분에 20건)",
        "causes": ["무차별 대입 공격 자동화"],
        "actions": ["로그인 성공(200/302) 응답이 섞여 있는지, 해당 IP를 차단해야 하는지 확인하세요."],
        "false_positive": "공용 IP(회사 NAT)에서 다수 사용자가 로그인한 경우.",
    },
    "script": {
        "label": "스크립트/도구 접근", "level": 1,
        "what": "User-Agent가 curl, python-requests 등 브라우저가 아닌 프로그램입니다.",
        "causes": ["자동화 스크립트, 모니터링 도구, 크롤러"],
        "actions": ["단독이면 참고만 하세요. 다른 탐지 항목과 함께 나타나면 의심 수준이 올라갑니다."],
        "false_positive": "내부 연동·점검 도구. allow_ips에 등록하세요.",
    },
}
