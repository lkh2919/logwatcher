"""nginx 접근 로그 파서 (스트리밍).

지원 형식
- combined (nginx 기본), 뒤에 필드가 더 붙은 사용자 정의 log_format
    1.2.3.4 - - [08/Oct/2026:10:12:01 +0900] "GET / HTTP/1.1" 200 512 "-" "ua"
    마지막에 "X-Forwarded-For" 값이 따옴표로 붙어 있으면 함께 읽는다.
- 대괄호형 사용자 정의 log_format
    1.2.3.4 - - [08/Oct/2026:10:12:01 +0900] [request "GET / HTTP/1.1"] [status 200] [body_bytes_sent 512] "-" "ua" "xff"
- JSON 한 줄 로그 (remote_addr, request, status ... 키를 느슨하게 인식)
- HAProxy HTTP 로그(option httplog, syslog 접두 유무 모두). 실제 접속자 IP가 바로 찍힌다.
    Oct  8 10:12:01 lb haproxy[123]: 1.2.3.4:51234 [08/Oct/2026:10:12:01.123] fe be/s1 0/0/1/2/3 200 512 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"
- nginx error.log (보안 관련 항목과 서버 상태만 사용)
- .gz 압축 파일

모든 시각은 '표시 시간대(기본 KST) 기준 벽시계 초'로 저장한다. time.gmtime(ts)로 바로 표시 시각을 얻는다.
"""
import calendar
import gzip
import json
import os
import re
import sys
from datetime import datetime

FMT_NGINX = "nginx"
FMT_NGINX_BR = "nginx_bracket"
FMT_JSON = "json"
FMT_ERROR = "nginx_error"
FMT_HAPROXY = "haproxy"
FORMAT_LABEL = {FMT_HAPROXY: "HAProxy HTTP 로그", FMT_NGINX: "nginx 접근로그", FMT_NGINX_BR: "nginx 접근로그(대괄호형)",
                FMT_JSON: "nginx JSON 로그", FMT_ERROR: "nginx 에러로그"}

# 접근 로그 레코드 튜플 인덱스
TS, IP, METHOD, PATH, QUERY, STATUS, BYTES, UA, REF, USER, XFF = range(11)
# 에러 로그 레코드 튜플 인덱스
E_TS, E_LEVEL, E_IP, E_MSG, E_REQ, E_SERVER = range(6)

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_Q = r'"((?:[^"\\]|\\.)*)"'
_NGINX_RE = re.compile(
    r'^(\S+) \S+ (\S+) \[([^\]]+)\] ' + _Q + r' (\d{3}) (\S+)(?: ' + _Q + ' ' + _Q + r')?(.*)$')
_BRACKET_RE = re.compile(
    r'^(\S+) \S+ (\S+) \[([^\]]+)\] \[request ' + _Q + r'\] \[status (\d{3})\] \[body_bytes_sent (\d+)\]'
    r'(?: ' + _Q + ' ' + _Q + r')?(.*)$')
# HAProxy는 log-format을 바꾸거나 로그 일부를 잘라 쓰는 경우가 많아, 고정된 전체 형식 대신 필수 요소만 찾는다:
#   접속자 `IP:포트` + `[접속시각]` + 따옴표로 둘러싼 요청줄. 응답코드·바이트는 있으면 읽는다.
_HAP_DATE_RE = re.compile(r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d\d:\d\d:\d\d)(?:\.\d+)?\]')
_HAP_CLIENT_RE = re.compile(r'^\[?([0-9A-Fa-f.:]+?)\]?:(\d{1,5})$')
_HAP_REQ_RE = re.compile(r'"((?:[A-Z]{3,10} \S+(?: HTTP/\d(?:\.\d)?)?)|<[A-Z]+>)"')
_HAP_STATUS_RE = re.compile(r'(?:^|\s)[+-]?\d+(?:/[+-]?\d+){2,4}\s+(-?\d{1,3})\s+\+?(\d+)(?=\s|$)')
_HAP_STATUS_FALLBACK_RE = re.compile(r'(?:^|\s)(\d{3})\s+\+?(\d+)(?=\s|$)')
# option tcplog: 요청 URL이 없다. 타이머 3개 + 바이트
_HAP_TCP_RE = re.compile(r'\[\d{2}/[A-Za-z]{3}/\d{4}:[\d:.]+\]\s+\S+\s+\S+\s+[+-]?\d+/[+-]?\d+/[+-]?\d+\s+\d+\s')
# 접속 로그가 아닌 HAProxy 줄: TLS 실패(접속 IP 있음), 서버 다운/복구, 프록시 시작·중지
_HAP_SSL_RE = re.compile(r'^\s*\S+\s+(SSL handshake failure|Connection closed during SSL handshake|Timeout during SSL handshake)')
_HAP_EVT_RE = re.compile(r'^(?:<\d+>)?([A-Z][a-z]{2}) +(\d+) (\d\d):(\d\d):(\d\d) (?:\S+ )?\S+\[\d+\]: '
                         r'((?:Server \S+ is (?:DOWN|UP)|backend \S+ has no server available|Proxy \S+ (?:stopped|started)|Stopping|Pausing|Proxy \S+ .*stopped).*)$')
_HAP_UA_RE = re.compile(r'Mozilla|curl/|python|Go-http|okhttp|[Bb]ot\b|[Ss]pider|[Ss]canner|/\d')
_ERR_RE = re.compile(r'^(\d{4})/(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d) \[(\w+)\] \d+#\d+: (?:\*\d+ )?(.*)$')
_ERR_CLIENT_RE = re.compile(r'(?:client: |^client )([0-9A-Fa-f.:]+)')
_ERR_SERVER_RE = re.compile(r', server: ([^,]*)')
_ERR_REQ_SEPS = ('", upstream: "', '", host: "', '", referrer: "')
_QUOTED_RE = re.compile(_Q)
_XFF_RE = re.compile(r'^[0-9A-Fa-f.:,\[\] ]+$')

_intern = sys.intern


def _parse_clf_time(s):
    """08/Oct/2026:10:12:01 +0900 -> UTC epoch (ValueError/KeyError 가능)."""
    d, mon, y = int(s[0:2]), _MONTHS[s[3:6]], int(s[7:11])
    hh, mm, ss = int(s[12:14]), int(s[15:17]), int(s[18:20])
    tz = s[21:26]
    tzsec = 0
    if len(tz) == 5 and tz[0] in "+-":
        tzsec = (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60) * (-1 if tz[0] == "-" else 1)
    return calendar.timegm((y, mon, d, hh, mm, ss, 0, 0, 0)) - tzsec


def _parse_iso_time(s):
    """ISO8601 -> (epoch, naive 여부). 시간대 표기가 없으면 이미 표시 시간대의 시각으로 본다."""
    s = s.strip().replace("Z", "+00:00")
    s = re.sub(r"([+-]\d\d)(\d\d)$", r"\1:\2", s)
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)   # 마이크로초 초과 자릿수 제거(3.8 호환)
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        return calendar.timegm(dt.timetuple()), True
    return calendar.timegm(dt.utctimetuple()), False


def _split_request(req):
    """요청 줄 -> (method, path, query). nginx는 비정상 바이트를 \\xHH 문자열로 남긴다."""
    if req.startswith("\\x16\\x03"):
        return "(TLS)", "", ""            # HTTP 포트로 들어온 HTTPS(TLS) 연결
    if req == "-" or req == "":
        return "-", "", ""                # 요청 줄을 못 받은 연결(408 등): 정상 취급
    parts = req.split(" ")
    method = parts[0]
    if len(parts) >= 2 and method.isalpha() and method.isascii() and len(method) <= 16:
        path, _, query = parts[1].partition("?")
        return _intern(method.upper()), path, query
    return "(INVALID)", req[:200], ""


class LineParser:
    def __init__(self, fmt, display_offset_h=9, error_offset_h=9, haproxy_offset_h=9):
        self.fmt = fmt
        self.offset = int(display_offset_h * 3600)
        self.hap_shift = int((display_offset_h - haproxy_offset_h) * 3600)
        self._hap_ym = None      # 마지막으로 본 접속 로그의 (연, 월): 연도 없는 syslog 시각 보정용
        # 에러로그는 시간대 표기가 없다: 기록 시간대(error_offset_h) -> 표시 시간대로 변환
        self.err_shift = int((display_offset_h - error_offset_h) * 3600)
        self.rx = _BRACKET_RE if fmt == FMT_NGINX_BR else _NGINX_RE

    def parse(self, line):
        if self.fmt == FMT_JSON:
            return self._json(line)
        if self.fmt == FMT_ERROR:
            return self._error(line)
        if self.fmt == FMT_HAPROXY:
            return self._haproxy(line)
        return self._nginx(line)

    def _haproxy_split(self, line):
        """(접속자 IP, 접속 시각 문자열, 날짜 뒤 나머지) 또는 None."""
        m = _HAP_DATE_RE.search(line)
        if not m:
            return None
        head = line[:m.start()].split()
        cm = _HAP_CLIENT_RE.match(head[-1]) if head else None
        if not cm:
            return None
        return cm.group(1), m.group(1), line[m.end():]

    def _haproxy_event(self, line, parts=None):
        """접속 로그가 아닌 상태 줄을 에러로그 형식 레코드(길이 6)로 바꾼다."""
        parts = parts or self._haproxy_split(line)
        if parts:
            ip, date, rest = parts
            m = _HAP_SSL_RE.match(rest)
            if m:
                try:
                    ts = _parse_clf_time(date + " +0000") + self.hap_shift
                except (KeyError, ValueError, IndexError):
                    return None
                return (ts, "warn", ip, m.group(1) + " (HAProxy)", "", "")
        m = _HAP_EVT_RE.match(line)
        if not m:
            return None
        mon, day, hh, mm, ss, msg = m.groups()
        if mon not in _MONTHS:
            return None
        year, last_mon = self._hap_ym or (datetime.utcnow().year, _MONTHS[mon])
        if _MONTHS[mon] < last_mon - 6:
            year += 1       # 연말 -> 연초 넘어감
        try:
            ts = calendar.timegm((year, _MONTHS[mon], int(day), int(hh), int(mm), int(ss), 0, 0, 0)) + self.hap_shift
        except (ValueError, OverflowError):
            return None
        level = "alert" if ("DOWN" in msg or "no server" in msg) else "notice"
        return (ts, level, "", msg[:300], "", "")

    def _haproxy(self, line):
        parts = self._haproxy_split(line)
        if parts is None:
            return self._haproxy_event(line)
        ip, date, rest = parts
        rm = _HAP_REQ_RE.search(rest)
        if rm is None:
            return self._haproxy_event(line, parts)
        sm = _HAP_STATUS_RE.search(rest[:rm.start()]) or _HAP_STATUS_FALLBACK_RE.search(rest[:rm.start()])
        status, size = (int(sm.group(1)), int(sm.group(2))) if sm else (0, 0)
        try:
            self._hap_ym = (int(date[7:11]), _MONTHS[date[3:6]])
            # 접속 시각에는 시간대 표기가 없다: HAProxy 서버의 로컬 시간(haproxy_log_utc_offset_hours)
            ts = _parse_clf_time(date + " +0000") + self.hap_shift
        except (KeyError, ValueError, IndexError):
            return None
        req = rm.group(1)
        hdrs = ""
        hm = re.search(r"\{([^}]*)\}", rest[:rm.start()])     # 캡처한 요청 헤더(있을 때): Host|User-Agent 등
        if hm:
            hdrs = hm.group(1)
        ua = ""
        for h in hdrs.split("|") if hdrs else ():
            if _HAP_UA_RE.search(h):
                ua = h
                break
        if req == "<BADREQ>" and status == 408:
            method, path, query = "-", "", ""       # 연결만 하고 요청을 보내지 않아 타임아웃: 위협 아님
        else:
            method, path, query = _split_request(req)
        return (ts, _intern(ip), method, path, query, status if status > 0 else 0, size, _intern(ua), "", "", "")

    def _error(self, line):
        m = _ERR_RE.match(line)
        if not m:
            return None
        y, mo, d, hh, mm, ss, level, msg = m.groups()
        try:
            ts = calendar.timegm((int(y), int(mo), int(d), int(hh), int(mm), int(ss), 0, 0, 0)) + self.err_shift
        except (ValueError, OverflowError):
            return None
        req = ""
        i = msg.find(', request: "')
        core = msg
        if i >= 0:
            rest = msg[i + 12:]
            cut = [rest.find(sep) for sep in _ERR_REQ_SEPS if sep in rest]
            rest = rest[:min(cut)] if cut else rest.rstrip('"')
            req, core = rest, msg[:i]
        c = _ERR_CLIENT_RE.search(core)
        sv = _ERR_SERVER_RE.search(msg)
        return (ts, level, c.group(1) if c else "", core[:300], req[:300], sv.group(1) if sv else "")

    def _nginx(self, line):
        m = self.rx.match(line)
        if not m:
            return None
        ip, user, ts_s, req, status, size, ref, ua, rest = m.groups()
        try:
            ts = _parse_clf_time(ts_s) + self.offset
        except (KeyError, ValueError, IndexError):
            return None
        xff = ""
        if rest:
            for q in _QUOTED_RE.findall(rest):
                if q != "-" and _XFF_RE.match(q):
                    xff = q
                    break
        method, path, query = _split_request(req)
        return (ts, _intern(ip), method, path, query, int(status),
                int(size) if size.isdigit() else 0,
                _intern(ua) if ua and ua != "-" else "",
                _intern(ref) if ref and ref != "-" else "",
                _intern(user) if user and user != "-" else "", xff)

    def _json(self, line):
        try:
            d = json.loads(line)
        except ValueError:
            return None
        if not isinstance(d, dict):
            return None

        def g(*names):
            for n in names:
                v = d.get(n)
                if v not in (None, "", "-"):
                    return v
            return ""

        ip = str(g("remote_addr", "client_ip", "clientip", "ip", "client"))
        if not ip:
            return None
        t = g("time_iso8601", "time_local", "time", "@timestamp", "timestamp", "msec")
        try:
            if isinstance(t, (int, float)):
                ts = int(t) + self.offset
            elif isinstance(t, str) and re.match(r"^\d{2}/[A-Za-z]{3}/\d{4}:", t):
                ts = _parse_clf_time(t) + self.offset
            elif isinstance(t, str) and re.match(r"^\d+(\.\d+)?$", t):
                ts = int(float(t)) + self.offset
            else:
                ts, naive = _parse_iso_time(str(t))
                if not naive:
                    ts += self.offset
        except (KeyError, ValueError, IndexError):
            return None
        req = g("request", "req")
        if req:
            method, path, query = _split_request(str(req))
        else:
            uri = str(g("request_uri", "uri", "url"))
            path, _, query = uri.partition("?")
            method = str(g("request_method", "method") or "-").upper()
        status = str(g("status", "response_code", "sc_status"))
        size = str(g("body_bytes_sent", "bytes_sent", "bytes", "size"))
        ua = str(g("http_user_agent", "user_agent", "agent", "ua"))
        ref = str(g("http_referer", "referer", "referrer"))
        user = str(g("remote_user", "user"))
        xff = str(g("http_x_forwarded_for", "x_forwarded_for", "xff"))
        if xff and not _XFF_RE.match(xff):
            xff = ""
        return (ts, _intern(ip), _intern(method), path, query,
                int(status) if status.isdigit() else 0, int(size) if size.isdigit() else 0,
                _intern(ua), _intern(ref), _intern(user), xff)


def open_text(path):
    """.gz 여부를 매직 바이트로 판별해 바이너리 줄 단위 파일 객체를 연다."""
    with open(path, "rb") as f:
        magic = f.read(2)
    return gzip.open(path, "rb") if magic == b"\x1f\x8b" else open(path, "rb")


def _count_matches(lines):
    """형식별로 몇 줄이 맞는지 센다."""
    hp = LineParser(FMT_HAPROXY)
    js = LineParser(FMT_JSON)
    c = {FMT_ERROR: 0, FMT_HAPROXY: 0, FMT_JSON: 0, FMT_NGINX_BR: 0, FMT_NGINX: 0, "haproxy_tcp": 0}
    for l in lines:
        if _ERR_RE.match(l):
            c[FMT_ERROR] += 1
        elif l.lstrip().startswith("{"):
            c[FMT_JSON] += js.parse(l) is not None
        elif _BRACKET_RE.match(l):
            c[FMT_NGINX_BR] += 1
        elif _NGINX_RE.match(l):
            c[FMT_NGINX] += 1
        else:
            r = hp.parse(l)
            if r is not None and len(r) == 11:
                c[FMT_HAPROXY] += 1
            elif r is None and _HAP_TCP_RE.search(l):
                c["haproxy_tcp"] += 1
    return c


def detect_format(sample_lines):
    """파일 앞부분 줄들로 형식을 판별한다. 지원하지 않으면 ValueError.

    일부를 잘라낸 로그도 읽을 수 있도록, 앞부분의 절반이 아니라 '가장 많이 맞는 형식'을
    (전체의 20% 이상일 때) 고른다. 상태 줄이나 깨진 줄이 섞여 있어도 판별된다.
    """
    lines = [l for l in sample_lines if l.strip()][:300]
    if not lines:
        raise ValueError("빈 파일입니다.")
    c = _count_matches(lines)
    best = max((FMT_ERROR, FMT_HAPROXY, FMT_JSON, FMT_NGINX_BR, FMT_NGINX), key=lambda k: c[k])
    if c[best] >= max(1, len(lines) // 5):
        return best
    if c["haproxy_tcp"]:
        raise ValueError("HAProxy TCP 모드 로그는 요청 URL이 없어 분석할 수 없습니다. HTTP 모드(option httplog) 로그를 올려주세요.")
    raise ValueError("지원하지 않는 로그 형식입니다 (nginx 접근로그[combined·대괄호형·JSON], nginx error.log, HAProxy HTTP 로그만 지원). "
                     "첫 줄: " + lines[0][:120])


BLOCK_LINES = 2048            # 시각 색인 단위(줄 수): 분석 범위 밖 블록은 읽지도 파싱하지도 않는다
SAMPLE_BYTES = 40_000_000     # 이 크기까지는 모든 줄을 파싱해 LB 통계를 구하고, 더 크면 일부 줄만 표본으로 쓴다

_MON_B = {m.encode(): i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
_FAST_ACCESS_RE = re.compile(rb"\[(\d\d)/([A-Za-z]{3})/(\d{4}):(\d\d):(\d\d):(\d\d)(?: ([+-])(\d\d)(\d\d))?[\].]")
_FAST_ERROR_RE = re.compile(rb"^(\d{4})/(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d) \[")


class _FastTS:
    """줄에서 시각만 정규식으로 뽑는다(디코딩·전체 파싱 없이). LineParser와 같은 값을 돌려준다.

    JSON처럼 시각 위치가 고정되지 않은 형식은 None을 돌려주고 호출자가 전체 파싱으로 처리한다.
    """

    def __init__(self, fmt, display_offset_h, error_offset_h, haproxy_offset_h):
        self.fmt = fmt
        self.off = int(display_offset_h * 3600)
        self.hap = int((display_offset_h - haproxy_offset_h) * 3600)
        self.err = int((display_offset_h - error_offset_h) * 3600)
        self.days = {}
        self.enabled = fmt != FMT_JSON

    def _midnight(self, y, mo, d):
        k = (y, mo, d)
        v = self.days.get(k)
        if v is None:
            v = self.days[k] = calendar.timegm((y, mo, d, 0, 0, 0, 0, 0, 0))
        return v

    def ts(self, raw):
        try:
            if self.fmt == FMT_ERROR:
                m = _FAST_ERROR_RE.match(raw)
                if not m:
                    return None
                y, mo, d, hh, mm, ss = map(int, m.groups())
                return self._midnight(y, mo, d) + hh * 3600 + mm * 60 + ss + self.err
            m = _FAST_ACCESS_RE.search(raw)
            if not m:
                return None
            d, mon, y, hh, mm, ss, sign, th, tm = m.groups()
            tz = 0
            if sign:
                tz = (int(th) * 3600 + int(tm) * 60) * (-1 if sign == b"-" else 1)
            t = self._midnight(int(y), _MON_B[mon], int(d)) + int(hh) * 3600 + int(mm) * 60 + int(ss) - tz
            return t + (self.hap if self.fmt == FMT_HAPROXY else self.off)
        except (KeyError, ValueError, OverflowError):
            return None


class LogReader:
    """로그 파일 하나를 읽는다.

    scan()  : 업로드 때 한 번. 형식·줄 수·기간(info)과 시각 블록 색인, LB 판별용 통계를 만든다.
    records(cutoff) : 분석 때. cutoff보다 오래된 블록은 건너뛰고(평문 파일은 seek) 레코드를 내보낸다.
    """

    def __init__(self, path, display_offset_h=9, error_offset_h=9, haproxy_offset_h=9):
        self.path = path
        self.offset = display_offset_h
        self.error_offset = error_offset_h
        self.haproxy_offset = haproxy_offset_h
        self.info = {"lines": 0, "parsed": 0, "skipped": 0, "skipped_samples": [],
                     "first": None, "last": None, "format": "", "format_label": ""}
        self.blocks = []          # [(바이트 오프셋, 줄 수, 읽은 줄 수, 최소 시각, 최대 시각), ...]
        with open(path, "rb") as f:
            self.gz = f.read(2) == b"\x1f\x8b"
        with open_text(path) as f:
            head = []
            for raw in f:
                head.append(raw.decode("utf-8", "replace").rstrip("\r\n"))
                if len(head) >= 300:
                    break
        self.fmt = detect_format(head)
        self.kind = "error" if self.fmt == FMT_ERROR else "access"
        self.info["format"] = self.fmt
        self.info["format_label"] = FORMAT_LABEL[self.fmt]

    def _parser(self):
        return LineParser(self.fmt, self.offset, self.error_offset, self.haproxy_offset)

    def scan(self):
        """파일을 한 번 훑는다. 반환: LB/프록시 판별용 {접속 IP: [요청 수, XFF 포함 수, XFF 값 종류]}.

        XFF가 붙은 IP만 기록하므로 메모리가 거의 들지 않는다. 큰 파일은 일부 줄만 표본으로 파싱해
        (요청 수는 표본 비율만큼 환산) 시간을 줄인다.
        """
        lp = self._parser()
        fast = _FastTS(self.fmt, self.offset, self.error_offset, self.haproxy_offset)
        info = self.info
        info.update(lines=0, parsed=0, skipped=0, skipped_samples=[], first=None, last=None)
        size = os.path.getsize(self.path) * (8 if self.gz else 1)
        step = max(1, size // SAMPLE_BYTES) if self.kind == "access" else 0
        stats, blocks, cur = {}, [], None
        idx = offset = 0
        with open_text(self.path) as f:
            for raw in f:
                if idx % BLOCK_LINES == 0:
                    cur = [offset, 0, 0, None, None]
                    blocks.append(cur)
                idx += 1
                cur[1] += 1
                offset += len(raw)
                if not raw.strip():
                    continue
                info["lines"] += 1
                ts = fast.ts(raw) if fast.enabled else None
                rec = None
                if ts is None or (step and info["lines"] % step == 0):
                    line = raw.decode("utf-8", "replace").rstrip("\r\n")
                    rec = lp.parse(line)
                    if rec is None and ts is None:
                        info["skipped"] += 1
                        if len(info["skipped_samples"]) < 5:
                            info["skipped_samples"].append(line[:300])
                        continue
                    if ts is None:
                        ts = rec[TS]
                info["parsed"] += 1
                cur[2] += 1
                if cur[3] is None or ts < cur[3]:
                    cur[3] = ts
                if cur[4] is None or ts > cur[4]:
                    cur[4] = ts
                if rec is not None and len(rec) == 11 and step:
                    st = stats.get(rec[IP])
                    if st is None and rec[XFF]:
                        st = stats[rec[IP]] = [0, 0, set()]
                    if st is not None:
                        st[0] += 1
                        if rec[XFF]:
                            st[1] += 1
                            if len(st[2]) < 5:
                                st[2].add(rec[XFF])
        self.blocks = [tuple(b) for b in blocks]
        mins = [b[3] for b in self.blocks if b[3] is not None]
        maxs = [b[4] for b in self.blocks if b[4] is not None]
        info["first"] = min(mins) if mins else None
        info["last"] = max(maxs) if maxs else None
        for st in stats.values():
            st[0] *= step
            st[1] *= step
        return stats

    @staticmethod
    def _skippable(block, cutoff):
        return block[4] is None or block[4] < cutoff

    def _read(self, f, lp, n_lines):
        """현재 위치에서 최대 n_lines줄(None이면 끝까지)을 읽어 레코드를 내보낸다."""
        info = self.info
        count = 0
        while n_lines is None or count < n_lines:
            raw = f.readline()
            if not raw:
                return
            count += 1
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if not line.strip():
                continue
            info["lines"] += 1
            r = lp.parse(line)
            if r is None:
                info["skipped"] += 1
                if len(info["skipped_samples"]) < 5:
                    info["skipped_samples"].append(line[:300])
                continue
            info["parsed"] += 1
            ts = r[TS]
            if info["first"] is None or ts < info["first"]:
                info["first"] = ts
            if info["last"] is None or ts > info["last"]:
                info["last"] = ts
            yield r

    def records(self, cutoff=None):
        """레코드를 내보낸다. cutoff(표시 시간대 기준 시각)가 주어지면 그보다 오래된 블록은 건너뛴다.

        블록 안에는 cutoff보다 오래된 레코드가 섞여 있을 수 있으므로 호출자가 한 번 더 걸러야 한다.
        """
        lp = self._parser()
        self.info.update(lines=0, parsed=0, skipped=0, skipped_samples=[], first=None, last=None)
        blocks = self.blocks
        with open_text(self.path) as f:
            if cutoff is None or not blocks:
                yield from self._read(f, lp, None)
                return
            i, nb = 0, len(blocks)
            while i < nb:
                if not self._skippable(blocks[i], cutoff):
                    yield from self._read(f, lp, blocks[i][1])
                    i += 1
                    continue
                j = i + 1                                   # 건너뛸 블록을 한꺼번에 묶는다
                while j < nb and self._skippable(blocks[j], cutoff):
                    j += 1
                if j >= nb:
                    return
                if self.gz:                                 # 압축 파일은 seek가 느려 읽기만 하고 파싱은 하지 않는다
                    for _ in range(sum(b[1] for b in blocks[i:j])):
                        f.readline()
                else:
                    f.seek(blocks[j][0])
                i = j
