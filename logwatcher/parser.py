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
_HAP_PREFIX = (r'^(?:<\d+>)?(?:[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d |\d{4}-\d\d-\d\d[T ]\S+ )?'
               r'(?:\S+ )?(?:\S+\[\d+\]: )?')
_HAP_HEAD = r'(\S+) \[(\d{2}/[A-Za-z]{3}/\d{4}:\d\d:\d\d:\d\d)(?:\.\d+)?\] (\S+) (\S+) '
_HAP_RE = re.compile(
    _HAP_PREFIX + _HAP_HEAD + r'[+-]?\d+/[+-]?\d+/[+-]?\d+/[+-]?\d+/[+-]?\d+ (-?\d+) \+?(\d+) \S+ \S+ \S{4} '
    r'\d+/\d+/\d+/\d+/\+?\d+ \d+/\d+(?: \{([^}]*)\})?(?: \{[^}]*\})? "(.*)"\s*$')
# option httplog가 아닌 tcplog: 요청 URL이 없어 분석할 수 없다
_HAP_TCP_RE = re.compile(_HAP_PREFIX + _HAP_HEAD + r'[+-]?\d+/[+-]?\d+/[+-]?\d+ \d+ \S{4} ')
# 접속 로그가 아닌 HAProxy 상태 줄: TLS 핸드셰이크 실패(접속 IP 있음), 서버 다운/복구, 프록시 시작·중지
_HAP_SSL_RE = re.compile(_HAP_PREFIX + _HAP_HEAD.split(r'(\S+) \[')[0] + r'(\S+) \[(\d{2}/[A-Za-z]{3}/\d{4}:\d\d:\d\d:\d\d)(?:\.\d+)?\] (\S+) SSL handshake failure')
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

    def _haproxy_event(self, line):
        """접속 로그가 아닌 상태 줄을 에러로그 형식 레코드(길이 6)로 바꾼다."""
        m = _HAP_SSL_RE.match(line)
        if m:
            cp, date, fe = m.group(1), m.group(2), m.group(3)
            ip = cp.rsplit(":", 1)[0].strip("[]") if ":" in cp else cp
            try:
                ts = _parse_clf_time(date + " +0000") + self.hap_shift
            except (KeyError, ValueError, IndexError):
                return None
            return (ts, "warn", ip, "SSL handshake failure (HAProxy)", "", fe)
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
        m = _HAP_RE.match(line)
        if not m:
            return self._haproxy_event(line)
        cp, date, _fe, _be, status, size, hdrs, req = m.groups()
        self._hap_ym = (int(date[7:11]), _MONTHS.get(date[3:6], 1))
        ip = cp.rsplit(":", 1)[0].strip("[]") if ":" in cp else cp
        try:
            # 접속 시각에는 시간대 표기가 없다: HAProxy 서버의 로컬 시간(haproxy_log_utc_offset_hours)
            ts = _parse_clf_time(date + " +0000") + self.hap_shift
        except (KeyError, ValueError, IndexError):
            return None
        ua = ""
        if hdrs:
            for h in hdrs.split("|"):
                if _HAP_UA_RE.search(h):
                    ua = h
                    break
        method, path, query = _split_request(req)
        st = int(status)
        return (ts, _intern(ip), method, path, query, st if st > 0 else 0, int(size), _intern(ua), "", "", "")

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


def detect_format(sample_lines):
    """파일 앞부분 줄들로 형식을 판별한다. 지원하지 않으면 ValueError."""
    lines = [l for l in sample_lines if l.strip()][:50]
    if not lines:
        raise ValueError("빈 파일입니다.")
    half = max(1, len(lines) // 2)
    if sum(1 for l in lines if _ERR_RE.match(l)) >= half:
        return FMT_ERROR
    if sum(1 for l in lines if _HAP_RE.match(l)) >= half:
        return FMT_HAPROXY
    if sum(1 for l in lines if _HAP_TCP_RE.match(l)) >= half:
        raise ValueError("HAProxy TCP 모드 로그는 요청 URL이 없어 분석할 수 없습니다. HTTP 모드(option httplog) 로그를 올려주세요.")
    if sum(1 for l in lines if l.lstrip().startswith("{")) >= half:
        if sum(1 for l in lines if LineParser(FMT_JSON).parse(l) is not None) >= half:
            return FMT_JSON
    elif sum(1 for l in lines if _BRACKET_RE.match(l)) >= half:
        return FMT_NGINX_BR
    elif sum(1 for l in lines if _NGINX_RE.match(l)) >= half:
        return FMT_NGINX
    raise ValueError("지원하지 않는 로그 형식입니다 (nginx 접근로그[combined·대괄호형·JSON], nginx error.log, HAProxy HTTP 로그만 지원).")


class LogReader:
    """파일을 한 줄씩 읽어 레코드를 내보낸다. 읽는 동안 info가 채워진다."""

    def __init__(self, path, display_offset_h=9, error_offset_h=9, haproxy_offset_h=9):
        self.path = path
        self.offset = display_offset_h
        self.error_offset = error_offset_h
        self.haproxy_offset = haproxy_offset_h
        self.info = {"lines": 0, "parsed": 0, "skipped": 0, "skipped_samples": [],
                     "first": None, "last": None, "format": "", "format_label": ""}
        with open_text(path) as f:
            head = []
            for raw in f:
                head.append(raw.decode("utf-8", "replace").rstrip("\r\n"))
                if len(head) >= 50:
                    break
        self.fmt = detect_format(head)
        self.kind = "error" if self.fmt == FMT_ERROR else "access"
        self.info["format"] = self.fmt
        self.info["format_label"] = FORMAT_LABEL[self.fmt]

    def scan_proxies(self):
        """접근 로그를 훑어 접속 IP별 (요청 수, XFF 포함 수, XFF 값 종류)를 센다. LB/프록시 자동 판별용."""
        stats = {}
        if self.kind != "access":
            return stats
        lp = LineParser(self.fmt, self.offset)
        with open_text(self.path) as f:
            for raw in f:
                r = lp.parse(raw.decode("utf-8", "replace").rstrip("\r\n"))
                if r is None or len(r) != 11:
                    continue
                st = stats.get(r[IP])
                if st is None:
                    st = stats[r[IP]] = [0, 0, set()]
                st[0] += 1
                if r[XFF]:
                    st[1] += 1
                    if len(st[2]) < 5:
                        st[2].add(r[XFF])
        return stats

    def records(self):
        lp = LineParser(self.fmt, self.offset, self.error_offset, self.haproxy_offset)
        info = self.info
        info.update(lines=0, parsed=0, skipped=0, skipped_samples=[], first=None, last=None)
        with open_text(self.path) as f:
            for raw in f:
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
