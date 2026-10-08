"""nginx 접근 로그 파서 (스트리밍).

지원 형식
- combined (nginx 기본), 뒤에 필드가 더 붙은 사용자 정의 log_format
    1.2.3.4 - - [08/Oct/2026:10:12:01 +0900] "GET / HTTP/1.1" 200 512 "-" "ua"
    마지막에 "X-Forwarded-For" 값이 따옴표로 붙어 있으면 함께 읽는다.
- JSON 한 줄 로그 (remote_addr, request, status ... 키를 느슨하게 인식)
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
FMT_JSON = "json"
FORMAT_LABEL = {FMT_NGINX: "nginx 접근로그", FMT_JSON: "nginx JSON 로그"}

# 레코드 튜플 인덱스
TS, IP, METHOD, PATH, QUERY, STATUS, BYTES, UA, REF, USER, XFF = range(11)

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_Q = r'"((?:[^"\\]|\\.)*)"'
_NGINX_RE = re.compile(
    r'^(\S+) \S+ (\S+) \[([^\]]+)\] ' + _Q + r' (\d{3}) (\S+)(?: ' + _Q + ' ' + _Q + r')?(.*)$')
_QUOTED_RE = re.compile(_Q)
_XFF_RE = re.compile(r'^[0-9A-Fa-f.:,\[\] ]+$')
_NGINX_ERRLOG_RE = re.compile(r'^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[(?:emerg|alert|crit|error|warn|notice|info|debug)\]')

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
    def __init__(self, fmt, display_offset_h=9):
        self.fmt = fmt
        self.offset = int(display_offset_h * 3600)

    def parse(self, line):
        return self._json(line) if self.fmt == FMT_JSON else self._nginx(line)

    def _nginx(self, line):
        m = _NGINX_RE.match(line)
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
    if any(_NGINX_ERRLOG_RE.match(l) for l in lines[:5]):
        raise ValueError("nginx error.log는 아직 지원하지 않습니다. 접근 로그(access.log)를 올려주세요.")
    half = max(1, len(lines) // 2)
    if sum(1 for l in lines if l.lstrip().startswith("{")) >= half:
        if sum(1 for l in lines if LineParser(FMT_JSON).parse(l) is not None) >= half:
            return FMT_JSON
    elif sum(1 for l in lines if _NGINX_RE.match(l)) >= half:
        return FMT_NGINX
    raise ValueError("지원하지 않는 로그 형식입니다 (nginx combined 형식 또는 JSON 로그만 지원).")


class LogReader:
    """파일을 한 줄씩 읽어 레코드를 내보낸다. 읽는 동안 info가 채워진다."""

    def __init__(self, path, display_offset_h=9):
        self.path = path
        self.offset = display_offset_h
        self.info = {"lines": 0, "parsed": 0, "skipped": 0, "skipped_samples": [],
                     "first": None, "last": None, "format": "", "format_label": ""}
        with open_text(path) as f:
            head = []
            for raw in f:
                head.append(raw.decode("utf-8", "replace").rstrip("\r\n"))
                if len(head) >= 50:
                    break
        self.fmt = detect_format(head)
        self.info["format"] = self.fmt
        self.info["format_label"] = FORMAT_LABEL[self.fmt]

    def records(self):
        lp = LineParser(self.fmt, self.offset)
        info = self.info
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
