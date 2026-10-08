"""탐지 엔진 (스트리밍 집계).

레코드를 한 줄씩 feed()로 넣으면 IP별 집계와 '요청 단위' 집계를 함께 쌓고,
result()에서 IP별 판정(ip 모드) 또는 요청 단위 판정(request 모드)을 만든다.
원본 로그를 메모리에 보관하지 않으므로 큰 파일도 처리할 수 있다.

위험도: 3=높음, 2=중간, 1=낮음
"""
import fnmatch
import heapq
import ipaddress
import re
from array import array
from collections import Counter
from urllib.parse import unquote_plus

from . import guide
from .geoip import PRIVATE, UNKNOWN, country_name, load_geo
from .netutil import is_internal, valid_ip  # noqa: F401  (is_internal은 테스트·호환용으로 재노출)
from .parser import IP, METHOD, PATH, QUERY, STATUS, TS, UA, XFF, _split_request

HIGH, MEDIUM, LOW = 3, 2, 1
LEVEL_LABEL = {HIGH: "높음", MEDIUM: "중간", LOW: "낮음", 0: "-"}

EVIDENCE_MAX = 30          # 항목별 근거 로그 보관 상한
SOFT_MAX = 10              # 에러/로그인 등 보조 근거 상한
FOREIGN_LIST_MAX = 2000    # 해외 접속만 있는 IP를 목록에 올리는 상한(요청 수가 많은 순)
URL_MAX = 300

# ---------------------------------------------------------------- URL 공격 패턴
ATTACK_RULES = [
    ("sqli", [
        # 주석(/* ... */)은 첫 */에서 반드시 끝나야 한다. (\s|/\*.*?\*/)+ 처럼 쓰면 같은 문자열을 나누는 방법이
        # 지수적으로 늘어 /**/ 를 반복한 URL 한 줄(400자)로 분석이 멈춘다(ReDoS).
        r"union(?:\s|/\*(?:[^*]|\*(?!/))*\*/)+(?:all(?:\s|/\*(?:[^*]|\*(?!/))*\*/)+)?select", r"'\s*(or|and)\s+['\"]?\w+['\"]?\s*(=|like)",
        r"\bor\s+1\s*=\s*1\b", r"sleep\(\s*\d+\s*\)", r"benchmark\(", r"waitfor\s+delay",
        r"information_schema", r"@@version", r"xp_cmdshell", r";\s*(drop|truncate|insert|delete|update)\s",
        r"extractvalue\(", r"updatexml\(", r"pg_sleep", r"dbms_pipe",
    ]),
    ("xss", [
        r"<\s*script", r"javascript:", r"\bon(error|load|mouseover|focus)\s*=", r"<\s*(svg|iframe|img|body)\b[^>]*\bon",
        r"document\.(cookie|domain)", r"\balert\s*\(", r"\bprompt\s*\(",
    ]),
    ("traversal", [
        r"\.\./", r"\.\.\\", r"/etc/(passwd|shadow|hosts)", r"win\.ini", r"boot\.ini", r"/proc/self",
        r"c:\\windows", r"(php|file|expect|data|zip|phar)://", r"\x00",
    ]),
    ("cmdi", [
        r"[;|`]\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|ping|nslookup)\b", r"\$\(\s*\w",
        r"/bin/(ba)?sh", r"cmd(\.exe)?\s*/c", r"powershell", r"\$\{jndi:", r"\$\{(env|sys|lower|upper|::)",
        r"class\.module\.classloader", r"%\{\(#",
    ]),
    ("probe", [
        r"/\.env\b", r"/\.git(/|$)", r"/\.svn/", r"/\.ds_store", r"/\.aws/", r"/\.htaccess", r"/\.htpasswd",
        r"/wp-(admin|login|content|includes)", r"/xmlrpc\.php", r"phpmyadmin", r"/pma/", r"adminer",
        r"/web\.config", r"/server-status", r"/actuator", r"/manager/html", r"/jmx-console", r"/invoker/",
        r"/console/login", r"/solr/", r"/cgi-bin/", r"/vendor/phpunit", r"/boaform", r"/hnap1",
        r"\.(bak|old|backup|orig|swp|sql|mdb)$", r"\.php\d?$",
        r"/(cmd|shell|webshell|c99|r57|wso|b374k)\.(jsp|jspx|asp|aspx|php)$", r"/autodiscover/",
        r"/owa/", r"/remote/login", r"/geoserver/", r"/telescope/", r"/_ignition/",
        r"swagger", r"api-docs", r"/jolokia", r"/druid/", r"/graphql", r"/\.well-known/security",
    ]),
]
# 정규식 검사 전 빠른 거르기용 문자열(소문자). 하나도 없으면 해당 규칙은 건너뛴다.
ATTACK_HINTS = {
    "sqli": ["union", "'", "or 1", "sleep(", "benchmark(", "waitfor", "information_schema", "@@version",
             "xp_cmdshell", ";", "extractvalue", "updatexml", "pg_sleep", "dbms_pipe"],
    "xss": ["<", "javascript:", "onerror", "onload", "onmouseover", "onfocus", "document.", "alert", "prompt"],
    "traversal": ["..", "/etc/", "win.ini", "boot.ini", "/proc/", "c:\\", "php://", "file://", "expect://",
                  "data://", "zip://", "phar://", "\x00"],
    "cmdi": [";", "|", "`", "$(", "/bin/", "cmd", "powershell", "${", "classloader", "%{"],
    "probe": ["/.", "wp-", "xmlrpc", "phpmyadmin", "/pma/", "adminer", "web.config", "server-status",
              "actuator", "manager/html", "jmx-console", "invoker", "console/login", "solr", "cgi-bin",
              "phpunit", "boaform", "hnap1", ".bak", ".old", ".backup", ".orig", ".swp", ".sql", ".mdb",
              ".php", "shell", "c99", "r57", "wso", "b374k", "autodiscover", "/owa/", "remote/login",
              "geoserver", "telescope", "_ignition", "swagger", "api-docs", "jolokia", "druid",
              "graphql", "/.well-known"],
}
_ATTACK_RE = [(k, re.compile("|".join("(?:%s)" % p for p in pats), re.I), ATTACK_HINTS[k])
              for k, pats in ATTACK_RULES]

SCANNER_UA = re.compile(
    r"sqlmap|nikto|nmap|masscan|zgrab|nuclei|acunetix|nessus|openvas|dirbuster|gobuster|dirb\b|wpscan|"
    r"hydra|wfuzz|ffuf|feroxbuster|whatweb|w3af|havij|netsparker|appscan|burp|owasp|zap/|jaeles|"
    r"censys|shodan|expanse|internet-measurement|l9explore|leakix|xpanse|nimbostratus|"
    r"odin\.io|httpx|projectdiscovery|fuzz|scanner|zmeu|morfeus", re.I)
SCRIPT_UA = re.compile(
    r"python-requests|python-urllib|aiohttp|curl/|wget/|go-http-client|libwww-perl|java/\d|"
    r"okhttp|httpclient|axios/|node-fetch|powershell|winhttp", re.I)

_AUTH_FAIL = frozenset((400, 401, 403, 422, 429))
_EXEC_EXT = re.compile(r"\.(jsp|jspx|php\d?|phtml|asp|aspx|cgi|pl|sh|exe|war)$", re.I)
_HEX_ESC = re.compile(r"\\x([0-9A-Fa-f]{2})")


MAX_URL_ANALYZE = 8192      # 이보다 긴 URL은 앞부분만 검사한다(nginx 요청 줄 기본 한도 8KB). 정규식 폭주의 이중 방어


def _decode(path, query):
    s = (path + ("?" + query if query else ""))[:MAX_URL_ANALYZE]
    if "\\x" in s:          # nginx가 비정상 바이트를 \xHH 문자열로 남긴 경우
        s = _HEX_ESC.sub(lambda m: chr(int(m.group(1), 16)), s)
    if "%" in s or "+" in s:
        try:
            s2 = unquote_plus(s)
            s = unquote_plus(s2) if "%" in s2 else s2   # 이중 인코딩 대응
        except Exception:
            pass
    return s


_ua_cache = {}
_url_cache = {}


def _ua_kind(ua):
    k = _ua_cache.get(ua)
    if k is None:
        k = "scanner" if SCANNER_UA.search(ua) else ("script" if SCRIPT_UA.search(ua) else "")
        if len(_ua_cache) > 100000:
            _ua_cache.clear()
        _ua_cache[ua] = k
    return k


class IpMatcher:
    """IP 문자열, CIDR(10.0.0.0/8), 와일드카드(198.51.*.*)를 섞은 목록의 포함 여부."""

    def __init__(self, items):
        self.exact, self.nets, self.pats = set(), [], []
        for it in items:
            it = str(it).strip()
            if not it:
                continue
            if "*" in it or "?" in it:
                self.pats.append(re.compile(fnmatch.translate(it.lower())))
            elif "/" in it:
                try:
                    self.nets.append(ipaddress.ip_network(it, strict=False))
                except ValueError:
                    pass
            else:
                self.exact.add(it)
        self._cache = {}

    def __bool__(self):
        return bool(self.exact or self.nets or self.pats)

    def __contains__(self, ip):
        if ip in self.exact:
            return True
        if not (self.nets or self.pats):
            return False
        v = self._cache.get(ip)
        if v is None:
            low = ip.lower()
            v = any(p.match(low) for p in self.pats)
            if not v and self.nets:
                try:
                    a = ipaddress.ip_address(ip)
                    v = any(a in n for n in self.nets)
                except ValueError:
                    v = False
            if len(self._cache) > 100000:
                self._cache.clear()
            self._cache[ip] = v
        return v


_valid_ip = valid_ip


def _max_window(times, window):
    """타임스탬프 목록에서 window초 구간 최대 건수와 시작 시각."""
    ts = sorted(times)
    best, best_t, j = 0, None, 0
    for i, t in enumerate(ts):
        while ts[j] <= t - window:
            j += 1
        if i - j + 1 > best:
            best, best_t = i - j + 1, ts[j]
    return best, best_t


def _is_static(path, static_ext):
    dot = path.rfind(".")
    if dot < 0 or dot < path.rfind("/"):
        return False
    return path[dot:].lower() in static_ext


def _proto_hint(method, path):
    """깨진 요청이 어떤 프로토콜을 노린 것인지 추정한다."""
    if method == "(TLS)":
        return "TLS(HTTPS)"
    head = path[:60]
    low = head.lower()
    for pref, name in guide.PROTO_HINTS:
        if (head.startswith(pref) if pref.startswith("*") else pref.lower() in low):
            return name
    return "기타"


def _extra_text(h, n=4):
    if not h.extra:
        return ""
    return " (" + ", ".join("%s %d건" % kv for kv in sorted(h.extra.items(), key=lambda kv: -kv[1])[:n]) + ")"


_ERR_RANK = {"emerg": 0, "alert": 1, "crit": 2, "error": 3, "warn": 4, "notice": 5, "info": 6, "debug": 7}
_ERR_OPS_LEVELS = ("emerg", "alert", "crit", "error")


def fmt_ts(ts):
    import time
    return "" if ts is None else time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))


class _Rows:
    """근거 로그 보관: 시각이 가장 이른 n건과 가장 늦은 n건만 둔다(파일·줄이 어떤 순서로 들어와도 같은 결과)."""
    __slots__ = ("n", "early", "late", "seq", "total")

    def __init__(self, n):
        self.n = n
        self.early = []      # 최대 힙(-시각): 가장 이른 n건
        self.late = []       # 최소 힙(시각): 가장 늦은 n건
        self.seq = 0
        self.total = 0

    def add(self, row):
        self.total += 1
        self.seq += 1
        ts, n = row[0], self.n
        if len(self.early) < n:
            heapq.heappush(self.early, (-ts, self.seq, row))
        elif ts < -self.early[0][0]:
            heapq.heapreplace(self.early, (-ts, self.seq, row))
        if len(self.late) < n:
            heapq.heappush(self.late, (ts, self.seq, row))
        elif ts > self.late[0][0]:
            heapq.heapreplace(self.late, (ts, self.seq, row))

    def items(self):
        """시각 오름차순 목록(중복 제거)."""
        seen, out = set(), []
        for _k, sq, r in self.early + self.late:
            if sq not in seen:
                seen.add(sq)
                out.append((r[0], sq, r))
        out.sort()
        return [r for _t, _s, r in out]


class _Hit:
    """규칙 하나의 누적 결과(건수, 2xx 응답 수, 상태코드 분포, 근거 로그)."""
    __slots__ = ("count", "success", "status", "rows", "ips", "level", "extra")

    def __init__(self):
        self.count = 0
        self.success = 0
        self.status = Counter()
        self.rows = _Rows(EVIDENCE_MAX)
        self.ips = set()
        self.level = 0       # 0이면 규칙 기본 등급 사용
        self.extra = {}      # 세부 분류(예: 프로토콜 이름) -> 건수


class _IpX:
    """드물게만 필요한 IP별 상세. 해당 요청이 나올 때만 만든다."""
    __slots__ = ("err_rows", "nf", "login_fail", "login_rows", "login_post", "script_n", "script_rows")

    def __init__(self):
        self.err_rows = None
        self.nf = None                # 404 경로 -> 근거 행
        self.login_fail = 0
        self.login_rows = None
        self.login_post = None        # 로그인 POST 시각(array)
        self.script_n = 0
        self.script_rows = None


_NO_X = _IpX()                        # 읽기 전용 빈 값(결과 계산 때 None 검사를 줄이기 위함)


class _IpAcc:
    """IP별 누적. 접속자는 많고 대부분 요청이 적으므로 필드를 최소로 두고 나머지는 필요할 때만 만든다."""
    __slots__ = ("n", "first", "last", "ok", "status", "ua", "ua_n", "ua_more", "dyn", "hits", "err", "x")

    def __init__(self):
        self.n = 0
        self.first = self.last = None
        self.ok = 0                   # 응답코드 200 건수 (가장 흔해서 dict를 만들지 않는다)
        self.status = None            # 200 이외 응답코드 -> 건수
        self.ua = None
        self.ua_n = 0
        self.ua_more = None
        self.dyn = None               # 정적 파일 제외 요청 시각: None / int(1건) / array
        self.hits = None              # 규칙 key -> _Hit
        self.err = 0
        self.x = None                 # _IpX

    def extra(self):
        x = self.x
        if x is None:
            x = self.x = _IpX()
        return x

    def user_agents(self):
        c = Counter(self.ua_more or {})
        if self.ua is not None:
            c[self.ua] += self.ua_n
        return c

    def statuses(self):
        c = Counter(self.status or {})
        if self.ok:
            c[200] += self.ok
        return c

    def dyn_times(self):
        d = self.dyn
        if d is None:
            return ()
        return (d,) if d.__class__ is int else d


class Analyzer:
    def __init__(self, cfg, geo=None):
        self.cfg = cfg
        self.geo = geo if geo is not None else load_geo(cfg)
        self.home = set(c.upper() for c in cfg["home_countries"])
        self.bots = [b.lower() for b in cfg["known_bots"] if b]
        self.allow = IpMatcher(cfg["allow_ips"])
        self.trusted = IpMatcher(cfg["trusted_proxies"])
        self.allowed_methods = set(m.upper() for m in cfg["allowed_methods"])
        self.rest_methods = set(m.upper() for m in cfg["rest_methods"])
        self.static_ext = set("." + e.lower().lstrip(".") for e in cfg["static_extensions"])
        self.login_re = re.compile(cfg["login_url_pattern"], re.I) if cfg["login_url_pattern"] else None
        self.ignore_re = [re.compile(p) for p in cfg["probe_ignore_paths"] if p]
        self.use_xff = bool(cfg["use_xff"])
        self.has_allow = bool(self.allow)
        self._trust_cache = {}
        self.total = 0
        self.allowed_skipped = 0
        self.xff_seen = 0
        self.xff_used = 0
        self.ips = {}
        self.glob = {}                # 요청 단위 집계 (IP 구분 불가 모드용)
        self.auto_proxies = {}        # 자동 판별된 LB/프록시 IP -> 요청 수
        self.first_ts = self.last_ts = None
        # 에러로그
        self._err_rules = [(k, re.compile(rx, re.I), kind, label, what, act) for k, rx, kind, label, what, act in guide.ERR_RULES]
        self.err_total = 0
        self.err_levels = {}
        self.err_noise = 0
        self.err_sec = 0
        self.ops = {}

    # ------------------------------------------------------------ 입력
    def _is_proxy(self, ip):
        v = self._trust_cache.get(ip)
        if v is None:
            a = _valid_ip(ip)
            v = bool(a and is_internal(a)) or ip in self.trusted or ip in self.auto_proxies
            if len(self._trust_cache) > 100000:
                self._trust_cache.clear()
            self._trust_cache[ip] = v
        return v

    def register_proxies(self, stats):
        """파일 하나의 접속 IP 통계(parser.LogReader.scan_proxies)로 LB/프록시를 자동 판별한다.

        요청 20건 이상, 90% 이상에 X-Forwarded-For가 붙고 값이 3종류 이상이면 프록시로 본다.
        화면에 목록을 보여주며 config.json의 auto_proxy=false로 끌 수 있다.
        """
        if not self.cfg.get("auto_proxy", True):
            return
        for ip, (n, nx, xs) in stats.items():
            if n >= 20 and nx / n >= 0.9 and len(xs) >= 3 and _valid_ip(ip) is not None and not self._is_proxy(ip):
                self.auto_proxies[ip] = n
        self._trust_cache.clear()

    def client_ip(self, rec):
        """접속 IP. 프록시가 보낸 X-Forwarded-For는 요청이 신뢰하는 프록시에서 왔을 때만 사용한다."""
        ip, xff = rec[IP], rec[XFF]
        if not xff:
            return ip
        self.xff_seen += 1
        if not self.use_xff or not self._is_proxy(ip):
            return ip
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        for p in reversed(parts):       # 오른쪽(가까운 쪽)부터, 신뢰하는 프록시는 건너뜀
            if _valid_ip(p) is None or self._is_proxy(p):
                continue
            self.xff_used += 1
            return p.strip("[]")
        if parts and _valid_ip(parts[0]):
            self.xff_used += 1
            return parts[0].strip("[]")
        return ip

    def _attack_kind(self, path, query):
        raw = path + "?" + query if query else path
        k = self._url_kind(raw, path, query)
        if k == "probe" and self.ignore_re and any(r.search(path) for r in self.ignore_re):
            return ""
        return k

    def _url_kind(self, raw, path, query):
        k = _url_cache.get(raw)
        if k is None:
            s = _decode(path, query)
            low = s.lower()
            k = ""
            for key, rx, hints in _ATTACK_RE:
                if any(h in low for h in hints) and rx.search(s):
                    k = key
                    break
            if len(_url_cache) > 100000:
                _url_cache.clear()
            _url_cache[raw] = k
        return k

    @staticmethod
    def _hit(store, key, row, status, ip=None):
        if isinstance(store, _IpAcc):
            if store.hits is None:
                store.hits = {}
            store = store.hits
        h = store.get(key)
        if h is None:
            h = store[key] = _Hit()
        h.count += 1
        if 200 <= status < 300:
            h.success += 1
        h.status[status] += 1
        h.rows.add(row)
        if ip is not None and len(h.ips) < 2000:
            h.ips.add(ip)
        return h

    def feed(self, rec):
        self.total += 1
        ip = rec[IP] if not rec[XFF] else self.client_ip(rec)
        if self.has_allow and ip in self.allow:
            self.allowed_skipped += 1
            return
        ts, method, path, query, status, ua = rec[TS], rec[METHOD], rec[PATH], rec[QUERY], rec[STATUS], rec[UA]
        if self.first_ts is None or ts < self.first_ts:
            self.first_ts = ts
        if self.last_ts is None or ts > self.last_ts:
            self.last_ts = ts
        a = self.ips.get(ip)
        if a is None:
            a = self.ips[ip] = _IpAcc()
        a.n += 1
        if a.first is None or ts < a.first:
            a.first = ts
        if a.last is None or ts > a.last:
            a.last = ts
        if status == 200:
            a.ok += 1
        else:
            d = a.status
            if d is None:
                d = a.status = {}
            d[status] = d.get(status, 0) + 1
        if a.ua is None:
            a.ua, a.ua_n = ua, 1
        elif ua == a.ua:
            a.ua_n += 1
        else:
            m = a.ua_more
            if m is None:
                m = a.ua_more = {}
            if ua in m or len(m) < 9:
                m[ua] = m.get(ua, 0) + 1

        proto_probe = method in ("(TLS)", "(INVALID)")   # HTTP가 아닌 데이터: URL 패턴 검사 대상이 아님
        kind = self._attack_kind(path, query) if (path or query) and not proto_probe else ""
        uk = _ua_kind(ua) if ua else ""
        bad_method = proto_probe or (method != "-" and method not in self.allowed_methods)
        # 프로토콜 스캔의 400 응답은 '깨진/바이너리 요청'으로 이미 집계하므로 에러 다수 규칙에서는 뺀다
        is_err = status >= 400 and status != 499 and not proto_probe
        nf = a.x.nf if a.x is not None else None
        is_404 = status == 404 and (nf is None or (path not in nf and len(nf) < 1000))
        dynamic = not _is_static(path, self.static_ext)
        login = dynamic and self.login_re is not None and self.login_re.search(path) is not None

        # 근거 행은 필요한 경우에만 만든다
        row = None
        if kind or uk or bad_method or is_err or is_404:
            row = (ts, ip, method, (path + "?" + query if query else path)[:URL_MAX], status, ua[:120])

        if kind:
            self._hit(a, kind, row, status)
            self._hit(self.glob, kind, row, status, ip)
        if uk == "scanner":
            self._hit(a, "scanner", row, status)
            self._hit(self.glob, "scanner", row, status, ip)
        elif uk == "script":
            x = a.extra()
            x.script_n += 1
            if x.script_rows is None:
                x.script_rows = _Rows(SOFT_MAX)
            x.script_rows.add(row)
        if bad_method:
            if proto_probe:
                key = "malformed"
            elif method in self.rest_methods and not _EXEC_EXT.search(path):
                key = "method_rest"      # PUT/DELETE/PATCH: API라면 정상. 실행 파일 확장자로 오면 업로드 시도라 '비정상 Method'
            else:
                key = "method"
            h1 = self._hit(a, key, row, status)
            h2 = self._hit(self.glob, key, row, status, ip)
            if key == "malformed":
                hint = _proto_hint(method, path)
                h1.extra[hint] = h1.extra.get(hint, 0) + 1
                h2.extra[hint] = h2.extra.get(hint, 0) + 1

        # 이하는 IP별 집계가 있어야 의미 있는 규칙
        if dynamic:
            d = a.dyn
            if d is None:
                a.dyn = ts
            elif d.__class__ is int:
                a.dyn = array("q", (d, ts))
            else:
                d.append(ts)
        if is_err:
            a.err += 1
            x = a.extra()
            if x.err_rows is None:
                x.err_rows = _Rows(SOFT_MAX)
            x.err_rows.add(row)
        if is_404:
            x = a.extra()
            if x.nf is None:
                x.nf = {}
            x.nf[path] = row
        if login:
            if status in _AUTH_FAIL:      # 5xx는 서버 장애일 가능성이 커서 인증 실패로 세지 않는다
                x = a.extra()
                x.login_fail += 1
                if x.login_rows is None:
                    x.login_rows = _Rows(SOFT_MAX)
                x.login_rows.add(row)
            if method == "POST":
                x = a.extra()
                if x.login_post is None:
                    x.login_post = array("q")
                x.login_post.append(ts)

    # ------------------------------------------------------------ 에러로그
    def feed_error(self, rec):
        ts, level, ip, core, req, _server = rec
        self.err_total += 1
        self.err_levels[level] = self.err_levels.get(level, 0) + 1
        if self.first_ts is None or ts < self.first_ts:
            self.first_ts = ts
        if self.last_ts is None or ts > self.last_ts:
            self.last_ts = ts
        rkey, kind, label, what, actions = "other", "other", "기타", "", ""
        for k, rx, kd, lb, wh, ac in self._err_rules:
            if rx.search(core):
                rkey, kind, label, what, actions = k, kd, lb, wh, ac
                break
        if kind == "other" and level in _ERR_OPS_LEVELS:
            kind, label = "ops", "기타 오류"
            rkey = "other:" + re.sub(r"\d+", "N", core)[:80]
        if kind == "ops":
            o = self.ops.get(rkey)
            if o is None and len(self.ops) < 60:
                o = self.ops[rkey] = {"label": label, "level": level, "count": 0, "first": ts, "last": ts,
                                      "sample": core[:200], "what": what, "actions": actions}
            if o is not None:
                o["count"] += 1
                o["first"], o["last"] = min(o["first"], ts), max(o["last"], ts)
                if _ERR_RANK.get(level, 9) < _ERR_RANK.get(o["level"], 9):
                    o["level"] = level
            return
        # 요청 URL에 공격 패턴이 있으면 연결 종료 같은 항목도 보안 신호로 본다
        atk = ""
        if req:
            _m, path, query = _split_request(req)
            atk = self._attack_kind(path, query) if path or query else ""
        if kind in ("noise", "nf", "other") and not atk:
            self.err_noise += 1
            return
        self.err_sec += 1
        ev_level = MEDIUM if (kind == "sec2" or atk) else LOW
        tag = label if not atk else "%s 패턴(%s)" % (guide.RULES[atk]["label"], label)
        row = (ts, ip, "(ERR)", (req or core)[:URL_MAX], 0, tag)
        targets = [(self.glob, ip or None)]
        if ip and not (self.has_allow and ip in self.allow):
            a = self.ips.get(ip)
            if a is None:
                a = self.ips[ip] = _IpAcc()
            if a.first is None or ts < a.first:
                a.first = ts
            if a.last is None or ts > a.last:
                a.last = ts
            targets.append((a, None))
        for store, ipv in targets:
            h = self._hit(store, "errlog", row, 0, ipv)
            h.level = max(h.level, ev_level)
            h.extra[tag] = h.extra.get(tag, 0) + 1

    def error_summary(self):
        if not self.err_total:
            return None
        ops = sorted(self.ops.values(), key=lambda o: (_ERR_RANK.get(o["level"], 9), -o["count"]))
        return {"total": self.err_total, "levels": dict(sorted(self.err_levels.items(), key=lambda kv: _ERR_RANK.get(kv[0], 9))),
                "noise": self.err_noise, "security": self.err_sec,
                "ops": [dict(o, first=fmt_ts(o["first"]), last=fmt_ts(o["last"])) for o in ops]}

    # ------------------------------------------------------------ 모드 판별
    def mode_info(self):
        """IP 구분이 믿을 만한지 판단한다 (LB 뒤 + X-Forwarded-For 없음 등)."""
        total = sum(a.n for a in self.ips.values())
        info = {"unreliable": False, "reason": "", "distinct_ips": len(self.ips),
                "xff_ratio": round(self.xff_used / self.total, 2) if self.total else 0.0}
        if total < 100 or info["xff_ratio"] >= 0.5:
            return info
        top_ip, top = max(((ip, a.n) for ip, a in self.ips.items()), key=lambda x: x[1])
        share = top / total
        ta = _valid_ip(top_ip)
        if share >= 0.8:
            info["reason"] = "요청의 %d%%가 한 IP(%s)에서 왔습니다." % (round(share * 100), top_ip)
        elif len(self.ips) <= 3:
            info["reason"] = "접속 IP가 %d개뿐입니다." % len(self.ips)
        elif share >= 0.5 and ta is not None and is_internal(ta):
            info["reason"] = "요청의 %d%%가 내부 IP(%s)에서 왔습니다." % (round(share * 100), top_ip)
        info["unreliable"] = bool(info["reason"])
        return info

    def resolve_mode(self, setting=None):
        setting = setting or self.cfg["ip_mode"]
        info = self.mode_info()
        if setting == "ip":
            used = "ip"
        elif setting == "none":
            used = "request"
        else:
            used = "request" if info["unreliable"] else "ip"
        return used, setting, info

    # ------------------------------------------------------------ 결과
    @staticmethod
    def _finding(key, level, desc, count, success, status, rows):
        return {"key": key, "label": guide.RULES[key]["label"], "level": level, "desc": desc,
                "count": count, "success": success, "status": dict(status.most_common(6)),
                "evidence": [_row_dict(r) for r in (rows.items() if isinstance(rows, _Rows) else rows)],
                "evidence_total": rows.total if isinstance(rows, _Rows) else len(rows)}

    def _hit_finding(self, key, h, desc):
        return self._finding(key, h.level or guide.RULES[key]["level"], desc, h.count, h.success, h.status, h.rows)

    def _ip_result(self, ip, a, build_foreign=False):
        """IP 하나의 탐지 결과. 해외 접속만 있는 IP는 build_foreign=False면 가벼운 표지만 돌려준다."""
        cfg = self.cfg
        fs = []
        hits = a.hits or {}
        for key in guide.REQUEST_LEVEL_KEYS:
            h = hits.get(key)
            if h:
                fs.append(self._hit_finding(key, h, "%s %d건%s" % (guide.RULES[key]["label"], h.count, _extra_text(h))))
        x = a.x or _NO_X
        if "scanner" not in hits and x.script_n >= max(5, a.n // 2):
            rows = x.script_rows.items() if x.script_rows else []
            fs.append(self._finding("script", LOW, "브라우저가 아닌 프로그램 접근 %d건 (%s)" % (
                x.script_n, rows[0][5][:60] if rows else ""), x.script_n, 0, Counter(r[4] for r in rows), rows))
        # 건수 조건을 못 채우는 IP는 시각 정렬 계산을 건너뛴다(대량 로그에서 속도 확보)
        dyn = a.dyn_times()
        if len(dyn) >= min(cfg["rate_max_requests"], cfg["burst_max"]):
            cnt, t0 = _max_window(dyn, cfg["rate_window_sec"])
            if cnt >= cfg["rate_max_requests"]:
                fs.append(self._finding("rate", MEDIUM, "%d초 동안 %d건 요청 (%s부터, 정적 파일 제외)" % (
                    cfg["rate_window_sec"], cnt, fmt_ts(t0)), cnt, 0, Counter(), []))
            else:
                bcnt, bt = _max_window(dyn, 1)
                if bcnt >= cfg["burst_max"]:
                    fs.append(self._finding("burst", LOW, "1초에 %d건 요청 (%s)" % (bcnt, fmt_ts(bt)),
                                            bcnt, 0, Counter(), []))
        if a.err >= cfg["error_min"] and a.err / a.n >= cfg["error_ratio"]:
            fs.append(self._finding("errors", MEDIUM, "전체 %d건 중 %d건(%.0f%%)이 에러 응답" % (
                a.n, a.err, 100.0 * a.err / a.n), a.err, 0,
                Counter({k: v for k, v in (a.status or {}).items() if k >= 400 and k != 499}), x.err_rows.items() if x.err_rows else []))
        if x.nf is not None and len(x.nf) >= cfg["notfound_distinct"]:
            fs.append(self._finding("notfound", MEDIUM, "존재하지 않는 경로 %d종 요청 (디렉터리 스캐닝 의심)" % len(x.nf),
                                    len(x.nf), 0, Counter({404: len(x.nf)}), _spread(x.nf.values(), EVIDENCE_MAX)))
        if x.login_fail >= cfg["login_fail_min"]:
            rows = x.login_rows.items() if x.login_rows else []
            fs.append(self._finding("login_fail", MEDIUM, "로그인 관련 요청 실패 %d건" % x.login_fail,
                                    x.login_fail, 0, Counter(r[4] for r in rows), rows))
        if x.login_post is not None and len(x.login_post) >= cfg["login_post_max"]:
            pc, _pt = _max_window(x.login_post, cfg["login_window_sec"])
            if pc >= cfg["login_post_max"]:
                fs.append(self._finding("login_burst", MEDIUM, "%d분 안에 로그인 POST %d건 (무차별 대입 의심)" % (
                    cfg["login_window_sec"] // 60, pc), pc, 0, Counter(), []))
        # 국가 판별: 국내(home_countries) 이외는 '해외'. 알려진 봇과 LB/프록시 자체는 제외한다.
        cc = self.geo.lookup(ip)
        foreign = cc not in self.home and cc not in (PRIVATE, UNKNOWN, "ZZ")
        uas = None
        if foreign and not (ip in self.auto_proxies or ip in self.trusted):
            uas = a.user_agents()
            if any(b in (u or "").lower() for u in uas for b in self.bots):
                foreign = False
        else:
            foreign = False
        if foreign:
            if x.login_post is not None and len(x.login_post):
                fs.append(self._finding("foreign_login", MEDIUM, "해외(%s)에서 로그인 관련 POST %d건" % (
                    country_name(cc), len(x.login_post)), len(x.login_post), 0, Counter(), []))
            if fs or build_foreign:
                fs.append(self._finding("foreign", LOW, "국가: %s, 요청 %d건" % (country_name(cc), a.n), a.n, 0, Counter(), []))
        if not fs:
            if foreign:                              # 해외 접속만 있는 IP: 목록에는 상위 N개만 올린다
                return {"level": 0, "foreign_only": True, "n": a.n}
            return {"level": 0}
        fs.sort(key=lambda f: (f["key"] == "foreign", -f["level"], -f["success"], -f["count"]))
        level = base = max(f["level"] for f in fs)
        other = max((f["level"] for f in fs if f["key"] != "foreign"), default=0)
        if foreign and other >= MEDIUM and level < HIGH:        # 해외 IP가 '중간' 이상 항목에 걸리면 한 단계 상향
            level += 1
        uas = uas if uas is not None else a.user_agents()
        return {
            "ip": ip, "level": level, "base_level": base, "level_label": LEVEL_LABEL[level],
            "country": cc, "country_name": country_name(cc), "foreign": foreign,
            "score": round(sum(f["level"] * 10 + min(f["count"], 100) / 10.0 for f in fs), 1),
            "requests": a.n, "errors": a.err, "first": fmt_ts(a.first), "last": fmt_ts(a.last),
            "success_warn": any(f["success"] and f["key"] in guide.SUCCESS_WARN_KEYS for f in fs),
            "findings": fs,
            "is_proxy": ip in self.auto_proxies or ip in self.trusted,
            "user_agent": uas.most_common(1)[0][0] if uas else "",
            "user_agents": uas.most_common(5),
            "statuses": a.statuses().most_common(8),
        }

    def result(self, setting=None):
        used, setting, info = self.resolve_mode(setting)
        res = {"mode": used, "setting": setting, "unreliable": info["unreliable"], "reason": info["reason"],
               "distinct_ips": len(self.ips), "xff_used": self.xff_used, "ips": [], "findings": [],
               "auto_proxies": [{"ip": ip, "requests": n} for ip, n in sorted(self.auto_proxies.items(), key=lambda kv: -kv[1])],
               "errorlog": self.error_summary(), "countries": [], "foreign_omitted": 0, "foreign_ips": 0,
               "geo": {"available": self.geo.available, "source": self.geo.source}}
        if used == "ip":
            ips, foreign_only, cstats = [], [], {}
            for ip, a in self.ips.items():
                r = self._ip_result(ip, a)
                cc = self.geo.lookup(ip)
                c = cstats.get(cc)
                if c is None:
                    c = cstats[cc] = [0, 0, 0]
                c[0] += a.n
                c[1] += 1
                if r["level"] >= MEDIUM:
                    c[2] += 1
                if r.get("foreign_only"):
                    foreign_only.append((r["n"], ip))
                elif r["level"]:
                    ips.append(r)
            with_findings = sum(1 for x in ips if x.get("foreign"))      # 다른 탐지 항목도 있는 해외 IP
            top = heapq.nlargest(FOREIGN_LIST_MAX, foreign_only)
            ips += [self._ip_result(ip, self.ips[ip], build_foreign=True) for _n, ip in top]
            res["foreign_omitted"] = len(foreign_only) - len(top)
            res["foreign_ips"] = len(foreign_only) + with_findings
            res["countries"] = [{"code": cc, "name": country_name(cc), "requests": v[0], "ips": v[1], "flagged": v[2],
                                 "foreign": cc not in self.home and cc not in (PRIVATE, UNKNOWN, "ZZ")}
                                for cc, v in sorted(cstats.items(), key=lambda kv: -kv[1][0])[:40]]
            res["home_countries"] = sorted(self.home)
            ips.sort(key=lambda x: (-x["level"], not x["success_warn"], -x["score"], -x["requests"]))
            res["ips"] = ips
            levels = Counter(x["level"] for x in ips)
        else:
            fs = []
            for key in guide.REQUEST_LEVEL_KEYS:
                h = self.glob.get(key)
                if h:
                    f = self._hit_finding(key, h, "%d건 (출처 IP %d개%s)%s" % (
                        h.count, len(h.ips), "+" if len(h.ips) >= 2000 else "", _extra_text(h)))
                    f["ips"] = len(h.ips)
                    fs.append(f)
            fs.sort(key=lambda f: (-f["level"], -f["success"], -f["count"]))
            res["findings"] = fs
            levels = Counter()
            for f in fs:
                levels[f["level"]] += 1
        high, med, low = levels.get(HIGH, 0), levels.get(MEDIUM, 0), levels.get(LOW, 0)
        alert = high + med > 0
        unit = "IP" if used == "ip" else "항목"
        if alert:
            text = "이상 징후 %d%s 발견 (높음 %d · 중간 %d)" % (high + med, unit, high, med)
        elif low:
            text = "이상 없음 (참고 %d%s)" % (low, unit)
        else:
            text = "이상 없음"
        res["verdict"] = {"status": "alert" if alert else "ok", "text": text,
                          "high": high, "medium": med, "low": low, "unit": unit}
        return res


def _spread(rows, n):
    """시각순으로 정렬해 가장 이른 n/2건과 가장 늦은 n/2건을 고른다."""
    rows = sorted(rows, key=lambda r: r[0])
    return rows if len(rows) <= n else rows[:n // 2] + rows[-(n // 2):]


def _row_dict(r):
    return {"ts": r[0], "time": fmt_ts(r[0]), "ip": r[1], "method": r[2], "url": r[3], "status": r[4], "ua": r[5]}
