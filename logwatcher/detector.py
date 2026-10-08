"""탐지 엔진 (스트리밍 집계).

레코드를 한 줄씩 feed()로 넣으면 IP별 집계와 '요청 단위' 집계를 함께 쌓고,
result()에서 IP별 판정(ip 모드) 또는 요청 단위 판정(request 모드)을 만든다.
원본 로그를 메모리에 보관하지 않으므로 큰 파일도 처리할 수 있다.

위험도: 3=높음, 2=중간, 1=낮음
"""
import ipaddress
import re
from array import array
from collections import Counter
from urllib.parse import unquote_plus

from . import guide
from .parser import IP, METHOD, PATH, QUERY, STATUS, TS, UA, XFF

HIGH, MEDIUM, LOW = 3, 2, 1
LEVEL_LABEL = {HIGH: "높음", MEDIUM: "중간", LOW: "낮음", 0: "-"}

EVIDENCE_MAX = 30          # 항목별 근거 로그 보관 상한
SOFT_MAX = 10              # 에러/로그인 등 보조 근거 상한
URL_MAX = 300

# ---------------------------------------------------------------- URL 공격 패턴
ATTACK_RULES = [
    ("sqli", [
        r"union(\s|/\*.*?\*/)+(all\s+)?select", r"'\s*(or|and)\s+['\"]?\w+['\"]?\s*(=|like)",
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

_HEX_ESC = re.compile(r"\\x([0-9A-Fa-f]{2})")


def _decode(path, query):
    s = path + ("?" + query if query else "")
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
    """IP 문자열 또는 CIDR 목록 포함 여부."""

    def __init__(self, items):
        self.exact, self.nets = set(), []
        for it in items:
            it = str(it).strip()
            if not it:
                continue
            if "/" in it:
                try:
                    self.nets.append(ipaddress.ip_network(it, strict=False))
                except ValueError:
                    pass
            else:
                self.exact.add(it)
        self._cache = {}

    def __contains__(self, ip):
        if ip in self.exact:
            return True
        if not self.nets:
            return False
        v = self._cache.get(ip)
        if v is None:
            try:
                a = ipaddress.ip_address(ip)
                v = any(a in n for n in self.nets)
            except ValueError:
                v = False
            if len(self._cache) > 100000:
                self._cache.clear()
            self._cache[ip] = v
        return v


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "::1/128", "fc00::/7", "fe80::/10")]


def is_internal(addr):
    """내부망/프록시로 볼 주소 (RFC1918, 루프백, 링크로컬, CGNAT, IPv6 ULA). 문서용 대역은 포함하지 않는다."""
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in n for n in _INTERNAL_NETS if n.version == addr.version)


def _valid_ip(s):
    try:
        return ipaddress.ip_address(s.strip("[]"))
    except ValueError:
        return None


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


def fmt_ts(ts):
    import time
    return "" if ts is None else time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))


class _Hit:
    """규칙 하나의 누적 결과(건수, 2xx 응답 수, 상태코드 분포, 근거 로그)."""
    __slots__ = ("count", "success", "status", "rows", "ips", "first_ua")

    def __init__(self):
        self.count = 0
        self.success = 0
        self.status = Counter()
        self.rows = []
        self.ips = set()
        self.first_ua = ""


class _IpAcc:
    """IP별 누적. 대부분의 IP는 요청이 적으므로 컨테이너는 필요할 때만 만든다(메모리 절약)."""
    __slots__ = ("n", "first", "last", "status", "ua", "ua_n", "ua_more", "dyn", "hits", "err", "err_rows",
                 "nf", "login_fail", "login_rows", "login_post", "script_n", "script_rows")

    def __init__(self):
        self.n = 0
        self.first = self.last = None
        self.status = {}
        self.ua = None
        self.ua_n = 0
        self.ua_more = None
        self.dyn = None               # 정적 파일 제외 요청 시각(array)
        self.hits = None              # 규칙 key -> _Hit
        self.err = 0
        self.err_rows = None
        self.nf = None                # 404 경로 -> 근거 행
        self.login_fail = 0
        self.login_rows = None
        self.login_post = None
        self.script_n = 0
        self.script_rows = None

    def user_agents(self):
        c = Counter(self.ua_more or {})
        if self.ua is not None:
            c[self.ua] += self.ua_n
        return c


class Analyzer:
    def __init__(self, cfg):
        self.cfg = cfg
        self.allow = IpMatcher(cfg["allow_ips"])
        self.trusted = IpMatcher(cfg["trusted_proxies"])
        self.allowed_methods = set(m.upper() for m in cfg["allowed_methods"])
        self.static_ext = set("." + e.lower().lstrip(".") for e in cfg["static_extensions"])
        self.login_re = re.compile(cfg["login_url_pattern"], re.I) if cfg["login_url_pattern"] else None
        self.ignore_re = [re.compile(p) for p in cfg["probe_ignore_paths"] if p]
        self.use_xff = bool(cfg["use_xff"])
        self.has_allow = bool(self.allow.exact or self.allow.nets)
        self._trust_cache = {}
        self.total = 0
        self.allowed_skipped = 0
        self.xff_seen = 0
        self.xff_used = 0
        self.ips = {}
        self.glob = {}                # 요청 단위 집계 (IP 구분 불가 모드용)

    # ------------------------------------------------------------ 입력
    def _is_proxy(self, ip):
        v = self._trust_cache.get(ip)
        if v is None:
            a = _valid_ip(ip)
            v = bool(a and is_internal(a)) or ip in self.trusted
            if len(self._trust_cache) > 100000:
                self._trust_cache.clear()
            self._trust_cache[ip] = v
        return v

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
            if len(_url_cache) > 300000:
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
        if len(h.rows) < EVIDENCE_MAX:
            h.rows.append(row)
        if ip is not None and len(h.ips) < 2000:
            h.ips.add(ip)

    def feed(self, rec):
        self.total += 1
        ip = rec[IP] if not rec[XFF] else self.client_ip(rec)
        if self.has_allow and ip in self.allow:
            self.allowed_skipped += 1
            return
        ts, method, path, query, status, ua = rec[TS], rec[METHOD], rec[PATH], rec[QUERY], rec[STATUS], rec[UA]
        a = self.ips.get(ip)
        if a is None:
            a = self.ips[ip] = _IpAcc()
        a.n += 1
        if a.first is None or ts < a.first:
            a.first = ts
        if a.last is None or ts > a.last:
            a.last = ts
        a.status[status] = a.status.get(status, 0) + 1
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

        kind = self._attack_kind(path, query) if path or query else ""
        uk = _ua_kind(ua) if ua else ""
        bad_method = method in ("(TLS)", "(INVALID)") or (method != "-" and method not in self.allowed_methods)
        is_err = status >= 400 and status != 499
        is_404 = status == 404 and (a.nf is None or (path not in a.nf and len(a.nf) < 1000))
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
            a.script_n += 1
            if a.script_rows is None:
                a.script_rows = []
            if len(a.script_rows) < SOFT_MAX:
                a.script_rows.append(row)
        if bad_method:
            key = "malformed" if method in ("(TLS)", "(INVALID)") else "method"
            self._hit(a, key, row, status)
            self._hit(self.glob, key, row, status, ip)

        # 이하는 IP별 집계가 있어야 의미 있는 규칙
        if dynamic:
            if a.dyn is None:
                a.dyn = array("q")
            a.dyn.append(ts)
        if is_err:
            a.err += 1
            if a.err_rows is None:
                a.err_rows = []
            if len(a.err_rows) < SOFT_MAX:
                a.err_rows.append(row)
        if is_404:
            if a.nf is None:
                a.nf = {}
            a.nf[path] = row
        if login:
            if is_err:
                a.login_fail += 1
                if a.login_rows is None:
                    a.login_rows = []
                if len(a.login_rows) < SOFT_MAX:
                    a.login_rows.append(row)
            if method == "POST":
                if a.login_post is None:
                    a.login_post = array("q")
                a.login_post.append(ts)

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
                "evidence": [_row_dict(r) for r in rows]}

    def _hit_finding(self, key, h, desc):
        return self._finding(key, guide.RULES[key]["level"], desc, h.count, h.success, h.status, h.rows)

    def _ip_result(self, ip, a):
        cfg = self.cfg
        fs = []
        hits = a.hits or {}
        for key in guide.REQUEST_LEVEL_KEYS:
            h = hits.get(key)
            if h:
                fs.append(self._hit_finding(key, h, "%s %d건" % (guide.RULES[key]["label"], h.count)))
        if "scanner" not in hits and a.script_n >= max(5, a.n // 2):
            rows = a.script_rows or []
            fs.append(self._finding("script", LOW, "브라우저가 아닌 프로그램 접근 %d건 (%s)" % (
                a.script_n, rows[0][5][:60] if rows else ""), a.script_n, 0, Counter(r[4] for r in rows), rows))
        # 건수 조건을 못 채우는 IP는 시각 정렬 계산을 건너뛴다(대량 로그에서 속도 확보)
        if a.dyn is not None and len(a.dyn) >= min(cfg["rate_max_requests"], cfg["burst_max"]):
            cnt, t0 = _max_window(a.dyn, cfg["rate_window_sec"])
            if cnt >= cfg["rate_max_requests"]:
                fs.append(self._finding("rate", MEDIUM, "%d초 동안 %d건 요청 (%s부터, 정적 파일 제외)" % (
                    cfg["rate_window_sec"], cnt, fmt_ts(t0)), cnt, 0, Counter(), []))
            else:
                bcnt, bt = _max_window(a.dyn, 1)
                if bcnt >= cfg["burst_max"]:
                    fs.append(self._finding("burst", LOW, "1초에 %d건 요청 (%s)" % (bcnt, fmt_ts(bt)),
                                            bcnt, 0, Counter(), []))
        if a.err >= cfg["error_min"] and a.err / a.n >= cfg["error_ratio"]:
            fs.append(self._finding("errors", MEDIUM, "전체 %d건 중 %d건(%.0f%%)이 에러 응답" % (
                a.n, a.err, 100.0 * a.err / a.n), a.err, 0,
                Counter({k: v for k, v in a.status.items() if k >= 400 and k != 499}), a.err_rows or []))
        if a.nf is not None and len(a.nf) >= cfg["notfound_distinct"]:
            fs.append(self._finding("notfound", MEDIUM, "존재하지 않는 경로 %d종 요청 (디렉터리 스캐닝 의심)" % len(a.nf),
                                    len(a.nf), 0, Counter({404: len(a.nf)}), list(a.nf.values())[:EVIDENCE_MAX]))
        if a.login_fail >= cfg["login_fail_min"]:
            rows = a.login_rows or []
            fs.append(self._finding("login_fail", MEDIUM, "로그인 관련 요청 실패 %d건" % a.login_fail,
                                    a.login_fail, 0, Counter(r[4] for r in rows), rows))
        if a.login_post is not None and len(a.login_post) >= cfg["login_post_max"]:
            pc, _pt = _max_window(a.login_post, cfg["login_window_sec"])
            if pc >= cfg["login_post_max"]:
                fs.append(self._finding("login_burst", MEDIUM, "%d분 안에 로그인 POST %d건 (무차별 대입 의심)" % (
                    cfg["login_window_sec"] // 60, pc), pc, 0, Counter(), []))
        if not fs:
            return {"level": 0}
        fs.sort(key=lambda f: (-f["level"], -f["success"], -f["count"]))
        level = max(f["level"] for f in fs)
        uas = a.user_agents()
        return {
            "ip": ip, "level": level, "level_label": LEVEL_LABEL[level],
            "score": round(sum(f["level"] * 10 + min(f["count"], 100) / 10.0 for f in fs), 1),
            "requests": a.n, "errors": a.err, "first": fmt_ts(a.first), "last": fmt_ts(a.last),
            "success_warn": any(f["success"] and f["key"] in guide.SUCCESS_WARN_KEYS for f in fs),
            "findings": fs,
            "user_agent": uas.most_common(1)[0][0] if uas else "",
            "user_agents": uas.most_common(5),
            "statuses": Counter(a.status).most_common(8),
        }

    def result(self, setting=None):
        used, setting, info = self.resolve_mode(setting)
        res = {"mode": used, "setting": setting, "unreliable": info["unreliable"], "reason": info["reason"],
               "distinct_ips": len(self.ips), "xff_used": self.xff_used, "ips": [], "findings": []}
        if used == "ip":
            ips = [self._ip_result(ip, a) for ip, a in self.ips.items()]
            ips = [x for x in ips if x["level"]]
            ips.sort(key=lambda x: (-x["level"], not x["success_warn"], -x["score"], -x["requests"]))
            res["ips"] = ips
            levels = Counter(x["level"] for x in ips)
        else:
            fs = []
            for key in guide.REQUEST_LEVEL_KEYS:
                h = self.glob.get(key)
                if h:
                    f = self._hit_finding(key, h, "%d건 (출처 IP %d개%s)" % (
                        h.count, len(h.ips), "+" if len(h.ips) >= 2000 else ""))
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


def _row_dict(r):
    return {"time": fmt_ts(r[0]), "ip": r[1], "method": r[2], "url": r[3], "status": r[4], "ua": r[5]}
