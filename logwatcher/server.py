"""PC 내부 전용(127.0.0.1) 웹 서버. 업로드된 로그는 PC 안에서만 처리하고 외부로 전송하지 않는다."""
import atexit
import csv
import hashlib
import io
import hmac
import ipaddress
import json
import os
import secrets
import shutil
import tempfile
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from . import VERSION, guide
from . import config as config_mod
from .analysis import analyze
from .detector import LEVEL_LABEL, fmt_ts
from .geoip import load_geo
from .parser import LogReader
from .resources import resource_path

TOKEN_HEADER = "X-LW-Token"
# 브라우저가 이 페이지에서 외부 주소로 요청을 보내거나 다른 페이지가 이 화면을 프레임에 넣지 못하게 한다(심층 방어)
SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                                "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
}
TOKEN = None        # 실행할 때마다 새로 만든 접근 토큰: make_server가 정한다

MODES = ("auto", "ip", "none")
# 최근 분석 결과를 보관해 범위를 되돌릴 때 다시 계산하지 않는다. 메모리를 아끼려고 IP가 많으면 적게 보관한다.
CACHE_MAX_ENTRIES = 3
CACHE_MAX_IPS = 300_000
SORT_KEYS = ("level", "last", "first", "requests", "ip", "country")
# 정렬 기준을 처음 고를 때의 기본 방향(날짜·건수·위험도는 큰 쪽부터, IP·첫 접근은 작은 쪽부터)
DEFAULT_DIR = {"level": "desc", "last": "desc", "first": "asc", "requests": "desc", "ip": "asc", "country": "asc"}
_LOCAL_HOSTS = ("127.0.0.1", "localhost")


def _ip_sort_key(ip):
    try:
        a = ipaddress.ip_address(ip)
        return (0, a.version, int(a), "")
    except ValueError:
        return (1, 0, 0, ip)


def csv_safe(v):
    """엑셀 수식 주입 방지: 로그 내용이 =,+,-,@ 로 시작하면 앞에 ' 를 붙인다."""
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


class State:
    """올린 파일을 세션 임시 폴더에 보관하고, 요청이 있을 때 전체를 합쳐 분석한다.

    분할 로그, HAProxy+nginx 동시 사용, 분석 범위(최근 N일) 변경을 위해 원본을 다시 읽는다.
    임시 폴더는 [전체 초기화]나 프로그램 종료 때 삭제한다.
    """

    def __init__(self, cfg=None, now_fn=time.time):
        self.lock = threading.RLock()                 # 파일 추가·분석처럼 오래 걸리는 일
        self.set_lock = threading.Lock()              # 설정 변경(범위·모드·정렬): 분석 중에도 즉시 반영
        self.version = 0                              # 설정이 바뀔 때마다 증가: 오래된 요청의 중복 분석을 건너뛰는 데 쓴다
        self.gen = 0                                  # 파일이 바뀔 때마다 증가
        self.cfg = cfg if cfg is not None else config_mod.load()
        self.mode = self.cfg["ip_mode"] if self.cfg["ip_mode"] in MODES else "auto"
        self.days = max(0, int(self.cfg["recent_days"]))
        self.anchor = self.cfg["recent_anchor"] if self.cfg["recent_anchor"] in ("latest", "now") else "latest"
        self.now_fn = now_fn
        self.sort_key, self.sort_dir, self.ev_dir = "level", "desc", "asc"     # IP 목록 정렬 / 근거 로그 시각순
        self.dir = None
        self.reset()

    # ------------------------------------------------------------ 파일 관리
    def reset(self):
        with self.lock:
            self.cleanup()
            self.entries = []
            self.hashes = set()
            self.gen += 1
            self._cache = OrderedDict()   # 키 -> 분석 결과 (최근 사용 순). 모드별 결과도 그 안에 함께 보관한다

    def cleanup(self):
        d, self.dir = self.dir, None
        if d:
            shutil.rmtree(d, ignore_errors=True)

    def add_file(self, name, tmp_path, digest):
        with self.lock:
            if digest in self.hashes:
                return {"name": name, "error": "이미 추가된 파일과 내용이 같아서 건너뛰었습니다."}
            if self.dir is None:
                self.dir = tempfile.mkdtemp(prefix="logwatcher_")
            dest = os.path.join(self.dir, "%04d.log" % (len(self.entries) + 1))
            shutil.copyfile(tmp_path, dest)      # 호출자의 파일은 건드리지 않는다(업로드 임시 파일은 호출자가 지움)
            try:
                reader = LogReader(dest, self.cfg["display_utc_offset_hours"],
                                   self.cfg["error_log_utc_offset_hours"], self.cfg["haproxy_log_utc_offset_hours"])
                proxies = reader.scan()          # 형식 판별 후 한 번 훑어 기간·LB 후보를 구함
            except ValueError as e:
                os.remove(dest)
                return {"name": name, "error": str(e)}
            info = dict(reader.info)
            if info["parsed"] == 0:
                os.remove(dest)
                return {"name": name, "error": "읽을 수 있는 로그 줄이 없습니다. 형식을 확인하세요."}
            self.hashes.add(digest)
            self.entries.append({"name": name, "reader": reader, "kind": reader.kind, "fmt": reader.fmt,
                                 "proxies": proxies, "info": info})
            self.gen += 1
            self._cache.clear()           # 파일이 바뀌면 이전 분석은 쓸 수 없다(메모리도 바로 반환)
            return self._file_view(len(self.entries) - 1)

    def _file_view(self, i):
        e = self.entries[i]
        info = e["info"]
        v = {"name": e["name"], "format_label": info["format_label"], "lines": info["lines"], "parsed": info["parsed"],
             "skipped": info["skipped"], "skipped_samples": info["skipped_samples"],
             "first": fmt_ts(info["first"]), "last": fmt_ts(info["last"])}
        an = self._current_analysis()
        if an is not None and i < len(an["per_file"]):
            v.update(an["per_file"][i])
        return v

    # ------------------------------------------------------------ 분석
    def _key(self):
        return (self.days, self.anchor, self.gen)

    def _current_analysis(self):
        """이미 계산된 분석 중 현재 설정과 파일 구성에 맞는 것(없으면 None). 계산은 하지 않는다."""
        return self._cache.get(self._key())

    def analysis(self):
        with self.lock:
            if not self.entries:
                return None
            key = self._key()
            an = self._cache.get(key)
            if an is None:
                an = analyze(self.entries, self.cfg, key[0], key[1], self.now_fn())
                an["results"] = {}            # IP 구분 모드별로 만든 결과(분석과 함께 버려진다)
                self._cache[key] = an
                self._evict()
            else:
                self._cache.move_to_end(key)
            return an

    def _evict(self):
        """오래 안 쓴 분석부터 버린다(가장 최근 것은 항상 남긴다)."""
        while len(self._cache) > 1 and (len(self._cache) > CACHE_MAX_ENTRIES or
                                        sum(len(a["analyzer"].ips) for a in self._cache.values()) > CACHE_MAX_IPS):
            self._cache.popitem(last=False)

    def set_mode(self, mode):
        if mode not in MODES:
            raise ValueError("bad mode")
        with self.set_lock:
            self.mode = mode
            self.version += 1

    def set_sort(self, key=None, direction=None, ev=None):
        """IP 목록 정렬(key: level/last/first/requests/ip/country, direction: asc/desc)과 근거 로그 시각순(ev: asc/desc)."""
        if key is not None and key not in SORT_KEYS:
            raise ValueError("bad sort key")
        if direction not in (None, "asc", "desc") or ev not in (None, "asc", "desc"):
            raise ValueError("bad sort direction")
        with self.set_lock:
            if key is not None:
                self.sort_key = key
                self.sort_dir = direction or DEFAULT_DIR[key]
            elif direction is not None:
                self.sort_dir = direction
            if ev is not None:
                self.ev_dir = ev
            self.version += 1

    def set_days(self, days):
        if not 0 <= days <= 3650:
            raise ValueError("bad days")
        with self.set_lock:
            self.days = days
            self.version += 1

    def sorted_ips(self, ips):
        """화면과 CSV가 같은 순서를 쓰도록 정렬 기준을 한 곳에서 적용한다."""
        key, desc = self.sort_key, self.sort_dir == "desc"
        if key == "level":
            return sorted(ips, key=lambda x: (x["level"], x["success_warn"], x["score"], x["requests"]), reverse=desc)
        if key == "requests":
            return sorted(ips, key=lambda x: (x["requests"], x["level"], x["score"]), reverse=desc)
        if key == "ip":
            return sorted(ips, key=lambda x: _ip_sort_key(x["ip"]), reverse=desc)
        if key == "country":
            return sorted(ips, key=lambda x: (x.get("country_name", ""), x["level"], x["score"]), reverse=desc)
        present = [x for x in ips if x[key]]           # first/last: 접근 기록이 없는(에러로그에만 나온) IP는 항상 맨 뒤
        present.sort(key=lambda x: (x[key], x["level"], x["score"]), reverse=desc)
        return present + [x for x in ips if not x[key]]

    def ordered_findings(self, findings):
        """근거 로그를 시각순(오름/내림)으로 정렬한 복사본."""
        desc = self.ev_dir == "desc"
        return [dict(f, evidence=sorted(f["evidence"], key=lambda e: e["ts"], reverse=desc)) for f in findings]

    def result(self):
        with self.lock:
            an = self.analysis()
            if an is None:
                return None
            res = an["results"].get(self.mode)
            if res is None:
                res = an["results"][self.mode] = an["analyzer"].result(self.mode)
            return res

    def _range(self, an):
        firsts = [e["info"]["first"] for e in self.entries if e["info"]["first"] is not None]
        lasts = [e["info"]["last"] for e in self.entries if e["info"]["last"] is not None]
        log_first = min(firsts) if firsts else None
        return {"days": self.days, "anchor": self.anchor, "from": fmt_ts(an["cutoff"]) if an["cutoff"] is not None else "",
                "to": fmt_ts(an["anchor"]), "excluded": an["excluded"], "in_range": an["in_range"],
                "log_from": fmt_ts(log_first), "log_to": fmt_ts(max(lasts)) if lasts else "",
                # 선택한 범위가 올린 로그의 전체 기간보다 길어서 범위를 바꿔도 결과가 같은 경우
                "covers_all": an["cutoff"] is None or (log_first is not None and an["cutoff"] <= log_first)}

    def summary(self, expect_version=None):
        """expect_version이 주어졌는데 그 사이 설정이 또 바뀌었으면 계산하지 않고 {"stale": True}를 돌려준다."""
        with self.lock:
            if expect_version is not None and expect_version != self.version:
                return {"stale": True, "version": self.version}
            out = self._summary()
            out["version"] = self.version
            return out

    def _summary(self):
        with self.lock:
            an = self.analysis()
            if an is None:
                return {"files": [], "empty": True, "mode_setting": self.mode, "days": self.days}
            files = [self._file_view(i) for i in range(len(self.entries))]
            a = an["analyzer"]
            if not (a.total or a.err_total):          # 분석 범위 안에 로그가 없음
                return {"files": files, "empty": True, "mode_setting": self.mode, "days": self.days,
                        "range": self._range(an), "notes": an["notes"]}
            res = self.result()
            return {
                "files": files, "empty": False, "total": a.total, "allowed_skipped": a.allowed_skipped,
                "unique_ips": res["distinct_ips"], "xff_used": res["xff_used"],
                "period": [fmt_ts(a.first_ts), fmt_ts(a.last_ts)], "range": self._range(an), "days": self.days,
                "auto_proxies": res["auto_proxies"], "errorlog": res["errorlog"], "notes": an["notes"],
                "mode": res["mode"], "mode_setting": self.mode, "unreliable": res["unreliable"],
                "reason": res["reason"], "verdict": res["verdict"],
                # 목록에는 근거 로그를 싣지 않는다(상세 조회 때만). 요청 단위 모드는 항목 수가 적어 포함.
                "ips": [self._ip_row(x) for x in self.sorted_ips(res["ips"])],
                "countries": res["countries"], "geo": res["geo"], "home_countries": res.get("home_countries", []),
                "foreign_omitted": res["foreign_omitted"], "foreign_ips": res["foreign_ips"],
                "findings": self.ordered_findings(res["findings"]),
                "sort": {"key": self.sort_key, "dir": self.sort_dir, "ev": self.ev_dir},
            }

    @staticmethod
    def _ip_row(x):
        return {"ip": x["ip"], "country": x.get("country", ""), "country_name": x.get("country_name", ""),
                "foreign": x.get("foreign", False), "level": x["level"], "level_label": x["level_label"], "score": x["score"],
                "requests": x["requests"], "errors": x["errors"], "first": x["first"], "last": x["last"],
                "success_warn": x["success_warn"], "user_agent": x["user_agent"], "is_proxy": x["is_proxy"],
                "findings": [{"key": f["key"], "label": f["label"], "level": f["level"],
                              "success": f["success"]} for f in x["findings"]]}

    def ip_detail(self, ip):
        with self.lock:
            res = self.result()
            if res is None:
                return None
            x = next((x for x in res["ips"] if x["ip"] == ip), None)
            return dict(x, findings=self.ordered_findings(x["findings"])) if x else None

    def result_csv(self):
        with self.lock:
            res = self.result() or {"mode": "ip", "ips": [], "findings": []}
            buf = io.StringIO()
            w = csv.writer(buf)
            if res["mode"] == "ip":
                w.writerow(["위험도", "IP", "국가", "요청수", "탐지 내용", "정상응답 경고", "첫 접근", "마지막 접근", "User-Agent"])
                for x in self.sorted_ips(res["ips"]):
                    w.writerow([x["level_label"], csv_safe(x["ip"]), x.get("country_name", ""), x["requests"],
                                csv_safe(" / ".join("%s(%s)" % (f["label"], f["desc"]) for f in x["findings"])),
                                "Y" if x["success_warn"] else "", x["first"], x["last"], csv_safe(x["user_agent"])])
            else:
                w.writerow(["위험도", "탐지 항목", "건수", "출처 IP 수", "2xx 응답", "시각", "IP", "Method", "URL", "응답코드"])
                for f in self.ordered_findings(res["findings"]):
                    for e in f["evidence"] or [None]:
                        w.writerow([LEVEL_LABEL[f["level"]], f["label"], f["count"], f.get("ips", ""), f["success"]] +
                                   ([e["time"], csv_safe(e["ip"]), e["method"], csv_safe(e["url"]), e["status"]]
                                    if e else ["", "", "", "", ""]))
            return buf.getvalue()


STATE = None


class Handler(BaseHTTPRequestHandler):
    server_version = "LogWatcher/" + VERSION

    def log_message(self, fmt, *args):
        pass

    def _allowed(self):
        """다른 웹페이지가 이 서버를 호출하지 못하도록 Host/Origin을 확인한다(DNS rebinding, CSRF 방지)."""
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        if host not in _LOCAL_HOSTS:
            return False
        origin = self.headers.get("Origin")
        if origin:
            oh = urlparse(origin).hostname
            if oh not in _LOCAL_HOSTS:
                return False
        return True

    def _authed(self):
        """같은 PC의 다른 사용자·다른 프로그램이 이 서버를 쓰지 못하도록 실행마다 새로 만든 토큰을 요구한다."""
        got = self.headers.get(TOKEN_HEADER) or ""
        return bool(TOKEN) and hmac.compare_digest(got.encode("utf-8", "replace"), TOKEN.encode("utf-8"))

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _query(self):
        u = urlparse(self.path)
        return u.path, {k: v[-1] for k, v in parse_qs(u.query).items()}

    def do_GET(self):
        if not self._allowed():
            return self._send(403, {"error": "forbidden"})
        path, q = self._query()
        try:
            if path in ("/", "/index.html"):          # 화면 파일 자체에는 데이터가 없어 토큰 없이 연다
                with open(resource_path("web", "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if path == "/favicon.ico":
                return self._send(204, b"", "image/x-icon")
            if not self._authed():
                return self._send(401, {"error": "unauthorized"})
            if path == "/api/status":
                geo = load_geo(STATE.cfg)
                return self._send(200, {"version": VERSION, "config": STATE.cfg, "geo": {"available": geo.available, "source": geo.source}, "level_guide": guide.LEVEL_GUIDE,
                                        "level_notes": guide.LEVEL_NOTES, "rules": guide.RULES,
                                        "success_warn": guide.SUCCESS_WARN_KEYS})
            if path == "/api/summary":
                return self._send(200, STATE.summary())
            if path == "/api/ip":
                d = STATE.ip_detail(q.get("ip", ""))
                return self._send(200 if d else 404, d or {"error": "not found"})
            if path == "/api/export/result.csv":
                fn = "suspicious_%s.csv" % time.strftime("%Y%m%d_%H%M")
                # 엑셀에서 한글이 깨지지 않도록 UTF-8 BOM 추가
                return self._send(200, "﻿" + STATE.result_csv(), "text/csv; charset=utf-8",
                                  {"Content-Disposition": 'attachment; filename="%s"' % fn})
            return self._send(404, {"error": "not found"})
        except Exception as e:
            return self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})

    def do_POST(self):
        if not self._allowed():
            return self._send(403, {"error": "forbidden"})
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        path, q = self._query()
        try:
            if path == "/api/upload":
                return self._upload(unquote(q.get("name", "upload.log")))
            if path == "/api/reset":
                STATE.reset()
                return self._send(200, {"ok": True})
            if path == "/api/mode":
                STATE.set_mode(q.get("mode", ""))
                return self._send(200, STATE.summary(STATE.version))
            if path == "/api/sort":
                STATE.set_sort(q.get("key"), q.get("dir"), q.get("ev"))
                return self._send(200, STATE.summary(STATE.version))
            if path == "/api/range":
                try:
                    STATE.set_days(int(q.get("days", "")))
                except (TypeError, ValueError):
                    raise ValueError("bad days")
                return self._send(200, STATE.summary(STATE.version))
            return self._send(404, {"error": "not found"})
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:
            return self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})

    def _upload(self, name):
        remaining = int(self.headers.get("Content-Length") or 0)
        h = hashlib.sha1()
        fd, tmp = tempfile.mkstemp(prefix="logwatcher_", suffix=".log")
        try:
            with os.fdopen(fd, "wb") as out:
                while remaining > 0:
                    chunk = self.rfile.read(min(1 << 20, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    h.update(chunk)
                    out.write(chunk)
            res = STATE.add_file(os.path.basename(name), tmp, h.hexdigest())
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
        return self._send(200 if "error" not in res else 400, res)


def make_server(port_candidates, cfg=None):
    global STATE, TOKEN
    STATE = State(cfg)
    TOKEN = os.environ.get("LOGWATCHER_TOKEN") or secrets.token_urlsafe(24)   # 환경변수는 자동화·점검용
    atexit.register(STATE.cleanup)
    last = None
    for p in port_candidates:
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", p), Handler)
            httpd.token = TOKEN
            return httpd
        except OSError as e:
            last = e
    raise last
