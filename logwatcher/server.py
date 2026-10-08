"""PC 내부 전용(127.0.0.1) 웹 서버. 업로드된 로그는 PC 안에서만 처리하고 외부로 전송하지 않는다."""
import csv
import hashlib
import io
import json
import os
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from . import VERSION, guide
from . import config as config_mod
from .detector import LEVEL_LABEL, Analyzer, fmt_ts
from .parser import LogReader
from .resources import resource_path

MODES = ("auto", "ip", "none")
_LOCAL_HOSTS = ("127.0.0.1", "localhost")


def csv_safe(v):
    """엑셀 수식 주입 방지: 로그 내용이 =,+,-,@ 로 시작하면 앞에 ' 를 붙인다."""
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


class State:
    def __init__(self, cfg=None):
        self.lock = threading.RLock()
        self.cfg = cfg if cfg is not None else config_mod.load()
        self.mode = self.cfg["ip_mode"] if self.cfg["ip_mode"] in MODES else "auto"
        self.reset()

    def reset(self):
        with self.lock:
            self.analyzer = Analyzer(self.cfg)
            self.files = []
            self.hashes = set()
            self._result = None

    def add_file(self, name, tmp_path, digest):
        with self.lock:
            if digest in self.hashes:
                return {"name": name, "error": "이미 추가된 파일과 내용이 같아서 건너뛰었습니다."}
            try:
                reader = LogReader(tmp_path, self.cfg["display_utc_offset_hours"])
            except ValueError as e:
                return {"name": name, "error": str(e)}
            for rec in reader.records():
                self.analyzer.feed(rec)
            i = reader.info
            if i["parsed"] == 0:
                return {"name": name, "error": "읽을 수 있는 로그 줄이 없습니다. 형식을 확인하세요."}
            self.hashes.add(digest)
            self._result = None
            view = {"name": name, "format_label": i["format_label"], "lines": i["lines"], "parsed": i["parsed"],
                    "skipped": i["skipped"], "skipped_samples": i["skipped_samples"],
                    "first": fmt_ts(i["first"]), "last": fmt_ts(i["last"])}
            self.files.append(view)
            return view

    def result(self):
        with self.lock:
            if self._result is None:
                self._result = self.analyzer.result(self.mode)
            return self._result

    def set_mode(self, mode):
        with self.lock:
            if mode not in MODES:
                raise ValueError("bad mode")
            self.mode = mode
            self._result = None

    def summary(self):
        with self.lock:
            if not self.analyzer.total:
                return {"files": self.files, "empty": True, "mode_setting": self.mode}
            res = self.result()
            a = self.analyzer
            firsts = [x.first for x in a.ips.values() if x.first is not None]
            lasts = [x.last for x in a.ips.values() if x.last is not None]
            return {
                "files": self.files, "empty": False, "total": a.total, "allowed_skipped": a.allowed_skipped,
                "unique_ips": res["distinct_ips"], "xff_used": res["xff_used"],
                "period": [fmt_ts(min(firsts)) if firsts else "", fmt_ts(max(lasts)) if lasts else ""],
                "mode": res["mode"], "mode_setting": self.mode, "unreliable": res["unreliable"],
                "reason": res["reason"], "verdict": res["verdict"],
                # 목록에는 근거 로그를 싣지 않는다(상세 조회 때만). 요청 단위 모드는 항목 수가 적어 포함.
                "ips": [self._ip_row(x) for x in res["ips"]],
                "findings": res["findings"],
            }

    @staticmethod
    def _ip_row(x):
        return {"ip": x["ip"], "level": x["level"], "level_label": x["level_label"], "score": x["score"],
                "requests": x["requests"], "errors": x["errors"], "first": x["first"], "last": x["last"],
                "success_warn": x["success_warn"], "user_agent": x["user_agent"],
                "findings": [{"key": f["key"], "label": f["label"], "level": f["level"],
                              "success": f["success"]} for f in x["findings"]]}

    def ip_detail(self, ip):
        with self.lock:
            if not self.analyzer.total:
                return None
            return next((x for x in self.result()["ips"] if x["ip"] == ip), None)

    def result_csv(self):
        with self.lock:
            res = self.result()
            buf = io.StringIO()
            w = csv.writer(buf)
            if res["mode"] == "ip":
                w.writerow(["위험도", "IP", "요청수", "탐지 내용", "정상응답 경고", "첫 접근", "마지막 접근", "User-Agent"])
                for x in res["ips"]:
                    w.writerow([x["level_label"], csv_safe(x["ip"]), x["requests"],
                                csv_safe(" / ".join("%s(%s)" % (f["label"], f["desc"]) for f in x["findings"])),
                                "Y" if x["success_warn"] else "", x["first"], x["last"], csv_safe(x["user_agent"])])
            else:
                w.writerow(["위험도", "탐지 항목", "건수", "출처 IP 수", "2xx 응답", "시각", "IP", "Method", "URL", "응답코드"])
                for f in res["findings"]:
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
            if path in ("/", "/index.html"):
                with open(resource_path("web", "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if path == "/favicon.ico":
                return self._send(204, b"", "image/x-icon")
            if path == "/api/status":
                return self._send(200, {"version": VERSION, "config": STATE.cfg, "level_guide": guide.LEVEL_GUIDE,
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
        path, q = self._query()
        try:
            if path == "/api/upload":
                return self._upload(unquote(q.get("name", "upload.log")))
            if path == "/api/reset":
                STATE.reset()
                return self._send(200, {"ok": True})
            if path == "/api/mode":
                STATE.set_mode(q.get("mode", ""))
                return self._send(200, {"ok": True})
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
    global STATE
    STATE = State(cfg)
    last = None
    for p in port_candidates:
        try:
            return ThreadingHTTPServer(("127.0.0.1", p), Handler)
        except OSError as e:
            last = e
    raise last
