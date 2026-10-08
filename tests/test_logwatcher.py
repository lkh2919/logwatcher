import gzip
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from logwatcher import config, parser, server  # noqa: E402
from logwatcher.detector import Analyzer  # noqa: E402

SAMPLES = os.path.join(ROOT, "samples")


def cfg(**kw):
    c = json.loads(json.dumps(config.DEFAULTS))
    c.update(kw)
    return c


def line(ip="1.2.3.4", req="GET / HTTP/1.1", status=200, ua="Mozilla/5.0", xff=None, t="08/Oct/2026:10:00:00 +0900"):
    s = '%s - - [%s] "%s" %d 100 "-" "%s"' % (ip, t, req, status, ua)
    return s + (' "%s"' % xff if xff is not None else "")


def run(lines, c=None, fmt=parser.FMT_NGINX):
    a = Analyzer(c or cfg())
    lp = parser.LineParser(fmt)
    for l in lines:
        r = lp.parse(l)
        assert r is not None, l
        a.feed(r)
    return a


class ParserTest(unittest.TestCase):
    def test_combined_and_time(self):
        r = parser.LineParser(parser.FMT_NGINX, 9).parse(line(t="08/Oct/2026:10:00:00 +0000"))
        self.assertEqual(r[parser.IP], "1.2.3.4")
        self.assertEqual(r[parser.METHOD], "GET")
        import time
        self.assertEqual(time.strftime("%H:%M", time.gmtime(r[parser.TS])), "19:00")   # UTC 10시 -> KST 19시

    def test_extra_fields_and_xff(self):
        r = parser.LineParser(parser.FMT_NGINX).parse(line(xff="9.9.9.9, 10.0.0.2") + " 0.012")
        self.assertEqual(r[parser.XFF], "9.9.9.9, 10.0.0.2")
        r = parser.LineParser(parser.FMT_NGINX).parse(line(xff="-"))
        self.assertEqual(r[parser.XFF], "")

    def test_binary_and_dash_request(self):
        lp = parser.LineParser(parser.FMT_NGINX)
        self.assertEqual(lp.parse(line(req="\\x16\\x03\\x01\\x02"))[parser.METHOD], "(TLS)")
        self.assertEqual(lp.parse(line(req="-", status=408))[parser.METHOD], "-")
        self.assertEqual(lp.parse(line(req="\\x00\\x01garbage"))[parser.METHOD], "(INVALID)")

    def test_json(self):
        d = {"time_iso8601": "2026-10-08T10:00:00+09:00", "remote_addr": "5.6.7.8", "request": "GET /a?b=1 HTTP/1.1",
             "status": "404", "body_bytes_sent": 12, "http_user_agent": "x", "http_x_forwarded_for": "1.1.1.1"}
        r = parser.LineParser(parser.FMT_JSON, 9).parse(json.dumps(d))
        self.assertEqual((r[parser.IP], r[parser.PATH], r[parser.QUERY], r[parser.STATUS], r[parser.XFF]),
                         ("5.6.7.8", "/a", "b=1", 404, "1.1.1.1"))
        self.assertIsNone(parser.LineParser(parser.FMT_JSON).parse("not json"))

    def test_detect_format_errors(self):
        with self.assertRaises(ValueError) as cm:
            parser.detect_format(["2026/10/08 10:00:00 [error] 12#0: *1 open() failed"])
        self.assertIn("error.log", str(cm.exception))
        with self.assertRaises(ValueError):
            parser.detect_format(["hello world", "foo bar"])
        with self.assertRaises(ValueError):
            parser.detect_format([])

    def test_gzip(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.log.gz")
            with gzip.open(p, "wt") as f:
                f.write(line() + "\n" + line(ip="2.2.2.2") + "\nbroken line\n")
            rd = parser.LogReader(p)
            self.assertEqual(len(list(rd.records())), 2)
            self.assertEqual(rd.info["skipped"], 1)


class DetectorTest(unittest.TestCase):
    def kinds(self, a):
        return {f["key"] for x in a.result()["ips"] for f in x["findings"]}

    def test_attack_kinds(self):
        a = run([line(req="GET /a?id=1%27%20UNION%20SELECT%201-- HTTP/1.1"),
                 line(ip="2.2.2.2", req="GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1"),
                 line(ip="3.3.3.3", req="GET /../../etc/passwd HTTP/1.1"),
                 line(ip="4.4.4.4", req="GET /?x=${jndi:ldap://e/a} HTTP/1.1"),
                 line(ip="5.5.5.5", req="GET /.env HTTP/1.1", status=404)])
        res = {x["ip"]: x for x in a.result()["ips"]}
        self.assertEqual(res["1.2.3.4"]["findings"][0]["key"], "sqli")
        self.assertEqual(res["2.2.2.2"]["findings"][0]["key"], "xss")
        self.assertEqual(res["3.3.3.3"]["findings"][0]["key"], "traversal")
        self.assertEqual(res["4.4.4.4"]["findings"][0]["key"], "cmdi")
        self.assertEqual((res["5.5.5.5"]["level"], res["5.5.5.5"]["findings"][0]["key"]), (2, "probe"))

    def test_clean_is_ok(self):
        a = run([line(ip="1.1.1.%d" % i, req="GET /page?id=%d HTTP/1.1" % i) for i in range(50)])
        v = a.result()["verdict"]
        self.assertEqual((v["status"], v["text"]), ("ok", "이상 없음"))

    def test_success_warning(self):
        a = run([line(req="GET /.env HTTP/1.1", status=200)])
        self.assertTrue(a.result()["ips"][0]["success_warn"])

    def test_nginx_hex_escape_decoded(self):
        a = run([line(req="GET /a?f=x\\x00.png HTTP/1.1")])
        self.assertIn("traversal", self.kinds(a))

    def test_scanner_and_method(self):
        a = run([line(ua="sqlmap/1.7"), line(ip="2.2.2.2", req="PUT /x HTTP/1.1", status=405)])
        self.assertEqual(self.kinds(a), {"scanner", "method"})

    def test_rate_login_notfound(self):
        rows = [line(req="POST /login HTTP/1.1", status=401, t="08/Oct/2026:10:00:%02d +0900" % (i % 60))
                for i in range(25)]
        rows += [line(ip="9.9.9.9", req="GET /nope%d HTTP/1.1" % i, status=404) for i in range(12)]
        k = self.kinds(run(rows, cfg(rate_max_requests=20)))
        self.assertTrue({"login_fail", "login_burst", "rate", "errors", "notfound"} <= k)

    def test_allow_ip_and_probe_ignore(self):
        a = run([line(ip="10.1.2.3", ua="sqlmap")], cfg(allow_ips=["10.0.0.0/8"]))
        self.assertEqual(a.result()["ips"], [])
        a = run([line(req="GET /graphql HTTP/1.1")], cfg(probe_ignore_paths=["^/graphql"]))
        self.assertEqual(a.result()["ips"], [])
        a = run([line(req="GET /graphql?q=union%20select%201 HTTP/1.1")], cfg(probe_ignore_paths=["^/graphql"]))
        self.assertIn("sqli", self.kinds(a))   # 허용 경로여도 SQLi는 계속 탐지

    def test_xff_trusted_only_from_proxy(self):
        # 사설 IP(LB)에서 온 XFF는 신뢰, 공인 IP가 보낸 XFF는 위조 가능하므로 무시
        a = run([line(ip="10.0.0.5", ua="sqlmap", xff="203.0.113.7"), line(ip="198.51.100.1", ua="sqlmap", xff="1.2.3.4")])
        self.assertEqual({x["ip"] for x in a.result()["ips"]}, {"203.0.113.7", "198.51.100.1"})

    def test_xff_chain_skips_proxies(self):
        a = run([line(ip="10.0.0.5", ua="sqlmap", xff="203.0.113.7, 10.0.0.9")])
        self.assertEqual(a.result()["ips"][0]["ip"], "203.0.113.7")
        a = run([line(ip="10.0.0.5", ua="sqlmap", xff="203.0.113.7, 198.51.100.9")], cfg(trusted_proxies=["198.51.100.9"]))
        self.assertEqual(a.result()["ips"][0]["ip"], "203.0.113.7")

    def test_unreliable_ip_switches_to_request_mode(self):
        rows = [line(ip="10.0.0.5", req="GET /p%d HTTP/1.1" % i) for i in range(150)]
        rows += [line(ip="10.0.0.5", req="GET /a?id=1%27%20UNION%20SELECT%201-- HTTP/1.1")] * 2
        a = run(rows)
        r = a.result()
        self.assertEqual((r["mode"], r["unreliable"]), ("request", True))
        self.assertEqual(r["ips"], [])
        self.assertEqual(r["findings"][0]["key"], "sqli")
        self.assertEqual(r["verdict"]["status"], "alert")
        self.assertEqual(a.result("ip")["mode"], "ip")          # 수동 전환
        self.assertEqual(a.result("none")["mode"], "request")

    def test_xff_present_keeps_ip_mode(self):
        rows = [line(ip="10.0.0.5", req="GET /p%d HTTP/1.1" % i, xff="175.1.1.%d" % (i % 50)) for i in range(150)]
        self.assertEqual(run(rows).result()["mode"], "ip")

    def test_internal_helper(self):
        from logwatcher.detector import is_internal
        import ipaddress as ia
        for ip, exp in [("10.1.1.1", True), ("172.20.0.1", True), ("192.168.1.1", True), ("127.0.0.1", True),
                        ("::ffff:10.0.0.1", True), ("fd00::1", True), ("203.0.113.9", False), ("8.8.8.8", False),
                        ("172.32.0.1", False)]:
            self.assertEqual(is_internal(ia.ip_address(ip)), exp, ip)

    def test_internal_many_users_keeps_ip_mode(self):
        rows = [line(ip="192.168.0.%d" % (i % 60), req="GET /p%d HTTP/1.1" % i) for i in range(300)]
        self.assertFalse(run(rows).result()["unreliable"])

    def test_samples(self):
        def go(name):
            rd = parser.LogReader(os.path.join(SAMPLES, name))
            a = Analyzer(cfg())
            for r in rd.records():
                a.feed(r)
            return rd, a.result()
        self.assertEqual(go("nginx_clean.log")[1]["verdict"]["status"], "ok")
        _, r = go("nginx_access.log")
        self.assertEqual((r["verdict"]["high"], r["verdict"]["medium"]), (3, 3))
        self.assertEqual(go("nginx_xff.log")[1]["verdict"], r["verdict"])
        self.assertEqual(go("nginx_json.log")[1]["verdict"], r["verdict"])
        self.assertEqual(go("nginx_behind_lb.log")[1]["mode"], "request")


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server.make_server([0], cfg())
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        return r.status, data

    def test_flow(self):
        self.req("POST", "/api/reset")
        with open(os.path.join(SAMPLES, "nginx_access.log"), "rb") as f:
            st, data = self.req("POST", "/api/upload?name=a.log", f.read())
        self.assertEqual(st, 200, data)
        with open(os.path.join(SAMPLES, "nginx_access.log"), "rb") as f:
            st, data = self.req("POST", "/api/upload?name=a.log", f.read())
        self.assertEqual(st, 400)   # 중복 업로드
        st, data = self.req("GET", "/api/summary")
        s = json.loads(data)
        self.assertEqual(s["verdict"]["status"], "alert")
        self.assertNotIn("evidence", s["ips"][0]["findings"][0])
        st, data = self.req("GET", "/api/ip?ip=" + s["ips"][0]["ip"])
        self.assertTrue(json.loads(data)["findings"][0]["evidence"])
        st, data = self.req("GET", "/api/export/result.csv")
        self.assertTrue(data.startswith(b"\xef\xbb\xbf"))
        st, _ = self.req("POST", "/api/mode?mode=none")
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(self.req("GET", "/api/summary")[1])["mode"], "request")
        self.assertEqual(self.req("POST", "/api/mode?mode=bad")[0], 400)
        self.req("POST", "/api/mode?mode=auto")

    def test_bad_file(self):
        st, data = self.req("POST", "/api/upload?name=x.log", b"hello\nworld\n")
        self.assertEqual(st, 400)
        self.assertIn("지원하지 않는", json.loads(data)["error"])

    def test_origin_and_host_checks(self):
        self.assertEqual(self.req("POST", "/api/reset", headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.req("GET", "/api/status", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.req("POST", "/api/reset", headers={"Origin": "http://127.0.0.1:%d" % self.port})[0], 200)

    def test_index_served(self):
        st, data = self.req("GET", "/")
        self.assertEqual(st, 200)
        self.assertIn("LogWatcher".encode(), data)

    def test_csv_injection_neutralized(self):
        self.assertEqual(server.csv_safe("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0")
        self.assertEqual(server.csv_safe("normal"), "normal")


if __name__ == "__main__":
    unittest.main()
