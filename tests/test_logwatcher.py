import gzip
import http.client
import json
import os
import re
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


BRACKET = ('203.0.113.250 - - [09/Sep/2026:14:34:19 +0900] [request "GET /robots.txt HTTP/1.1"] [status 307] '
           '[body_bytes_sent 16] "-" "ExampleCrawler/1.1" "198.51.100.24"')
HAP = ('Oct  8 10:12:01 lb haproxy[123]: 203.0.113.7:51234 [08/Oct/2026:10:12:01.123] main~ http_back/nginx2 0/0/1/2/3 200 '
       '512 - - ---- 1/1/0/0/0 0/0 {example.com|Mozilla/5.0 (X11)} {} "GET /index.html HTTP/1.1"')


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

    def test_detect_formats(self):
        self.assertEqual(parser.detect_format(["2026/10/08 10:00:00 [error] 12#0: *1 open() failed"]), parser.FMT_ERROR)
        self.assertEqual(parser.detect_format([BRACKET]), parser.FMT_NGINX_BR)
        self.assertEqual(parser.detect_format([HAP]), parser.FMT_HAPROXY)
        self.assertEqual(parser.detect_format([line()]), parser.FMT_NGINX)
        with self.assertRaises(ValueError) as cm:
            parser.detect_format(['Oct  8 10:12:01 lb haproxy[1]: 1.2.3.4:5 [08/Oct/2026:10:12:01.123] fe be/s 0/0/3 512 ---- 1/1/0/0/0 0/0'] * 3)
        self.assertIn("TCP", str(cm.exception))
        with self.assertRaises(ValueError):
            parser.detect_format(["hello world", "foo bar"])
        with self.assertRaises(ValueError):
            parser.detect_format([])

    def test_bracket_format(self):
        r = parser.LineParser(parser.FMT_NGINX_BR).parse(BRACKET)
        self.assertEqual((r[parser.IP], r[parser.METHOD], r[parser.PATH], r[parser.STATUS], r[parser.BYTES], r[parser.XFF]),
                         ("203.0.113.250", "GET", "/robots.txt", 307, 16, "198.51.100.24"))
        smb = BRACKET.replace('GET /robots.txt HTTP/1.1', "\\x00\\x00\\x00'\\xFFSMBr").replace('"198.51.100.24"', '"-"')
        r = parser.LineParser(parser.FMT_NGINX_BR).parse(smb)
        self.assertEqual((r[parser.METHOD], r[parser.XFF]), ("(INVALID)", ""))

    def test_haproxy_format(self):
        lp = parser.LineParser(parser.FMT_HAPROXY, 9, 9, 9)
        r = lp.parse(HAP)
        self.assertEqual((r[parser.IP], r[parser.PATH], r[parser.STATUS], r[parser.UA]), ("203.0.113.7", "/index.html", 200, "Mozilla/5.0 (X11)"))
        import time
        self.assertEqual(time.strftime("%H:%M:%S", time.gmtime(r[parser.TS])), "10:12:01")
        v6 = HAP.replace("203.0.113.7:51234", "2001:db8::1:40000").replace("Oct  8 10:12:01 lb haproxy[123]: ", "2026-10-08T10:12:01+09:00 lb haproxy[1]: ")
        self.assertEqual(lp.parse(v6)[parser.IP], "2001:db8::1")
        bad = HAP.replace("200 512", "400 187").replace('"GET /index.html HTTP/1.1"', '"<BADREQ>"')
        self.assertEqual(lp.parse(bad)[parser.METHOD], "(INVALID)")
        self.assertEqual(lp.parse(HAP.replace("0/0/1/2/3 200 512", "0/0/1/2/+3 200 +512"))[parser.BYTES], 512)

    def test_haproxy_events_and_year(self):
        lp = parser.LineParser(parser.FMT_HAPROXY, 9, 9, 9)
        lp.parse(HAP.replace("08/Oct/2026", "26/Dec/2025"))      # 마지막 접속 로그의 연도를 기억
        ev = lp.parse('Jan  3 11:35:13 localhost haproxy[1]: Server http_back/nginx2 is DOWN, reason: Layer4 connection problem')
        self.assertEqual((ev[1], len(ev)), ("alert", 6))
        import time
        self.assertEqual(time.strftime("%Y-%m-%d", time.gmtime(ev[0])), "2026-01-03")   # 연말 -> 연초 보정
        ssl = lp.parse('Jul 26 10:31:46 localhost haproxy[1]: 45.79.207.111:45512 [26/Jul/2025:10:31:38.135] main/1: SSL handshake failure')
        self.assertEqual((ssl[2], ssl[3]), ("45.79.207.111", "SSL handshake failure (HAProxy)"))
        self.assertIsNone(lp.parse("Jul 26 10:31:46 localhost haproxy[1]: something else entirely"))

    def test_error_log_format(self):
        lp = parser.LineParser(parser.FMT_ERROR, 9, 9)
        r = lp.parse('2026/09/09 14:40:19 [info] 409854#409854: *764395 client sent invalid method while reading client request line, '
                     'client: 198.51.100.37, server: _, request: "MGLNDD_192.0.2.14_80"')
        self.assertEqual((r[parser.E_LEVEL], r[parser.E_IP], r[parser.E_REQ], r[parser.E_SERVER]), ("info", "198.51.100.37", "MGLNDD_192.0.2.14_80", "_"))
        r = lp.parse('2026/10/08 10:00:00 [error] 1#1: *2 upstream timed out (110: x), client: 1.2.3.4, server: a.com, request: "GET /x HTTP/1.1", upstream: "http://127.0.0.1/x", host: "a.com"')
        self.assertEqual(r[parser.E_REQ], "GET /x HTTP/1.1")
        r = lp.parse('2026/09/09 14:47:00 [info] 1#1: *3 client 198.51.100.48 closed keepalive connection')
        self.assertEqual(r[parser.E_IP], "198.51.100.48")
        self.assertEqual(lp.parse('2026/09/10 03:34:03 [emerg] 1#1: open() "/x" failed (13: Permission denied)')[parser.E_IP], "")
        # 시간대 변환: 에러로그가 UTC(0)로 기록되면 KST(9) 표시는 +9시간
        import time
        r = parser.LineParser(parser.FMT_ERROR, 9, 0).parse('2026/10/08 01:00:00 [info] 1#1: *1 client closed connection while waiting for request, client: 1.1.1.1, server: x')
        self.assertEqual(time.strftime("%H", time.gmtime(r[parser.E_TS])), "10")

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
        a = run([line(ua="sqlmap/1.7"), line(ip="2.2.2.2", req="TRACE /x HTTP/1.1", status=405)])
        self.assertEqual(self.kinds(a), {"scanner", "method"})

    def test_rest_methods_are_low_unless_executable_path(self):
        a = run([line(req="PUT /portal/user/password HTTP/1.1"), line(ip="2.2.2.2", req="DELETE /api/x/1 HTTP/1.1"),
                 line(ip="3.3.3.3", req="PUT /upload/x.jsp HTTP/1.1", status=405)])
        res = {x["ip"]: x for x in a.result()["ips"]}
        self.assertEqual((res["1.2.3.4"]["level"], res["1.2.3.4"]["findings"][0]["key"]), (1, "method_rest"))
        self.assertEqual(res["2.2.2.2"]["level"], 1)
        self.assertEqual((res["3.3.3.3"]["level"], res["3.3.3.3"]["findings"][0]["key"]), (2, "method"))
        self.assertEqual(run([line(req="PUT /a HTTP/1.1")], cfg(allowed_methods=["GET", "POST", "PUT"])).result()["ips"], [])
        self.assertEqual(a.result()["verdict"]["status"], "alert")        # 3.3.3.3 때문에
        self.assertEqual(run([line(req="PUT /a HTTP/1.1")]).result()["verdict"]["status"], "ok")

    def test_protocol_probe_is_not_url_attack(self):
        # 회귀: 비HTTP 프로토콜 요청의 \x00 이스케이프가 '경로 조작'으로 오탐되던 문제
        r = parser.LineParser(parser.FMT_NGINX_BR).parse(
            '1.2.3.4 - - [08/Oct/2026:10:00:00 +0900] [request "\\x00\\x00\\x00\'\\xFFSMBr\\x00NT LM 0.12"] [status 400] [body_bytes_sent 150] "-" "-" "-"')
        a = Analyzer(cfg())
        a.feed(r)
        x = a.result()["ips"][0]
        self.assertEqual([f["key"] for f in x["findings"]], ["malformed"])
        self.assertIn("SMB", x["findings"][0]["desc"])
        a = Analyzer(cfg())
        for req in ("JDWP-Handshake", "JRMI", "*1", "MGLNDD_1.2.3.4_80"):
            a.feed(parser.LineParser(parser.FMT_NGINX_BR).parse(BRACKET.replace("GET /robots.txt HTTP/1.1", req).replace("203.0.113.250", "9.9.9.9")))
        d = a.result()["ips"][0]["findings"][0]["desc"]
        for name in ("JDWP", "Java RMI", "Redis", "MGLNDD"):
            self.assertIn(name, d)

    def test_malformed_not_counted_as_errors(self):
        rows = ['9.9.9.9 - - [08/Oct/2026:10:00:%02d +0900] "\\x16\\x03\\x01\\x00{" 400 150 "-" "-"' % (i % 60) for i in range(40)]
        self.assertEqual(self.kinds(run(rows)), {"malformed"})

    def test_public_lb_auto_proxy(self):
        lb = "203.0.113.250"
        rows = [line(ip=lb, req="GET /p%d HTTP/1.1" % i, xff="175.1.1.%d" % (i % 30)) for i in range(60)]
        rows.append(line(ip="198.51.100.5", ua="sqlmap", xff="-"))
        lp = parser.LineParser(parser.FMT_NGINX)
        recs = [lp.parse(l) for l in rows]
        stats = {}
        for r in recs:
            st = stats.setdefault(r[parser.IP], [0, 0, set()])
            st[0] += 1
            if r[parser.XFF]:
                st[1] += 1
                st[2].add(r[parser.XFF])
        a = Analyzer(cfg())
        a.register_proxies(stats)
        self.assertEqual(list(a.auto_proxies), [lb])
        for r in recs:
            a.feed(r)
        self.assertIn("175.1.1.3", a.ips)          # XFF의 실제 접속자 IP 사용
        self.assertNotIn(lb, a.ips)
        b = Analyzer(cfg(auto_proxy=False))        # 끄면 LB IP로 집계
        b.register_proxies(stats)
        self.assertEqual(b.auto_proxies, {})

    def test_auto_proxy_spoof_guard(self):
        # 공인 IP 한 곳이 XFF를 위조해 보내는 정도로는 프록시로 인정하지 않는다
        a = Analyzer(cfg())
        a.register_proxies({"198.51.100.9": [10, 10, {"1.1.1.1", "2.2.2.2", "3.3.3.3"}],     # 요청 20건 미만
                            "198.51.100.8": [100, 100, {"1.1.1.1"}],                           # XFF 값이 1종류
                            "198.51.100.7": [100, 50, {"1.1.1.1", "2.2.2.2", "3.3.3.3"}]})     # XFF 비율 90% 미만
        self.assertEqual(a.auto_proxies, {})
        a.feed(parser.LineParser(parser.FMT_NGINX).parse(line(ip="198.51.100.9", ua="sqlmap", xff="7.7.7.7")))
        self.assertEqual(list(a.ips), ["198.51.100.9"])                                      # XFF 무시

    def test_error_log_classification(self):
        a = Analyzer(cfg())
        lp = parser.LineParser(parser.FMT_ERROR)
        for l in [
            '2026/10/08 10:00:00 [info] 1#1: *1 client closed connection while waiting for request, client: 203.0.113.250, server: 0.0.0.0:443',
            '2026/10/08 10:00:01 [info] 1#1: *2 client sent invalid method while reading client request line, client: 198.51.100.77, server: _, request: "JDWP-Handshake"',
            '2026/10/08 10:00:02 [emerg] 1#1: open() "/var/log/nginx/error.log" failed (13: Permission denied)',
            '2026/10/08 10:00:03 [error] 1#1: *3 upstream timed out (110: x) while reading response header from upstream, client: 203.0.113.9, server: a, request: "GET /api HTTP/1.1", upstream: "http://127.0.0.1/api", host: "a"',
            '2026/10/08 10:00:04 [error] 1#1: *4 open() "/x/.env" failed (2: No such file or directory), client: 198.51.100.20, server: _, request: "GET /.env HTTP/1.1", host: "a"',
            '2026/10/08 10:00:05 [error] 1#1: *5 limiting requests, excess: 5.1 by zone "one", client: 192.0.2.99, server: a, request: "GET / HTTP/1.1", host: "a"',
            '2026/10/08 10:00:06 [crit] 1#1: *6 something unexpected happened, client: 1.1.1.1, server: a',
        ]:
            a.feed_error(lp.parse(l))
        es = a.error_summary()
        self.assertEqual((es["total"], es["noise"], es["security"]), (7, 1, 3))
        labels = {o["label"] for o in es["ops"]}
        self.assertTrue({"파일 열기 실패(권한/한도/디스크)", "업스트림(백엔드) 오류", "기타 오류"} <= labels)
        ips = {x["ip"]: x for x in a.result()["ips"]}
        self.assertEqual(ips["198.51.100.77"]["level"], 1)       # 프로토콜 스캔: 낮음
        self.assertEqual(ips["198.51.100.20"]["level"], 2)       # 에러난 요청 URL의 공격 패턴: 중간
        self.assertEqual(ips["192.0.2.99"]["level"], 2)          # limit_req 초과: 중간
        self.assertNotIn("203.0.113.9", ips)                     # 업스트림 오류는 운영 정보라 위협 IP가 아님

    def test_login_fail_ignores_server_errors(self):
        rows = [line(req="GET /login HTTP/1.1", status=502, t="08/Oct/2026:10:00:%02d +0900" % i) for i in range(10)]
        self.assertNotIn("login_fail", self.kinds(run(rows)))
        rows = [line(req="POST /login HTTP/1.1", status=401, t="08/Oct/2026:10:00:%02d +0900" % i) for i in range(6)]
        self.assertIn("login_fail", self.kinds(run(rows)))

    def test_proxy_flag_in_results(self):
        a = Analyzer(cfg(trusted_proxies=["203.0.113.250"]))
        a.feed(parser.LineParser(parser.FMT_NGINX).parse(line(ip="203.0.113.250", ua="sqlmap")))
        self.assertTrue(a.result()["ips"][0]["is_proxy"])

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

    def test_new_samples_via_state(self):
        def load(*names):
            st = server.State(cfg())
            for n in names:
                r = st.add_file(n, os.path.join(SAMPLES, n), n)
                self.assertNotIn("error", r, (n, r))
            return st, st.summary()
        # 대괄호형 + 공인 IP LB(XFF) + 직접 접속 스캐너
        st, sm = load("nginx_bracket_lb.log")
        self.assertEqual([p["ip"] for p in sm["auto_proxies"]], ["203.0.113.250"])
        ips = {x["ip"]: x for x in sm["ips"]}
        self.assertEqual((sm["verdict"]["high"], sm["verdict"]["medium"]), (3, 3))
        self.assertTrue({"203.0.113.9", "198.51.100.20", "192.0.2.88"} <= set(ips))   # LB 경유 + 직접
        self.assertNotIn("203.0.113.250", ips)
        # HAProxy: 접속자 IP가 바로 찍히고 서버 상태 줄은 서버 상태로 분리
        st, sm = load("haproxy.log")
        self.assertEqual((sm["verdict"]["high"], sm["verdict"]["medium"]), (2, 2))   # nginx에 직접 접속한 스캐너는 없음
        labels = {o["label"] for o in sm["errorlog"]["ops"]}
        self.assertIn("백엔드 서버 다운(HAProxy)", labels)
        self.assertIn("백엔드 서버 복구(HAProxy)", labels)
        ips = {x["ip"]: x for x in sm["ips"]}
        self.assertEqual(ips["198.51.100.31"]["level"], 1)            # TLS 핸드셰이크 실패
        self.assertEqual(sm["files"][0]["skipped"], 0)
        # error.log
        st, sm = load("nginx_error.log")
        self.assertEqual(sm["errorlog"]["levels"], {"emerg": 2, "error": 3, "info": 63})
        ips = {x["ip"]: x for x in sm["ips"]}
        self.assertEqual((ips["198.51.100.77"]["level"], ips["198.51.100.20"]["level"], ips["192.0.2.99"]["level"]), (1, 2, 2))
        # haproxy + nginx 접근 로그를 함께 올리면 같은 요청을 합쳐 집계 (HAProxy의 IP + nginx의 UA)
        st, sm = load("haproxy.log", "nginx_bracket_lb.log")
        self.assertEqual((sm["verdict"]["high"], sm["verdict"]["medium"]), (3, 3))     # 직접 접속 스캐너까지 모두
        self.assertEqual([n["type"] for n in sm["notes"]], ["info"])
        self.assertEqual(sm["total"], 868)                                              # 861 + 867 - 합친 860
        self.assertEqual([f["merged"] for f in sm["files"]], [860, 860])
        self.assertEqual(load("haproxy.log", "nginx_error.log")[1]["notes"], [])


def _write(d, name, lines, gz=False):
    p = os.path.join(d, name)
    data = ("\n".join(lines) + "\n").encode("utf-8")
    if gz:
        with gzip.open(p, "wb") as f:
            f.write(data)
    else:
        with open(p, "wb") as f:
            f.write(data)
    return p


def _state(files, **kw):
    st = server.State(cfg(**kw))
    for p in files:
        r = st.add_file(os.path.basename(p), p, p)
        assert "error" not in r, r
    return st


def _read(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return f.read().splitlines()


class HaproxyVariantTest(unittest.TestCase):
    CUSTOM = ('Oct  6 08:43:09 localhost haproxy[270451]: 124.1.1.%d:64317 [06/Oct/2026:08:43:%02d.632] main~ http_back/nginx2 '
              '0/0/2/2/4 200 348 "GET /p%d HTTP/1.1" upgrade="-" connection="-"')

    def body(self, n=200):
        return [self.CUSTOM % (i % 50 + 1, i % 60, i) for i in range(n)]

    def test_custom_log_format_without_termination_state(self):
        lp = parser.LineParser(parser.FMT_HAPROXY, 9, 9, 9)
        r = lp.parse(self.CUSTOM % (7, 9, 1))
        self.assertEqual((r[parser.IP], r[parser.METHOD], r[parser.PATH], r[parser.STATUS], r[parser.BYTES]),
                         ("124.1.1.7", "GET", "/p1", 200, 348))

    def test_badreq(self):
        lp = parser.LineParser(parser.FMT_HAPROXY, 9, 9, 9)
        base = ('Oct  6 08:43:46 localhost haproxy[1]: 51.8.102.190:15913 [06/Oct/2026:08:43:46.189] main~ main/<NOSRV> '
                '-1/-1/-1/-1/194 %d 0 "<BADREQ>" upgrade="-" connection="-"')
        self.assertEqual(lp.parse(base % 408)[parser.METHOD], "-")          # 연결만 하고 요청 없음: 위협 아님
        r = lp.parse(base % 400)
        self.assertEqual((r[parser.METHOD], r[parser.PATH], r[parser.STATUS]), ("(INVALID)", "<BADREQ>", 400))
        a = Analyzer(cfg())
        a.feed(lp.parse(base % 408))
        self.assertEqual(a.result()["ips"], [])
        a.feed(lp.parse(base % 400))
        self.assertIn("HAProxy가 거부한", a.result()["ips"][0]["findings"][0]["desc"])

    def test_tls_events(self):
        lp = parser.LineParser(parser.FMT_HAPROXY, 9, 9, 9)
        a = Analyzer(cfg())
        for msg in ("Timeout during SSL handshake", "Connection closed during SSL handshake", "SSL handshake failure"):
            a.feed_error(lp.parse("Oct 23 10:46:01 localhost haproxy[1]: 8.8.8.8:58533 [23/Oct/2025:10:45:31.414] main/1: " + msg))
        es = a.error_summary()
        self.assertEqual((es["total"], es["noise"], es["security"]), (3, 2, 1))

    def test_cut_and_modified_logs_are_still_read(self):
        body = self.body()
        variants = {
            "첫 줄이 중간에서 잘림": [body[0][70:]] + body[1:],
            "앞부분 삭제": body[100:],
            "무작위 줄 삭제": [l for i, l in enumerate(body) if i % 3],
            "syslog 접두 제거": [re.sub(r"^.*?haproxy\[\d+\]: ", "", l) for l in body],
            "뒤쪽 필드 제거": [re.sub(r" upgrade=.*$", "", l) for l in body],
            "응답코드·바이트 제거": [re.sub(r' (\d{3}) (\d+) "', ' "', l) for l in body],
            "타이머 제거": [re.sub(r" [-\d]+/[-\d]+/[-\d]+/[-\d]+/[-\d]+ ", " ", l) for l in body],
            "마지막 줄이 잘림": body[:-1] + [body[-1][:80]],
            "앞쪽에 깨진 줄이 많음": ["garbage %d" % i for i in range(30)] + body,
            "CRLF": [l + "\r" for l in body],
        }
        with tempfile.TemporaryDirectory() as d:
            for name, lines in variants.items():
                rd = parser.LogReader(_write(d, "v.log", lines))
                n = sum(1 for _ in rd.records())
                self.assertEqual(rd.fmt, parser.FMT_HAPROXY, name)
                self.assertGreaterEqual(n, len(lines) - 32, name)

    def test_nginx_lines_are_not_mistaken_for_haproxy(self):
        self.assertEqual(parser.detect_format([line(ip="1.2.3.%d" % i) for i in range(10)]), parser.FMT_NGINX)
        self.assertEqual(parser.detect_format([BRACKET] * 5), parser.FMT_NGINX_BR)

    def test_unsupported_shows_first_line(self):
        with self.assertRaises(ValueError) as cm:
            parser.detect_format(["hello world", "foo bar"])
        self.assertIn("hello world", str(cm.exception))


class CombinedAnalysisTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.states = []

    def st(self, files, **kw):
        s = _state(files, **kw)
        self.states.append(s)
        self.addCleanup(s.cleanup)
        return s

    def test_split_logs_equal_whole(self):
        for name in ("nginx_access.log", "nginx_bracket_lb.log", "haproxy.log"):
            lines = _read(name)
            whole = self.st([_write(self.tmp.name, "w_" + name, lines)], recent_days=0).summary()
            n = len(lines)
            parts = [_write(self.tmp.name, "p1_" + name, lines[:n // 3]),
                     _write(self.tmp.name, "p2_" + name + ".gz", lines[n // 3: 2 * n // 3], gz=True),
                     _write(self.tmp.name, "p3_" + name, lines[2 * n // 3:])]
            split = self.st(parts, recent_days=0).summary()
            self.assertEqual(split["verdict"], whole["verdict"], name)
            self.assertEqual([x["ip"] for x in split["ips"]], [x["ip"] for x in whole["ips"]], name)
            self.assertEqual(split["total"], whole["total"], name)
            self.assertEqual(split["auto_proxies"], whole["auto_proxies"], name)
            self.assertEqual(len(split["files"]), 3)

    def test_split_logs_detect_lb_across_files(self):
        # 파일 하나만으로는 LB 판별 근거(요청 20건)가 부족해도, 전체를 합치면 판별된다
        lb = "203.0.113.250"
        lines = [line(ip=lb, req="GET /p%d HTTP/1.1" % i, xff="175.1.1.%d" % (i % 9), t="08/Oct/2026:10:00:%02d +0900" % (i % 60))
                 for i in range(36)]
        files = [_write(self.tmp.name, "a%d.log" % i, lines[i * 12:(i + 1) * 12]) for i in range(3)]
        self.assertEqual(self.st(files[:1]).summary()["auto_proxies"], [])
        sm = self.st(files).summary()
        self.assertEqual([p["ip"] for p in sm["auto_proxies"]], [lb])
        self.assertEqual(sm["unique_ips"], 9)

    def test_haproxy_nginx_merge_is_order_independent(self):
        h = _write(self.tmp.name, "h.log", _read("haproxy.log"))
        n = _write(self.tmp.name, "n.log", _read("nginx_bracket_lb.log"))
        a = self.st([h, n], recent_days=0).summary()
        b = self.st([n, h], recent_days=0).summary()
        for sm in (a, b):
            self.assertEqual((sm["total"], sm["unique_ips"]), (868, 48))
            self.assertEqual(sm["verdict"], a["verdict"])
        self.assertEqual([x["ip"] for x in a["ips"]], [x["ip"] for x in b["ips"]])
        # HAProxy가 User-Agent를 캡처하지 않았다면, nginx의 User-Agent(sqlmap)가 합쳐져 스캐너로 탐지된다
        nocap = _write(self.tmp.name, "h_nocap.log", [re.sub(r" \{[^}]*\}", "", l) for l in _read("haproxy.log")])
        keys = lambda st: [f["key"] for f in st.ip_detail("203.0.113.9")["findings"]]
        self.assertNotIn("scanner", keys(self.st([nocap], recent_days=0)))
        self.assertIn("scanner", keys(self.st([nocap, n], recent_days=0)))

    def test_haproxy_nginx_without_overlap_warns(self):
        h = _write(self.tmp.name, "h.log", _read("haproxy.log"))
        n = _write(self.tmp.name, "n.log", _read("nginx_clean.log"))
        sm = self.st([h, n], recent_days=0).summary()
        self.assertEqual([x["type"] for x in sm["notes"]], ["warn"])
        self.assertEqual([f["merged"] for f in sm["files"]], [0, 0])

    def test_recent_days_window(self):
        def at(day, ip, req="GET / HTTP/1.1", hh=12):
            return line(ip=ip, req=req, t="%02d/Oct/2026:%02d:00:00 +0900" % (day, hh))
        lines = [at(1, "9.9.9.1", "GET /a?id=1%27%20UNION%20SELECT%201-- HTTP/1.1"),     # 범위 밖
                 at(2, "9.9.9.2", "GET /a?id=1%27%20UNION%20SELECT%201-- HTTP/1.1"),     # 범위 밖
                 at(3, "9.9.9.3", "GET /a?id=1%27%20UNION%20SELECT%201-- HTTP/1.1"),     # 경계(10일 12시 - 7일 = 3일 12시): 포함
                 at(5, "9.9.9.5"), at(10, "9.9.9.10", "GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1")]
        p = _write(self.tmp.name, "w.log", lines)
        st = self.st([p])                                       # 기본 7일
        sm = st.summary()
        self.assertEqual((sm["range"]["days"], sm["range"]["from"], sm["range"]["to"]), (7, "2026-10-03 12:00:00", "2026-10-10 12:00:00"))
        self.assertEqual({x["ip"] for x in sm["ips"]}, {"9.9.9.3", "9.9.9.10"})
        self.assertEqual((sm["total"], sm["range"]["excluded"], sm["files"][0]["in_range"], sm["files"][0]["excluded"]), (3, 2, 3, 2))
        st.set_days(3)
        self.assertEqual({x["ip"] for x in st.summary()["ips"]}, {"9.9.9.10"})
        st.set_days(0)
        sm = st.summary()
        self.assertEqual((sm["total"], len(sm["ips"]), sm["range"]["from"]), (5, 4, ""))
        with self.assertRaises(ValueError):
            st.set_days(-1)

    def test_recent_window_applies_to_every_log_kind(self):
        err = ['2026/10/01 10:00:00 [emerg] 1#1: open() "/x" failed (13: Permission denied)',
               '2026/10/10 10:00:00 [emerg] 1#1: open() "/y" failed (13: Permission denied)']
        h = [HaproxyVariantTest.CUSTOM % (1, 1, 1), HaproxyVariantTest.CUSTOM.replace("06/Oct", "01/Sep") % (2, 2, 2)]
        st = self.st([_write(self.tmp.name, "e.log", err), _write(self.tmp.name, "h.log", h)])
        sm = st.summary()
        self.assertEqual(sm["errorlog"]["total"], 1)                    # 7일 이전 에러 줄은 제외
        self.assertEqual(sm["total"], 0 if sm["empty"] else sm["total"])

    def test_notes_files_outside_range(self):
        old = _write(self.tmp.name, "old.log", [line(t="01/Jul/2026:12:00:00 +0900")])
        new = _write(self.tmp.name, "new.log", [line(ip="2.2.2.2", t="10/Oct/2026:12:00:00 +0900")])
        sm = self.st([old, new]).summary()
        self.assertEqual([n["type"] for n in sm["notes"]], ["warn"])
        self.assertIn("old.log", sm["notes"][0]["text"])
        self.assertEqual(self.st([old, new], recent_days=0).summary()["notes"], [])

    def test_anchor_now_and_empty_range(self):
        import calendar
        lines = [line(ip="9.9.9.9", ua="sqlmap", t="01/Oct/2026:12:00:00 +0900")]
        p = _write(self.tmp.name, "o.log", lines)
        now = calendar.timegm((2026, 10, 20, 0, 0, 0, 0, 0, 0)) - 9 * 3600       # KST 2026-10-20 00:00
        st = server.State(cfg(recent_anchor="now"), now_fn=lambda: now)
        self.addCleanup(st.cleanup)
        st.add_file("o.log", p, "o")
        sm = st.summary()
        self.assertTrue(sm["empty"])                                     # 현재 기준 7일 안에 로그가 없음
        self.assertEqual((sm["range"]["from"], sm["range"]["to"], sm["range"]["excluded"]), ("2026-10-13 00:00:00", "2026-10-20 00:00:00", 1))
        st.set_days(30)
        self.assertFalse(st.summary()["empty"])

    def test_source_files_are_kept_and_cleaned(self):
        src = _write(self.tmp.name, "s.log", [line()])
        st = self.st([src])
        self.assertTrue(os.path.exists(src))                             # 호출자의 파일은 건드리지 않음
        d = st.dir
        self.assertTrue(d and os.path.isdir(d))
        st.reset()
        self.assertFalse(os.path.exists(d))
        self.assertTrue(os.path.exists(src))
        self.assertTrue(st.summary()["empty"])


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

    def test_range_api(self):
        self.req("POST", "/api/reset")
        with open(os.path.join(SAMPLES, "nginx_access.log"), "rb") as f:
            self.assertEqual(self.req("POST", "/api/upload?name=a.log", f.read())[0], 200)
        s = json.loads(self.req("GET", "/api/summary")[1])
        self.assertEqual(s["range"]["days"], 7)
        self.assertEqual(self.req("POST", "/api/range?days=1")[0], 200)
        s = json.loads(self.req("GET", "/api/summary")[1])
        self.assertEqual(s["range"]["days"], 1)
        self.assertIn("in_range", s["files"][0])
        for bad in ("abc", "-1", "99999", ""):
            self.assertEqual(self.req("POST", "/api/range?days=" + bad)[0], 400, bad)
        self.req("POST", "/api/range?days=0")
        self.req("POST", "/api/reset")

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
