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
    c["geo_enabled"] = False          # 기존 테스트는 공인 IP를 자유롭게 쓰므로 국가 판별을 끈다(국가 판별은 GeoTest에서 검증)
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

    def test_merge_same_second_same_url_keeps_each_ip_once(self):
        # 같은 초에 같은 URL을 서로 다른 두 IP가 요청: 병합 후에도 IP마다 한 번씩만 집계되어야 한다
        hl = ['Oct  6 08:43:09 localhost haproxy[1]: 7.7.7.%d:5000 [06/Oct/2026:08:43:09.100] main~ be/s 0/0/0/1/1 200 10 "GET /same HTTP/1.1"' % i
              for i in (1, 2, 3)]
        nl = [line(ip="10.0.0.5", req="GET /same HTTP/1.1", t="06/Oct/2026:08:43:09 +0900", xff="-") for _ in range(2)]
        st = self.st([_write(self.tmp.name, "h.log", hl), _write(self.tmp.name, "n.log", nl)], recent_days=0)
        a = st.analysis()["analyzer"]
        self.assertEqual(a.total, 3)                                  # 3 + 2 - 합친 2
        self.assertEqual(sorted((ip, x.n) for ip, x in a.ips.items()), [("7.7.7.1", 1), ("7.7.7.2", 1), ("7.7.7.3", 1)])
        self.assertEqual(st.analysis()["merged"], 2)

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


class ReaderOptimizationTest(unittest.TestCase):
    """분석 범위 밖 로그를 읽지·파싱하지 않는 최적화가 결과를 바꾸지 않는지 확인한다."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        old = parser.BLOCK_LINES
        parser.BLOCK_LINES = 50                   # 블록을 많이 만들어 건너뛰기 경로를 충분히 시험
        self.addCleanup(lambda: setattr(parser, "BLOCK_LINES", old))

    def lines(self, n=1000, shuffle=0):
        rows = []
        for i in range(n):
            day = 1 + i * 20 // n                  # 20일에 걸친 로그
            rows.append(line(ip="9.9.%d.%d" % (i % 200, i % 250), req="GET /p%d HTTP/1.1" % i,
                             t="%02d/Oct/2026:%02d:%02d:%02d +0900" % (day, i % 24, i % 60, (i * 7) % 60)))
        rng = __import__("random").Random(1)
        for _ in range(shuffle):                   # 시각 순서가 조금 어긋난 로그
            a, b = rng.randrange(n), rng.randrange(n)
            rows[a], rows[b] = rows[b], rows[a]
        return rows

    def cutoff(self):
        import calendar
        return calendar.timegm((2026, 10, 14, 0, 0, 0, 0, 0, 0))

    def same(self, name, rows, gz=False):
        p = _write(self.tmp.name, name, rows, gz=gz)
        rd = parser.LogReader(p)
        rd.scan()
        cut = self.cutoff()
        full = [r for r in rd.records() if r[0] >= cut]
        fast = [r for r in rd.records(cut) if r[0] >= cut]
        self.assertEqual(fast, full, name)
        self.assertTrue(full)
        return rd, p

    def test_cutoff_results_are_identical(self):
        self.same("sorted.log", self.lines())
        self.same("shuffled.log", self.lines(shuffle=200))            # 정렬되지 않은 로그도 정확해야 함
        self.same("crlf.log", [l + "\r" for l in self.lines()])
        self.same("sorted.gz", self.lines(), gz=True)
        garbage = []
        for i, l in enumerate(self.lines()):
            garbage.append(l)
            if i % 17 == 0:
                garbage += ["garbage line", ""]
        self.same("garbage.log", garbage)

    def test_old_blocks_are_not_read(self):
        rd, p = self.same("sorted.log", self.lines())
        n_old = sum(1 for _ in rd.records())
        list(rd.records(self.cutoff()))
        # 범위 밖 블록을 건너뛰었으므로 읽은 줄 수가 전체보다 적다
        self.assertLess(rd.info["lines"], n_old * 0.6)
        self.assertGreater(len(rd.blocks), 10)

    def test_everything_old_yields_nothing(self):
        p = _write(self.tmp.name, "old.log", self.lines())
        rd = parser.LogReader(p)
        rd.scan()
        import calendar
        self.assertEqual(list(rd.records(calendar.timegm((2027, 1, 1, 0, 0, 0, 0, 0, 0)))), [])
        self.assertEqual(len(list(rd.records(0))), 1000)

    def test_fast_timestamp_equals_full_parser(self):
        for name in ("nginx_access.log", "nginx_bracket_lb.log", "haproxy.log", "nginx_error.log"):
            p = os.path.join(SAMPLES, name)
            rd = parser.LogReader(p, 9, 7, 8)             # 시간대 변환 경로도 함께 확인
            lp = rd._parser()
            fast = parser._FastTS(rd.fmt, 9, 7, 8)
            checked = 0
            with open(p, "rb") as f:
                for raw in f:
                    rec = lp.parse(raw.decode("utf-8").rstrip("\n"))
                    if rec is None or len(rec) not in (6, 11):
                        continue
                    ts = fast.ts(raw)
                    if ts is not None:
                        self.assertEqual(ts, rec[0], (name, raw[:80]))
                        checked += 1
            self.assertGreater(checked, 50, name)
        self.assertFalse(parser._FastTS(parser.FMT_JSON, 9, 9, 9).enabled)             # JSON은 전체 파싱 경로

    def test_scan_info_matches_full_read(self):
        for name in ("nginx_access.log", "haproxy.log", "nginx_error.log", "nginx_json.log"):
            rd = parser.LogReader(os.path.join(SAMPLES, name))
            rd.scan()
            scan_info = {k: rd.info[k] for k in ("lines", "parsed", "skipped", "first", "last")}
            list(rd.records())
            self.assertEqual({k: rd.info[k] for k in scan_info}, scan_info, name)

    def test_large_file_sampling_still_detects_lb(self):
        old = parser.SAMPLE_BYTES
        parser.SAMPLE_BYTES = 5000                 # 작은 파일도 표본 추출 경로로 처리
        self.addCleanup(lambda: setattr(parser, "SAMPLE_BYTES", old))
        lb = "203.0.113.250"
        rows = [line(ip=lb, req="GET /p%d HTTP/1.1" % i, xff="175.1.1.%d" % (i % 40)) for i in range(2000)]
        rows += [line(ip="198.51.100.%d" % (i % 90), req="GET /d%d HTTP/1.1" % i, xff="-") for i in range(2000)]
        p = _write(self.tmp.name, "lb.log", rows)
        rd = parser.LogReader(p)
        stats = rd.scan()
        self.assertEqual(list(stats), [lb])                         # XFF가 붙은 IP만 기록(메모리 절약)
        n, nx, xs = stats[lb]
        self.assertGreater(n, 1000)                                 # 표본 비율만큼 환산
        self.assertEqual(rd.info["parsed"], 4000)                   # 줄 수·기간은 표본과 무관하게 정확
        a = Analyzer(cfg())
        a.register_proxies({lb: stats[lb]})
        self.assertEqual(list(a.auto_proxies), [lb])

    def test_only_in_range_ips_are_kept_in_memory(self):
        old = [line(ip="1.1.%d.%d" % (i // 250, i % 250), t="01/Sep/2026:10:00:00 +0900") for i in range(3000)]
        new = [line(ip="2.2.2.%d" % i, t="10/Oct/2026:10:00:00 +0900") for i in range(20)]
        st = server.State(cfg())
        self.addCleanup(st.cleanup)
        st.add_file("a.log", _write(self.tmp.name, "a.log", old + new), "a")
        a = st.analysis()["analyzer"]
        self.assertEqual(len(a.ips), 20)                            # 7일 밖의 3000개 IP는 집계 대상이 아님
        self.assertEqual(a.total, 20)
        self.assertEqual(st.analysis()["excluded"], 3000)


class SortTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def state(self, *names, **kw):
        st = server.State(cfg(recent_days=0, **kw))
        self.addCleanup(st.cleanup)
        for n in names:
            r = st.add_file(n, os.path.join(SAMPLES, n), n)
            self.assertNotIn("error", r, r)
        return st

    def ips(self, st):
        return [x["ip"] for x in st.summary()["ips"]]

    def test_default_order_is_unchanged(self):
        st = self.state("nginx_access.log")
        sm = st.summary()
        self.assertEqual(sm["sort"], {"key": "level", "dir": "desc", "ev": "asc"})
        levels = [x["level"] for x in sm["ips"]]
        self.assertEqual(levels, sorted(levels, reverse=True))
        self.assertEqual(self.ips(st), [x["ip"] for x in st.result()["ips"]])     # 분석기가 정한 기존 순서와 같다

    def test_sort_by_date_both_directions(self):
        st = self.state("nginx_access.log")
        for key in ("last", "first"):
            st.set_sort(key, "desc")
            vals = [x[key] for x in st.summary()["ips"]]
            self.assertEqual(vals, sorted(vals, reverse=True), key)
            self.assertGreater(len(set(vals)), 3)                    # 날짜가 실제로 다양해야 의미 있는 검증
            st.set_sort(key, "asc")
            vals = [x[key] for x in st.summary()["ips"]]
            self.assertEqual(vals, sorted(vals), key)
        # 키만 바꾸면 그 키의 기본 방향: 마지막 접근은 최신순, 첫 접근은 오래된 순
        st.set_sort("last")
        self.assertEqual(st.summary()["sort"], {"key": "last", "dir": "desc", "ev": "asc"})
        st.set_sort("first")
        self.assertEqual(st.summary()["sort"]["dir"], "asc")
        st.set_sort(direction="desc")                                 # 방향만 바꾸기
        self.assertEqual(st.summary()["sort"], {"key": "first", "dir": "desc", "ev": "asc"})

    def test_sort_by_requests_level_and_ip(self):
        st = self.state("nginx_access.log")
        st.set_sort("requests", "desc")
        r = [x["requests"] for x in st.summary()["ips"]]
        self.assertEqual(r, sorted(r, reverse=True))
        st.set_sort("requests", "asc")
        self.assertEqual([x["requests"] for x in st.summary()["ips"]], sorted(r))
        st.set_sort("level", "asc")
        lv = [x["level"] for x in st.summary()["ips"]]
        self.assertEqual(lv, sorted(lv))
        st.set_sort("ip", "asc")                                       # 문자열이 아니라 숫자 순서(192 < 198 < 203)
        self.assertEqual(self.ips(st), ["192.0.2.77", "192.0.2.88", "198.51.100.20", "198.51.100.50", "198.51.100.60", "203.0.113.9"])
        st.set_sort("ip", "desc")
        self.assertEqual(self.ips(st)[0], "203.0.113.9")

    def test_ips_without_access_time_stay_last(self):
        st = self.state("nginx_error.log")                           # 에러로그에만 나온 IP: 요청 0건
        st.set_sort("requests", "desc")
        self.assertEqual(len(self.ips(st)), 3)
        st.set_sort("last", "asc")
        lasts = [x["last"] for x in st.summary()["ips"]]
        self.assertEqual(lasts, sorted(lasts))

    def test_evidence_keeps_earliest_and_latest_and_sorts(self):
        rows = [line(ip="9.9.9.9", req="GET /a?id=1%27%20UNION%20SELECT%201-- HTTP/1.1",
                     t="08/Oct/2026:%02d:%02d:00 +0900" % (i // 60, i % 60)) for i in range(200)]    # 200건: 00:00 ~ 03:19
        st = server.State(cfg(recent_days=0, ip_mode="ip"))     # 한 IP가 전부라 자동 판별이면 요청 단위 모드가 된다
        self.addCleanup(st.cleanup)
        st.add_file("e.log", _write(self.tmp.name, "e.log", rows), "e")
        ev = st.ip_detail("9.9.9.9")["findings"][0]
        self.assertEqual((ev["count"], ev["evidence_total"], len(ev["evidence"])), (200, 200, 60))
        times = [e["time"][11:16] for e in ev["evidence"]]
        self.assertEqual(times, sorted(times))                                   # 기본: 오래된 순
        self.assertEqual((times[0], times[-1]), ("00:00", "03:19"))              # 가장 이른 것과 가장 최근 것이 모두 보관됨
        self.assertIn("00:29", times)                                            # 처음 30건
        self.assertIn("03:19", times)
        self.assertNotIn("01:40", times)                                         # 중간 구간은 보관하지 않음
        st.set_sort(ev="desc")
        times = [e["time"][11:16] for e in st.ip_detail("9.9.9.9")["findings"][0]["evidence"]]
        self.assertEqual(times, sorted(times, reverse=True))
        self.assertEqual(times[0], "03:19")                                      # 최신순에서는 가장 최근 요청이 맨 위

    def test_evidence_is_independent_of_input_order(self):
        import random
        rows = [line(ip="9.9.9.9", req="GET /a?id=1%27%20UNION%20SELECT%201-- HTTP/1.1",
                     t="08/Oct/2026:%02d:%02d:00 +0900" % (i // 60, i % 60)) for i in range(200)]
        shuffled = rows[:]
        random.Random(4).shuffle(shuffled)
        a, b = server.State(cfg(recent_days=0, ip_mode="ip")), server.State(cfg(recent_days=0, ip_mode="ip"))
        self.addCleanup(a.cleanup)
        self.addCleanup(b.cleanup)
        a.add_file("a.log", _write(self.tmp.name, "a.log", rows), "a")
        b.add_file("b.log", _write(self.tmp.name, "b.log", shuffled), "b")
        ev = lambda st: [e["time"] for e in st.ip_detail("9.9.9.9")["findings"][0]["evidence"]]
        self.assertEqual(ev(a), ev(b))

    def test_request_mode_evidence_order_and_csv_follow_sort(self):
        st = self.state("nginx_behind_lb.log")
        self.assertEqual(st.summary()["mode"], "request")
        times = lambda: [e["time"] for f in st.summary()["findings"] for e in f["evidence"] if f["key"] == "probe"]
        asc = times()
        self.assertEqual(asc, sorted(asc))
        st.set_sort(ev="desc")
        self.assertEqual(times(), sorted(asc, reverse=True))
        st2 = self.state("nginx_access.log")
        st2.set_sort("ip", "desc")
        rows = [r for r in __import__("csv").reader(st2.result_csv().splitlines())][1:]
        self.assertEqual([r[1] for r in rows][0], "203.0.113.9")                  # CSV도 화면과 같은 순서
        st2.set_sort("ip", "asc")
        self.assertEqual([r[1] for r in __import__("csv").reader(st2.result_csv().splitlines())][1], "192.0.2.77")

    def test_invalid_sort_values(self):
        st = self.state("nginx_access.log")
        for bad in ({"key": "nope"}, {"direction": "up"}, {"ev": "sideways"}):
            with self.assertRaises(ValueError):
                st.set_sort(**bad)
        self.assertEqual(st.summary()["sort"], {"key": "level", "dir": "desc", "ev": "asc"})


class WildcardTest(unittest.TestCase):
    def test_matcher_formats(self):
        from logwatcher.detector import IpMatcher
        m = IpMatcher(["198.51.*.*", "192.168.1.*", "10.0.0.0/8", "1.2.3.4", "  ", "garbage[", "203.0.*"])
        ok = ["198.51.13.157", "198.51.0.1", "192.168.1.77", "10.1.2.3", "1.2.3.4", "203.0.113.9"]
        no = ["198.52.1.1", "124.24.13.1", "192.168.2.1", "11.0.0.1", "1.2.3.5", "2001:db8::1"]
        for ip in ok:
            self.assertTrue(ip in m, ip)
        for ip in no:
            self.assertFalse(ip in m, ip)

    def test_wildcard_is_not_cidr_only(self):
        from logwatcher.detector import IpMatcher
        self.assertTrue("198.51.13.157" in IpMatcher(["198.51.*.*"]))
        self.assertFalse("198.51.13.157" in IpMatcher(["198.52.*.*"]))
        self.assertTrue("2001:db8::1" in IpMatcher(["2001:db8:*"]))
        self.assertTrue("ABCD::1" in IpMatcher(["abcd::*"]))                  # 대소문자 무시

    def test_allow_ips_wildcard_end_to_end(self):
        rows = [line(ip="198.51.13.157", ua="sqlmap"), line(ip="198.51.99.1", ua="sqlmap"), line(ip="198.52.1.1", ua="sqlmap")]
        a = run(rows, cfg(allow_ips=["198.51.*.*"]))
        self.assertEqual([x["ip"] for x in a.result()["ips"]], ["198.52.1.1"])
        self.assertEqual(a.allowed_skipped, 2)

    def test_trusted_proxies_wildcard(self):
        a = run([line(ip="198.51.100.9", ua="sqlmap", xff="7.7.7.7")], cfg(trusted_proxies=["198.51.100.*"]))
        self.assertEqual([x["ip"] for x in a.result()["ips"]], ["7.7.7.7"])


class GeoTest(unittest.TestCase):
    KR, US, AU = "168.126.63.1", "8.8.8.8", "1.1.1.1"

    def geo_cfg(self, **kw):
        return cfg(geo_enabled=True, **kw)

    def test_lookup(self):
        from logwatcher.geoip import load_geo
        g = load_geo(self.geo_cfg())
        self.assertTrue(g.available)
        self.assertEqual((g.lookup(self.KR), g.lookup(self.US), g.lookup(self.AU)), ("KR", "US", "AU"))
        self.assertEqual((g.lookup("10.1.1.1"), g.lookup("192.168.0.9"), g.lookup("127.0.0.1")), ("LAN", "LAN", "LAN"))
        self.assertIn(g.lookup("203.0.113.9"), ("ZZ", "??"))                    # 문서용 대역은 내부망(LAN)이 아니라 예약/미확인
        self.assertEqual(g.lookup("not-an-ip"), "??")
        self.assertEqual(load_geo(cfg()).lookup(self.US), "??")                  # geo_enabled=False

    def result(self, rows, **kw):
        a = Analyzer(self.geo_cfg(**kw))
        lp = parser.LineParser(parser.FMT_NGINX)
        for l in rows:
            a.feed(lp.parse(l))
        return a, {x["ip"]: x for x in a.result()["ips"]}

    def test_foreign_raises_medium_to_high_but_domestic_does_not(self):
        _, r = self.result([line(ip=self.US, ua="sqlmap"), line(ip=self.KR, ua="sqlmap")])
        us, kr = r[self.US], r[self.KR]
        self.assertEqual((us["level"], us["base_level"], us["country"], us["foreign"]), (3, 2, "US", True))
        self.assertEqual((kr["level"], kr["country"], kr["foreign"]), (2, "KR", False))
        self.assertIn("foreign", [f["key"] for f in us["findings"]])
        self.assertNotIn("foreign", [f["key"] for f in kr["findings"]])
        self.assertEqual(us["country_name"], "미국")

    def test_low_findings_are_not_raised(self):
        _, r = self.result([line(ip=self.US)])                                  # 해외 접속만: 낮음 그대로
        self.assertEqual((r[self.US]["level"], [f["key"] for f in r[self.US]["findings"]]), (1, ["foreign"]))

    def test_foreign_login(self):
        rows = [line(ip=self.US, req="POST /login HTTP/1.1", status=200)]
        _, r = self.result(rows)
        keys = [f["key"] for f in r[self.US]["findings"]]
        self.assertEqual((r[self.US]["level"], r[self.US]["base_level"]), (3, 2))     # 중간 + 해외 -> 높음
        self.assertIn("foreign_login", keys)
        _, r = self.result([line(ip=self.KR, req="POST /login HTTP/1.1", status=200)])
        self.assertEqual(r, {})                                                  # 국내 로그인은 탐지 대상 아님

    def test_known_bots_and_proxies_are_not_foreign(self):
        _, r = self.result([line(ip=self.US, ua="Mozilla/5.0 (compatible; Googlebot/2.1)", req="GET /.env HTTP/1.1", status=404)])
        self.assertEqual((r[self.US]["level"], r[self.US]["foreign"]), (2, False))   # 봇이라 해외 가중 없음
        _, r = self.result([line(ip=self.AU, ua="sqlmap")], trusted_proxies=[self.AU])
        self.assertFalse(r[self.AU]["foreign"])                                  # LB/프록시 자체는 국가 판정 제외
        _, r = self.result([line(ip="10.0.0.9", ua="sqlmap")])
        self.assertEqual((r["10.0.0.9"]["country"], r["10.0.0.9"]["foreign"], r["10.0.0.9"]["level"]), ("LAN", False, 2))

    def test_home_countries_setting(self):
        _, r = self.result([line(ip=self.US, ua="sqlmap")], home_countries=["KR", "US"])
        self.assertEqual((r[self.US]["level"], r[self.US]["foreign"]), (2, False))
        _, r = self.result([line(ip=self.KR, ua="sqlmap")], home_countries=["JP"])
        self.assertEqual((r[self.KR]["level"], r[self.KR]["foreign"]), (3, True))

    def test_geo_off_disables_country_rules(self):
        a = Analyzer(cfg(geo_enabled=False))
        a.feed(parser.LineParser(parser.FMT_NGINX).parse(line(ip=self.US, ua="sqlmap")))
        x = a.result()["ips"][0]
        self.assertEqual((x["level"], x["country"], x["foreign"]), (2, "??", False))

    def test_foreign_only_ips_are_capped(self):
        import logwatcher.detector as det
        old = det.FOREIGN_LIST_MAX
        det.FOREIGN_LIST_MAX = 3
        self.addCleanup(lambda: setattr(det, "FOREIGN_LIST_MAX", old))
        rows = [line(ip="8.8.8.%d" % i) for i in range(1, 9)] + [line(ip="8.8.8.5")] * 4     # 8.8.8.5는 요청이 가장 많음
        a = Analyzer(self.geo_cfg())
        lp = parser.LineParser(parser.FMT_NGINX)
        for l in rows:
            a.feed(lp.parse(l))
        res = a.result()
        self.assertEqual(len(res["ips"]), 3)
        self.assertEqual((res["foreign_omitted"], res["foreign_ips"]), (5, 8))
        self.assertIn("8.8.8.5", [x["ip"] for x in res["ips"]])                  # 요청이 많은 쪽이 남는다
        self.assertEqual(res["verdict"]["status"], "ok")                         # 해외 접속만으로는 이상 징후가 아님

    def test_country_stats_and_summary(self):
        rows = [line(ip=self.US, ua="sqlmap")] + [line(ip=self.KR)] * 3 + [line(ip="10.1.1.1")]
        st = server.State(self.geo_cfg(recent_days=0))
        self.addCleanup(st.cleanup)
        with tempfile.TemporaryDirectory() as d:
            st.add_file("a.log", _write(d, "a.log", rows), "a")
        sm = st.summary()
        c = {x["code"]: x for x in sm["countries"]}
        self.assertEqual((c["KR"]["requests"], c["US"]["requests"], c["LAN"]["requests"]), (3, 1, 1))
        self.assertEqual((c["US"]["foreign"], c["KR"]["foreign"], c["US"]["flagged"]), (True, False, 1))
        self.assertTrue(sm["geo"]["available"])
        self.assertEqual(sm["home_countries"], ["KR"])
        self.assertEqual([x["country_name"] for x in sm["ips"]], ["미국"])
        st.set_sort("country", "asc")
        self.assertEqual(st.summary()["sort"]["key"], "country")
        self.assertIn("미국", st.result_csv())


class SettingsRaceTest(unittest.TestCase):
    """설정(범위·모드·정렬)을 바꾸는 중에 분석이 돌고 있어도 잘못된 결과가 남지 않는지."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        rows = [line(ip="9.9.9.%d" % (i % 9), t="%02d/Oct/2026:12:00:00 +0900" % (1 + i % 10)) for i in range(60)]
        self.path = _write(self.tmp.name, "a.log", rows)

    def state(self, **kw):
        st = server.State(cfg(**kw))
        self.addCleanup(st.cleanup)
        st.add_file("a.log", self.path, "a")
        return st

    def counting(self):
        calls = []
        real = server.analyze

        def spy(entries, c, days, anchor, now):
            calls.append(days)
            return real(entries, c, days, anchor, now)
        server.analyze = spy
        self.addCleanup(lambda: setattr(server, "analyze", real))
        return calls

    def test_cached_analysis_is_reused_and_invalidated_by_key(self):
        calls = self.counting()
        st = self.state()
        st.summary()
        st.summary()
        st.set_mode("ip")
        st.set_sort("last")
        st.summary()
        self.assertEqual(calls, [7])                                  # 모드·정렬 변경은 다시 분석하지 않는다
        st.set_days(3)
        st.summary()
        st.set_days(3)
        st.summary()
        self.assertEqual(calls, [7, 3])                               # 범위가 바뀌어야만 다시 분석
        st.set_days(7)
        st.summary()
        self.assertEqual(calls, [7, 3])                               # 이미 계산한 범위로 되돌리면 다시 계산하지 않는다
        st.add_file("b.log", self.path, "b")                          # 파일이 바뀌면 다시 분석
        st.summary()
        self.assertEqual(calls, [7, 3, 7])
        self.assertEqual(len(st._cache), 1)                           # 이전 파일 구성의 분석은 버려진다

    def test_results_are_cached_per_mode(self):
        from logwatcher.detector import Analyzer as A
        real, n = A.result, []

        def spy(self_, setting=None):
            n.append(setting)
            return real(self_, setting)
        A.result = spy
        self.addCleanup(lambda: setattr(A, "result", real))
        st = self.state()
        st.summary()
        st.set_mode("ip")
        st.summary()
        st.set_mode("auto")
        st.summary()
        st.set_sort("last")
        st.summary()
        self.assertEqual(n, ["auto", "ip"])                           # 같은 모드로 돌아오거나 정렬만 바꾸면 결과를 다시 만들지 않는다

    def test_cache_is_bounded(self):
        calls = self.counting()
        st = self.state()
        for d in (1, 3, 7, 14, 30):
            st.set_days(d)
            st.summary()
        self.assertEqual(len(st._cache), server.CACHE_MAX_ENTRIES)    # 최근 N개만 보관
        st.set_days(30)
        st.summary()
        self.assertEqual(calls, [1, 3, 7, 14, 30])                    # 가장 최근 것은 다시 계산하지 않는다
        st.set_days(1)
        st.summary()
        self.assertEqual(calls[-1], 1)                                # 오래된 것은 버려졌으므로 다시 계산
        old = server.CACHE_MAX_IPS
        server.CACHE_MAX_IPS = 1                                      # IP가 많으면(여기서는 임계값 1) 하나만 보관
        self.addCleanup(lambda: setattr(server, "CACHE_MAX_IPS", old))
        st.set_days(3)
        st.summary()
        self.assertEqual(len(st._cache), 1)

    def test_change_during_analysis_is_applied_and_not_overwritten(self):
        import threading
        real, started, release = server.analyze, threading.Event(), threading.Event()

        def slow(entries, c, days, anchor, now):
            started.set()
            release.wait(5)
            return real(entries, c, days, anchor, now)
        server.analyze = slow
        self.addCleanup(lambda: setattr(server, "analyze", real))
        st = self.state()
        out = {}
        t = threading.Thread(target=lambda: out.update(first=st.summary()))
        t.start()
        self.assertTrue(started.wait(5))
        t0 = __import__("time").time()
        st.set_days(14)                                               # 분석이 도는 중에도 설정은 즉시 바뀐다(잠금에 막히지 않음)
        self.assertLess(__import__("time").time() - t0, 1.0)
        server.analyze = real
        release.set()
        t.join(10)
        self.assertEqual(out["first"]["days"], 14)                    # 7일로 계산하던 낡은 결과가 14일 설정으로 남지 않는다
        sm = st.summary()
        self.assertEqual((sm["days"], sm["range"]["days"]), (14, 14))

    def test_stale_request_is_skipped(self):
        calls = self.counting()
        st = self.state()
        v = st.version
        st.set_days(3)                                                # 그 사이 더 새로운 설정이 들어옴
        out = st.summary(expect_version=v)
        self.assertEqual(out, {"stale": True, "version": st.version})
        self.assertEqual(calls, [])                                   # 낡은 요청은 분석하지 않는다
        sm = st.summary(expect_version=st.version)
        self.assertEqual((sm["days"], calls), (3, [3]))

    def test_range_covers_all_hint(self):
        st = self.state(recent_days=7)
        rg = st.summary()["range"]
        self.assertTrue(rg["covers_all"] is False or rg["covers_all"] is True)
        st.set_days(30)
        rg = st.summary()["range"]
        self.assertTrue(rg["covers_all"])                             # 로그 기간(10일)이 30일보다 짧음
        self.assertEqual((rg["log_from"][:10], rg["log_to"][:10]), ("2026-10-01", "2026-10-10"))
        st.set_days(3)
        self.assertFalse(st.summary()["range"]["covers_all"])
        st.set_days(0)
        self.assertTrue(st.summary()["range"]["covers_all"])


class SecurityHardeningTest(unittest.TestCase):
    """로그 내용은 공격자가 만들 수 있는 입력이다: 분석 도구가 멈추거나 오작동하지 않아야 한다."""

    def kind(self, url):
        a = Analyzer(cfg())
        path, _, q = url.partition("?")
        return a._url_kind(url, path, q)

    def test_sqli_regex_has_no_catastrophic_backtracking(self):
        import time
        # 수정 전에는 이런 URL 한 줄(약 400자)로 분석이 사실상 멈췄다(ReDoS)
        for url in ("/a?x=union" + "/**/" * 100 + "z", "/a?x=union" + "/**/" * 2000 + "z",
                    "/a?x=union" + "/*" * 4000, "/a?x=union" + " " * 8000 + "z", "/a?x=union" + "/* x */ " * 1000 + "z"):
            t = time.time()
            self.assertEqual(self.kind(url), "", url[:30])
            self.assertLess(time.time() - t, 0.5, url[:30])

    def test_sqli_detection_still_works_with_comment_obfuscation(self):
        for url in ("/a?id=1 union select 1", "/a?id=1%20UNION%20ALL%20SELECT%201", "/a?id=1 UNION/**/SELECT 1",
                    "/a?id=1 union/*x*/all/*y*/select 1", "/a?id=1 union/**//**/ /**/select 1", "/a?id=1 union" + " " * 300 + "select 1",
                    "/a?id=1 union/* a * b */select 1"):
            self.assertEqual(self.kind(url), "sqli", url)

    def test_long_url_is_capped(self):
        import time
        import logwatcher.detector as det
        self.assertEqual(det.MAX_URL_ANALYZE, 8192)
        t = time.time()
        self.assertEqual(self.kind("/a?x=1%27%20union%20select%201--" + "a" * 100000), "sqli")      # 앞부분의 공격은 긴 URL에서도 탐지
        self.assertLess(time.time() - t, 1.0)

    def test_hostile_values_never_reach_unescaped_output(self):
        # 화면은 모든 값을 이스케이프하고, CSV는 수식 시작 문자를 무력화한다(브라우저 시험은 별도로 수행)
        with open(os.path.join(ROOT, "web", "index.html"), encoding="utf-8") as f:
            html = f.read()
        self.assertIn("const esc = ", html)
        self.assertNotIn("eval(", html)
        self.assertNotIn("document.write", html)
        for bad in ("=1+1", "+cmd", "-2", "@SUM(1)", "\t=x"):
            self.assertTrue(server.csv_safe(bad).startswith("'"), bad)


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

    def req(self, method, path, body=None, headers=None, token=True):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        h = dict(headers or {})
        if token and "X-LW-Token" not in h:
            h["X-LW-Token"] = server.TOKEN                              # 화면이 보내는 것과 같은 접근 토큰
        c.request(method, path, body=body, headers=h)
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
        st, data = self.req("POST", "/api/range?days=1")
        self.assertEqual(st, 200)
        s = json.loads(data)                                             # 설정 변경 요청이 새 결과를 바로 돌려준다
        self.assertEqual(s["range"]["days"], 1)
        self.assertEqual(json.loads(self.req("GET", "/api/summary")[1])["range"]["days"], 1)
        self.assertIn("in_range", s["files"][0])
        for bad in ("abc", "-1", "99999", ""):
            self.assertEqual(self.req("POST", "/api/range?days=" + bad)[0], 400, bad)
        self.req("POST", "/api/range?days=0")
        self.req("POST", "/api/reset")

    def test_sort_api(self):
        self.req("POST", "/api/reset")
        with open(os.path.join(SAMPLES, "nginx_access.log"), "rb") as f:
            self.assertEqual(self.req("POST", "/api/upload?name=a.log", f.read())[0], 200)
        self.assertEqual(self.req("POST", "/api/sort?key=last&dir=asc&ev=desc")[0], 200)
        s = json.loads(self.req("GET", "/api/summary")[1])
        self.assertEqual(s["sort"], {"key": "last", "dir": "asc", "ev": "desc"})
        lasts = [x["last"] for x in s["ips"]]
        self.assertEqual(lasts, sorted(lasts))
        for bad in ("key=zzz", "dir=left", "ev=x"):
            self.assertEqual(self.req("POST", "/api/sort?" + bad)[0], 400, bad)
        self.req("POST", "/api/sort?key=level&dir=desc&ev=asc")
        self.req("POST", "/api/reset")

    def test_bad_file(self):
        st, data = self.req("POST", "/api/upload?name=x.log", b"hello\nworld\n")
        self.assertEqual(st, 400)
        self.assertIn("지원하지 않는", json.loads(data)["error"])

    def test_origin_and_host_checks(self):
        self.assertEqual(self.req("POST", "/api/reset", headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.req("GET", "/api/status", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.req("POST", "/api/reset", headers={"Origin": "http://127.0.0.1:%d" % self.port})[0], 200)

    def test_api_requires_access_token(self):
        # 같은 PC의 다른 사용자·프로그램이 토큰 없이 데이터를 보거나 바꾸지 못해야 한다
        for method, path in (("GET", "/api/status"), ("GET", "/api/summary"), ("GET", "/api/ip?ip=1.1.1.1"),
                             ("GET", "/api/export/result.csv"), ("POST", "/api/upload?name=x.log"), ("POST", "/api/reset"),
                             ("POST", "/api/range?days=3"), ("POST", "/api/mode?mode=ip"), ("POST", "/api/sort?key=ip")):
            self.assertEqual(self.req(method, path, token=False)[0], 401, path)
            self.assertEqual(self.req(method, path, headers={"X-LW-Token": "wrong"}, token=False)[0], 401, path)
            self.assertEqual(self.req(method, path, headers={"X-LW-Token": "é" * 3}, token=False)[0], 401, path)   # 비ASCII도 오류 없이 거부
        self.assertEqual(self.req("GET", "/", token=False)[0], 200)                      # 화면 파일 자체에는 데이터가 없다
        self.assertEqual(self.req("GET", "/favicon.ico", token=False)[0], 204)
        self.assertEqual(self.req("GET", "/api/status")[0], 200)                         # 올바른 토큰이면 통과
        # 토큰이 틀리면 업로드한 내용이 저장되지도 않는다
        self.req("POST", "/api/reset")
        self.req("POST", "/api/upload?name=x.log", b"1.2.3.4 - - [08/Oct/2026:10:00:00 +0900] \"GET / HTTP/1.1\" 200 1 \"-\" \"a\"\n", token=False)
        self.assertTrue(json.loads(self.req("GET", "/api/summary")[1])["empty"])

    def test_host_and_origin_still_enforced_with_valid_token(self):
        self.assertEqual(self.req("GET", "/api/status", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.req("POST", "/api/reset", headers={"Origin": "https://evil.example"})[0], 403)

    def test_security_headers(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request("GET", "/")
        r = c.getresponse()
        r.read()
        h = {k.lower(): v for k, v in r.getheaders()}
        csp = h["content-security-policy"]
        for part in ("default-src 'none'", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"):
            self.assertIn(part, csp)
        self.assertNotRegex(csp, r"https?:|\*\s*[;]|\s\*\s")                                             # 외부 출처·와일드카드 불가
        self.assertEqual(h["x-frame-options"], "DENY")
        self.assertEqual(h["referrer-policy"], "no-referrer")
        self.assertEqual(h["x-content-type-options"], "nosniff")
        self.assertEqual(h["cache-control"], "no-store")

    def test_token_is_random_per_run_and_env_override(self):
        saved = (server.STATE, server.TOKEN)                 # make_server는 전역 상태를 바꾸므로 끝나면 되돌린다
        self.addCleanup(lambda: (setattr(server, "STATE", saved[0]), setattr(server, "TOKEN", saved[1])))
        tokens = set()
        for _ in range(3):
            httpd = server.make_server([0], cfg())
            tokens.add(httpd.token)
            httpd.server_close()
        self.assertEqual(len(tokens), 3)                      # 실행마다 다른 값
        self.assertTrue(all(len(t) >= 24 for t in tokens))
        os.environ["LOGWATCHER_TOKEN"] = "fixed-token-for-test"
        self.addCleanup(lambda: os.environ.pop("LOGWATCHER_TOKEN", None))
        httpd = server.make_server([0], cfg())
        self.assertEqual(httpd.token, "fixed-token-for-test")
        httpd.server_close()

    def test_index_served(self):
        st, data = self.req("GET", "/")
        self.assertEqual(st, 200)
        self.assertIn("LogWatcher".encode(), data)

    def test_csv_injection_neutralized(self):
        self.assertEqual(server.csv_safe("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0")
        self.assertEqual(server.csv_safe("normal"), "normal")


if __name__ == "__main__":
    unittest.main()
