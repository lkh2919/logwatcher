"""실행 진입점: PC 내부 웹 서버를 띄우고 브라우저를 연다."""
import sys
import threading
import webbrowser

from . import VERSION
from .server import make_server

PORTS = [8765, 8766, 8767, 8768, 8769, 0]


def _say(msg):
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode("ascii", "replace").decode())


def main():
    httpd = make_server(PORTS)
    url = "http://127.0.0.1:%d/" % httpd.server_address[1]
    _say("=" * 60)
    _say(" LogWatcher %s - nginx·HAProxy 위협 로그 점검" % VERSION)
    _say("=" * 60)
    _say(" 화면 주소 : %s" % url)
    _say(" 브라우저가 자동으로 열리지 않으면 위 주소를 직접 여세요.")
    _say(" 업로드한 로그는 이 PC 안에서만 처리되며 외부로 전송되지 않습니다.")
    _say(" 종료하려면 이 창을 닫거나 Ctrl+C 를 누르세요.")
    _say("=" * 60)
    if "--no-browser" not in sys.argv:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
