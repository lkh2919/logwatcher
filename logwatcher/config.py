"""탐지 기준 설정. exe 옆의 config.json을 메모장으로 편집하면 다음 실행부터 적용된다."""
import copy
import json
import os

from .resources import app_dir

DEFAULTS = {
    # IP 구분 방식: auto(자동 판별) / ip(항상 IP별 판정) / none(IP 구분 안 함, 요청 단위 판정)
    "ip_mode": "auto",
    # 완전히 신뢰하는 IP/대역(CIDR 가능): 모든 탐지에서 제외
    "allow_ips": [],
    # X-Forwarded-For를 믿을 프록시/LB 대역(CIDR 가능). 사설 IP(10.x, 172.16.x, 192.168.x)는 자동 신뢰
    "trusted_proxies": [],
    # X-Forwarded-For가 로그에 있으면 실제 접속자 IP로 사용
    "use_xff": True,
    # 공인 IP의 LB라도 요청 대부분에 X-Forwarded-For를 붙여 보내면 프록시로 자동 판단(화면에 표시됨)
    "auto_proxy": True,
    # 취약경로 탐색 규칙에서 제외할 요청 경로(정규식). 예: ["^/graphql", "^/swagger"]
    "probe_ignore_paths": [],
    # 정상으로 보는 HTTP Method
    "allowed_methods": ["GET", "POST", "HEAD", "OPTIONS"],
    # REST API에서 흔한 Method: 비정상 Method(중간)가 아니라 '낮음'으로 표시. 정상 서비스면 allowed_methods로 옮기세요
    "rest_methods": ["PUT", "DELETE", "PATCH"],
    # 접속량 계산에서 제외할 정적 파일 확장자
    "static_extensions": [
        "css", "js", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp",
        "woff", "woff2", "ttf", "eot", "otf", "mp4", "mp3", "webm",
    ],
    # 과다 접속: rate_window_sec 동안 정적 파일 제외 요청이 rate_max_requests 이상
    "rate_window_sec": 60,
    "rate_max_requests": 300,
    # 순간 집중: 1초에 정적 파일 제외 요청이 burst_max 이상
    "burst_max": 30,
    # 에러 다수: 4xx/5xx(499 제외)가 error_min 이상이고 비율이 error_ratio 이상
    "error_min": 20,
    "error_ratio": 0.5,
    # 없는 경로 탐색: 서로 다른 404 경로가 notfound_distinct 이상
    "notfound_distinct": 10,
    # 로그인 관련 URL(정규식, 대소문자 무시)
    "login_url_pattern": r"login|logon|signin|sign-in|auth|passw|otp|account",
    "login_fail_min": 5,
    "login_window_sec": 600,
    "login_post_max": 20,
    # 분석 범위: 최근 recent_days일만 분석(0이면 전체). 기준 시각은 recent_anchor:
    #   latest = 올린 로그의 마지막 시각, now = 현재 시각
    "recent_days": 7,
    "recent_anchor": "latest",
    # 화면 표시 시간대(KST=9)
    "display_utc_offset_hours": 9,
    # nginx error.log 기록 시간대(시간대 표기가 없는 로그라 서버 로컬 시간 기준, KST=9)
    "error_log_utc_offset_hours": 9,
    # HAProxy 로그의 접속 시각(시간대 표기 없음) 기록 시간대(서버 로컬 시간 기준, KST=9)
    "haproxy_log_utc_offset_hours": 9,
}

CONFIG_FILE = "config.json"


def path():
    return os.path.join(app_dir(), CONFIG_FILE)


def load():
    """config.json이 없으면 기본값으로 만들어 두고(편집용), 있으면 알려진 키만 덮어쓴다."""
    cfg = copy.deepcopy(DEFAULTS)
    try:
        with open(path(), encoding="utf-8") as f:
            user = json.load(f)
        for k, v in user.items():
            if k in cfg and type(v) is type(DEFAULTS[k]):
                cfg[k] = v
    except FileNotFoundError:
        try:
            with open(path(), "w", encoding="utf-8") as f:
                json.dump(DEFAULTS, f, ensure_ascii=False, indent=2)
        except OSError:
            pass
    except (OSError, ValueError):
        pass
    return cfg
