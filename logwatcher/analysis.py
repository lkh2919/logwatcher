"""여러 로그 파일을 하나로 합쳐 분석한다.

- 분할(회전)된 로그 여러 개를 하나처럼 분석한다. LB/프록시 자동 판별도 전체 파일을 합쳐서 한다.
- HAProxy 로그와 nginx 접근 로그를 함께 분석하면 같은 요청을 하나로 합친다
  (접속자 IP는 HAProxy 기준, User-Agent는 nginx 기준).
- 분석 범위는 최근 N일: 기준 시각은 로그의 마지막 시각(latest) 또는 현재 시각(now).
"""
import gc
import time

from .detector import Analyzer
from .parser import FMT_HAPROXY, IP, METHOD, PATH, QUERY, TS, UA, XFF

# nginx 요청 시각(응답 완료)과 HAProxy 접속 시각이 몇 초 어긋날 수 있다
_DEDUPE_OFFSETS = (0, -1, 1, -2, 2)


def merge_proxy_stats(entries):
    """파일별 (요청 수, XFF 포함 수, XFF 값 종류)를 합친다."""
    agg = {}
    for e in entries:
        for ip, (n, nx, xs) in e["proxies"].items():
            t = agg.get(ip)
            if t is None:
                agg[ip] = [n, nx, set(xs)]
            else:
                t[0] += n
                t[1] += nx
                if len(t[2]) < 5:
                    t[2] |= xs
    return agg


def window_bounds(entries, cfg, days, anchor_mode="latest", now_ts=None):
    """(기준 시각, 범위 시작 시각). days<=0이면 범위 제한 없음. 시각은 표시 시간대 기준 벽시계 초."""
    lasts = [e["info"]["last"] for e in entries if e["info"]["last"] is not None]
    if anchor_mode == "now" or not lasts:
        anchor = int(now_ts if now_ts is not None else time.time()) + int(cfg["display_utc_offset_hours"] * 3600)
    else:
        anchor = max(lasts)
    cutoff = anchor - int(days) * 86400 if days and days > 0 else None
    return anchor, cutoff


def _hkey(rec):
    """HAProxy·nginx의 같은 요청을 짝짓는 키: (Method, URL)의 해시를 시각과 하나의 정수로 합친 값."""
    return (hash((rec[METHOD], rec[PATH], rec[QUERY])) & 0xFFFFFFFFFFFF) << 32


def analyze(entries, cfg, days, anchor_mode="latest", now_ts=None):
    """entries: [{name, reader, kind, fmt, proxies, info}] -> 분석 결과 dict.

    분석 범위 밖의 로그는 읽지도 파싱하지도 않고(블록 단위로 건너뜀), 범위 안의 요청만 메모리에 집계한다.
    """
    gc_was_enabled = gc.isenabled()
    gc.disable()            # 집계 중에는 순환 참조가 생기지 않아 GC가 시간만 쓴다
    try:
        return _analyze(entries, cfg, days, anchor_mode, now_ts)
    finally:
        if gc_was_enabled:
            gc.enable()


def _analyze(entries, cfg, days, anchor_mode, now_ts):
    a = Analyzer(cfg)
    a.register_proxies(merge_proxy_stats(entries))
    anchor, cutoff = window_bounds(entries, cfg, days, anchor_mode, now_ts)
    per = [{"in_range": 0, "excluded": 0, "merged": 0} for _ in entries]

    has_hap = any(e["fmt"] == FMT_HAPROXY for e in entries)
    has_nginx = any(e["kind"] == "access" and e["fmt"] != FMT_HAPROXY for e in entries)
    merge_mode = has_hap and has_nginx
    # 병합용 색인: 키 -> [(HAProxy IP, User-Agent), ...]. 전체 레코드는 보관하지 않는다(메모리 절약).
    hmap = {}
    consumed = {}                  # nginx 요청과 짝지어진 HAProxy 요청 수(키별) -> 나중에 HAProxy를 다시 읽을 때 건너뜀
    merged_total = 0
    # HAProxy를 먼저 읽어 nginx 요청과 짝을 지을 수 있게 한다
    order = sorted(range(len(entries)), key=lambda i: entries[i]["fmt"] != FMT_HAPROXY)
    for i in order:
        e, st = entries[i], per[i]
        reader = e["reader"]
        if e["kind"] == "error":
            for rec in reader.records(cutoff):
                if cutoff is None or rec[0] >= cutoff:
                    st["in_range"] += 1
                    a.feed_error(rec)
        elif e["fmt"] == FMT_HAPROXY:
            for rec in reader.records(cutoff):
                ts = rec[0]
                if cutoff is not None and ts < cutoff:
                    continue
                st["in_range"] += 1
                if len(rec) == 6:                     # 서버 다운/복구, TLS 실패 같은 상태 줄
                    a.feed_error(rec)
                elif merge_mode:
                    hmap.setdefault(_hkey(rec) | ts, []).append((rec[IP], rec[UA]))
                else:
                    a.feed(rec)
        else:
            for rec in reader.records(cutoff):
                ts = rec[TS]
                if cutoff is not None and ts < cutoff:
                    continue
                st["in_range"] += 1
                if hmap and a._is_proxy(rec[IP]):     # LB/HAProxy를 거쳐 온 요청만 짝 후보
                    k = _hkey(rec)
                    for dt in _DEDUPE_OFFSETS:
                        key = k | (ts + dt)
                        lst = hmap.get(key)
                        if lst:
                            hip, hua = lst.pop(0)     # 파일 순서대로: 나중에 HAProxy를 다시 읽을 때 앞에서부터 건너뛰는 것과 같은 순서
                            if not lst:
                                del hmap[key]
                            consumed[key] = consumed.get(key, 0) + 1
                            st["merged"] += 1
                            merged_total += 1
                            rec = (rec[0], hip) + rec[2:UA] + (rec[UA] or hua,) + rec[UA + 1:XFF] + ("",)
                            break
                a.feed(rec)
    # nginx와 짝이 없는 HAProxy 요청: HAProxy 파일을 범위 안만 다시 읽어 집계한다
    if merge_mode:
        for i, e in enumerate(entries):
            if e["fmt"] != FMT_HAPROXY:
                continue
            for rec in e["reader"].records(cutoff):
                if len(rec) == 6 or (cutoff is not None and rec[0] < cutoff):
                    continue
                key = _hkey(rec) | rec[0]
                if consumed.get(key):                 # 이미 nginx 요청과 합쳐진 요청
                    consumed[key] -= 1
                    per[i]["merged"] += 1
                    continue
                a.feed(rec)
    for e, st in zip(entries, per):
        st["excluded"] = e["info"]["parsed"] - st["in_range"]

    notes = []
    if merge_mode:
        hap_in = sum(per[i]["in_range"] for i, e in enumerate(entries) if e["fmt"] == FMT_HAPROXY)
        ng_in = sum(per[i]["in_range"] for i, e in enumerate(entries) if e["kind"] == "access" and e["fmt"] != FMT_HAPROXY)
        if merged_total:
            notes.append({"type": "info", "text": "HAProxy와 nginx 로그를 함께 분석했습니다. 같은 요청 %s건을 하나로 합쳐 집계했습니다 "
                                                 "(접속자 IP는 HAProxy 기준, User-Agent는 nginx 기준)." % format(merged_total, ",")})
        elif hap_in and ng_in:
            notes.append({"type": "warn", "text": "HAProxy와 nginx 로그에서 같은 요청을 찾지 못해 합치지 못했습니다. 두 로그의 기간이 다르거나, "
                                                 "nginx 로그에 찍힌 HAProxy의 IP가 프록시로 인식되지 않았을 수 있습니다. 같은 요청이 두 번 집계될 수 있으니 "
                                                 "그 IP를 config.json의 trusted_proxies에 넣으세요."})
    unused = [e["name"] for e, p in zip(entries, per) if p["in_range"] == 0 and e["info"]["parsed"] > 0]
    if unused and len(unused) < len(entries):
        notes.append({"type": "warn", "text": "분석 범위(%s)에 해당하는 줄이 없어 결과에 반영되지 않은 파일: %s. 범위를 늘리면 반영됩니다." % (
            "전체" if cutoff is None else "최근 %d일" % days, ", ".join(unused[:5]) + (" 외 %d개" % (len(unused) - 5) if len(unused) > 5 else ""))})
    return {"analyzer": a, "anchor": anchor, "cutoff": cutoff, "days": days, "per_file": per,
            "notes": notes, "merged": merged_total,
            "excluded": sum(p["excluded"] for p in per), "in_range": sum(p["in_range"] for p in per)}
