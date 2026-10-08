"""여러 로그 파일을 하나로 합쳐 분석한다.

- 분할(회전)된 로그 여러 개를 하나처럼 분석한다. LB/프록시 자동 판별도 전체 파일을 합쳐서 한다.
- HAProxy 로그와 nginx 접근 로그를 함께 분석하면 같은 요청을 하나로 합친다
  (접속자 IP는 HAProxy 기준, User-Agent는 nginx 기준).
- 분석 범위는 최근 N일: 기준 시각은 로그의 마지막 시각(latest) 또는 현재 시각(now).
"""
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


def analyze(entries, cfg, days, anchor_mode="latest", now_ts=None):
    """entries: [{name, reader, kind, fmt, proxies, info}] -> 분석 결과 dict."""
    a = Analyzer(cfg)
    a.register_proxies(merge_proxy_stats(entries))
    anchor, cutoff = window_bounds(entries, cfg, days, anchor_mode, now_ts)
    per = [{"in_range": 0, "excluded": 0, "merged": 0} for _ in entries]

    def inside(ts):
        return cutoff is None or ts >= cutoff

    has_hap = any(e["fmt"] == FMT_HAPROXY for e in entries)
    has_nginx = any(e["kind"] == "access" and e["fmt"] != FMT_HAPROXY for e in entries)
    merge_mode = has_hap and has_nginx
    hmap = {}                      # (요청 해시, 시각) -> [(HAProxy 레코드, 파일 번호)]
    merged_total = 0
    # HAProxy를 먼저 읽어 nginx 요청과 짝을 지을 수 있게 한다
    order = sorted(range(len(entries)), key=lambda i: entries[i]["fmt"] != FMT_HAPROXY)
    for i in order:
        e, st = entries[i], per[i]
        if e["kind"] == "error":
            for rec in e["reader"].records():
                if inside(rec[0]):
                    st["in_range"] += 1
                    a.feed_error(rec)
                else:
                    st["excluded"] += 1
        elif e["fmt"] == FMT_HAPROXY:
            for rec in e["reader"].records():
                if not inside(rec[0]):
                    st["excluded"] += 1
                    continue
                st["in_range"] += 1
                if len(rec) == 6:                     # 서버 다운/복구, TLS 실패 같은 상태 줄
                    a.feed_error(rec)
                elif merge_mode:
                    hmap.setdefault((hash((rec[METHOD], rec[PATH], rec[QUERY])), rec[TS]), []).append((rec, i))
                else:
                    a.feed(rec)
        else:
            for rec in e["reader"].records():
                if not inside(rec[TS]):
                    st["excluded"] += 1
                    continue
                st["in_range"] += 1
                if hmap and a._is_proxy(rec[IP]):     # LB/HAProxy를 거쳐 온 요청만 짝 후보
                    k = hash((rec[METHOD], rec[PATH], rec[QUERY]))
                    for dt in _DEDUPE_OFFSETS:
                        lst = hmap.get((k, rec[TS] + dt))
                        if lst:
                            hrec, hi = lst.pop()
                            if not lst:
                                del hmap[(k, rec[TS] + dt)]
                            per[hi]["merged"] += 1
                            st["merged"] += 1
                            merged_total += 1
                            rec = (rec[0], hrec[IP]) + rec[2:UA] + (rec[UA] or hrec[UA],) + rec[UA + 1:XFF] + ("",)
                            break
                a.feed(rec)
    for lst in hmap.values():                         # nginx와 짝이 없는 HAProxy 요청
        for hrec, _hi in lst:
            a.feed(hrec)

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
