"""DB-IP Lite 국가 CSV를 프로그램 내장용 압축 데이터(data/geoip.bin)로 변환한다.

사용법:
    python tools/build_geodb.py dbip-country-lite-YYYY-MM.csv.gz

원본: https://db-ip.com/db/download/ip-to-country-lite (CC BY 4.0)
"""
import gzip
import ipaddress
import json
import os
import struct
import sys
import zlib
from array import array

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "geoip.bin")
MAGIC = b"LWGEO1"


def build(src):
    opener = gzip.open if src.endswith(".gz") else open
    codes = []
    code_idx = {}
    v4_starts, v4_codes = array("I"), array("H")
    v6_starts, v6_codes = [], array("H")
    last4 = last6 = None
    n = 0
    with opener(src, "rt", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) < 3:
                continue
            start, end, cc = parts[0], parts[1], parts[2].strip().upper() or "ZZ"
            if cc not in code_idx:
                code_idx[cc] = len(codes)
                codes.append(cc)
            ci = code_idx[cc]
            n += 1
            ip = ipaddress.ip_address(start)
            # 연속된 같은 국가 대역은 하나로 합친다 (시작 주소만 저장, 다음 시작 전까지가 범위)
            if ip.version == 4:
                if last4 != ci:
                    v4_starts.append(int(ip))
                    v4_codes.append(ci)
                    last4 = ci
            else:
                if last6 != ci:
                    v6_starts.append(int(ip))
                    v6_codes.append(ci)
                    last6 = ci

    v6_bytes = b"".join(s.to_bytes(16, "big") for s in v6_starts)
    meta = json.dumps({"codes": codes, "source": os.path.basename(src), "rows": n}).encode()
    body = b"".join([
        struct.pack("<III", len(meta), len(v4_starts), len(v6_starts)),
        meta,
        v4_starts.tobytes(), v4_codes.tobytes(),
        v6_bytes, v6_codes.tobytes(),
    ])
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(MAGIC + zlib.compress(body, 9))
    print("원본 %d행 -> IPv4 %d / IPv6 %d 구간, %s (%.1f MB)"
          % (n, len(v4_starts), len(v6_starts), OUT, os.path.getsize(OUT) / 1e6))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    build(sys.argv[1])
