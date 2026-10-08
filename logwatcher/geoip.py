"""내장 IP-국가 데이터(data/geoip.bin) 조회.

데이터 출처: DB-IP Lite (https://db-ip.com, CC BY 4.0)
"""
import ipaddress
import json
import struct
import zlib
from array import array
from bisect import bisect_right

from .netutil import is_internal
from .resources import resource_path

PRIVATE = "LAN"   # 사설/내부망
UNKNOWN = "??"

COUNTRY_KO = {
    "KR": "대한민국", "KP": "북한", "US": "미국", "CN": "중국", "JP": "일본", "TW": "대만",
    "HK": "홍콩", "MO": "마카오", "SG": "싱가포르", "VN": "베트남", "TH": "태국", "PH": "필리핀",
    "MY": "말레이시아", "ID": "인도네시아", "IN": "인도", "PK": "파키스탄", "BD": "방글라데시",
    "MN": "몽골", "KH": "캄보디아", "LA": "라오스", "MM": "미얀마", "NP": "네팔", "LK": "스리랑카",
    "KZ": "카자흐스탄", "UZ": "우즈베키스탄", "AU": "호주", "NZ": "뉴질랜드", "CA": "캐나다",
    "MX": "멕시코", "BR": "브라질", "AR": "아르헨티나", "CL": "칠레", "CO": "콜롬비아", "PE": "페루",
    "VE": "베네수엘라", "EC": "에콰도르", "UY": "우루과이", "PY": "파라과이", "BO": "볼리비아",
    "GB": "영국", "IE": "아일랜드", "FR": "프랑스", "DE": "독일", "NL": "네덜란드", "BE": "벨기에",
    "LU": "룩셈부르크", "CH": "스위스", "AT": "오스트리아", "IT": "이탈리아", "ES": "스페인",
    "PT": "포르투갈", "SE": "스웨덴", "NO": "노르웨이", "DK": "덴마크", "FI": "핀란드", "IS": "아이슬란드",
    "PL": "폴란드", "CZ": "체코", "SK": "슬로바키아", "HU": "헝가리", "RO": "루마니아", "BG": "불가리아",
    "GR": "그리스", "TR": "튀르키예", "RU": "러시아", "UA": "우크라이나", "BY": "벨라루스",
    "LT": "리투아니아", "LV": "라트비아", "EE": "에스토니아", "MD": "몰도바", "RS": "세르비아",
    "HR": "크로아티아", "SI": "슬로베니아", "BA": "보스니아 헤르체고비나", "AL": "알바니아",
    "MK": "북마케도니아", "CY": "키프로스", "MT": "몰타", "GE": "조지아", "AM": "아르메니아",
    "AZ": "아제르바이잔", "IL": "이스라엘", "IR": "이란", "IQ": "이라크", "SA": "사우디아라비아",
    "AE": "아랍에미리트", "QA": "카타르", "KW": "쿠웨이트", "BH": "바레인", "OM": "오만", "JO": "요르단",
    "LB": "레바논", "SY": "시리아", "YE": "예멘", "EG": "이집트", "ZA": "남아프리카공화국",
    "NG": "나이지리아", "KE": "케냐", "MA": "모로코", "DZ": "알제리", "TN": "튀니지", "GH": "가나",
    "ET": "에티오피아", "SC": "세이셸", "MU": "모리셔스", "PA": "파나마", "CR": "코스타리카",
    "DO": "도미니카공화국", "PR": "푸에르토리코", "BZ": "벨리즈", "VG": "영국령 버진아일랜드",
    "KY": "케이맨제도", "BS": "바하마", "ZZ": "예약/미할당",
    PRIVATE: "내부망", UNKNOWN: "미확인",
}


def country_name(code):
    return COUNTRY_KO.get(code, code)


class GeoIP:
    def __init__(self, path=None):
        self.available = False
        self.source = ""
        path = path or resource_path("data", "geoip.bin")
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError:
            return
        if not raw.startswith(b"LWGEO1"):
            return
        body = zlib.decompress(raw[6:])
        meta_len, n4, n6 = struct.unpack_from("<III", body, 0)
        off = 12
        meta = json.loads(body[off:off + meta_len])
        off += meta_len
        self.codes = meta["codes"]
        self.source = meta.get("source", "")
        self.v4_starts = array("I")
        self.v4_starts.frombytes(body[off:off + 4 * n4]); off += 4 * n4
        self.v4_codes = array("H")
        self.v4_codes.frombytes(body[off:off + 2 * n4]); off += 2 * n4
        self._v6_raw = body[off:off + 16 * n6]; off += 16 * n6
        self.v6_codes = array("H")
        self.v6_codes.frombytes(body[off:off + 2 * n6])
        self._v6_starts = None
        self._cache = {}
        self.available = True

    def _v6(self):
        if self._v6_starts is None:
            r = self._v6_raw
            self._v6_starts = [int.from_bytes(r[i:i + 16], "big") for i in range(0, len(r), 16)]
        return self._v6_starts

    def lookup(self, ip):
        """국가 코드 반환. 사설 IP는 'LAN', 판별 불가는 '??'."""
        c = self._cache.get(ip) if self.available else None
        if c is not None:
            return c
        try:
            addr = ipaddress.ip_address(ip.strip("[]"))
        except ValueError:
            return UNKNOWN
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if is_internal(addr):
            c = PRIVATE
        elif not self.available:
            c = UNKNOWN
        elif addr.version == 4:
            i = bisect_right(self.v4_starts, int(addr)) - 1
            c = self.codes[self.v4_codes[i]] if i >= 0 else UNKNOWN
        else:
            i = bisect_right(self._v6(), int(addr)) - 1
            c = self.codes[self.v6_codes[i]] if i >= 0 else UNKNOWN
        if self.available:
            if len(self._cache) > 200000:
                self._cache.clear()
            self._cache[ip] = c
        return c


class NoGeo:
    """국가 판별을 끈 경우(config.json의 geo_enabled=false)나 데이터가 없을 때 쓰는 빈 구현."""
    available = False
    source = ""

    def lookup(self, ip):
        return UNKNOWN


_SHARED = {}


def load_geo(cfg):
    """설정에 따라 국가 판별기를 만든다(데이터 파일은 한 번만 읽어 재사용)."""
    if not cfg.get("geo_enabled", True):
        return NoGeo()
    g = _SHARED.get("geo")
    if g is None:
        g = _SHARED["geo"] = GeoIP()
    return g if g.available else NoGeo()
