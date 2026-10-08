"""IP 주소 판별 보조 함수."""
import ipaddress

_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "::1/128", "fc00::/7", "fe80::/10")]


def is_internal(addr):
    """내부망/프록시로 볼 주소 (RFC1918, 루프백, 링크로컬, CGNAT, IPv6 ULA). 문서용 대역은 포함하지 않는다."""
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in n for n in _INTERNAL_NETS if n.version == addr.version)


def valid_ip(s):
    try:
        return ipaddress.ip_address(s.strip("[]"))
    except ValueError:
        return None
