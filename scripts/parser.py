"""
Parses vless:// and trojan:// URIs into plain dicts that xray_config.py
can turn into an Xray outbound. Anything else (vmess, ss, etc.) is
detected and skipped upstream in main.py.
"""

import ipaddress
import re
from urllib.parse import parse_qs, unquote, urlparse

_URI_RE = re.compile(r"(?:vless|trojan)://[^\s<>\"'`]+", re.IGNORECASE)

_NETWORK_ALIASES = {
    "websocket": "ws",
    "splithttp": "xhttp",
    "http": "h2",
    "raw": "tcp",
}


def detect_type(uri: str) -> str | None:
    """Return 'vless', 'trojan', or None for anything else."""
    uri = uri.strip()
    if uri.startswith("vless://"):
        return "vless"
    if uri.startswith("trojan://"):
        return "trojan"
    return None


def _valid_host(host: str | None) -> bool:
    """Reject obviously malformed hostnames/IPs before we ever try to
    connect to them. IPv4/IPv6 are accepted as-is; DNS names still
    reject empty or oversized labels."""
    if not host or len(host) > 253:
        return False
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    for label in host.split("."):
        if len(label) == 0 or len(label) > 63:
            return False
    return True


def _q(query: dict, key: str, default: str = "") -> str:
    vals = query.get(key)
    if not vals or vals[0] is None:
        return default
    return vals[0]


def _truthy(val: str) -> bool:
    return val.lower() in ("1", "true", "yes")


def _parse_alpn(raw: str) -> list[str]:
    if not raw:
        return []
    return [part.strip() for part in unquote(raw).split(",") if part.strip()]


def _normalize_network(raw: str) -> str:
    network = (raw or "tcp").lower()
    return _NETWORK_ALIASES.get(network, network)


def _stream_fields(query: dict, hostname: str, default_security: str) -> dict:
    host_header = _q(query, "host", hostname)
    insecure = _q(query, "allowInsecure") or _q(query, "allow_insecure") or "0"
    return {
        "security": _q(query, "security", default_security),
        "sni": _q(query, "sni", host_header or hostname),
        "network": _normalize_network(_q(query, "type", "tcp")),
        "path": unquote(_q(query, "path", "/")),
        "host_header": host_header,
        "fp": _q(query, "fp", "chrome") or "chrome",
        "alpn": _parse_alpn(_q(query, "alpn", "")),
        "allow_insecure": _truthy(insecure),
        "header_type": _q(query, "headerType", "none"),
        "mode": _q(query, "mode", ""),
        "authority": unquote(_q(query, "authority", "")),
        "service_name": unquote(_q(query, "serviceName", "")),
        "pbk": _q(query, "pbk", ""),
        "sid": _q(query, "sid", ""),
        "spx": unquote(_q(query, "spx", "")),
    }


def parse_vless(uri: str) -> dict | None:
    try:
        parsed = urlparse(uri)
        query = parse_qs(parsed.query)
        if not parsed.hostname or not parsed.port or not parsed.username:
            return None
        if not _valid_host(parsed.hostname):
            return None
        node = {
            "type": "vless",
            "uuid": parsed.username,
            "address": parsed.hostname,
            "port": parsed.port,
            "encryption": _q(query, "encryption", "none"),
            "flow": _q(query, "flow", ""),
            "name": unquote(parsed.fragment) if parsed.fragment else "vless-node",
            "raw": uri,
        }
        node.update(_stream_fields(query, parsed.hostname, "none"))
        return node
    except Exception:
        return None


def parse_trojan(uri: str) -> dict | None:
    try:
        parsed = urlparse(uri)
        query = parse_qs(parsed.query)
        if not parsed.hostname or not parsed.port or not parsed.username:
            return None
        if not _valid_host(parsed.hostname):
            return None
        node = {
            "type": "trojan",
            "password": parsed.username,
            "address": parsed.hostname,
            "port": parsed.port,
            "name": unquote(parsed.fragment) if parsed.fragment else "trojan-node",
            "raw": uri,
        }
        node.update(_stream_fields(query, parsed.hostname, "tls"))
        return node
    except Exception:
        return None


def parse_node(uri: str) -> dict | None:
    """Dispatch to the right parser based on scheme. Returns None if
    the scheme isn't vless/trojan, or if the URI is malformed."""
    kind = detect_type(uri)
    if kind == "vless":
        return parse_vless(uri)
    if kind == "trojan":
        return parse_trojan(uri)
    return None


def extract_uris(text: str) -> list[str]:
    """Pull vless/trojan URIs out of a subscription body (plain lines,
    trailing comments, or HTML/JSON wrapping)."""
    found: list[str] = []
    seen: set[str] = set()

    def add(uri: str) -> None:
        uri = uri.strip().rstrip(".,;)]}\"")
        if uri and detect_type(uri) and uri not in seen:
            seen.add(uri)
            found.append(uri)

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        add(line.split()[0])

    for match in _URI_RE.findall(text):
        add(match)

    return found


def node_fingerprint(node: dict) -> tuple:
    """Identity used for deduplication -- ignores cosmetic differences
    like #name, but keeps everything that actually affects how the
    connection is made."""
    cred = node.get("uuid") or node.get("password")
    return (
        node["type"],
        node["address"],
        node["port"],
        cred,
        node.get("network"),
        node.get("security"),
        node.get("sni"),
        node.get("path"),
        node.get("pbk"),
        node.get("sid"),
        node.get("flow"),
        node.get("service_name"),
        node.get("host_header"),
        node.get("header_type"),
        node.get("mode"),
        tuple(node.get("alpn") or []),
    )


def dedupe_nodes(nodes: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for node in nodes:
        fingerprint = node_fingerprint(node)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        unique.append(node)
    return unique
