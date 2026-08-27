"""
Parses vless:// and trojan:// URIs into plain dicts that xray_config.py
can turn into an Xray outbound. Anything else (vmess, ss, etc.) is
detected and skipped upstream in main.py.
"""

from urllib.parse import urlparse, parse_qs, unquote


def detect_type(uri: str) -> str | None:
    """Return 'vless', 'trojan', or None for anything else."""
    uri = uri.strip()
    if uri.startswith("vless://"):
        return "vless"
    if uri.startswith("trojan://"):
        return "trojan"
    return None


def parse_vless(uri: str) -> dict | None:
    try:
        p = urlparse(uri)
        q = parse_qs(p.query)
        if not p.hostname or not p.port or not p.username:
            return None
        return {
            "type": "vless",
            "uuid": p.username,
            "address": p.hostname,
            "port": p.port,
            "encryption": q.get("encryption", ["none"])[0],
            "flow": q.get("flow", [""])[0],
            "security": q.get("security", ["none"])[0],
            "sni": q.get("sni", [q.get("host", [p.hostname])[0]])[0],
            "network": q.get("type", ["tcp"])[0],
            "path": unquote(q.get("path", ["/"])[0]),
            "host_header": q.get("host", [p.hostname])[0],
            "pbk": q.get("pbk", [""])[0],       # REALITY public key
            "sid": q.get("sid", [""])[0],       # REALITY short id
            "fp": q.get("fp", ["chrome"])[0],   # TLS fingerprint
            "service_name": unquote(q.get("serviceName", [""])[0]),
            "name": unquote(p.fragment) if p.fragment else "vless-node",
            "raw": uri,
        }
    except Exception:
        return None


def parse_trojan(uri: str) -> dict | None:
    try:
        p = urlparse(uri)
        q = parse_qs(p.query)
        if not p.hostname or not p.port or not p.username:
            return None
        return {
            "type": "trojan",
            "password": p.username,
            "address": p.hostname,
            "port": p.port,
            "security": q.get("security", ["tls"])[0],
            "sni": q.get("sni", [p.hostname])[0],
            "network": q.get("type", ["tcp"])[0],
            "path": unquote(q.get("path", ["/"])[0]),
            "service_name": unquote(q.get("serviceName", [""])[0]),
            "allow_insecure": q.get("allowInsecure", ["0"])[0] == "1",
            "name": unquote(p.fragment) if p.fragment else "trojan-node",
            "raw": uri,
        }
    except Exception:
        return None


def parse_node(uri: str) -> dict | None:
    """Dispatch to the right parser based on scheme. Returns None if
    the scheme isn't vless/trojan, or if the URI is malformed."""
    t = detect_type(uri)
    if t == "vless":
        return parse_vless(uri)
    if t == "trojan":
        return parse_trojan(uri)
    return None


def node_fingerprint(node: dict) -> tuple:
    """Identity used for deduplication -- ignores cosmetic differences
    like #name, but keeps everything that actually affects how the
    connection is made. Same host/port/credential with a different
    transport or security setting (e.g. REALITY vs plain TLS) is a
    genuinely different config, not a duplicate."""
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
    )


def dedupe_nodes(nodes: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for n in nodes:
        fp = node_fingerprint(n)
        if fp in seen:
            continue
        seen.add(fp)
        unique.append(n)
    return unique
