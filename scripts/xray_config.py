"""
Turns a parsed node dict (from parser.py) into a minimal Xray JSON
config: one SOCKS inbound on 127.0.0.1:<local_port>, one outbound
pointing at the remote node.
"""


def build_config(node: dict, local_port: int) -> dict:
    stream_settings = {"network": node["network"]}

    security = node.get("security", "none")

    if security == "tls":
        stream_settings["security"] = "tls"
        stream_settings["tlsSettings"] = {
            "serverName": node["sni"],
            "allowInsecure": node.get("allow_insecure", False),
        }
    elif security == "reality":
        stream_settings["security"] = "reality"
        stream_settings["realitySettings"] = {
            "serverName": node["sni"],
            "publicKey": node["pbk"],
            "shortId": node["sid"],
            "fingerprint": node["fp"],
        }
    # security == "none" -> plain TCP/WS, no TLS block needed

    if node["network"] == "ws":
        stream_settings["wsSettings"] = {
            "path": node["path"],
            "headers": {"Host": node.get("host_header", node["address"])},
        }
    elif node["network"] == "grpc":
        stream_settings["grpcSettings"] = {
            "serviceName": node.get("service_name", "")
        }

    if node["type"] == "vless":
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": node["address"],
                    "port": node["port"],
                    "users": [{
                        "id": node["uuid"],
                        "encryption": node.get("encryption", "none"),
                        "flow": node.get("flow", ""),
                    }],
                }]
            },
            "streamSettings": stream_settings,
        }
    else:  # trojan
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": node["address"],
                    "port": node["port"],
                    "password": node["password"],
                }]
            },
            "streamSettings": stream_settings,
        }

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": local_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [outbound],
    }
