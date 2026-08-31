<div align="center">
🦁 PersianRay Public Config
Free, auto-tested VLESS & Trojan configs for V2Ray and any Xray-core based client
![Update Frequency](https://img.shields.io/badge/updates-every%203h-blue)
![Protocols](https://img.shields.io/badge/protocols-VLESS%20%7C%20Trojan-green)
![Status](https://img.shields.io/badge/tested-Xray--core-orange)
</div>
---
What this is
PersianRay Public Config is a public, auto-updating list of working proxy
configs, published as a subscription link you can drop straight into any
V2Ray / Xray-core based client (v2rayNG, v2rayN, NekoBox, Streisand, Shadowrocket,
Hiddify, Sing-box, and others that support VLESS/Trojan subscriptions).
Recommended: use PersianRay on Android, Windows or iOS. Direct Mode for configs work directly or you can use the "SNI Spoof" mode to use these configs.
Every config in this repo has been tested minutes before publishing — not
scraped and republished blindly. Dead, unreachable, or misconfigured nodes are
filtered out automatically before they ever reach `working.txt`.
Only collects VLESS and Trojan
This repo only collects and tests:
`vless://` — TLS (with fingerprint/ALPN), REALITY, WebSocket, gRPC, XHTTP, HTTPUpgrade, and TCP HTTP obfuscation
`trojan://` — TLS (with fingerprint/ALPN), WebSocket, gRPC, XHTTP, and HTTPUpgrade
Anything else pulled in from a source list — VMess, Shadowsocks, SSR, Hysteria,
etc. — is automatically detected and discarded during parsing. This is a
deliberate scope choice, not a limitation of the source lists: keeping the
protocol surface narrow means every config gets a real, protocol-correct proxy
test rather than a shallow reachability guess.
How configs are tested
Every update cycle runs a genuine two-stage test using real Xray-core, not
a simulation:
TCP reachability check — a raw connection attempt to the node's host
and port. Dead or firewalled servers are dropped immediately.
Full proxy handshake + request — for nodes that pass stage 1, an actual
Xray-core process is started locally with that exact config, and a real
HTTPS request is routed through it. Only HTTP 204 from the probe within the
timeout counts as working (HTTP 200 is treated as a hijack).
Nodes are deduplicated first (same host/port/credential/transport counted
once, regardless of how many source lists repost it), then sorted by latency
so the fastest working nodes are listed first.
How to use it
Add this as a subscription URL in your client of choice:
```
https://raw.githubusercontent.com/persianray/free-configs/main/working_base64.txt
```
Or browse the human-readable version, with latency shown per node:
```
https://raw.githubusercontent.com/persianray/free-configs/main/working.txt
```
Most clients (v2rayN, v2rayNG, NekoBox, Hiddify, etc.) let you add a
subscription by URL and will refresh it on your own schedule — matching this
repo's update cycle means you're always pulling a freshly tested list.
Update schedule
This list is regenerated every 3 hours via GitHub Actions:
All source lists are re-fetched
Every node is re-tested from scratch (no assumptions carried over)
`working.txt` and `working_base64.txt` are overwritten with whatever passes
Because free public nodes churn quickly, "working" means verified at the
last scheduled run — not a permanent guarantee. If a node stops working
between cycles, it'll simply disappear on the next update.
Important notes
Tests run on GitHub-hosted runners (US datacenter IPs). A node that passes
here may still fail from your network, and latency order is runner-relative.
These are third-party, publicly shared servers that PersianRay does not
operate or control. Do not route sensitive, authenticated, or personal
traffic through unverified public nodes.
Availability, speed, and geographic location of nodes will vary and are
not guaranteed.
This project only aggregates and tests connectivity — it does not create,
host, or operate any proxy servers itself.
---
<div align="center">
<sub>Built and maintained with an automated Xray-core testing pipeline · Updated every 3 hours</sub>
</div>
