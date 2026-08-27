<div align="center">

# 🦁 PersianRay Public Config

**Free, auto-tested VLESS & Trojan configs for V2Ray and any Xray-core based client**

![Update Frequency](https://img.shields.io/badge/updates-every%206h-blue)
![Protocols](https://img.shields.io/badge/protocols-VLESS%20%7C%20Trojan-green)
![Status](https://img.shields.io/badge/tested-Xray--core-orange)

</div>

---

## What this is

**PersianRay Public Config** is a public, auto-updating list of working proxy
configs, published as a subscription link you can drop straight into any
V2Ray / Xray-core based client (v2rayNG, v2rayN, NekoBox, Streisand, Shadowrocket,
Hiddify, Sing-box, and others that support VLESS/Trojan subscriptions).

**Recommended:** use PersianRay on Android, Windows or iOS. Direct Mode for configs work directly or you can use the "SNI Spoof" mode to use these configs.

Every config in this repo has been **tested minutes before publishing** — not
scraped and republished blindly. Dead, unreachable, or misconfigured nodes are
filtered out automatically before they ever reach `working.txt`.

## Only collects VLESS and Trojan

This repo **only** collects and tests:

- `vless://` — including plain TLS, REALITY, WebSocket, and gRPC transports
- `trojan://` — including plain TLS and WebSocket transports

Anything else pulled in from a source list — VMess, Shadowsocks, SSR, Hysteria,
etc. — is **automatically detected and discarded** during parsing. This is a
deliberate scope choice, not a limitation of the source lists: keeping the
protocol surface narrow means every config gets a real, protocol-correct proxy
test rather than a shallow reachability guess.

## How configs are tested

Every update cycle runs a genuine two-stage test using **real Xray-core**, not
a simulation:

1. **TCP reachability check** — a raw connection attempt to the node's host
   and port. Dead or firewalled servers are dropped immediately.
2. **Full proxy handshake + request** — for nodes that pass stage 1, an actual
   Xray-core process is started locally with that exact config, and a real
   HTTPS request is routed through it. Only a successful response within the
   timeout counts as *working*.

Nodes are deduplicated first (same host/port/credential/transport counted
once, regardless of how many source lists repost it), then sorted by latency
so the fastest working nodes are listed first.

## How to use it

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

## Update schedule

This list is regenerated **every 6 hours** via GitHub Actions:

- All source lists are re-fetched
- Every node is re-tested from scratch (no assumptions carried over)
- `working.txt` and `working_base64.txt` are overwritten with whatever passes

Because free public nodes churn quickly, "working" means *verified at the
last scheduled run* — not a permanent guarantee. If a node stops working
between cycles, it'll simply disappear on the next update.

## Important notes

- These are third-party, publicly shared servers that PersianRay does not
  operate or control. **Do not route sensitive, authenticated, or personal
  traffic** through unverified public nodes.
- Availability, speed, and geographic location of nodes will vary and are
  not guaranteed.
- This project only aggregates and tests connectivity — it does not create,
  host, or operate any proxy servers itself.

---

<div align="center">
<sub>Built and maintained with an automated Xray-core testing pipeline · Updated every 6 hours</sub>
</div>
