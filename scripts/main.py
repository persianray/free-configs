"""
End to end pipeline:

  1. Read sources.txt (one subscription URL per line, # comments allowed)
  2. Fetch each source, base64-decode if needed, split into raw URIs
  3. Parse only vless:// and trojan:// (everything else is skipped)
  4. Deduplicate by (type, host, port, credential)
  5. Test each node: TCP connect -> full Xray proxy request
  6. Write working.txt (plain list) and working_base64.txt (subscription
     format most clients can consume directly)
"""

import asyncio
import base64
import binascii
import os
import sys
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(__file__))
from parser import parse_node, dedupe_nodes  # noqa: E402
from tester import run_all_tests  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES_FILE = os.path.join(ROOT, "sources.txt")
OUT_PLAIN = os.path.join(ROOT, "working.txt")
OUT_B64 = os.path.join(ROOT, "working_base64.txt")

FETCH_TIMEOUT = 15
CONCURRENCY = 50


def read_sources() -> list[str]:
    if not os.path.exists(SOURCES_FILE):
        print(f"No sources.txt found at {SOURCES_FILE}")
        return []
    urls = []
    with open(SOURCES_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


def maybe_b64_decode(text: str) -> str:
    """Subscription bodies are often base64 of a newline-separated URI
    list. If it decodes cleanly to something that looks like URIs,
    use that; otherwise assume it's already plaintext."""
    stripped = text.strip()
    try:
        padded = stripped + "=" * (-len(stripped) % 4)
        decoded = base64.b64decode(padded, validate=True).decode("utf-8", errors="strict")
        if "://" in decoded:
            return decoded
    except (binascii.Error, UnicodeDecodeError, ValueError):
        pass
    return text


def fetch_source(url: str) -> list[str]:
    try:
        resp = requests.get(url, timeout=FETCH_TIMEOUT)
        resp.raise_for_status()
        body = maybe_b64_decode(resp.text)
        return [line.strip() for line in body.splitlines() if line.strip()]
    except requests.RequestException as e:
        print(f"  [!] failed to fetch {url}: {e}")
        return []


def collect_all_uris(source_urls: list[str]) -> list[str]:
    all_uris = []
    for url in source_urls:
        print(f"Fetching source: {url}")
        lines = fetch_source(url)
        print(f"  -> {len(lines)} lines")
        all_uris.extend(lines)
    return all_uris


def parse_all(uris: list[str]) -> list[dict]:
    nodes = []
    skipped = 0
    for uri in uris:
        node = parse_node(uri)
        if node is None:
            skipped += 1
            continue
        nodes.append(node)
    print(f"Parsed {len(nodes)} vless/trojan nodes ({skipped} lines skipped: "
          f"unsupported scheme or malformed)")
    return nodes


def write_outputs(working: list[dict]):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    with open(OUT_PLAIN, "w") as f:
        f.write(f"# Updated: {timestamp}\n")
        f.write(f"# {len(working)} working nodes (sorted fastest first)\n\n")
        for r in working:
            latency_ms = int(r["latency"] * 1000)
            f.write(f"{r['raw']}  # {latency_ms}ms\n")

    joined = "\n".join(r["raw"] for r in working)
    b64_blob = base64.b64encode(joined.encode("utf-8")).decode("ascii")
    with open(OUT_B64, "w") as f:
        f.write(b64_blob)

    print(f"Wrote {OUT_PLAIN} and {OUT_B64}")


async def main():
    source_urls = read_sources()
    if not source_urls:
        print("No sources configured, nothing to do.")
        return

    all_uris = collect_all_uris(source_urls)
    print(f"Collected {len(all_uris)} raw lines from {len(source_urls)} sources")

    nodes = parse_all(all_uris)
    nodes = dedupe_nodes(nodes)
    print(f"{len(nodes)} unique nodes after dedup")

    if not nodes:
        write_outputs([])
        return

    print(f"Testing {len(nodes)} nodes (concurrency={CONCURRENCY})...")
    working, all_results, elapsed = await run_all_tests(nodes, concurrency=CONCURRENCY)

    tcp_fail = sum(1 for r in all_results if r and r.get("fail_stage") == "tcp")
    proxy_fail = sum(1 for r in all_results if r and r.get("fail_stage") == "proxy")

    print(f"Done in {elapsed:.1f}s")
    print(f"  working:        {len(working)}")
    print(f"  failed at TCP:  {tcp_fail}")
    print(f"  failed at proxy: {proxy_fail}")

    write_outputs(working)


if __name__ == "__main__":
    asyncio.run(main())
