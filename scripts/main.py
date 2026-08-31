"""
End to end pipeline:

  1. Read sources.txt (one subscription URL per line, # comments allowed)
  2. Fetch each source in parallel (retries + User-Agent), base64-decode
     if needed, extract vless:// and trojan:// URIs
  3. Parse only vless:// and trojan:// (everything else is skipped)
  4. Deduplicate by connection-affecting fields
  5. Test each node: TCP connect -> full Xray proxy request
  6. Atomically write working.txt and working_base64.txt only after a
     complete successful run
"""

import asyncio
import base64
import binascii
import os
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(__file__))
from parser import dedupe_nodes, extract_uris, parse_node  # noqa: E402
from tester import run_all_tests  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES_FILE = os.path.join(ROOT, "sources.txt")
OUT_PLAIN = os.path.join(ROOT, "working.txt")
OUT_B64 = os.path.join(ROOT, "working_base64.txt")

FETCH_TIMEOUT = 15
FETCH_RETRIES = 3
FETCH_BACKOFF = 1.5
CONCURRENCY = 20
USER_AGENT = "Mozilla/5.0 (compatible; PersianRayTester/1.0)"


def read_sources() -> list[str]:
    if not os.path.exists(SOURCES_FILE):
        print(f"No sources.txt found at {SOURCES_FILE}")
        return []
    urls = []
    with open(SOURCES_FILE, encoding="utf-8") as handle:
        for line in handle:
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
    last_error = None
    for attempt in range(1, FETCH_RETRIES + 1):
        try:
            resp = requests.get(
                url,
                timeout=FETCH_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
            )
            resp.raise_for_status()
            return extract_uris(maybe_b64_decode(resp.text))
        except requests.RequestException as exc:
            last_error = exc
            print(f"  [!] fetch {url} attempt {attempt}/{FETCH_RETRIES}: {exc}")
            if attempt < FETCH_RETRIES:
                time.sleep(FETCH_BACKOFF * attempt)
    print(f"  [!] failed to fetch {url}: {last_error}")
    return []


def collect_all_uris(source_urls: list[str]) -> list[str]:
    all_uris: list[str] = []
    workers = min(8, max(1, len(source_urls)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch_source, url): url for url in source_urls}
        for future in as_completed(futures):
            url = futures[future]
            try:
                lines = future.result()
            except Exception as exc:
                print(f"Fetched {url} -> error: {exc}")
                continue
            print(f"Fetched {url} -> {len(lines)} URIs")
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
    print(
        f"Parsed {len(nodes)} vless/trojan nodes ({skipped} lines skipped: "
        "unsupported scheme or malformed)"
    )
    return nodes


def atomic_write(path: str, data: str) -> None:
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_out_", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(data)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def write_outputs(working: list[dict]) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"# Updated: {timestamp}\n",
        f"# {len(working)} working nodes (sorted fastest first)\n\n",
    ]
    for row in working:
        latency_ms = int(row["latency"] * 1000)
        lines.append(f"{row['raw']}  # {latency_ms}ms\n")
    atomic_write(OUT_PLAIN, "".join(lines))

    joined = "\n".join(row["raw"] for row in working)
    blob = base64.b64encode(joined.encode("utf-8")).decode("ascii")
    atomic_write(OUT_B64, blob)
    print(f"Wrote {OUT_PLAIN} and {OUT_B64}")


def write_step_summary(
    working_count: int,
    tcp_fail: int,
    proxy_fail: int,
    elapsed: float,
    unique_nodes: int,
) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("## Proxy check\n\n")
        handle.write(f"- unique nodes tested: {unique_nodes}\n")
        handle.write(f"- working: {working_count}\n")
        handle.write(f"- failed at TCP: {tcp_fail}\n")
        handle.write(f"- failed at proxy: {proxy_fail}\n")
        handle.write(f"- elapsed: {elapsed:.1f}s\n")


async def main() -> int:
    source_urls = read_sources()
    if not source_urls:
        print("No sources configured; refusing to overwrite previous results.")
        return 1

    all_uris = collect_all_uris(source_urls)
    print(f"Collected {len(all_uris)} raw URIs from {len(source_urls)} sources")
    if not all_uris:
        print("No URIs collected from any source; keeping previous results.")
        return 1

    nodes = parse_all(all_uris)
    nodes = dedupe_nodes(nodes)
    print(f"{len(nodes)} unique nodes after dedup")

    if not nodes:
        write_outputs([])
        write_step_summary(0, 0, 0, 0.0, 0)
        return 0

    print(f"Testing {len(nodes)} nodes (concurrency={CONCURRENCY})...")
    working, all_results, elapsed = await run_all_tests(nodes, concurrency=CONCURRENCY)

    tcp_fail = sum(1 for row in all_results if row and row.get("fail_stage") == "tcp")
    proxy_fail = sum(1 for row in all_results if row and row.get("fail_stage") == "proxy")

    print(f"Done in {elapsed:.1f}s")
    print(f"  working:        {len(working)}")
    print(f"  failed at TCP:  {tcp_fail}")
    print(f"  failed at proxy: {proxy_fail}")

    write_outputs(working)
    write_step_summary(len(working), tcp_fail, proxy_fail, elapsed, len(nodes))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except SystemExit:
        raise
    except Exception as exc:
        print(f"Pipeline failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
