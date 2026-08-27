"""
Two-stage node testing:

  1. tcp_check    - cheap raw TCP connect to (host, port). Kills most
                     dead nodes almost for free, no Xray process spawn.
  2. full_proxy_check - only runs if stage 1 passes. Spins up a real
                     Xray process for the node, then makes an actual
                     HTTP request through it to a lightweight,
                     reliable endpoint (gstatic's generate_204).

A node only counts as "working" if both stages pass.
"""

import asyncio
import json
import os
import time

from xray_config import build_config

TEST_URL = "https://www.gstatic.com/generate_204"
TCP_TIMEOUT = 3.0
PROXY_TIMEOUT = 8.0
XRAY_STARTUP_DELAY = 1.0


async def tcp_check(host: str, port: int, timeout: float = TCP_TIMEOUT) -> bool:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (asyncio.TimeoutError, OSError):
        return False


async def full_proxy_check(node: dict, local_port: int, timeout: float = PROXY_TIMEOUT):
    """Returns (ok: bool, latency_seconds: float|None)."""
    config_path = f"/tmp/xray_cfg_{local_port}.json"
    with open(config_path, "w") as f:
        json.dump(build_config(node, local_port), f)

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "xray", "run", "-c", config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.sleep(XRAY_STARTUP_DELAY)

        # If xray already died (bad config), don't bother testing
        if proc.returncode is not None:
            return False, None

        curl = await asyncio.create_subprocess_exec(
            "curl", "-s", "-o", "/dev/null",
            "-w", "%{http_code} %{time_total}",
            "--socks5-hostname", f"127.0.0.1:{local_port}",
            "--max-time", str(timeout),
            TEST_URL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await curl.communicate()
        out = stdout.decode().strip()
        parts = out.split()
        if len(parts) != 2:
            return False, None
        code, latency = parts[0], float(parts[1])
        ok = code in ("204", "200")
        return ok, (latency if ok else None)
    except Exception:
        return False, None
    finally:
        if proc is not None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=2)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
        try:
            os.remove(config_path)
        except OSError:
            pass


async def test_node(node: dict, local_port: int) -> dict:
    """Runs both stages. Returns a result dict merged onto the node."""
    result = {**node, "ok": False, "latency": None}

    if not await tcp_check(node["address"], node["port"]):
        result["fail_stage"] = "tcp"
        return result

    ok, latency = await full_proxy_check(node, local_port)
    result["ok"] = ok
    result["latency"] = latency
    if not ok:
        result["fail_stage"] = "proxy"
    return result


async def run_all_tests(nodes: list[dict], concurrency: int = 50, base_port: int = 20000):
    sem = asyncio.Semaphore(concurrency)
    results = [None] * len(nodes)

    async def worker(i, node):
        async with sem:
            results[i] = await test_node(node, base_port + i)

    t0 = time.time()
    await asyncio.gather(*(worker(i, n) for i, n in enumerate(nodes)))
    elapsed = time.time() - t0

    working = [r for r in results if r and r["ok"]]
    working.sort(key=lambda r: r["latency"])  # fastest first

    return working, results, elapsed
