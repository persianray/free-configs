"""
Two-stage node testing:

  1. tcp_check    - cheap raw TCP connect to (host, port). Kills most
                     dead nodes almost for free, no Xray process spawn.
  2. full_proxy_check - only runs if stage 1 passes. Spins up a real
                     Xray process for the node, then makes an actual
                     HTTP request through it to a lightweight,
                     reliable endpoint (gstatic's generate_204).

A node only counts as "working" if both stages pass and generate_204
returns HTTP 204 (200 is treated as a hijack / captive portal).
"""

import asyncio
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

from xray_config import build_config

TEST_URL = "https://www.gstatic.com/generate_204"
TCP_TIMEOUT = 3.0
PROXY_TIMEOUT = 8.0
XRAY_READY_TIMEOUT = 3.0
SOCKS_POLL = 0.05


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
    except (asyncio.TimeoutError, OSError, UnicodeError, ValueError):
        # OSError covers connection failures/DNS resolution errors.
        # UnicodeError covers malformed hostnames (e.g. empty labels,
        # labels over 63 chars) that fail IDNA encoding before a
        # connection is even attempted -- these come from garbage/
        # malformed entries in public source lists, not real servers.
        return False


def _spawn_kwargs() -> dict:
    kwargs = {
        "stdout": asyncio.subprocess.DEVNULL,
        "stderr": asyncio.subprocess.DEVNULL,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return kwargs


def _signal_group(proc, sig) -> None:
    if proc is None or proc.returncode is not None:
        return
    try:
        if sys.platform == "win32":
            proc.terminate()
        else:
            os.killpg(proc.pid, sig)
    except (ProcessLookupError, OSError, ValueError):
        try:
            proc.terminate()
        except ProcessLookupError:
            pass


async def _stop_proc(proc) -> None:
    if proc is None or proc.returncode is not None:
        return
    _signal_group(proc, signal.SIGTERM)
    try:
        await asyncio.wait_for(proc.wait(), timeout=2)
        return
    except asyncio.TimeoutError:
        pass
    try:
        if sys.platform == "win32":
            proc.kill()
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, OSError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=1)
    except (asyncio.TimeoutError, ProcessLookupError):
        pass


async def wait_for_socks(port: int, proc, timeout: float = XRAY_READY_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.returncode is not None:
            return False
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port),
                timeout=SOCKS_POLL,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (OSError, asyncio.TimeoutError):
            await asyncio.sleep(SOCKS_POLL)
    return False


async def full_proxy_check(node: dict, local_port: int, timeout: float = PROXY_TIMEOUT):
    """Returns (ok: bool, latency_seconds: float|None)."""
    fd, config_path = tempfile.mkstemp(prefix=f"xray_cfg_{local_port}_", suffix=".json")
    os.close(fd)
    with open(config_path, "w", encoding="utf-8") as handle:
        json.dump(build_config(node, local_port), handle)

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "xray", "run", "-c", config_path, **_spawn_kwargs()
        )
        if not await wait_for_socks(local_port, proc):
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
        parts = stdout.decode().strip().split()
        if len(parts) != 2:
            return False, None
        code, latency = parts[0], float(parts[1])
        ok = code == "204"
        return ok, (latency if ok else None)
    except Exception:
        return False, None
    finally:
        await _stop_proc(proc)
        try:
            os.remove(config_path)
        except OSError:
            pass


async def test_node(node: dict, local_port: int) -> dict:
    """Runs both stages. Returns a result dict merged onto the node.
    Wrapped so that any unexpected error from a single malformed node
    (bad hostname, weird encoding, etc.) can never take down the whole
    batch -- it just gets recorded as a failure and testing continues."""
    result = {**node, "ok": False, "latency": None}
    try:
        if not await tcp_check(node["address"], node["port"]):
            result["fail_stage"] = "tcp"
            return result

        ok, latency = await full_proxy_check(node, local_port)
        result["ok"] = ok
        result["latency"] = latency
        if not ok:
            result["fail_stage"] = "proxy"
        return result
    except Exception as exc:
        result["fail_stage"] = "error"
        result["error"] = str(exc)
        return result


async def run_all_tests(nodes: list[dict], concurrency: int = 20, base_port: int = 20000):
    concurrency = max(1, min(int(concurrency), 20))
    ports = asyncio.Queue()
    for offset in range(concurrency):
        ports.put_nowait(base_port + offset)

    results = [None] * len(nodes)

    async def worker(index, node):
        port = await ports.get()
        try:
            results[index] = await test_node(node, port)
        finally:
            ports.put_nowait(port)

    started = time.time()
    await asyncio.gather(*(worker(i, node) for i, node in enumerate(nodes)))
    elapsed = time.time() - started

    working = [row for row in results if row and row["ok"]]
    working.sort(key=lambda row: row["latency"])

    return working, results, elapsed
