# api/bypass.py
"""
Robust Loot-only bypass API.

Notes:
- Optional websockets support: if `websockets` cannot be imported or if WS step fails,
  the function will continue and return the best result it can (no crash).
- This file logs steps using the logging module which will show up in Vercel function logs.
"""

import asyncio
import base64
import json
import logging
import re
import ssl
import traceback
from typing import Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx

# Try to import websockets optionally
try:
    import websockets  # type: ignore
    WEBSOCKETS_AVAILABLE = True
except Exception:
    websockets = None
    WEBSOCKETS_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("bypass")

app = FastAPI()

LOOT_DOMAINS = {
    "lootlinks.co",
    "loot-links.com",
    "loot-link.com",
    "linksloot.net",
    "lootdest.com",
    "lootlink.org",
    "lootdest.info",
    "lootdest.org",
    "links-loot.com",
}

HTTP_TIMEOUT = 30.0
WS_TIMEOUT = 15.0
KEEPALIVE_INTERVAL = 1.0

# ----- Utilities -----


def decode_js_atob_to_utf8(b64str: str) -> str:
    try:
        raw = base64.b64decode(b64str)
    except Exception:
        return b64str
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pct = "".join("%%%02x" % b for b in raw)
        return unquote(pct)


def xor_decrypt_with_key_from_prefix(combination_b64: str) -> Optional[str]:
    try:
        combo = base64.b64decode(combination_b64)
    except Exception:
        return None
    if len(combo) <= 5:
        return None
    combo_text = "".join(chr(b) for b in combo)
    key = combo_text[:5]
    enc_link = combo_text[5:]
    out = []
    for i, ch in enumerate(enc_link):
        out.append(chr(ord(ch) ^ ord(key[i % len(key)])))
    return "".join(out)


def shard_from_urid(urid: str) -> int:
    tail = urid[-5:]
    try:
        val = int(tail)
        return val % 3
    except Exception:
        return sum(ord(c) for c in tail) % 3


def extract_vars_from_text(text: str) -> dict:
    out = {}
    patterns = {
        "INCENTIVE_SERVER_DOMAIN": r'INCENTIVE_SERVER_DOMAIN\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
        "INCENTIVE_SYNCER_DOMAIN": r'INCENTIVE_SYNCER_DOMAIN\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
        "TID": r'\bTID\s*[:=]\s*[\'"]?([A-Za-z0-9_\-]+)[\'"]?',
        "KEY": r'\bKEY\s*[:=]\s*[\'"]?([A-Za-z0-9_\-+=/]+)[\'"]?',
    }
    for key, pat in patterns.items():
        m = re.search(pat, text)
        if m:
            out[key] = m.group(1)
    return out


# ----- HTTP helpers -----


async def fetch_url_text(client: httpx.AsyncClient, url: str) -> Tuple[str, int, dict]:
    r = await client.get(url, follow_redirects=True, timeout=HTTP_TIMEOUT)
    return r.text, r.status_code, dict(r.headers)


async def fetch_json_if_possible(client: httpx.AsyncClient, url: str) -> Optional[object]:
    try:
        r = await client.get(url, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        ct = r.headers.get("content-type", "")
        if "application/json" in ct or r.text.strip().startswith(("[", "{")):
            return r.json()
    except Exception:
        try:
            return json.loads(r.text)
        except Exception:
            return None
    return None


async def attempt_handle_response_from_json(client: httpx.AsyncClient, data_obj) -> Optional[str]:
    items = []
    if isinstance(data_obj, list):
        items = data_obj
    elif isinstance(data_obj, dict):
        if "data" in data_obj and isinstance(data_obj["data"], list):
            items = data_obj["data"]
        else:
            for v in data_obj.values():
                if isinstance(v, list):
                    items = v
                    break
            if not items:
                items = [data_obj]

    urid = None
    action_pixel_url = None
    for it in items:
        if not isinstance(it, dict):
            continue
        if "urid" in it and it["urid"]:
            urid = it["urid"]
        if "action_pixel_url" in it and it["action_pixel_url"]:
            action_pixel_url = it["action_pixel_url"]

    if action_pixel_url:
        try:
            await client.get(action_pixel_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10.0)
        except Exception:
            pass

    if urid:
        # best-effort find base64 candidates in items
        text_blob = json.dumps(items)
        b64s = re.findall(r'([A-Za-z0-9+/=]{24,400})', text_blob)
        for cand in b64s:
            dec = xor_decrypt_with_key_from_prefix(cand)
            if dec and dec.startswith("http"):
                return dec
        return urid
    return None


async def perform_websocket_and_wait_for_r(urid: str, incentive_server_domain: str, key: str, task_id: int, timeout: float = WS_TIMEOUT) -> Optional[str]:
    if not WEBSOCKETS_AVAILABLE:
        log.info("Websockets not available in environment; skipping WS step.")
        return None
    if not incentive_server_domain:
        log.info("No incentive_server_domain provided; skipping WS step.")
        return None

    shard = shard_from_urid(urid)
    wss_url = f"wss://{shard}.{incentive_server_domain}/c?uid={urid}&cat={task_id}&key={key or ''}"
    log.info(f"Attempting WS -> {wss_url}")
    ssl_context = ssl.create_default_context()
    try:
        # websockets.connect returns an async context manager
        async with websockets.connect(wss_url, ssl=ssl_context, max_size=None) as ws:
            async def keepalive():
                try:
                    while True:
                        await ws.send("0")
                        await asyncio.sleep(KEEPALIVE_INTERVAL)
                except Exception:
                    return

            keep_task = asyncio.create_task(keepalive())
            try:
                while True:
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    except asyncio.TimeoutError:
                        keep_task.cancel()
                        log.info("WS recv timed out")
                        return None
                    if not isinstance(msg, (str, bytes)):
                        continue
                    message = msg if isinstance(msg, str) else msg.decode("utf-8", errors="ignore")
                    log.info(f"WS msg: {message[:200]}")
                    if "r:" in message:
                        payload = message.split("r:", 1)[1]
                        final = xor_decrypt_with_key_from_prefix(payload)
                        keep_task.cancel()
                        return final
            finally:
                keep_task.cancel()
    except Exception as e:
        log.info(f"WS exception: {e}")
        return None


# ----- Main flow -----


async def do_bypass(url: str) -> str:
    log.info(f"do_bypass start for url: {url}")
    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0]
    headers = {"User-Agent": "Mozilla/5.0"}

    if not any(domain.endswith(d) for d in LOOT_DOMAINS):
        log.info("Not a loot domain; following redirects")
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            try:
                r = await client.get(url, follow_redirects=True, timeout=HTTP_TIMEOUT)
                log.info(f"Followed to {r.url}")
                return str(r.url)
            except Exception as e:
                log.exception("Error following redirects")
                return url

    qs = parse_qs(parsed.query)
    if "r" in qs and qs["r"]:
        r_val = qs["r"][0]
        try:
            final = decode_js_atob_to_utf8(r_val)
            log.info(f"Decoded r param -> {final}")
            return final
        except Exception:
            log.exception("Failed to decode r param")
            return url

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        try:
            page_text, status, headers_resp = await fetch_url_text(client, url)
            log.info(f"Fetched page status={status} len={len(page_text)}")
        except Exception:
            log.exception("Failed to fetch page")
            return url

        # find /tc endpoints
        tc_urls = re.findall(r'https?://[^\s\'"]+/tc[^\s\'"]*', page_text)
        log.info(f"Found tc urls: {tc_urls}")

        urid = None
        action_pixel_url = None
        incentive_server_domain = None
        incentive_syncer_domain = None
        tid = ""
        key = ""

        vars_found = extract_vars_from_text(page_text)
        incentive_server_domain = vars_found.get("INCENTIVE_SERVER_DOMAIN")
        incentive_syncer_domain = vars_found.get("INCENTIVE_SYNCER_DOMAIN")
        tid = vars_found.get("TID", "")
        key = vars_found.get("KEY", "")
        log.info(f"vars_found: {vars_found}")

        # process tc urls
        for tc in tc_urls:
            try:
                data = await fetch_json_if_possible(client, tc)
                log.info(f"tc {tc} returned json? {bool(data)}")
                if data:
                    result = await attempt_handle_response_from_json(client, data)
                    log.info(f"attempt_handle_response_from_json -> {result}")
                    if result and isinstance(result, str) and result.startswith("http"):
                        log.info("Got final URL from tc JSON")
                        return result
                    if result and isinstance(result, str):
                        urid = result
                        parsed_tc = urlparse(tc)
                        if not incentive_syncer_domain:
                            incentive_syncer_domain = parsed_tc.netloc
                        log.info(f"Set urid={urid} incentive_syncer_domain={incentive_syncer_domain}")
            except Exception:
                log.exception(f"Error processing tc url {tc}")
                continue

        # fallback search in page text
        if not urid:
            m = re.search(r'"urid"\s*:\s*"([^"]+)"', page_text)
            if m:
                urid = m.group(1)
        if not action_pixel_url:
            m = re.search(r'"action_pixel_url"\s*:\s*"([^"]+)"', page_text)
            if m:
                action_pixel_url = m.group(1)
        if not urid:
            m = re.search(r"urid\s*[:=]\s*['\"]([^'\"]+)['\"]", page_text)
            if m:
                urid = m.group(1)
        if not action_pixel_url:
            m = re.search(r"action_pixel_url\s*[:=]\s*['\"]([^'\"]+)['\"]", page_text)
            if m:
                action_pixel_url = m.group(1)

        log.info(f"Post-extract urid={urid} action_pixel_url={action_pixel_url}")

        if action_pixel_url:
            try:
                await client.get(action_pixel_url, headers=headers, timeout=10.0)
            except Exception:
                log.exception("Failed action_pixel_url")

        if not urid:
            log.info("No urid found; cannot proceed to WS; returning original url")
            return url

        # try to discover incentive domains heuristically
        if not incentive_server_domain:
            m = re.search(r'["\']([a-z0-9\.\-]+incentive[a-z0-9\.\-]*)["\']', page_text, flags=re.I)
            if m:
                incentive_server_domain = m.group(1)
        if not incentive_syncer_domain:
            m = re.search(r'["\']([a-z0-9\.\-]+incentive[a-z0-9\.\-]*syncer[a-z0-9\.\-]*)["\']', page_text, flags=re.I)
            if m:
                incentive_syncer_domain = m.group(1)
        if not incentive_syncer_domain and tc_urls:
            parsed_tc = urlparse(tc_urls[0])
            incentive_syncer_domain = parsed_tc.netloc

        log.info(f"incentive_server_domain={incentive_server_domain} incentive_syncer_domain={incentive_syncer_domain} tid={tid} key_set={bool(key)}")

        task_id = 54
        # send st and td calls as JS would
        try:
            if incentive_server_domain:
                shard = shard_from_urid(urid)
                st_url = f"https://{shard}.{incentive_server_domain}/st?uid={urid}&cat={task_id}"
                try:
                    await client.get(st_url, headers=headers, timeout=5.0)
                except Exception:
                    log.exception("st call failed")
            if incentive_syncer_domain:
                td_url = f"https://{incentive_syncer_domain}/td?ac=1&urid={urid}&&cat={task_id}&tid={tid}"
                try:
                    await client.get(td_url, headers=headers, timeout=5.0)
                except Exception:
                    log.exception("td call failed")
        except Exception:
            log.exception("Error during st/td calls")

        # attempt websocket step if websockets available
        final = None
        try:
            final = await perform_websocket_and_wait_for_r(urid, incentive_server_domain or "", key or "", task_id, timeout=WS_TIMEOUT)
            log.info(f"Websocket returned: {final}")
        except Exception:
            log.exception("Websocket step failed")

        if final and final.startswith("http"):
            return final

        log.info("No final URL from WS; returning original url")
        return url


# ----- FastAPI endpoints -----


@app.get("/", include_in_schema=False)
async def home():
    return {"message": "Loot-only bypass API is alive!"}


@app.api_route("/bypass", methods=["GET", "POST"])
async def bypass(request: Request):
    try:
        if request.method == "GET":
            url = request.query_params.get("url")
        else:
            try:
                data = await request.json()
            except Exception:
                return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
            url = data.get("url")

        if not url:
            return JSONResponse({"error": "Missing url parameter"}, status_code=400)

        destination = await do_bypass(url)
        return {"success": True, "destination": destination}
    except Exception as e:
        # Log full traceback so Vercel logs show why it crashed
        tb = traceback.format_exc()
        log.error("Unhandled exception in /bypass:\n" + tb)
        # return a JSON 500 rather than letting Vercel show the generic FUNCTION_INVOCATION_FAILED page
        return JSONResponse({"error": "internal_server_error", "details": str(e)}, status_code=500)
