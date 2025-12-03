# api/bypass.py
import asyncio
import base64
import json
import re
import ssl
from typing import Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx
import websockets

app = FastAPI()

# Loot domains list (from your JS matches)
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

# timeouts
HTTP_TIMEOUT = 30.0
WS_TIMEOUT = 15.0
KEEPALIVE_INTERVAL = 1.0  # seconds - JS used setInterval(() => ws.send('0'), 1000)

# Helpers -------------------------------------------------------------------

def decode_js_atob_to_utf8(b64str: str) -> str:
    """
    Replicate JS: decodeURIComponent(escape(atob(r)))
    Convert base64->bytes then try utf8; if fails, percent-encode bytes then unquote.
    """
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
    """
    Implements the JS decryptData:
    - atob(encodedData) -> first 5 chars = key
    - remaining chars XOR with repeated key bytes
    """
    try:
        combo = base64.b64decode(combination_b64)
    except Exception:
        return None
    if len(combo) <= 5:
        return None
    # treat bytes as iso-8859-1 / latin-1 so 1:1 mapping to codepoints
    combo_text = "".join(chr(b) for b in combo)
    key = combo_text[:5]
    enc_link = combo_text[5:]
    out = []
    for i, ch in enumerate(enc_link):
        out.append(chr(ord(ch) ^ ord(key[i % len(key)])))
    return "".join(out)

def shard_from_urid(urid: str) -> int:
    """
    Emulate JS: urid.substr(-5) % 3
    Try numeric conversion, else sum char codes mod 3.
    """
    tail = urid[-5:]
    try:
        val = int(tail)
        return val % 3
    except Exception:
        s = sum(ord(c) for c in tail)
        return s % 3

def extract_vars_from_text(text: str) -> dict:
    """
    Try to find INCENTIVE_SERVER_DOMAIN, INCENTIVE_SYNCER_DOMAIN, TID, KEY in page text.
    Returns dict with any matches.
    """
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

# Core logic ----------------------------------------------------------------

async def fetch_url_text(client: httpx.AsyncClient, url: str) -> Tuple[str, int, dict]:
    """
    Fetch url text; returns (text, status_code, headers)
    """
    r = await client.get(url, follow_redirects=True, timeout=HTTP_TIMEOUT)
    return r.text, r.status_code, dict(r.headers)

async def fetch_json_if_possible(client: httpx.AsyncClient, url: str) -> Optional[object]:
    """
    Try to fetch JSON from a URL; return python object or None.
    """
    try:
        r = await client.get(url, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        ct = r.headers.get("content-type", "")
        if "application/json" in ct or r.text.strip().startswith(("[", "{")):
            return r.json()
    except Exception:
        try:
            # attempt to parse even if content-type is odd
            return json.loads(r.text)
        except Exception:
            return None
    return None

async def attempt_handle_response_from_json(client: httpx.AsyncClient, data_obj) -> Optional[str]:
    """
    Emulate JS handleResponse when given JSON (array of items):
    - Extract urid and action_pixel_url from data items
    - Perform side calls: action_pixel_url, td syncer
    - Attempt to find base64 candidates to decrypt to final URL
    Returns the discovered URL or None.
    """
    # data_obj could be list or dict
    items = []
    if isinstance(data_obj, list):
        items = data_obj
    elif isinstance(data_obj, dict):
        # maybe single object or wrapper with array property
        # try to find first array-like value with urid inside
        if "data" in data_obj and isinstance(data_obj["data"], list):
            items = data_obj["data"]
        else:
            # if dict has keys with list values, pick first
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

    # If no urid found, bail
    if not urid:
        return None

    # call action_pixel_url if present (simulate pixel)
    headers = {"User-Agent": "Mozilla/5.0"}
    if action_pixel_url:
        try:
            await client.get(action_pixel_url, headers=headers, timeout=10.0)
        except Exception:
            pass

    # attempt to find/infer incentive domains from earlier fetched page or use placeholders
    # original JS would grab INCENTIVE_SERVER_DOMAIN and INCENTIVE_SYNCER_DOMAIN from scope;
    # server-side we cannot guarantee them — but if items contain such fields, use them
    incentive_server_domain = None
    incentive_syncer_domain = None
    for it in items:
        if isinstance(it, dict):
            if "incentive_server_domain" in it:
                incentive_server_domain = it["incentive_server_domain"]
            if "incentive_syncer_domain" in it:
                incentive_syncer_domain = it["incentive_syncer_domain"]

    # fallback placeholders — best-effort; many real pages will reveal domains in page source
    if not incentive_server_domain:
        incentive_server_domain = None  # we'll attempt to discover elsewhere
    if not incentive_syncer_domain:
        incentive_syncer_domain = None

    # Task id as per example
    task_id = 54

    # attempt /td syncer call if we have incentive_syncer_domain; else skip
    # TID unknown; build empty tid
    tid = ""
    if incentive_syncer_domain:
        td_url = f"https://{incentive_syncer_domain}/td?ac=1&urid={urid}&&cat={task_id}&tid={tid}"
        try:
            await client.get(td_url, headers=headers, timeout=10.0)
        except Exception:
            pass

    # attempt to produce candidate final URL by searching base64-like strings in item fields
    # try to decrypt any base64-like string in JSON items
    base64_candidates = []
    text_blob = json.dumps(items)
    b64s = re.findall(r'([A-Za-z0-9+/=]{24,400})', text_blob)
    base64_candidates.extend(b64s)
    for cand in base64_candidates:
        dec = xor_decrypt_with_key_from_prefix(cand)
        if dec and dec.startswith("http"):
            return dec

    # if we couldn't decrypt here, return a tuple-like placeholder so caller proceeds to websocket step
    return urid  # return urid so caller can continue to websocket attempt

async def perform_websocket_and_wait_for_r(urid: str, incentive_server_domain: str, key: str, task_id: int, timeout: float = WS_TIMEOUT) -> Optional[str]:
    """
    Connect to wss://{shard}.{incentive_server_domain}/c?uid={urid}&cat={task_id}&key={KEY}
    Send keepalive '0' every second, wait for message that contains 'r:', then decrypt the payload.
    """
    if not incentive_server_domain:
        return None
    shard = shard_from_urid(urid)
    wss_url = f"wss://{shard}.{incentive_server_domain}/c?uid={urid}&cat={task_id}&key={key or ''}"

    # websockets client; create ssl context to allow wss
    ssl_context = ssl.create_default_context()
    try:
        async with websockets.connect(wss_url, ssl=ssl_context, max_size=None) as ws:
            # start keepalive
            async def keepalive():
                try:
                    while True:
                        await ws.send("0")
                        await asyncio.sleep(KEEPALIVE_INTERVAL)
                except Exception:
                    return

            keep_task = asyncio.create_task(keepalive())

            try:
                # wait for messages until timeout
                while True:
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    except asyncio.TimeoutError:
                        keep_task.cancel()
                        return None
                    if not isinstance(msg, (str, bytes)):
                        continue
                    message = msg if isinstance(msg, str) else msg.decode("utf-8", errors="ignore")
                    if "r:" in message:
                        payload = message.split("r:", 1)[1]
                        # decrypt payload — it's expected to be base64-like
                        final = xor_decrypt_with_key_from_prefix(payload)
                        keep_task.cancel()
                        return final
                    # otherwise continue waiting
            finally:
                keep_task.cancel()
    except Exception:
        return None

# Main bypass flow ----------------------------------------------------------

async def do_bypass(url: str) -> str:
    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0]

    # If it's plainly not a loot domain, follow redirects and return final URL
    if not any(domain.endswith(d) for d in LOOT_DOMAINS):
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            try:
                r = await client.get(url, follow_redirects=True, timeout=HTTP_TIMEOUT)
                return str(r.url)
            except Exception:
                return url

    # If query param r exists -> decode and return final URL (JS: r decoded via atob->escape->decodeURIComponent)
    qs = parse_qs(parsed.query)
    if "r" in qs and qs["r"]:
        r_val = qs["r"][0]
        final = decode_js_atob_to_utf8(r_val)
        return final

    # Not r-case -> emulate fetch interception & handleResponse flow
    headers = {"User-Agent": "Mozilla/5.0"}
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        try:
            page_text, status, _ = await fetch_url_text(client, url)
        except Exception:
            return url

        # 1) Try to extract the TC endpoint(s) present in page JS (URLs that contain '/tc')
        tc_urls = re.findall(r'https?://[^\s\'"]+/tc[^\s\'"]*', page_text)
        urid = None
        action_pixel_url = None
        incentive_server_domain = None
        incentive_syncer_domain = None
        tid = ""
        key = ""

        # Attempt to extract global vars from the page
        vars_found = extract_vars_from_text(page_text)
        incentive_server_domain = vars_found.get("INCENTIVE_SERVER_DOMAIN")
        incentive_syncer_domain = vars_found.get("INCENTIVE_SYNCER_DOMAIN")
        tid = vars_found.get("TID", "")
        key = vars_found.get("KEY", "")

        # 2) If there are tc URLs, call them and process JSON like JS's handleResponse
        for tc in tc_urls:
            try:
                data = await fetch_json_if_possible(client, tc)
                if data:
                    result = await attempt_handle_response_from_json(client, data)
                    # result might be final URL, or urid string to continue to websocket step
                    if result and result.startswith("http"):
                        return result
                    if isinstance(result, str):
                        # assume urid returned
                        urid = result
                        # derive incentive domains from the tc url if not found
                        parsed_tc = urlparse(tc)
                        if not incentive_syncer_domain:
                            incentive_syncer_domain = parsed_tc.netloc
                    # if we found action_pixel_url inside the JSON earlier, client already fetched it
            except Exception:
                continue

        # 3) If we didn't find urid from tc calls, search page_text for urid/action_pixel_url directly
        if not urid:
            m = re.search(r'"urid"\s*:\s*"([^"]+)"', page_text)
            if m:
                urid = m.group(1)
        if not action_pixel_url:
            m = re.search(r'"action_pixel_url"\s*:\s*"([^"]+)"', page_text)
            if m:
                action_pixel_url = m.group(1)

        # fallback assignments
        if not urid:
            m = re.search(r"urid\s*[:=]\s*['\"]([^'\"]+)['\"]", page_text)
            if m:
                urid = m.group(1)
        if not action_pixel_url:
            m = re.search(r"action_pixel_url\s*[:=]\s*['\"]([^'\"]+)['\"]", page_text)
            if m:
                action_pixel_url = m.group(1)

        # If action_pixel_url exists, call it (simulate pixel)
        if action_pixel_url:
            try:
                await client.get(action_pixel_url, headers=headers, timeout=10.0)
            except Exception:
                pass

        # Ensure we have urid; if not, nothing we can do reliably
        if not urid:
            return url

        # Attempt to discover incentive domains if still missing by looking for hostnames with 'incentive' or 'incentive-server' patterns in page_text
        if not incentive_server_domain:
            m = re.search(r'["\']([a-z0-9\.\-]+incentive[a-z0-9\.\-]*)["\']', page_text, flags=re.I)
            if m:
                incentive_server_domain = m.group(1)
        if not incentive_syncer_domain:
            m = re.search(r'["\']([a-z0-9\.\-]+incentive[a-z0-9\.\-]*syncer[a-z0-9\.\-]*)["\']', page_text, flags=re.I)
            if m:
                incentive_syncer_domain = m.group(1)

        # If still missing incentive_syncer_domain, try deriving from any tc url
        if not incentive_syncer_domain and tc_urls:
            parsed_tc = urlparse(tc_urls[0])
            incentive_syncer_domain = parsed_tc.netloc

        # 4) Send beacon / td / action_pixel as in JS
        task_id = 54
        try:
            # navigator.sendBeacon in JS -> server-side do a GET to st? endpoint
            if incentive_server_domain:
                shard = shard_from_urid(urid)
                st_url = f"https://{shard}.{incentive_server_domain}/st?uid={urid}&cat={task_id}"
                try:
                    await client.get(st_url, headers=headers, timeout=5.0)
                except Exception:
                    pass
            # call td on incentive syncer
            if incentive_syncer_domain:
                td_url = f"https://{incentive_syncer_domain}/td?ac=1&urid={urid}&&cat={task_id}&tid={tid}"
                try:
                    await client.get(td_url, headers=headers, timeout=5.0)
                except Exception:
                    pass
        except Exception:
            pass

        # 5) WebSocket step: try to connect and wait for r: message
        if not key:
            # attempt to find KEY in page again in different patterns
            m = re.search(r'["\']KEY["\']\s*[:=]\s*["\']?([A-Za-z0-9_\-+=/]+)["\']?', page_text)
            if m:
                key = m.group(1)
        # If still no incentive_server_domain but incentive_syncer_domain exists, try heuristics:
        if not incentive_server_domain and incentive_syncer_domain:
            # a common pattern: syncer domain might be like "syncer.example" and server domain might be "incentive.example"
            # best-effort: replace 'syncer' with 'server' or strip subdomain
            incentive_server_domain = incentive_syncer_domain.replace("syncer", "server")
        # finally attempt websocket
        final = None
        try:
            final = await perform_websocket_and_wait_for_r(urid, incentive_server_domain or "", key or "", task_id, timeout=WS_TIMEOUT)
        except Exception:
            final = None

        if final and final.startswith("http"):
            return final

        # If websocket didn't yield a final link, we return original url (or we could return urid to aid debugging)
        return url

# FastAPI endpoints ---------------------------------------------------------

@app.get("/", include_in_schema=False)
async def home():
    return {"message": "Loot-only bypass API is alive!"}

@app.api_route("/bypass", methods=["GET", "POST"])
async def bypass(request: Request):
    # defensive request parsing
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
