# api/bypass.py
import base64
import re
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx

app = FastAPI()

# Only support these loot domains (as in your JS matches list)
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

async def fetch_text(client: httpx.AsyncClient, url: str, headers: dict):
    r = await client.get(url, headers=headers, follow_redirects=True, timeout=30.0)
    return r

def decode_js_atob_to_utf8(b64str: str) -> str:
    """
    Replicate JS: decodeURIComponent(escape(atob(r)))
    Common pattern to convert base64-of-utf8 -> proper text.
    """
    try:
        raw = base64.b64decode(b64str)
    except Exception:
        # invalid base64
        return b64str

    # try direct utf-8 first (most common)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        # fallback: percent-encode each byte (like JS escape(atob(...))) then unquote
        pct = "".join("%%%02x" % b for b in raw)
        return unquote(pct)

def xor_decrypt_with_key_from_prefix(combination_b64: str) -> Optional[str]:
    """
    Implements the JS decryptData: atob(encodedData) -> first 5 chars = key,
    then XOR each remaining byte with key byte repeated.
    Returns decrypted string if it works, else None.
    """
    try:
        combo = base64.b64decode(combination_b64)
    except Exception:
        return None
    if len(combo) <= 5:
        return None
    try:
        combo_text = combo.decode("latin-1")  # treat bytes as 1:1
    except Exception:
        combo_text = "".join(chr(b) for b in combo)
    key = combo_text[:5]
    enc_link = combo_text[5:]
    out_chars = []
    for i, ch in enumerate(enc_link):
        out_chars.append(chr(ord(ch) ^ ord(key[i % len(key)])))
    return "".join(out_chars)

async def handle_loot_page(client: httpx.AsyncClient, url: str, page_text: str):
    """
    Try to emulate what the JS handleResponse does:
      - find urid and action_pixel_url inside JSON or JS on the page
      - if found, call the action_pixel_url and the syncer td endpoint (best-effort)
      - (websocket step omitted here — see comments)
    Returns either a discovered destination (if we deduce it) or the original url.
    """
    headers = {"User-Agent": "Mozilla/5.0"}
    # try to find a JSON array with objects containing "urid" and "action_pixel_url"
    urid = None
    action_pixel_url = None

    # quick JSON-like search
    m = re.search(r'"urid"\s*:\s*"([^"]+)"', page_text)
    if m:
        urid = m.group(1)

    m2 = re.search(r'"action_pixel_url"\s*:\s*"([^"]+)"', page_text)
    if m2:
        action_pixel_url = m2.group(1)

    # fallback: look for urid in assignment style: urid = "..."
    if not urid:
        m = re.search(r"urid\s*[:=]\s*['\"]([^'\"]+)['\"]", page_text)
        if m:
            urid = m.group(1)

    # fallback: action_pixel_url assignment
    if not action_pixel_url:
        m = re.search(r"action_pixel_url\s*[:=]\s*['\"]([^'\"]+)['\"]", page_text)
        if m:
            action_pixel_url = m.group(1)

    # if we got an action_pixel_url, fire it (simulate image/pixel fetch)
    if action_pixel_url:
        try:
            await client.get(action_pixel_url, headers=headers, timeout=10.0)
        except Exception:
            pass

    # if we got an urid, attempt a 'td' syncer call (best-effort)
    if urid:
        # many pages use dynamic domains for incentive syncer; try to find the domain from page
        m = re.search(r'(["\'])([a-z0-9\.\-]+incentive[a-z0-9\.\-]*)\1', page_text)
        incentive_domain = m.group(2) if m else None

        # fallback: try common hostnames (this is heuristic)
        if not incentive_domain:
            incentive_domain = "incentive-syncer.example"  # placeholder; most real pages will include an actual domain

        # task_id used in example (magic number)
        task_id = 54
        # TID unknown on server-side; many sites embed it in page as TID variable — try to find it
        tid_match = re.search(r'\bTID\s*[:=]\s*["\']?([A-Za-z0-9_\-]+)["\']?', page_text)
        tid = tid_match.group(1) if tid_match else ""

        # call the /td endpoint (best-effort); ignore errors
        if incentive_domain and urid:
            td_url = f"https://{incentive_domain}/td?ac=1&urid={urid}&&cat={task_id}&tid={tid}"
            try:
                await client.get(td_url, headers=headers, timeout=10.0)
            except Exception:
                pass

        # After these calls the browser JS sets up a websocket and waits for an `r:` message.
        # We cannot reliably reproduce the websocket handshake here (missing TID/KEY and dynamic domains).
        # If the page contained any base64-like string that looks like the 'r:' payload we can try to decrypt:
        # search for base64 candidates in page and attempt XOR-decrypt heuristic.
        b64_candidates = re.findall(r'["\']([A-Za-z0-9+/=]{20,200})["\']', page_text)
        for cand in b64_candidates:
            dec = xor_decrypt_with_key_from_prefix(cand)
            if dec and dec.startswith("http"):
                return dec

    # nothing discovered — return original url
    return url

async def do_bypass(url: str) -> str:
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    # narrow to host (remove port)
    domain_only = domain.split(":")[0]

    # only process loot-like domains
    if not any(domain_only.endswith(d) for d in LOOT_DOMAINS):
        # not a loot link — return supplied url (or follow redirects by fetching)
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                r = await client.get(url, follow_redirects=True)
                return str(r.url)
            except Exception:
                return url

    # If query param r exists -> decode and return final URL
    qs = parse_qs(parsed.query)
    if "r" in qs and qs["r"]:
        r_val = qs["r"][0]
        final = decode_js_atob_to_utf8(r_val)
        return final

    # otherwise fetch the page and attempt to emulate the fetch/handleResponse flow
    headers = {"User-Agent": "Mozilla/5.0"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            r = await fetch_text(client, url, headers)
            page_text = r.text
            dest = await handle_loot_page(client, url, page_text)
            return dest
        except Exception:
            return url

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
