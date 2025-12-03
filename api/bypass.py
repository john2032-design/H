# api/bypass.py
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx
import re
from urllib.parse import urlparse
import json
import base64
import codecs  # For rot13 in Adf.ly

app = FastAPI()

async def do_bypass(url: str) -> str:
    domain = urlparse(url).netloc.lower().replace("www.", "")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    async with httpx.AsyncClient(timeout=45.0, follow_redirects=False, headers=headers) as client:
        try:
            r = await client.get(url)
            r.raise_for_status()

            # ——— LINKVERTISE (2025: base64 JSON token + o: fallback) ———
            if "linkvertise" in domain:
                # Primary: decodeTarget base64 (from bypass.vip userscript)
                token_match = re.search(r'decodeTarget\s*=\s*"([^"]+)"', r.text)
                if token_match:
                    encoded = token_match.group(1)
                    try:
                        decoded = base64.b64decode(encoded + "==").decode('utf-8')
                        data = json.loads(decoded)
                        return data.get("target") or data.get("destination") or url
                    except:
                        pass
                # Fallback: o: pattern (updated 2025 regex)
                o_match = re.search(r'o:"(https?://[^"]+)', r.text)
                if o_match:
                    return o_match.group(1)

            # ——— LOOTLINKS / LOOTDEST / LOOTLABS / ADM AVEN (2025 JSON extract) ———
            if any(x in domain for x in ["loot-link", "lootlinks", "lootdest", "lootlabs", "admaven"]):
                # Unescape and parse (from Link-Bypasser-Bot)
                cleaned = r.text.replace("\\", "")
                match = re.search(r'"link":"(https?://[^"]+)', cleaned)
                if match:
                    return match.group(1)
                # Alt: encrypted payload
                enc_match = re.search(r'"encoded":"([^"]+)', cleaned)
                if enc_match:
                    try:
                        decoded = base64.b64decode(enc_match.group(1)).decode('utf-8')
                        link_match = re.search(r'(https?://[^"\s]+)', decoded)
                        if link_match:
                            return link_match.group(1)
                    except:
                        pass

            # ——— WORK.INK / BOOST.INK / MBOOST.ME / CUTY.IO (JS redirect hooks) ———
            if any(x in domain for x in ["work.ink", "boost.ink", "mboost.me", "cuty.io", "cety.io"]):
                # window.location extract (from bypass-userscripts)
                match = re.search(r'window\.location\s*=\s*["\']([^"\']+)', r.text)
                if match:
                    return match.group(1)
                # Alt: setTimeout redirect
                time_match = re.search(r'setTimeout\s*\(\s*function\s*\(\)\s*\{\s*window\.location\s*=\s*["\']([^"\']+)', r.text)
                if time_match:
                    return time_match.group(1)

            # ——— REKONISE (Direct API slug) ———
            if "rekonise" in domain:
                slug = url.split("/")[-1] if "/" in url else ""
                if slug:
                    api_url = f"https://api.rekonise.com/unlock/{slug}"
                    api_r = await client.get(api_url, headers=headers)
                    if api_r.status_code == 200:
                        data = api_r.json()
                        return data.get("url") or data.get("destination") or url

            # ——— SUB2UNLOCK / SUB2GET / SOCIAL-UNLOCK (Const target var) ———
            if any(x in domain for x in ["sub2unlock", "sub2get", "social-unlock", "socialwolvez"]):
                match = re.search(r'const target\s*=\s*["\']([^"\']+)', r.text)
                if match:
                    return match.group(1)
                # Fallback: data-target attr
                target_match = re.search(r'data-target=["\']([^"\']+)', r.text)
                if target_match:
                    return target_match.group(1)

            # ——— ADF.LY / SHORTE.ST / FC.LC / OUO.IO (Rot13 base64 classic) ———
            if any(x in domain for x in ["adf.ly", "shorte.st", "fc.lc", "ouo.io"]):
                ysmm = re.search(r"ysmm\s*=\s*'([^']+)", r.text)
                if ysmm:
                    try:
                        rot13 = codecs.decode(ysmm.group(1), 'rot13')
                        decoded = base64.b64decode(rot13.encode()).decode('utf-8')
                        final = re.search(r'"(https?://[^"]+)', decoded)
                        if final:
                            return final.group(1)
                    except:
                        pass
                # OUO alt: adLink extract
                if "ouo" in domain:
                    ad_match = re.search(r'adLink\s*=\s*["\']([^"\']+)', r.text)
                    if ad_match:
                        return ad_match.group(1)

            # ——— PASTE R.SO / G.G / AD FOC.US / YTSUBME (Quick JSON/attr) ———
            if any(x in domain for x in ["paster.so", "paster.gg", "adfoc.us", "ytsubme"]):
                json_match = re.search(r'"url"\s*:\s*"([^"]+)', r.text)
                if json_match:
                    return json_match.group(1)
                attr_match = re.search(r'href=["\']([^"\']+)', r.text, re.DOTALL)
                if attr_match and "direct" in attr_match.group(1).lower():
                    return attr_match.group(1)

            # ——— FINAL FALLBACK: Multi-redirect follow (with 2nd GET if needed) ———
            final_r = await client.get(url, follow_redirects=True, timeout=30.0)
            return str(final_r.url)

        except Exception as e:
            # Log for Vercel: print(f"Bypass error for {domain}: {e}")
            return url  # Graceful fail to original

# Your existing endpoint (unchanged, but with minor tweak for JSON safety)
@app.get("/", include_in_schema=False)
async def home():
    return {"message": "Your bypass API is working! Supports 20+ 2025 shorteners."}

@app.api_route("/bypass", methods=["GET", "POST"])
async def bypass(request: Request):
    try:
        if request.method == "GET":
            url = request.query_params.get("url")
        else:  # POST
            try:
                data = await request.json()
            except Exception:
                return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
            url = data.get("url")
    except Exception:
        return JSONResponse({"error": "Failed to read request"}, status_code=400)

    if not url or not url.startswith(('http://', 'https://')):
        return JSONResponse({"error": "Missing or invalid URL parameter"}, status_code=400)

    destination = await do_bypass(url)
    return {"success": True, "destination": destination, "original": url}

# Add Vercel handler if needed (from earlier fixes)
def handler(event, context=None):
    from mangum import Mangum
    return Mangum(app)(event, context)
