import json
import re
from urllib.parse import urlparse
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

async def bypass_link(url: str) -> str:
    """Core bypass logic - unchanged but with better error handling."""
    try:
        url = url.strip()
        domain = urlparse(url).netloc.lower().replace("www.", "")

        async with httpx.AsyncClient(timeout=20.0, follow_redirects=False) as client:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

            # Linkvertise
            if "linkvertise" in domain:
                r = await client.get(url, headers=headers)
                m = re.search(r'location\.href\s*=\s*"([^"]+)', r.text)
                if m: return m.group(1)

            # Loot-Link family
            if any(x in domain for x in ["loot-link", "lootlinks", "lootdest", "lootlabs"]):
                r = await client.get(url, headers=headers)
                m = re.search(r'"link":"(https?://[^"]+)', r.text.replace("\\", ""))
                if m: return m.group(1)

            # Work.ink / Boost.ink / Mboost
            if any(x in domain for x in ["work.ink", "boost.ink", "mboost.me"]):
                r = await client.get(url, headers={**headers, "Referer": url})
                m = re.search(r'window\.location\s*=\s*"([^"]+)', r.text)
                if m: return m.group(1)

            # Rekonise
            if "rekonise.com" in domain:
                slug = url.split("/")[-1]
                r = await client.get(f"https://api.rekonise.com/unlock/{slug}", headers=headers)
                data = r.json()
                return data.get("url") or url

            # Adf.ly / Shorte.st / FC.LC
            if any(x in domain for x in ["adf.ly", "shorte.st", "fc.lc"]):
                r = await client.get(url, headers=headers)
                m = re.search(r"ysmm\s*=\s*'([^']+)", r.text)
                if m:
                    import base64
                    import codecs
                    rot13 = codecs.decode(m.group(1), 'rot13')
                    decoded = base64.b64decode(rot13.encode()).decode()
                    link = re.search(r'"(https?://[^"]+)', decoded)
                    if link: return link.group(1)

            # Fallback: Follow redirects
            r = await client.get(url, headers=headers, follow_redirects=True)
            return str(r.url)

    except Exception as e:
        print(f"Bypass error: {e}")  # Logs to Vercel
        return url  # Graceful fallback

@app.get("/")
async def root():
    return {"message": "YourBypass is live! Use /bypass?url=shortlink"}

@app.post("/bypass")
@app.get("/bypass")
async def bypass(request: Request):
    try:
        if request.method == "POST":
            body = await request.json()
            url = body.get("url") or body.get("link")
        else:  # GET
            url = request.query_params.get("url")
        
        if not url:
            return JSONResponse({"error": "Missing 'url' param"}, status_code=400)
        
        direct = await bypass_link(url)
        return {"success": True, "destination": direct}
    
    except Exception as e:
        print(f"Endpoint error: {e}")
        return JSONResponse({"error": "Internal error"}, status_code=500)

# Vercel serverless handler (required for Python)
def handler(request):
    from mangum import Mangum  # Vercel's ASGI adapter
    return Mangum(app)(request)
