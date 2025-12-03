# api/bypass.py
from fastapi import Request, Response
import httpx
import re
from urllib.parse import urlparse

async def bypass_link(raw_url: str) -> str:
    url = raw_url.strip()
    domain = urlparse(url).netloc.lower().replace("www.", "")

    async with httpx.AsyncClient(timeout=20.0, follow_redirects=False) as client:

        # Linkvertise
        if "linkvertise" in domain:
            r = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            m = re.search(r'location\.href\s*=\s*"([^"]+)', r.text)
            if m: return m.group(1)

        # Loot-Link / Lootlabs / Lootdest
        if any(x in domain for x in ["loot-link", "lootlinks", "lootdest", "lootlabs"]):
            r = await client.get(url)
            m = re.search(r'"link":"(https?://[^"]+)', r.text.replace("\\", ""))
            if m: return m.group(1)

        # Work.ink / Boost.ink / Mboost
        if any(x in domain for x in ["work.ink", "boost.ink", "mboost.me"]):
            r = await client.get(url, headers={"Referer": url})
            m = re.search(r'window\.location\s*=\s*"([^"]+)', r.text)
            if m: return m.group(1)

        # Rekonise
        if "rekonise.com" in domain:
            slug = url.split("/")[-1]
            r = await client.get(f"https://api.rekonise.com/unlock/{slug}")
            return r.json().get("url", url)

        # Adf.ly / Shorte.st / FC.LC
        if any(x in domain for x in ["adf.ly", "shorte.st", "fc.lc"]):
            r = await client.get(url)
            m = re.search(r"ysmm\s*=\s*'([^']+)", r.text)
            if m:
                import base64, codecs
                b64 = codecs.decode(m.group(1), 'rot13')
                link = re.search(r'"(https?://[^"]+)', base64.b64decode(b64).decode())
                if link: return link.group(1)

        # Fallback: just follow redirects
        r = await client.get(url, follow_redirects=True)
        return str(r.url)

# Vercel entry point
def handler(request: Request):
    from fastapi import FastAPI
    app = FastAPI()

    @app.post("/bypass")
    @app.get("/bypass")
    async def bypass_endpoint(url: str = None, request: Request = None):
        if not url:
            body = await request.json()
            url = body.get("url") or body.get("link")
        if not url:
            return Response(content='{"error": "Missing url"}', status_code=400)
        try:
            direct = await bypass_link(url)
            return {"success": true, "destination": direct}
        except:
            return {"success": false, "destination": url}

    return app(request.scope, request.receive, request._send)
