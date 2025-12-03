import json
import re
from urllib.parse import urlparse, parse_qs
import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse

async def bypass(url: str) -> str:
    domain = urlparse(url).netloc.lower()

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

        # Linkvertise
        if "linkvertise" in domain:
            r = await client.get(url, headers=headers)
            m = re.search(r'location\.href\s*=\s*"([^"]+)', r.text)
            if m: return m.group(1)

        # Lootlinks / Work.ink / Boost.ink etc.
        if any(x in domain for x in ["loot", "work.ink", "boost.ink", "mboost"]):
            r = await client.get(url, headers={**headers, "Referer": url})
            m = re.search(r'window\.location\s*=\s*"([^"]+)', r.text)
            if m: return m.group(1)

        # Rekonise
        if "rekonise.com" in domain:
            slug = url.split("/")[-1]
            r = await client.get(f"https://api.rekonise.com/unlock/{slug}")
            return r.json().get("url", url)

        # Adf.ly family
        if any(x in domain for x in ["adf.ly", "shorte.st", "fc.lc"]):
            r = await client.get(url, headers=headers)
            m = re.search(r"ysmm\s*=\s*'([^']+)", r.text)
            if m:
                import base64, codecs
                link = base64.b64decode(codecs.decode(m.group(1), 'rot13').encode()).decode()
                m2 = re.search(r'"(https?://[^"]+)', link)
                if m2: return m2.group(1)

        # Fallback: just follow redirects
        r = await client.get(url, headers=headers, follow_redirects=True)
        return str(r.url)

# ←←← THIS IS THE ONLY HANDLER VERCEL NEEDS ←←←
def handler(event: dict, context=None):
    # Vercel sends AWS-style event, we convert to FastAPI
    from mangum import Mangum
    from fastapi import FastAPI

    app = FastAPI()

    @app.get("/")
    async def root():
        return {"message": "Your bypass.vip clone is working!"}

    @app.get("/bypass")
    @app.post("/bypass")
    async def main(request: Request):
        url = None
        if request.method == "GET":
            url = request.query_params.get("url")
        else:
            body = await request.json()
            url = body.get("url") or body.get("link")

        if not url:
            return JSONResponse({"error": "Missing url"}, status_code=400)

        try:
            dest = await bypass(url)
            return {"success": True, "destination": dest}
        except:
            return {"success": False, "destination": url}

    # Mangum makes it work on Vercel
    return Mangum(app, lifespan="off")(event, context)
