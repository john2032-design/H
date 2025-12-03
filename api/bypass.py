# api/bypass.py
from mangum import Mangum
from fastapi import FastAPI, Request
import httpx
import re
from urllib.parse import urlparse

app = FastAPI()

async def do_bypass(url: str) -> str:
    domain = urlparse(url).netloc.lower()
    headers = {"User-Agent": "Mozilla/5.0"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            # Linkvertise
            if "linkvertise" in domain:
                r = await client.get(url, headers=headers)
                m = re.search(r'location\.href="([^"]+)', r.text)
                if m: return m.group(1)

            # Loot, Work.ink, etc.
            if any(x in domain for x in ["loot", "work.ink", "boost.ink"]):
                r = await client.get(url, headers={**headers, "Referer": url})
                m = re.search(r'window\.location="([^"]+)', r.text)
                if m: return m.group(1)

            # Fallback
            r = await client.get(url, headers=headers, follow_redirects=True)
            return str(r.url)
        except:
            return url

@app.get("/")
async def home():
    return {"message": "Your bypass API is working!"}

@app.get("/bypass")
@app.post("/bypass")
async def bypass(request: Request):
    url = (request.query_params.get("url") or 
           (await request.json()).get("url") if request.method == "POST" else None)
    if not url:
        return {"error": "Missing url parameter"}
    return {"success": True, "destination": await do_bypass(url)}

# This line is REQUIRED for Vercel
def handler(event, context=None):
    return Mangum(app, lifespan="off")(event, context)
