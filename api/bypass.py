# api/bypass.py
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
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
                if m:
                    return m.group(1)

            # Loot, Work.ink, boost.ink
            if any(x in domain for x in ["loot", "work.ink", "boost.ink"]):
                r = await client.get(url, headers={**headers, "Referer": url})
                m = re.search(r'window\.location="([^"]+)', r.text)
                if m:
                    return m.group(1)

            # Fallback: follow redirects
            r = await client.get(url, headers=headers, follow_redirects=True)
            return str(r.url)
        except Exception:
            # on any network/parsing error, return original url
            return url

@app.get("/", include_in_schema=False)
async def home():
    return {"message": "Your bypass API is working!"}

@app.api_route("/bypass", methods=["GET", "POST"])
async def bypass(request: Request):
    try:
        if request.method == "GET":
            url = request.query_params.get("url")
        else:  # POST
            # be defensive: body might not be JSON
            try:
                data = await request.json()
            except Exception:
                return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
            url = data.get("url")
    except Exception:
        return JSONResponse({"error": "Failed to read request"}, status_code=400)

    if not url:
        return JSONResponse({"error": "Missing url parameter"}, status_code=400)

    destination = await do_bypass(url)
    return {"success": True, "destination": destination}
