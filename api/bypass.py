# api/bypass.py
import json
import httpx
import re
from urllib.parse import urlparse
import time
import base64

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

            # ——— LINKVERTISE (2025 API method from jonathanlin0/Linkvertise-Bypass-Bot) ———
            if "linkvertise" in domain:
                # Extract middle part (e.g., '6012345/example')
                path = urlparse(url).path.strip('/')
                if '?' in path:
                    path = path.split('?')[0]
                if path:
                    # Step 1: Get static link ID
                    static_url = f"https://publisher.linkvertise.com/api/v1/redirect/link/static/{path}"
                    static_r = await client.get(static_url)
                    static_r.raise_for_status()
                    data = static_r.json()
                    link_id = data.get('data', {}).get('link', {}).get('id')
                    if link_id:
                        # Step 2: Create serial payload
                        payload = {
                            "timestamp": int(time.time() * 1000),
                            "random": "6548307",
                            "link_id": link_id
                        }
                        serial = base64.b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8').rstrip('=')
                        # Step 3: Get target
                        target_url = f"https://publisher.linkvertise.com/api/v1/redirect/link/{path}/target?serial={serial}"
                        target_r = await client.get(target_url)
                        target_r.raise_for_status()
                        target_data = target_r.json()
                        return target_data.get('data', {}).get('link', {}).get('url') or url
                # Fallback regex if API fails
                o_match = re.search(r'o:"(https?://[^"]+)', r.text)
                if o_match:
                    return o_match.group(1)

            # ——— LOOTLINKS / LOOTDEST / LOOTLABS / ADM AVEN ———
            if any(x in domain for x in ["loot-link", "lootlinks", "lootdest", "lootlabs", "admaven"]):
                cleaned = r.text.replace("\\", "")
                match = re.search(r'"link":"(https?://[^"]+)', cleaned)
                if match:
                    return match.group(1)

            # ——— WORK.INK / BOOST.INK / MBOOST.ME / CUTY.IO ———
            if any(x in domain for x in ["work.ink", "boost.ink", "mboost.me", "cuty.io", "cety.io"]):
                match = re.search(r'window\.location\s*=\s*["\']([^"\']+)', r.text)
                if match:
                    return match.group(1)

            # ——— REKONISE ———
            if "rekonise" in domain:
                slug = url.split("/")[-1]
                if slug:
                    api_url = f"https://api.rekonise.com/unlock/{slug}"
                    api_r = await client.get(api_url)
                    if api_r.status_code == 200:
                        return api_r.json().get("url", url)

            # ——— SUB2UNLOCK / SUB2GET / SOCIAL-UNLOCK ———
            if any(x in domain for x in ["sub2unlock", "sub2get", "social-unlock"]):
                match = re.search(r'const target\s*=\s*["\']([^"\']+)', r.text)
                if match:
                    return match.group(1)

            # ——— ADF.LY / SHORTE.ST / FC.LC / OUO.IO ———
            if any(x in domain for x in ["adf.ly", "shorte.st", "fc.lc", "ouo.io"]):
                ysmm = re.search(r"ysmm\s*=\s*'([^']+)", r.text)
                if ysmm:
                    rot13 = codecs.decode(ysmm.group(1), 'rot13')
                    decoded = base64.b64decode(rot13.encode()).decode()
                    final = re.search(r'"(https?://[^"]+)', decoded)
                    if final:
                        return final.group(1)

            # Fallback redirect follow
            final_r = await client.get(url, follow_redirects=True)
            return str(final_r.url)

        except Exception:
            return url

# Vercel handler (plain Python, no Mangum/FastAPI)
def handler(event, context):
    try:
        # Parse request
        method = event['httpMethod']
        query = event.get('queryStringParameters', {})
        body = event.get('body', '')
        if body:
            body = json.loads(body) if event.get('isBase64Encoded', False) else body

        url = query.get('url') if method == 'GET' else (body.get('url') if isinstance(body, dict) else None)
        if not url:
            return {
                'statusCode': 400,
                'body': json.dumps({"error": "Missing url"}),
                'headers': {'Content-Type': 'application/json'}
            }

        # Run bypass (sync wrapper for async)
        import asyncio
        destination = asyncio.run(do_bypass(url))

        return {
            'statusCode': 200,
            'body': json.dumps({"success": True, "destination": destination}),
            'headers': {'Content-Type': 'application/json'}
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({"error": str(e)}),
            'headers': {'Content-Type': 'application/json'}
        }
