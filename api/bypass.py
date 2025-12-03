# api/bypass.py
import json
import httpx
import re
from urllib.parse import urlparse
import time
import base64
import codecs
import traceback

def do_bypass(url: str) -> str:
    domain = urlparse(url).netloc.lower().replace("www.", "")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        # don't set Accept-Encoding if httpx should handle decompression automatically
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    # synchronous client for serverless handler
    with httpx.Client(timeout=45.0, follow_redirects=False, headers=headers) as client:
        try:
            r = client.get(url)
            r.raise_for_status()

            # ——— LINKVERTISE (API approach) ———
            if "linkvertise" in domain:
                path = urlparse(url).path.strip('/')
                if '?' in path:
                    path = path.split('?')[0]
                if path:
                    static_url = f"https://publisher.linkvertise.com/api/v1/redirect/link/static/{path}"
                    static_r = client.get(static_url)
                    static_r.raise_for_status()
                    data = static_r.json()
                    link_id = data.get('data', {}).get('link', {}).get('id')
                    if link_id:
                        payload = {
                            "timestamp": int(time.time() * 1000),
                            "random": "6548307",
                            "link_id": link_id
                        }
                        serial = base64.b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8').rstrip('=')
                        target_url = f"https://publisher.linkvertise.com/api/v1/redirect/link/{path}/target?serial={serial}"
                        target_r = client.get(target_url)
                        target_r.raise_for_status()
                        target_data = target_r.json()
                        return target_data.get('data', {}).get('link', {}).get('url') or url
                # fallback regex
                o_match = re.search(r'o:"(https?://[^"]+)', r.text)
                if o_match:
                    return o_match.group(1)

            # ——— LOOT / ADMAVEN ———
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
                    api_r = client.get(api_url)
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
                    try:
                        rot13 = codecs.decode(ysmm.group(1), 'rot_13')
                    except Exception:
                        rot13 = ysmm.group(1)
                    try:
                        decoded = base64.b64decode(rot13.encode()).decode()
                        final = re.search(r'"(https?://[^"]+)', decoded)
                        if final:
                            return final.group(1)
                    except Exception:
                        pass

            # fallback: follow redirects synchronously
            final_r = client.get(url, follow_redirects=True)
            return str(final_r.url)

        except Exception:
            # let logs show a full traceback for debugging
            traceback.print_exc()
            return url

# Vercel-style handler (synchronous)
def handler(event, context):
    try:
        method = event.get('httpMethod', 'GET').upper()
        query = event.get('queryStringParameters') or {}
        body_raw = event.get('body', '')
        is_b64 = event.get('isBase64Encoded', False)

        body = {}
        if body_raw:
            try:
                if is_b64:
                    decoded = base64.b64decode(body_raw).decode('utf-8')
                    body = json.loads(decoded)
                else:
                    # body_raw may be a JSON string
                    body = json.loads(body_raw)
            except Exception:
                # not JSON — keep body as empty dict
                body = {}

        url = None
        if method == 'GET':
            url = query.get('url')
        else:
            if isinstance(body, dict):
                url = body.get('url')

        if not url:
            return {
                'statusCode': 400,
                'body': json.dumps({"error": "Missing url"}),
                'headers': {'Content-Type': 'application/json'}
            }

        destination = do_bypass(url)

        return {
            'statusCode': 200,
            'body': json.dumps({"success": True, "destination": destination}),
            'headers': {'Content-Type': 'application/json'}
        }

    except Exception as e:
        traceback.print_exc()
        # do not leak stack to client; give a friendly message
        return {
            'statusCode': 500,
            'body': json.dumps({"error": "Internal server error — check function logs"}),
            'headers': {'Content-Type': 'application/json'}
        }
