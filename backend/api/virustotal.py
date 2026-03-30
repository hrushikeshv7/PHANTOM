import httpx
import base64
import os
from dotenv import load_dotenv
from db.cache import cache

load_dotenv()

VT_API_KEY  = os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS     = {"x-apikey": VT_API_KEY, "Accept": "application/json"}

async def analyze_ip(ip: str) -> dict:
    cached = cache.get("virustotal", ip)
    if cached:
        return cached
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            r = await client.get(f"{VT_BASE_URL}/ip_addresses/{ip}", headers=HEADERS)
            r.raise_for_status()
            result = _parse_ip(r.json())
            cache.set("virustotal", ip, result)
            return result
        except Exception as e:
            return _err(str(e))

async def analyze_url(url: str) -> dict:
    cached = cache.get("virustotal", url)
    if cached:
        return cached
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            r = await client.get(f"{VT_BASE_URL}/urls/{url_id}", headers=HEADERS)
            r.raise_for_status()
            result = _parse_url(r.json())
            cache.set("virustotal", url, result)
            return result
        except Exception as e:
            return _err(str(e))

async def analyze_hash(h: str) -> dict:
    cached = cache.get("virustotal", h)
    if cached:
        return cached
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            r = await client.get(f"{VT_BASE_URL}/files/{h}", headers=HEADERS)
            r.raise_for_status()
            result = _parse_file(r.json())
            cache.set("virustotal", h, result)
            return result
        except Exception as e:
            return _err(str(e))

def _parse_ip(data):
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    mal   = stats.get("malicious", 0)
    total = sum(stats.values())
    return {
        "source": "virustotal", "success": True, "ioc_type": "ip",
        "malicious": mal, "total_engines": total,
        "vt_score": round((mal/total)*100, 2) if total else 0.0,
        "categories": list(attrs.get("categories", {}).values()),
        "tags": attrs.get("tags", []),
        "country": attrs.get("country", "Unknown"),
        "org": attrs.get("as_owner", "Unknown"),
        "raw_label": _label(mal, total),
    }

def _parse_url(data):
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    mal   = stats.get("malicious", 0)
    total = sum(stats.values())
    return {
        "source": "virustotal", "success": True, "ioc_type": "url",
        "malicious": mal, "total_engines": total,
        "vt_score": round((mal/total)*100, 2) if total else 0.0,
        "tags": attrs.get("tags", []),
        "raw_label": _label(mal, total),
    }

def _parse_file(data):
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    mal   = stats.get("malicious", 0)
    total = sum(stats.values())
    return {
        "source": "virustotal", "success": True, "ioc_type": "hash",
        "malicious": mal, "total_engines": total,
        "vt_score": round((mal/total)*100, 2) if total else 0.0,
        "file_name": attrs.get("meaningful_name", "Unknown"),
        "raw_label": _label(mal, total),
    }

def _label(mal, total):
    if not total: return "Unknown"
    r = mal/total
    if r >= 0.5: return "Highly Malicious"
    if r >= 0.2: return "Suspicious"
    if r > 0:    return "Low Threat"
    return "Clean"

def _err(msg):
    return {"source": "virustotal", "success": False, "error": msg, "vt_score": 0.0}
