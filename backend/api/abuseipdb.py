import httpx
import os
from dotenv import load_dotenv
from db.cache import cache

load_dotenv()

ABUSE_API_KEY  = os.getenv("ABUSEIPDB_API_KEY")
ABUSE_BASE_URL = "https://api.abuseipdb.com/api/v2"
HEADERS        = {"Key": ABUSE_API_KEY, "Accept": "application/json"}

CATEGORIES = {
    3:"Fraud",4:"DDoS",7:"Phishing",9:"Open Proxy",
    10:"Web Spam",11:"Email Spam",14:"Port Scan",
    15:"Hacking",16:"SQL Injection",18:"Brute Force",
    19:"Bad Bot",20:"Exploited Host",21:"Web App Attack",
    22:"SSH Abuse",23:"IoT Targeted",
}

async def check_ip(ip: str) -> dict:
    cached = cache.get("abuseipdb", ip)
    if cached:
        return cached
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            r = await client.get(
                f"{ABUSE_BASE_URL}/check", headers=HEADERS,
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
            )
            r.raise_for_status()
            result = _parse(r.json())
            cache.set("abuseipdb", ip, result)
            return result
        except Exception as e:
            return _err(str(e))

def _parse(data):
    d    = data.get("data", {})
    cats = set()
    for rep in d.get("reports", []):
        cats.update(rep.get("categories", []))
    return {
        "source": "abuseipdb", "success": True,
        "abuse_score":    float(d.get("abuseConfidenceScore", 0)),
        "is_whitelisted": d.get("isWhitelisted", False),
        "isp":            d.get("isp", "Unknown"),
        "usage_type":     d.get("usageType", "Unknown"),
        "country":        d.get("countryName", "Unknown"),
        "country_code":   d.get("countryCode", "??"),
        "total_reports":  d.get("totalReports", 0),
        "last_reported":  d.get("lastReportedAt"),
        "categories":     [CATEGORIES.get(c, f"Cat {c}") for c in cats],
    }

def _err(msg):
    return {"source":"abuseipdb","success":False,"error":msg,"abuse_score":0.0}
