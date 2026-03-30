import httpx
import asyncio
import math
import os
from dotenv import load_dotenv
from db.cache import cache

load_dotenv()

OTX_API_KEY  = os.getenv("OTX_API_KEY")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
HEADERS      = {"X-OTX-API-KEY": OTX_API_KEY}

async def get_ip_indicators(ip: str) -> dict:
    cached = cache.get("otx", ip)
    if cached:
        return cached
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            gen, mal = await asyncio.gather(
                client.get(f"{OTX_BASE_URL}/indicators/IPv4/{ip}/general", headers=HEADERS),
                client.get(f"{OTX_BASE_URL}/indicators/IPv4/{ip}/malware",  headers=HEADERS),
            )
            result = _parse_ip(ip, gen.json(), mal.json())
            cache.set("otx", ip, result)
            return result
        except Exception as e:
            return _err(str(e))

async def get_latest_pulses(limit: int = 20) -> list:
    cached = cache.get("otx", f"pulses:{limit}")
    if cached:
        return cached
    async with httpx.AsyncClient(timeout=20.0) as client:
        try:
            r = await client.get(
                f"{OTX_BASE_URL}/pulses/subscribed",
                headers=HEADERS, params={"limit": limit, "sort": "-created"}
            )
            pulses = _parse_pulses(r.json().get("results", []))
            cache.set("otx", f"pulses:{limit}", pulses)
            return pulses
        except Exception:
            return []

def _parse_ip(ip, general, malware):
    pulse_info  = general.get("pulse_info", {})
    count       = pulse_info.get("count", 0)
    pulses      = pulse_info.get("pulses", [])
    tags, fams  = [], []
    for p in pulses:
        tags.extend(p.get("tags", []))
        fams.extend(p.get("malware_families", []))
    mal_names = list({s.get("label","") for s in malware.get("data",[]) if s.get("label")})
    otx_score = min(math.log(count+1,10)*40, 100) if count else 0.0
    return {
        "source": "otx", "success": True, "ip": ip,
        "pulse_count": count,
        "otx_score": round(otx_score, 2),
        "tags": list(set(tags))[:15],
        "malware_families": list(set(fams+mal_names))[:10],
        "country": general.get("country_name","Unknown"),
    }

def _parse_pulses(pulses):
    return [{
        "id":          p.get("id"),
        "name":        p.get("name"),
        "description": p.get("description","")[:200],
        "tags":        p.get("tags",[])[:5],
        "ioc_count":   p.get("indicator_count",0),
        "created":     p.get("created"),
        "author":      p.get("author",{}).get("username","Unknown"),
    } for p in pulses]

def _err(msg):
    return {"source":"otx","success":False,"error":msg,"otx_score":0.0,"pulse_count":0}
