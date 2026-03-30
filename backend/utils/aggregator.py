"""
PHANTØM — Async Threat Aggregator with Geo Fallback
"""

import asyncio
from api import virustotal, shodan, abuseipdb, otx
from utils.helpers import get_ip_geo


async def aggregate_threat_intel(ioc: str, ioc_type: str = "ip") -> dict:
    if ioc_type == "ip":
        results = await asyncio.gather(
            virustotal.analyze_ip(ioc),
            shodan.get_host_info(ioc),
            abuseipdb.check_ip(ioc),
            otx.get_ip_indicators(ioc),
            return_exceptions=True
        )
        vt, sh, ab, ox = results

        # ── Geo fallback ──────────────────────────────────────
        # If Shodan didn't return coordinates, use ip-api.com
        if not isinstance(sh, Exception):
            if not sh.get("latitude") or not sh.get("longitude"):
                geo = await get_ip_geo(ioc)
                sh["latitude"]  = geo.get("latitude")
                sh["longitude"] = geo.get("longitude")
                if sh.get("country") in (None, "Unknown"):
                    sh["country"] = geo.get("country", "Unknown")

    elif ioc_type == "domain":
        results = await asyncio.gather(
            virustotal.analyze_url(ioc),
            abuseipdb.check_ip(ioc),
            otx.get_ip_indicators(ioc),
            return_exceptions=True
        )
        vt, ab, ox = results
        sh = {"source": "shodan", "success": False, "shodan_score": 0.0}

    else:
        vt = await virustotal.analyze_hash(ioc)
        sh = ab = ox = {
            "success": False,
            "shodan_score": 0.0,
            "abuse_score":  0.0,
            "otx_score":    0.0,
        }

    def safe(r, fallback):
        return r if not isinstance(r, Exception) else fallback

    return {
        "ioc":       ioc,
        "ioc_type":  ioc_type,
        "virustotal": safe(vt, {"source": "virustotal", "success": False, "vt_score": 0.0}),
        "shodan":     safe(sh, {"source": "shodan",     "success": False, "shodan_score": 0.0}),
        "abuseipdb":  safe(ab, {"source": "abuseipdb",  "success": False, "abuse_score": 0.0}),
        "otx":        safe(ox, {"source": "otx",        "success": False, "otx_score": 0.0}),
    }
