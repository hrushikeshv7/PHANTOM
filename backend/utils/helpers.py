"""
PHANTØM — Helper Utilities
IP geolocation fallback using ip-api.com (free, no key needed)
"""

import httpx

async def get_ip_geo(ip: str) -> dict:
    """
    Fetch geolocation for an IP using ip-api.com.
    Used as fallback when Shodan doesn't return coordinates.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,org,as")
            data = r.json()
            if data.get("status") == "success":
                return {
                    "latitude":     data.get("lat"),
                    "longitude":    data.get("lon"),
                    "country":      data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "??"),
                    "city":         data.get("city", "Unknown"),
                    "org":          data.get("org", "Unknown"),
                    "asn":          data.get("as", "Unknown"),
                }
    except Exception:
        pass
    return {"latitude": None, "longitude": None, "country": "Unknown"}
