import httpx
import os
from dotenv import load_dotenv
from db.cache import cache

load_dotenv()

SHODAN_API_KEY  = os.getenv("SHODAN_API_KEY")
SHODAN_BASE_URL = "https://api.shodan.io"

CRITICAL_PORTS = {22:"SSH",23:"Telnet",445:"SMB",3389:"RDP",
                  1433:"MSSQL",3306:"MySQL",5432:"PostgreSQL",
                  27017:"MongoDB",6379:"Redis",9200:"Elasticsearch"}

async def get_host_info(ip: str) -> dict:
    cached = cache.get("shodan", ip)
    if cached:
        return cached
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            r = await client.get(
                f"{SHODAN_BASE_URL}/shodan/host/{ip}",
                params={"key": SHODAN_API_KEY}
            )
            r.raise_for_status()
            result = _parse(r.json())
            cache.set("shodan", ip, result)
            return result
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return {"source":"shodan","success":True,"not_indexed":True,
                        "open_ports":[],"cves":[],"shodan_score":0.0}
            return _err(str(e))
        except Exception as e:
            return _err(str(e))

def _parse(data):
    ports        = data.get("ports", [])
    cves         = list({c for item in data.get("data",[]) for c in item.get("vulns",{}).keys()})
    critical     = [p for p in ports if p in CRITICAL_PORTS]
    shodan_score = min(len(critical)*15 + len(cves)*10, 100)
    services     = [
        f"{i.get('product','')} {i.get('version','')} (port {i.get('port')})".strip()
        for i in data.get("data",[]) if i.get("product")
    ][:10]
    return {
        "source": "shodan", "success": True,
        "open_ports": ports,
        "critical_ports": {str(p): CRITICAL_PORTS[p] for p in critical},
        "services": services, "cves": cves, "cve_count": len(cves),
        "os": data.get("os","Unknown"),
        "country": data.get("country_name","Unknown"),
        "latitude": data.get("latitude"), "longitude": data.get("longitude"),
        "org": data.get("org","Unknown"), "hostnames": data.get("hostnames",[]),
        "shodan_score": shodan_score,
    }

def _err(msg):
    return {"source":"shodan","success":False,"error":msg,"shodan_score":0.0}
