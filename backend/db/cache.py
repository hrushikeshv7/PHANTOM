import redis
import json
import os
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

TTL_CONFIG = {
    "virustotal": 3600,
    "shodan":     86400,
    "abuseipdb":  3600,
    "otx":        1800,
    "ai_summary": 7200,
}

class CacheManager:
    def __init__(self):
        self.client = redis.from_url(REDIS_URL, decode_responses=True)

    def _make_key(self, source: str, ioc: str) -> str:
        return f"phantom:{source}:{ioc.lower().strip()}"

    def get(self, source: str, ioc: str):
        key = self._make_key(source, ioc)
        cached = self.client.get(key)
        if cached:
            return json.loads(cached)
        return None

    def set(self, source: str, ioc: str, data: dict) -> bool:
        key = self._make_key(source, ioc)
        ttl = TTL_CONFIG.get(source, 3600)
        return self.client.setex(key, ttl, json.dumps(data))

    def delete(self, source: str, ioc: str) -> bool:
        return bool(self.client.delete(self._make_key(source, ioc)))

    def is_cached(self, source: str, ioc: str) -> bool:
        return bool(self.client.exists(self._make_key(source, ioc)))

    def health_check(self) -> bool:
        try:
            return self.client.ping()
        except Exception:
            return False

cache = CacheManager()
