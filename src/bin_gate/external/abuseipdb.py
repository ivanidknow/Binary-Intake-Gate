# abuseipdb.py — проверка репутации IP через AbuseIPDB API (опционально AlienVault)
from __future__ import annotations
import os
import time
from typing import Dict, Any, Optional

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_TIMEOUT = int(os.getenv("BIN_GATE_ABUSEIPDB_TIMEOUT", "10"))
# Кэш: ip -> (result, timestamp), TTL 1 час
_cache: Dict[str, tuple] = {}
_CACHE_TTL = 3600


def check_ip_abuseipdb(ip: str, timeout_sec: int = ABUSEIPDB_TIMEOUT) -> Dict[str, Any]:
    """
    Проверка IP через AbuseIPDB API. Если адрес в C2/злоупотреблениях — confidenceScore и usageType.
    Возвращает: { "checked": True, "c2_detected": bool, "confidence_score": 0-100, "usage_type": str, "error": str? }
    """
    out: Dict[str, Any] = {
        "checked": False,
        "c2_detected": False,
        "confidence_score": 0,
        "usage_type": None,
        "error": None,
    }
    if not ABUSEIPDB_API_KEY or not ip or not ip.strip():
        return out
    ip = ip.strip()
    now = time.time()
    if ip in _cache:
        cached, ts = _cache[ip]
        if now - ts < _CACHE_TTL:
            return dict(cached)
    try:
        import urllib.request
        import urllib.error
        import json
        import ssl
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(
            url,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            method="GET",
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout_sec, context=ctx) as resp:
            data = json.loads(resp.read().decode())
        out["checked"] = True
        out["confidence_score"] = int(data.get("data", {}).get("abuseConfidenceScore", 0))
        out["usage_type"] = (data.get("data", {}).get("usageType") or "").strip() or None
        # C2/злоупотребление: высокий abuseConfidenceScore (75+ считаем C2-активностью)
        if out["confidence_score"] >= 75:
            out["c2_detected"] = True
        _cache[ip] = (dict(out), now)
        return out
    except Exception as e:
        out["error"] = str(e)[:200]
        return out
