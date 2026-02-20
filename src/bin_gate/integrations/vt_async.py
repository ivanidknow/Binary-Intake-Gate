# vt_async.py — async VirusTotal lookups for batch (I/O-bound)
from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple
import asyncio
import os
import time

_API_BASE = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT = int(os.getenv("VT_TIMEOUT_SEC", "20"))
# Public API: не более 3 запросов в минуту (жёсткий лимит)
VT_REQUESTS_PER_MINUTE = int(os.getenv("VT_REQUESTS_PER_MINUTE", "3"))
VT_ASYNC_CONCURRENCY = min(int(os.getenv("VT_ASYNC_CONCURRENCY", "1")), VT_REQUESTS_PER_MINUTE)
# Exponential backoff on 429
VT_429_MAX_RETRIES = int(os.getenv("VT_429_MAX_RETRIES", "5"))
VT_429_BASE_DELAY = float(os.getenv("VT_429_BASE_DELAY", "2.0"))
VT_429_MAX_DELAY = float(os.getenv("VT_429_MAX_DELAY", "120.0"))


class _RateLimiter:
    """Не более N запросов в минуту (sliding window)."""
    def __init__(self, max_per_minute: int = 3):
        self._max = max_per_minute
        self._timestamps: List[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            while len(self._timestamps) >= self._max:
                wait = (self._timestamps[0] + 60.0) - now
                if wait > 0:
                    await asyncio.sleep(wait)
                    now = time.monotonic()
                self._timestamps.pop(0)
            self._timestamps.append(now)


_vt_rate_limiter: Optional[_RateLimiter] = None


def _get_rate_limiter() -> _RateLimiter:
    global _vt_rate_limiter
    if _vt_rate_limiter is None:
        _vt_rate_limiter = _RateLimiter(max_per_minute=VT_REQUESTS_PER_MINUTE)
    return _vt_rate_limiter


def _auth_headers(api_key: Optional[str]) -> Dict[str, str]:
    return {"x-apikey": api_key} if api_key else {}


async def _vt_lookup_one(
    client: Any,
    sha256: str,
    api_key: Optional[str],
    timeout_sec: int = DEFAULT_TIMEOUT,
) -> Tuple[str, Optional[Dict[str, Any]], List[str]]:
    """Single async GET /files/{sha256}. Returns (sha256, data_or_None, errors). On 429 uses exponential backoff."""
    errs: List[str] = []
    if not api_key:
        return sha256, None, ["vt_no_api_key"]
    last_err: Optional[str] = None
    for attempt in range(VT_429_MAX_RETRIES):
        try:
            r = await client.get(
                f"{_API_BASE}/files/{sha256}",
                headers=_auth_headers(api_key),
                timeout=timeout_sec,
            )
        except asyncio.TimeoutError:
            return sha256, None, [f"vt_timeout({timeout_sec}s)"]
        except Exception as e:
            return sha256, None, [f"vt_http_error:{e}"]

        if r.status_code == 404:
            return sha256, {"found": False, "sha256": sha256}, errs
        if r.status_code == 429:
            last_err = f"vt_http_status:429"
            delay = min(VT_429_MAX_DELAY, VT_429_BASE_DELAY * (2.0 ** attempt))
            await asyncio.sleep(delay)
            continue
        if r.status_code != 200:
            return sha256, None, [f"vt_http_status:{r.status_code}"]
        break
    else:
        # Исчерпали ретраи по 429 — возвращаем объект для негативного кэша
        if last_err:
            return sha256, {"status": "429", "sha256": sha256}, [last_err]
        return sha256, {"status": "429", "sha256": sha256}, ["vt_http_status:429"]

    try:
        data = r.json() or {}
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        results = attrs.get("last_analysis_results") or {}
        out: Dict[str, Any] = {
            "found": True,
            "sha256": sha256,
            "detections": {
                "stats": stats,
                "engines": [
                    {"engine": k, "category": (v or {}).get("category"), "result": (v or {}).get("result")}
                    for k, v in list(results.items())[:20]
                ],
            },
            "reputation": attrs.get("reputation"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        }
        return sha256, out, errs
    except Exception as e:
        return sha256, None, [f"vt_json_error:{e}"]


async def vt_lookup_batch_async(
    sha256_list: List[str],
    api_key: Optional[str],
    *,
    timeout_sec: int = DEFAULT_TIMEOUT,
    concurrency: int = VT_ASYNC_CONCURRENCY,
    stop_on_429: bool = True,
) -> Dict[str, Optional[Dict[str, Any]]]:
    """
    Fetch VT file report for many hashes. Strict rate limit: не более VT_REQUESTS_PER_MINUTE в минуту.
    If stop_on_429=True (default), при первом же 429 прекращаем запросы и возвращаем только то, что уже получили.
    """
    try:
        import httpx
    except ImportError:
        from .virustotal import vt_lookup_sha256
        result: Dict[str, Optional[Dict[str, Any]]] = {}
        for i, sha in enumerate(sha256_list):
            if i > 0:
                await asyncio.sleep(20)
            summary, errs = vt_lookup_sha256(sha, api_key, timeout_sec=timeout_sec, min_interval_sec=20)
            if summary and summary.get("found"):
                result[sha] = {
                    "sha256": sha,
                    "found": True,
                    "detections": summary.get("detections", summary.get("stats", {})),
                    "reputation": summary.get("reputation"),
                    "permalink": f"https://www.virustotal.com/gui/file/{sha}",
                }
            else:
                result[sha] = None
            if stop_on_429 and errs and any("429" in str(e) for e in errs):
                break
        return result

    results: Dict[str, Optional[Dict[str, Any]]] = {}
    limiter = _get_rate_limiter()

    if stop_on_429:
        async with httpx.AsyncClient() as client:
            for sha in sha256_list:
                await limiter.acquire()
                _, data, _ = await _vt_lookup_one(client, sha, api_key, timeout_sec)
                results[sha] = data
                if isinstance(data, dict) and data.get("status") == "429":
                    break
        return results

    sem = asyncio.Semaphore(concurrency)

    async def bounded_lookup(sha: str) -> None:
        async with sem:
            await limiter.acquire()
            async with httpx.AsyncClient() as client:
                _, data, _ = await _vt_lookup_one(client, sha, api_key, timeout_sec)
                results[sha] = data

    await asyncio.gather(*[bounded_lookup(sha) for sha in sha256_list])
    return results


def vt_lookup_batch_sync(
    sha256_list: List[str],
    api_key: Optional[str],
    *,
    timeout_sec: int = DEFAULT_TIMEOUT,
    stop_on_429: bool = True,
) -> Dict[str, Optional[Dict[str, Any]]]:
    """Synchronous wrapper: run async batch in event loop. По умолчанию при 429 прекращаем запросы."""
    if not sha256_list:
        return {}
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            vt_lookup_batch_async(
                sha256_list, api_key, timeout_sec=timeout_sec, stop_on_429=stop_on_429
            )
        )
    finally:
        loop.close()
