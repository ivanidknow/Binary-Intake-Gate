# vt_full.py
from __future__ import annotations
from typing import Dict, Any, List, Tuple, Optional
import os, time, requests

_API_BASE = "https://www.virustotal.com/api/v3"

# Быстрый режим по умолчанию: берём только /files/{sha256}
FAST_MODE = os.getenv("VT_FULL_FAST", "1") == "1"
# Ультра-быстрый режим: отключает любой троттлинг внутри этого модуля
ULTRA_FAST = os.getenv("VT_ULTRA_FAST", "0") == "1"

DEFAULT_TIMEOUT = int(os.getenv("VT_TIMEOUT_SEC", "15"))
DEFAULT_MIN_INTERVAL = float(os.getenv("VT_MIN_INTERVAL", "6.0"))
MAX_ENGINES = int(os.getenv("VT_FULL_MAX_ENGINES", "20"))

_last_ts: Optional[float] = None
_min_interval: float = DEFAULT_MIN_INTERVAL

def _throttle():
    global _last_ts
    if ULTRA_FAST:
        _last_ts = time.time()
        return
    now = time.time()
    if _last_ts is None:
        _last_ts = now
        return
    delta = now - _last_ts
    if delta < _min_interval:
        time.sleep(_min_interval - delta)
    _last_ts = time.time()

def _auth_hdr(api_key: Optional[str]) -> Dict[str, str]:
    return {"x-apikey": api_key} if api_key else {}

def vt_fetch_full_metrics(
    sha256: str,
    api_key: Optional[str],
    *,
    timeout_sec: int = DEFAULT_TIMEOUT,
    min_interval_sec: Optional[float] = None,
    include_relationships: Optional[List[str]] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Ультра-быстрый сбор: один запрос /files/{sha256}, без behaviours/relations/comments.
    Совместим по сигнатуре с прежним вызовом из cli.py.
    """
    errs: List[str] = []
    out: Dict[str, Any] = {
        "sha256": sha256,
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        "detections": {},
    }

    # Если из CLI пришёл min_interval_sec — примем, но в ULTRA_FAST троттлинг всё равно отключён
    global _min_interval
    if min_interval_sec is not None:
        try:
            _min_interval = float(min_interval_sec)
        except Exception:
            _min_interval = DEFAULT_MIN_INTERVAL

    try:
        _throttle()
        r = requests.get(f"{_API_BASE}/files/{sha256}", headers=_auth_hdr(api_key), timeout=timeout_sec)
    except Exception as e:
        return out, [f"vt_core_error:{e}"]

    if r.status_code != 200:
        return out, [f"vt_http_status:{r.status_code}"]

    try:
        data = (r.json() or {}).get("data", {}) or {}
        attrs = data.get("attributes", {}) or {}
        out["detections"]["stats"] = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {}) or {}
        engines = []
        for eng, res in list(results.items())[:MAX_ENGINES]:
            engines.append({
                "engine": eng,
                "category": res.get("category"),
                "result": (res.get("result") or "")[:200],
            })
        out["detections"]["engines"] = engines
        out["detections"]["reputation"] = attrs.get("reputation")
        out["detections"]["threat_label"] = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
        out["meaningful_name"] = attrs.get("meaningful_name") or (attrs.get("names") or [None])[0]
        out["size"] = attrs.get("size")
        out["type_extension"] = attrs.get("type_extension")
        out["first_submission_date"] = attrs.get("first_submission_date")
        out["last_submission_date"] = attrs.get("last_submission_date")
    except Exception as e:
        errs.append(f"vt_json_error:{e}")

    # FAST_MODE всегда True — расширения не тянем
    return out, errs
