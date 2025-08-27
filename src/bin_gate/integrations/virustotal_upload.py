from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import os, time, requests

VT_API = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT = int(os.getenv("VT_TIMEOUT_SEC", "30"))
DEFAULT_MIN_INTERVAL = float(os.getenv("VT_MIN_INTERVAL", "20.0"))  # free API
DEFAULT_POLL_INTERVAL = int(os.getenv("VT_POLL_SEC", "15"))
DEFAULT_POLL_TIMEOUT = int(os.getenv("VT_POLL_TIMEOUT", "300"))     # 5 min

_last_call: Optional[float] = None
def _throttle(min_interval: float) -> None:
    global _last_call
    now = time.time()
    if _last_call is None:
        _last_call = now; return
    delta = now - _last_call
    if delta < min_interval:
        time.sleep(min_interval - delta)
    _last_call = time.time()

def _key(k: Optional[str]) -> Optional[str]:
    return k or os.getenv("VT_API_KEY")

def upload_file(path: Path, *, key: Optional[str]=None, timeout: int=DEFAULT_TIMEOUT, min_interval: float=DEFAULT_MIN_INTERVAL) -> Tuple[Optional[str], list[str]]:
    """Возвращает (analysis_id, errors)."""
    errs: list[str] = []
    k = _key(key)
    if not k:
        return None, ["vt_no_api_key"]
    files = {"file": (path.name, open(path, "rb"))}
    try:
        _throttle(min_interval)
        r = requests.post(f"{VT_API}/files", headers={"x-apikey": k}, files=files, timeout=timeout)
    except requests.Timeout:
        return None, [f"vt_timeout({timeout}s)"]
    except Exception as e:
        return None, [f"vt_http_error:{e}"]
    finally:
        try: files["file"][1].close()
        except Exception: pass

    if r.status_code == 403:
        return None, ["vt_forbidden_upload"]  # ключ не даёт аплоад (часто на public API)
    if r.status_code not in (200, 202):
        return None, [f"vt_http_status:{r.status_code}"]

    try:
        data = r.json().get("data") or {}
        analysis_id = data.get("id")
    except Exception as e:
        return None, [f"vt_json_error:{e}"]
    return analysis_id, errs

def poll_analysis(analysis_id: str, *, key: Optional[str]=None, poll_interval: int=DEFAULT_POLL_INTERVAL, timeout_sec: int=DEFAULT_POLL_TIMEOUT) -> Tuple[Optional[Dict[str, Any]], list[str]]:
    """Ждёт завершения анализа и возвращает атрибуты /analyses/{id}."""
    errs: list[str] = []
    k = _key(key)
    if not k:
        return None, ["vt_no_api_key"]
    start = time.time()
    while time.time() - start < timeout_sec:
        try:
            r = requests.get(f"{VT_API}/analyses/{analysis_id}", headers={"x-apikey": k}, timeout=20)
        except requests.Timeout:
            return None, [f"vt_timeout(20s)"]
        except Exception as e:
            return None, [f"vt_http_error:{e}"]
        if r.status_code != 200:
            time.sleep(poll_interval); continue
        try:
            data = r.json().get("data") or {}
        except Exception as e:
            return None, [f"vt_json_error:{e}"]
        status = (data.get("attributes") or {}).get("status")
        if status in ("completed","partial"):
            return data, errs
       
