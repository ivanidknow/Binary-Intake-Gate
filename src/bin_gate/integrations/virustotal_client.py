from __future__ import annotations
from typing import Dict, Any, Optional, Tuple, List
import os, time, requests

VT_API = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT = int(os.getenv("VT_TIMEOUT_SEC", "20"))
DEFAULT_MIN_INTERVAL = float(os.getenv("VT_MIN_INTERVAL", "20.0"))  # free API ≈ 4 rpm

_last_call: Optional[float] = None

def _api_key(explicit: Optional[str] = None) -> Optional[str]:
    return explicit or os.getenv("VT_API_KEY")

def _throttle(min_interval_sec: float) -> None:
    global _last_call
    now = time.time()
    if _last_call is None:
        _last_call = now
        return
    delta = now - _last_call
    if delta < min_interval_sec:
        time.sleep(min_interval_sec - delta)
    _last_call = time.time()

def _get(path: str, key: str, timeout: int, min_interval: float) -> requests.Response:
    _throttle(min_interval)
    return requests.get(f"{VT_API}{path}", headers={"x-apikey": key}, timeout=timeout)

def normalize_summary(file_doc: Dict[str, Any]) -> Dict[str, Any]:
    attr = file_doc.get("attributes", {}) if file_doc else {}
    stats = attr.get("last_analysis_stats", {}) or {}
    return {
        "found": True,
        "sha256": attr.get("sha256") or file_doc.get("id"),
        "stats": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "timeout": stats.get("timeout", 0),
        },
        "reputation": attr.get("reputation"),
        "threat_label": (attr.get("popular_threat_classification") or {}).get("suggested_threat_label"),
        "last_analysis_date": attr.get("last_analysis_date"),
        "permalink": f"https://www.virustotal.com/gui/file/{attr.get('sha256') or file_doc.get('id')}"
    }

def lookup_by_sha256(sha256: str, *, key: Optional[str]=None, timeout: int=DEFAULT_TIMEOUT, min_interval: float=DEFAULT_MIN_INTERVAL) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    errs: List[str] = []
    k = _api_key(key)
    if not k:
        return None, ["vt_no_api_key"]
    try:
        r = _get(f"/files/{sha256}", k, timeout, min_interval)
    except requests.Timeout:
        return None, [f"vt_timeout({timeout}s)"]
    except Exception as e:
        return None, [f"vt_http_error:{e}"]

    if r.status_code == 404:
        return {"found": False, "sha256": sha256}, errs
    if r.status_code != 200:
        return None, [f"vt_http_status:{r.status_code}"]

    try:
        doc = r.json().get("data") or {}
    except Exception as e:
        return None, [f"vt_json_error:{e}"]
    return normalize_summary(doc), errs

def fetch_behaviours(sha256: str, *, key: Optional[str]=None, timeout: int=DEFAULT_TIMEOUT, min_interval: float=DEFAULT_MIN_INTERVAL) -> Tuple[List[Dict[str, Any]], List[str]]:
    k = _api_key(key); errs: List[str] = []
    if not k: return [], ["vt_no_api_key"]
    try:
        r = _get(f"/files/{sha256}/behaviours", k, timeout, min_interval)
    except requests.Timeout:
        return [], [f"vt_timeout({timeout}s)"]
    except Exception as e:
        return [], [f"vt_http_error:{e}"]
    if r.status_code != 200:
        return [], [f"vt_http_status:{r.status_code}"]
    try:
        data = r.json().get("data", []) or []
    except Exception as e:
        return [], [f"vt_json_error:{e}"]
    out: List[Dict[str, Any]] = []
    for entry in data[:3]:  # ограничим до 3 песочниц
        attr = entry.get("attributes", {})
        out.append({
            "sandbox_id": entry.get("id"),
            "summary": attr.get("summary") or {},
            "key_counts": {k: (len(v) if isinstance(v, list) else v) for k, v in attr.items() if k in {
                "files_written","files_deleted","registry_keys_opened","mutexes_created","services_started",
                "services_installed","command_executions","dns_lookups","processes_created","registry_keys_set",
                "windows_run_keys_set","modules_loaded","imported_dlls","http_conversations","hosts_contacted",
                "file_accessed","memory_dumps","attempted_processes_injection","attempted_unhooking","dlls_loaded"
            }}
        })
    return out, errs

def fetch_detections(sha256: str, *, key: Optional[str]=None, timeout: int=DEFAULT_TIMEOUT, min_interval: float=DEFAULT_MIN_INTERVAL, max_results: int=20) -> Tuple[Dict[str, Any], List[str]]:
    k = _api_key(key); errs: List[str] = []
    if not k: return {}, ["vt_no_api_key"]
    try:
        r = _get(f"/files/{sha256}", k, timeout, min_interval)
    except requests.Timeout:
        return {}, [f"vt_timeout({timeout}s)"]
    except Exception as e:
        return {}, [f"vt_http_error:{e}"]
    if r.status_code != 200:
        return {}, [f"vt_http_status:{r.status_code}"]
    try:
        attr = (r.json().get("data") or {}).get("attributes", {}) or {}
    except Exception as e:
        return {}, [f"vt_json_error:{e}"]
    results = attr.get("last_analysis_results", {}) or {}
    top = []
    for engine, res in list(results.items())[:max_results]:
        top.append({"engine": engine, "category": res.get("category"), "result": res.get("result")})
    return {"engines": top, "stats": attr.get("last_analysis_stats", {})}, errs

def fetch_relations(sha256: str, *, key: Optional[str]=None, timeout: int=DEFAULT_TIMEOUT, min_interval: float=DEFAULT_MIN_INTERVAL) -> Tuple[Dict[str, Any], List[str]]:
    k = _api_key(key); errs: List[str] = []
    if not k: return {}, ["vt_no_api_key"]
    kinds = ["contacted_urls","contacted_domains","contacted_ips","bundled_files"]
    out: Dict[str, Any] = {}
    for rel in kinds:
        try:
            r = _get(f"/files/{sha256}/relationships/{rel}", k, timeout, min_interval)
        except requests.Timeout:
            errs.append(f"vt_timeout({timeout}s)"); continue
        except Exception as e:
            errs.append(f"vt_http_error:{e}"); continue
        if r.status_code != 200:
            errs.append(f"vt_http_status:{r.status_code}"); continue
        try:
            data = r.json().get("data", []) or []
        except Exception as e:
            errs.append(f"vt_json_error:{e}"); continue
        if rel in ("contacted_urls","contacted_domains"):
            out[rel] = [ (item.get("attributes") or {}).get("url") or (item.get("attributes") or {}).get("host_name") for item in data[:10] ]
        elif rel == "contacted_ips":
            out[rel] = [ (item.get("attributes") or {}).get("ip_address") for item in data[:10] ]
        else:
            out[rel] = [ (item.get("attributes") or {}).get("sha256") for item in data[:10] ]
    return out, errs

def fetch_comments(sha256: str, *, key: Optional[str]=None, timeout: int=DEFAULT_TIMEOUT, min_interval: float=DEFAULT_MIN_INTERVAL, max_items: int=5) -> Tuple[List[Dict[str, Any]], List[str]]:
    k = _api_key(key); errs: List[str] = []
    if not k: return [], ["vt_no_api_key"]
    try:
        r = _get(f"/files/{sha256}/comments", k, timeout, min_interval)
    except requests.Timeout:
        return [], [f"vt_timeout({timeout}s)"]
    except Exception as e:
        return [], [f"vt_http_error:{e}"]
    if r.status_code != 200:
        return [], [f"vt_http_status:{r.status_code}"]
    try:
        data = r.json().get("data", []) or []
    except Exception as e:
        return [], [f"vt_json_error:{e}"]
    out = []
    for entry in data[:max_items]:
        author = ((entry.get("attributes") or {}).get("author") or {}).get("id", "anon")
        text = (entry.get("attributes") or {}).get("text","") or ""
        out.append({"author": author, "text": text.strip()})
    return out, errs
