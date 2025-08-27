from __future__ import annotations
from typing import Dict, Any, List, Tuple, Optional
import requests, time

_API_BASE = "https://www.virustotal.com/api/v3"
_last_ts: Optional[float] = None

def _throttle(min_interval_sec: float) -> None:
    global _last_ts
    now = time.time()
    if _last_ts is None: _last_ts = now; return
    if now - _last_ts < min_interval_sec: time.sleep(min_interval_sec - (now - _last_ts))
    _last_ts = time.time()

def _auth_hdr(api_key: Optional[str]) -> Dict[str, str]:
    return {"x-apikey": api_key, "Authorization": f"Bearer {api_key}"} if api_key else {}

def vt_fetch_full_metrics(sha256: str,
                          api_key: Optional[str],
                          *,
                          timeout_sec: int = 20,
                          min_interval_sec: float = 15.0,
                          max_results: int = 15) -> Tuple[Optional[Dict[str, Any]], list[str]]:
    """
    Собирает то же, что твой vt.py: behaviours, detections (stats+subset engines),
    relations (urls/domains/ips/files), comments — с лимитами, безопасно. Возвращает (dict, errors).
    """
    errs: List[str] = []
    if not api_key:
        return None, ["vt_no_api_key"]

    out: Dict[str, Any] = {"sha256": sha256, "behaviours": [], "detections": {}, "relations": {}, "comments": []}

    # --- behaviours
    try:
        _throttle(min_interval_sec)
        r = requests.get(f"{_API_BASE}/files/{sha256}/behaviours", headers=_auth_hdr(api_key), timeout=timeout_sec)
        if r.status_code == 200:
            data = (r.json() or {}).get("data", []) or []
            for entry in data[:5]:
                attrs = entry.get("attributes", {}) or {}
                # берём только summary и важные счетчики
                out["behaviours"].append({
                    "id": entry.get("id"),
                    "summary": attrs.get("summary", {}),
                })
    except Exception as e:
        errs.append(f"vt_behaviours_error:{e}")

    # --- detections (stats + subset of engines)
    try:
        _throttle(min_interval_sec)
        r = requests.get(f"{_API_BASE}/files/{sha256}", headers=_auth_hdr(api_key), timeout=timeout_sec)
        if r.status_code == 200:
            data = (r.json() or {}).get("data", {}) or {}
            attrs = data.get("attributes", {}) or {}
            out["detections"]["stats"] = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {}) or {}
            # до max_results движков
            engines = []
            for eng, res in list(results.items())[:max_results]:
                engines.append({"engine": eng, "category": res.get("category"), "result": res.get("result")})
            out["detections"]["engines"] = engines
            out["detections"]["reputation"] = attrs.get("reputation")
            out["detections"]["threat_label"] = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
            out["permalink"] = f"https://www.virustotal.com/gui/file/{sha256}"
    except Exception as e:
        errs.append(f"vt_detections_error:{e}")

    # --- relations (subset)
    for rel in ["contacted_urls", "contacted_domains", "contacted_ips", "bundled_files"]:
        try:
            _throttle(min_interval_sec)
            r = requests.get(f"{_API_BASE}/files/{sha256}/relationships/{rel}", headers=_auth_hdr(api_key), timeout=timeout_sec)
            if r.status_code == 200:
                data = (r.json() or {}).get("data", []) or []
                items: List[str] = []
                for obj in data[:10]:
                    attr = obj.get("attributes", {}) or {}
                    if "url" in attr: items.append(attr.get("url"))
                    elif "ip_address" in attr: items.append(attr.get("ip_address"))
                    elif "host_name" in attr: items.append(attr.get("host_name"))
                    elif "sha256" in attr: items.append(attr.get("sha256"))
                out["relations"][rel] = items
        except Exception as e:
            errs.append(f"vt_rel_error:{rel}:{e}")

    # --- comments (subset)
    try:
        _throttle(min_interval_sec)
        r = requests.get(f"{_API_BASE}/files/{sha256}/comments", headers=_auth_hdr(api_key), timeout=timeout_sec)
        if r.status_code == 200:
            data = (r.json() or {}).get("data", []) or []
            for entry in data[:5]:
                attrs = entry.get("attributes", {}) or {}
                author = (attrs.get("author", {}) or {}).get("id", "anon")
                text = (attrs.get("text") or "").strip()
                out["comments"].append({"author": author, "text": text[:200]})
    except Exception as e:
        errs.append(f"vt_comments_error:{e}")

    return out, errs
