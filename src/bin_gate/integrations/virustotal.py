from __future__ import annotations
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
import requests, time, os

_API_FILE      = "https://www.virustotal.com/api/v3/files/{sha256}"
_API_UPLOAD    = "https://www.virustotal.com/api/v3/files"
_API_ANALYSES  = "https://www.virustotal.com/api/v3/analyses/{id}"
# UI fallback отключён по умолчанию (медленно); включается только явным флагом --vt-ui-force
ENABLE_UI_FALLBACK = os.getenv("VT_ENABLE_UI_FALLBACK", "0") == "1"
HEADLESS_UI        = os.getenv("VT_UI_HEADLESS", "1") == "1"
UI_BROWSER         = os.getenv("VT_UI_BROWSER", "chromium")

_last_call_ts: Optional[float] = None

def _throttle(min_interval_sec: float) -> None:
    global _last_call_ts
    now = time.time()
    if _last_call_ts is None:
        _last_call_ts = now; return
    delta = now - _last_call_ts
    if delta < min_interval_sec:
        time.sleep(min_interval_sec - delta)
    _last_call_ts = time.time()

def _auth_hdr(api_key: Optional[str]) -> Dict[str, str]:
    if not api_key:
        return {}
    # поддерживаем оба варианта заголовка
    return {"x-apikey": api_key, "Authorization": f"Bearer {api_key}"}

def vt_lookup_sha256(sha256: str,
                     api_key: Optional[str],
                     *,
                     timeout_sec: int = 20,
                     min_interval_sec: float = 20.0,
                     max_retries: int = 3) -> Tuple[Optional[Dict[str, Any]], list[str]]:
    errs: list[str] = []
    if not api_key:
        return None, ["vt_no_api_key"]

    backoff = 2.0
    for _ in range(max_retries):
        try:
            _throttle(min_interval_sec)
            r = requests.get(_API_FILE.format(sha256=sha256), headers=_auth_hdr(api_key), timeout=timeout_sec)
        except requests.Timeout:
            errs.append(f"vt_timeout({timeout_sec}s)"); return None, errs
        except Exception as e:
            errs.append(f"vt_http_error:{e}"); return None, errs

        if r.status_code == 429:
            time.sleep(backoff); backoff *= 2.0; continue
        if r.status_code == 404:
            return {"found": False, "sha256": sha256}, errs
        if r.status_code >= 500:
            time.sleep(backoff); backoff *= 2.0; continue
        if r.status_code != 200:
            errs.append(f"vt_http_status:{r.status_code}"); return None, errs

        try:
            doc = r.json()
        except Exception as e:
            errs.append(f"vt_json_error:{e}"); return None, errs

        data = (doc or {}).get("data") or {}
        attr = data.get("attributes") or {}
        stats = attr.get("last_analysis_stats") or {}
        rep = attr.get("reputation")
        results = attr.get("last_analysis_results") or {}
        threat = (attr.get("popular_threat_classification") or {}).get("suggested_threat_label")
        out: Dict[str, Any] = {
            "found": True,
            "sha256": sha256,
            "stats": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless":  stats.get("harmless", 0),
                "timeout":   stats.get("timeout", 0),
            },
            "reputation": rep,
            "threat_label": threat,
            "last_analysis_date": attr.get("last_analysis_date"),
            "last_analysis_results": results,            # сырой слепок
            "detections": {                              # то, что читает другая часть кода
                "stats": stats,
                "reputation": rep,
                "engines": [
                    {"engine": eng, "category": (res or {}).get("category"), "result": (res or {}).get("result")}
                    for eng, res in list(results.items())[:20]
                ],
            },
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}"
        }
        return out, errs

    errs.append("vt_retries_exhausted")
    return None, errs

def vt_upload_file_api(path: Path,
                       api_key: Optional[str],
                       *,
                       timeout_sec: int = 60,
                       allow_ui_fallback: bool = False) -> Tuple[Optional[str], list[str]]:
    """Возвращает (analysis_id | 'ui:<sha256>', errors). При 401/403 UI только если allow_ui_fallback=True (--vt-ui-force). При 429 UI не вызываем."""
    errs: list[str] = []
    if not api_key:
        return None, ["vt_no_api_key"]
    try:
        with path.open("rb") as f:
            r = requests.post(_API_UPLOAD, headers=_auth_hdr(api_key), files={"file": (path.name, f)}, timeout=timeout_sec)
    except requests.Timeout:
        return None, [f"vt_upload_timeout({timeout_sec}s)"]
    except Exception as e:
        return None, [f"vt_upload_http_error:{e}"]

    if r.status_code in (200, 201):
        try:
            doc = r.json()
            analysis_id = (doc or {}).get("data", {}).get("id")
            if not analysis_id:
                return None, ["vt_upload_no_analysis_id"]
            return analysis_id, errs
        except Exception as e:
            return None, [f"vt_upload_json_error:{e}"]

    if r.status_code in (401, 403):
        errs.append(f"vt_upload_forbidden:{r.status_code}")
        if allow_ui_fallback or ENABLE_UI_FALLBACK:
            try:
                try:
                    from .vt_playwright import vt_upload_file_ui  # type: ignore
                except Exception:
                    from vt_playwright import vt_upload_file_ui  # type: ignore
                ui_sha, e2 = vt_upload_file_ui(path, timeout_sec=min(60, timeout_sec), headless=HEADLESS_UI, browser=UI_BROWSER)
                errs.extend(e2 or [])
                if ui_sha:
                    return f"ui:{ui_sha}", errs
            except Exception as e:
                errs.append(f"vt_ui_fallback_error:{e}")
        return None, errs

    if r.status_code == 429:
        return None, ["vt_upload_rate_limited"]
    if r.status_code >= 500:
        return None, [f"vt_upload_status:{r.status_code}"]
    return None, [f"vt_upload_status:{r.status_code}"]


def vt_poll_analysis(analysis_id: str,
                     api_key: Optional[str],
                     *,
                     timeout_total_sec: int = 180,
                     poll_interval_sec: float = 5.0) -> Tuple[Optional[Dict[str, Any]], list[str]]:
    """Ждём завершение анализа и возвращаем JSON ответа /analyses/{id}."""
    errs: list[str] = []
    if not api_key:
        return None, ["vt_no_api_key"]
    deadline = time.time() + timeout_total_sec
    while time.time() < deadline:
        try:
            r = requests.get(_API_ANALYSES.format(id=analysis_id), headers=_auth_hdr(api_key), timeout=20)
        except Exception as e:
            return None, [f"vt_poll_http_error:{e}"]
        if r.status_code != 200:
            time.sleep(poll_interval_sec); continue
        try:
            doc = r.json()
        except Exception as e:
            return None, [f"vt_poll_json_error:{e}"]
        status = (doc.get("data", {}).get("attributes", {}) or {}).get("status")
        if status in ("completed", "finished", "done"):
            return doc, errs
        time.sleep(poll_interval_sec)
    return None, ["vt_poll_timeout"]

def vt_extract_sha_from_analysis(doc: Dict[str, Any]) -> Optional[str]:
    try:
        meta = (doc.get("data", {}) or {}).get("meta", {}) or {}
        file_info = meta.get("file_info") or {}
        return file_info.get("sha256")
    except Exception:
        return None
