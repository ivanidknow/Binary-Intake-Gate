# virustotal_upload.py
from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
import os, time, requests, hashlib

VT_API = "https://www.virustotal.com/api/v3"

DEFAULT_TIMEOUT       = int(os.getenv("VT_TIMEOUT_SEC", "20"))
DEFAULT_MIN_INTERVAL  = float(os.getenv("VT_MIN_INTERVAL", "6.0"))     # адаптивный старт
DEFAULT_POLL_INTERVAL = int(os.getenv("VT_POLL_SEC", "6"))
DEFAULT_POLL_TIMEOUT  = int(os.getenv("VT_POLL_TIMEOUT", "180"))

# UI fallback только по явному --vt-ui-force (при 429/401 не переключаемся на браузер)
ENABLE_UI_FALLBACK  = os.getenv("VT_ENABLE_UI_FALLBACK", "0") == "1"
UI_FORCE_UPLOAD     = os.getenv("VT_UI_FORCE_UPLOAD", "1") == "1"
HEADLESS_UI         = os.getenv("VT_UI_HEADLESS", "1") == "1"

_last_call: Optional[float] = None
_min_interval: float = DEFAULT_MIN_INTERVAL

def _throttle() -> None:
    global _last_call
    now = time.time()
    if _last_call is None:
        _last_call = now; return
    delta = now - _last_call
    if delta < _min_interval:
        time.sleep(_min_interval - delta)
    _last_call = time.time()

def _on_rate_feedback(code: int) -> None:
    global _min_interval
    if code == 429:
        _min_interval = min(_min_interval * 1.8, 30.0)
    elif code == 200:
        _min_interval = max(DEFAULT_MIN_INTERVAL, _min_interval * 0.9)

def _auth_hdr(api_key: Optional[str]) -> Dict[str, str]:
    return {"x-apikey": api_key} if api_key else {}

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def vt_upload_file_api(path: Path,
                       api_key: Optional[str],
                       *,
                       timeout_sec: int = DEFAULT_TIMEOUT,
                       allow_ui_fallback: Optional[bool] = None) -> Tuple[Optional[str], List[str]]:
    """
    Пытаемся загрузить через API. При 401/403 — UI только если allow_ui_fallback=True (--vt-ui-force).
    При 429 UI не вызываем. Возвращает (analysis_id | 'ui:<sha256>' | None, errors).
    """
    errs: List[str] = []
    if allow_ui_fallback is None:
        allow_ui_fallback = ENABLE_UI_FALLBACK

    # 0) Если не форсим UI-аплоад — можно быстро проверить существование по SHA
    sha = _sha256_file(path)
    if not UI_FORCE_UPLOAD:
        try:
            _throttle()
            r = requests.get(f"{VT_API}/files/{sha}", headers=_auth_hdr(api_key), timeout=timeout_sec)
            _on_rate_feedback(r.status_code)
            if r.status_code == 200:
                # Уже есть на VT — вернём «существует», можно сразу парсить детекты
                return f"exists:{sha}", errs
        except Exception:
            # не критично — продолжаем как есть
            pass

    # 1) Пробуем API upload
    files = {"file": (path.name, path.open("rb"))}
    try:
        _throttle()
        r = requests.post(f"{VT_API}/files", headers=_auth_hdr(api_key), files=files, timeout=timeout_sec)
        _on_rate_feedback(r.status_code)
    except requests.Timeout:
        return None, [f"vt_timeout({timeout_sec}s)"]
    except Exception as e:
        return None, [f"vt_http_error:{e}"]

    if r.status_code == 200:
        try:
            analysis_id = (r.json().get("data") or {}).get("id")
        except Exception as e:
            return None, [f"vt_json_error:{e}"]
        return analysis_id, errs

    # 2) 401/403 → UI только при явном allow_ui_fallback (--vt-ui-force)
    if r.status_code in (401, 403):
        errs.append("vt_forbidden_upload")
        if allow_ui_fallback:
            try:
                try:
                    from .vt_playwright import vt_upload_file_ui  # пакетный импорт
                except Exception:
                    from vt_playwright import vt_upload_file_ui    # локальный файл
                ui_sha, e2 = vt_upload_file_ui(path, timeout_sec=60, headless=HEADLESS_UI)
                errs.extend(e2)
                if ui_sha:
                    return f"ui:{ui_sha}", errs
            except Exception as e:
                errs.append(f"vt_ui_failed:{e}")
        return None, errs

    # 3) Прочие временные коды
    if r.status_code in (429, 503, 504):
        return None, [f"vt_http_status:{r.status_code}"]

    return None, [f"vt_http_status:{r.status_code}"]

def vt_poll_analysis(
    analysis_id: str,
    api_key: Optional[str],
    *,
    timeout_sec: int = DEFAULT_POLL_TIMEOUT,
    poll_every_sec: int = DEFAULT_POLL_INTERVAL,
    timeout_total_sec: Optional[int] = None,   # <— добавили алиас
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """
    Ожидаем завершения анализа (API only).
    Если analysis_id начинается с 'ui:' или 'exists:' — polling не требуется.
    """
    if timeout_total_sec is not None:
        timeout_sec = int(timeout_total_sec)

    errs: List[str] = []
    if analysis_id.startswith("ui:") or analysis_id.startswith("exists:"):
        return None, errs

    started = time.time()
    while time.time() - started < timeout_sec:
        try:
            _throttle()
            r = requests.get(f"{VT_API}/analyses/{analysis_id}",
                             headers=_auth_hdr(api_key),
                             timeout=DEFAULT_TIMEOUT)
            _on_rate_feedback(r.status_code)
        except requests.Timeout:
            return None, [f"vt_timeout({DEFAULT_TIMEOUT}s)"]
        except Exception as e:
            return None, [f"vt_http_error:{e}"]

        if r.status_code != 200:
            time.sleep(poll_every_sec)
            continue

        try:
            data = r.json().get("data") or {}
        except Exception as e:
            return None, [f"vt_json_error:{e}"]

        status = (data.get("attributes") or {}).get("status")
        if status in ("completed", "partial", "finished", "done"):
            return data, errs

        time.sleep(poll_every_sec)

    return None, ["vt_poll_timeout"]
