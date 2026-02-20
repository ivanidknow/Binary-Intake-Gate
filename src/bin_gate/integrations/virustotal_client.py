from __future__ import annotations
from typing import Dict, Any, Optional, Tuple, List
import os, time, requests
HARDCODED_VT_API_KEY = ""  # REMOVED: use VT_API_KEY env variable or --vt-api-key CLI arg
VT_API = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT = int(os.getenv("VT_TIMEOUT_SEC", "20"))
DEFAULT_MIN_INTERVAL = float(os.getenv("VT_MIN_INTERVAL", "6.0"))
ULTRA_FAST = os.getenv("VT_ULTRA_FAST", "0") == "1"

_last_call: Optional[float] = None
_min_interval: float = DEFAULT_MIN_INTERVAL


def _api_key(explicit: Optional[str] = None) -> Optional[str]:
    # порядок приоритета: явный → переменная окружения → захардкоженный ключ
    return explicit or os.getenv("VT_API_KEY") or HARDCODED_VT_API_KEY

def fetch_network_relations(sha256: str, *, key: Optional[str]=None,
                            timeout: int=DEFAULT_TIMEOUT, min_interval: float=DEFAULT_MIN_INTERVAL
                           ) -> Tuple[Dict[str, list], list[str]]:
    k = _api_key(key); errs: list[str] = []; out = {"domains": [], "ips": [], "http": []}
    if not k: return out, ["vt_no_api_key"]

    def _rel(path: str) -> list[str]:
        try:
            r = _get(path, k, timeout, min_interval)
            if r.status_code != 200: 
                errs.append(f"vt_http_status:{r.status_code}"); return []
            js = r.json() or {}
            data = js.get("data") or []
            vals = []
            for it in data:
                attr = (it.get("attributes") or {})
                # domains
                if "host" in attr: vals.append(attr["host"])
                if "domain" in attr: vals.append(attr["domain"])
                # ips
                if "ip_address" in attr: vals.append(attr["ip_address"])
                # urls
                if "url" in attr: vals.append(attr["url"])
            return [str(x) for x in vals if x]
        except Exception as e:
            errs.append(f"vt_rel_error:{e}"); return []

    out["domains"] = _rel(f"/files/{sha256}/relationships/contacted_domains")
    out["ips"]     = _rel(f"/files/{sha256}/relationships/contacted_ips")
    out["http"]    = _rel(f"/files/{sha256}/relationships/contacted_urls")
    return out, errs

def fetch_behaviour_details(sha256: str, *, key: Optional[str]=None,
                            timeout: int=DEFAULT_TIMEOUT, min_interval: float=DEFAULT_MIN_INTERVAL
                           ) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Возвращает список нормализованных behaviour-объектов с полями:
    summary, network, files, registry, processes, mutexes, mitre_attack, key_counts.
    Склеивает /behaviour_summary и /behaviour.
    """
    k = _api_key(key); errs: List[str] = []
    if not k: return [], ["vt_no_api_key"]

    def _json_or(path: str) -> Dict[str, Any] | List[Any]:
        try:
            r = _get(path, k, timeout, min_interval)
        except requests.Timeout:
            errs.append(f"vt_timeout({timeout}s)"); return {}
        except Exception as e:
            errs.append(f"vt_http_error:{e}"); return {}
        if r.status_code != 200:
            errs.append(f"vt_http_status:{r.status_code}"); return {}
        try:
            return r.json() or {}
        except Exception as e:
            errs.append(f"vt_json_error:{e}"); return {}

    sum_doc = _json_or(f"/files/{sha256}/behaviour_summary")
    full_doc = _json_or(f"/files/{sha256}/behaviour")

    # Извлечём items из summary
    items: List[Dict[str, Any]] = []
    if isinstance(sum_doc, dict):
        # типичные варианты
        cand = (sum_doc.get("data") or sum_doc.get("attributes") or sum_doc.get("behaviour") or sum_doc.get("behaviors") or sum_doc.get("items"))
        if isinstance(cand, dict):
            items.append(cand)
        elif isinstance(cand, list):
            for x in cand:
                if isinstance(x, dict):
                    items.append(x.get("attributes") or x.get("data") or x)

    # Извлечём attributes из полного отчёта песочниц
    full_items: List[Dict[str, Any]] = []
    if isinstance(full_doc, dict):
        arr = full_doc.get("data") or full_doc.get("items") or full_doc.get("behaviours") or full_doc.get("behaviors") or []
        if isinstance(arr, list):
            for it in arr:
                if isinstance(it, dict):
                    full_items.append(it.get("attributes") or it.get("data") or it)

    def _extract_maps(b: Dict[str, Any]) -> Dict[str, Any]:
        summ = b.get("summary") if isinstance(b.get("summary"), dict) else {}
        return {
            "summary": summ,
            "network": b.get("network") or summ.get("network") or {},
            "files": b.get("files") or summ.get("files") or [],
            "registry": b.get("registry") or summ.get("registry") or [],
            "processes": b.get("processes") or summ.get("processes") or [],
            "mutexes": b.get("mutexes") or summ.get("mutexes") or [],
            "mitre_attack": b.get("mitre_attack") or summ.get("mitre_attack") or [],
            "key_counts": b.get("key_counts") or {},
        }

    out: List[Dict[str, Any]] = []
    if items:
        out.append(_extract_maps(items[0]))  # обычно summary один
    for fb in full_items:
        if not isinstance(fb, dict): continue
        base = _extract_maps(fb)
        if out:
            cur = out[0]
            # дополняем недостающие секции
            for k in ("network","files","registry","processes","mutexes","mitre_attack","key_counts"):
                if not cur.get(k) and base.get(k):
                    cur[k] = base[k]
        else:
            out.append(base)

    return out, errs

def _throttle(min_interval: Optional[float] = None) -> None:
    global _last_call, _min_interval
    if min_interval is not None:
        try:
            _min_interval = float(min_interval)
        except Exception:
            pass
    if ULTRA_FAST:
        _last_call = time.time()
        return
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

# Exponential backoff on 429
_429_MAX_RETRIES = int(os.getenv("VT_429_MAX_RETRIES", "5"))
_429_BASE_DELAY = float(os.getenv("VT_429_BASE_DELAY", "2.0"))
_429_MAX_DELAY = float(os.getenv("VT_429_MAX_DELAY", "120.0"))


def _get(path: str, key: str, timeout: int, min_interval: float) -> requests.Response:
    """GET with exponential backoff on 429 (Too Many Requests)."""
    for attempt in range(_429_MAX_RETRIES):
        _throttle(min_interval)
        r = requests.get(f"{VT_API}{path}", headers={"x-apikey": key}, timeout=timeout)
        if r.status_code == 429:
            _on_rate_feedback(429)
            delay = min(_429_MAX_DELAY, _429_BASE_DELAY * (2.0 ** attempt))
            time.sleep(delay)
            continue
        return r
    return r  # last 429 response after retries

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

def fetch_behaviours(sha256: str, *, key: Optional[str]=None,
                     timeout: int=DEFAULT_TIMEOUT, min_interval: float=DEFAULT_MIN_INTERVAL
                    ) -> Tuple[List[Dict[str, Any]], List[str]]:
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
    for entry in data[:3]:  # можно оставить ограничение на 3 песочницы
        attr = entry.get("attributes", {}) or {}

        # считаем «счётчики» дополнительно, но НИЧЕГО из атрибутов не выбрасываем
        key_counts = {k: (len(v) if isinstance(v, list) else v) for k, v in attr.items() if k in {
            "files_written","files_deleted","registry_keys_opened","mutexes_created","services_started",
            "services_installed","command_executions","dns_lookups","processes_created","registry_keys_set",
            "windows_run_keys_set","modules_loaded","imported_dlls","http_conversations","hosts_contacted",
            "file_accessed","memory_dumps","attempted_processes_injection","attempted_unhooking","dlls_loaded"
        }}

        # пробрасываем все поля песочницы, чтобы рендер смог их увидеть
        payload = dict(attr)
        payload["sandbox_id"] = entry.get("id")
        payload["summary"] = payload.get("summary") or {}
        payload["key_counts"] = key_counts

        out.append(payload)

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


import os, sys, json, time

def _vt_tap(msg: str):
    # 1) stderr (если не глотают — смотрим файл)
    try:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()
    except Exception:
        pass
    # 2) файл рядом с отчётом
    vt_debug_log(msg)

def vt_debug_log(msg: str):
    """Пишет строку только в vt_debug.log (без stderr). Для детального дебага VT."""
    try:
        from bin_gate.vt_debug import vt_debug_log as _write
        _write(msg)
    except Exception:
        try:
            with open("vt_debug.log", "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
        except Exception:
            pass

# ---- RAW VT behaviours (как в vt.py) ----
import requests

def vt_fetch_behaviours_raw(sha256: str, *, api_key: str, timeout_sec: int = DEFAULT_TIMEOUT):
    """
    Прямой RAW: GET /api/v3/files/{sha}/behaviours → (list[attributes], errors)
    Печатает в консоль debug: url, status, bytes, len(data).
    """
    url = f"{VT_API}/files/{sha256}/behaviours"
    headers = {"x-apikey": api_key}
    try:
        _vt_tap(f"[vt] GET {url}")
        r = requests.get(url, headers=headers, timeout=timeout_sec)
        text_len = len(r.text or "")
        _vt_tap(f"[vt] <- status={r.status_code}, bytes={text_len}")
    except requests.Timeout:
        _vt_tap(f"[vt] !! timeout after {timeout_sec}s")
        return [], [f"vt_timeout({timeout_sec}s)"]
    except Exception as e:
        _vt_tap(f"[vt] !! http_error: {e}")
        return [], [f"vt_http_error:{e}"]

    if r.status_code != 200:
        _vt_tap(f"[vt] !! http_status={r.status_code} (no JSON)")
        return [], [f"vt_http_status:{r.status_code}"]

    try:
        js = r.json() or {}
    except Exception as e:
        _vt_tap(f"[vt] !! json_error: {e}")
        return [], [f"vt_json_error:{e}"]

    data = js.get("data") or []
    _vt_tap(f"[vt] data_len={len(data)} (behaviours sessions)")

    out = []
    if isinstance(data, list):
        for it in data:
            if not isinstance(it, dict):
                continue
            b = it.get("attributes") or it.get("data") or it
            if isinstance(b, dict):
                out.append(b)

    # Как в vt.py: ключи первой сессии + какие блоки непустые
    if out:
        keys = sorted(list(out[0].keys()))[:25]
        _vt_tap(f"[vt] attributes[0].keys={keys}")
        sumk = sorted(list((out[0].get('summary') or {}).keys()))[:25]
        _vt_tap(f"[vt] summary[0].keys={sumk}")
        # Дебаг по образцу vt.py: какие атрибуты с данными
        vt_py_keys = [
            "files_written", "files_deleted", "registry_keys_opened", "mutexes_created",
            "command_executions", "dns_lookups", "processes_created", "processes_tree",
            "registry_keys_set", "http_conversations", "hosts_contacted", "file_accessed",
            "modules_loaded", "imported_dlls", "sandbox_name",
        ]
        for i, att in enumerate(out[:3]):
            non_empty = [k for k in vt_py_keys if att.get(k)]
            cnt = {k: len(att[k]) if isinstance(att.get(k), list) else 1 for k in non_empty if att.get(k)}
            vt_debug_log(f"[vt] session[{i}] sha={sha256} non_empty={non_empty} counts={cnt}")
    else:
        _vt_tap("[vt] no attributes extracted from data[]")
        vt_debug_log(f"[vt] sha={sha256} data_len=0 (no behaviours)")

    return out, []


# Кэш behaviours в рамках одного запуска: один GET на хэш, повторные вызовы берут из кэша
_behaviours_run_cache: dict[str, tuple[list[dict], list[str]]] = {}


def vt_wait_behaviours_raw(sha256: str, *, api_key: str,
                           timeout_total_sec: int = 180,
                           poll_interval_sec: int = 8) -> tuple[list[dict], list[str]]:
    """
    Один запрос GET /behaviours на хэш. Пустой data (200) = «нет сессий», сразу возврат без поллинга.
    В рамках запуска кэш по sha256 — повторные вызовы без сети. При 429 — до 3 ретраев с backoff.
    """
    if not api_key:
        return [], ["vt_no_api_key"]
    cached = _behaviours_run_cache.get(sha256)
    if cached is not None:
        vt_debug_log(f"[vt_wait_behaviours_raw] sha256={sha256[:16]}... ENTER cache_hit=True -> return sessions={len(cached[0])} (no GET)")
        return cached[0], list(cached[1])

    vt_debug_log(f"[vt_wait_behaviours_raw] sha256={sha256[:16]}... ENTER cache_hit=False -> one GET then cache")
    errs: list[str] = []
    out: list[dict] = []
    max_429_retries = 3

    for attempt in range(max_429_retries + 1):
        vt_debug_log(f"[vt_wait_behaviours_raw] sha256={sha256[:16]}... FETCH attempt={attempt + 1}")
        data, e = vt_fetch_behaviours_raw(sha256, api_key=api_key, timeout_sec=15)
        if e:
            errs.extend(e)
            if any("429" in str(x) for x in e) and attempt < max_429_retries:
                time.sleep(min(60, 15 * (attempt + 1)))
                continue
            out = []
            break
        # Успешный 200: пустой data = финальный ответ «нет сессий». Один GET на hash, без поллинга.
        out = data if data else []
        break  # не повторяем запрос при data_len=0

    # Пустой out при успешном 200 — норма («нет сессий»), не помечаем как timeout
    if not out and errs and "vt_429_rate_limit_give_up" not in errs and "vt_beh_wait_timeout" not in errs:
        errs.append("vt_beh_wait_timeout")
    _behaviours_run_cache[sha256] = (out, errs)
    vt_debug_log(f"[vt_wait_behaviours_raw] sha256={sha256[:16]}... EXIT from_cache=False sessions={len(out)} errs={errs[:3]}")
    return out, errs
