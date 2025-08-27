from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple
import time
import requests

_OSV_QUERY = "https://api.osv.dev/v1/query"
_OSV_QUERY_BATCH = "https://api.osv.dev/v1/querybatch"

_USER_AGENT = "bin-gate/1.0 (+https://example.local/bin-gate)"

def _best_id(vuln: Dict[str, Any]) -> str:
    """
    Возвращает «читаемый» ID: сначала CVE из aliases, иначе OSV id.
    """
    aliases = vuln.get("aliases") or []
    for a in aliases:
        if isinstance(a, str) and a.upper().startswith("CVE-"):
            return a
    return vuln.get("id") or (aliases[0] if aliases else "UNKNOWN")

def _sev_from_scores(sev_list: List[Dict[str, Any]], db_sev: Optional[str] = None) -> Tuple[Optional[float], Optional[str]]:
    """
    Извлекает лучший CVSS и метку severity.
    Правила:
      - Берём максимум по CVSS (v3.1 > v3 > v2), если есть.
      - Если численного CVSS нет — фолбэк на строковую severitу из db (HIGH/CRITICAL/...).
    """
    best_score: Optional[float] = None
    best_kind_weight = -1  # v3.1=3, v3=2, v2=1

    for s in sev_list or []:
        try:
            stype = str(s.get("type", "")).strip().upper()
            score = float(s.get("score", 0.0))
        except Exception:
            continue

        kind_weight = 0
        if "CVSS" in stype:
            if "3.1" in stype:
                kind_weight = 3
            elif "3" in stype:
                kind_weight = 2
            elif "2" in stype:
                kind_weight = 1

        if (kind_weight > best_kind_weight) or (kind_weight == best_kind_weight and (best_score is None or score > best_score)):
            best_kind_weight = kind_weight
            best_score = score

    # Строковая метка по числу
    if best_score is not None:
        if best_score >= 9.0: return best_score, "CRITICAL"
        if best_score >= 7.0: return best_score, "HIGH"
        if best_score >= 4.0: return best_score, "MEDIUM"
        return best_score, "LOW"

    # Фолбэк: строковый severity из database_specific (например, GHSA)
    if db_sev:
        label = str(db_sev).upper()
        if label in ("CRITICAL","HIGH","MEDIUM","LOW"):
            return None, label

    return None, None

def _request_json(url: str, payload: Dict[str, Any], *, timeout_sec: int, retries: int = 3) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """
    Выполняет POST JSON с простым экспоненциальным бэкоффом для 429/5xx.
    """
    errs: List[str] = []
    backoff = 0.7
    for attempt in range(retries):
        try:
            r = requests.post(
                url,
                json=payload,
                headers={"User-Agent": _USER_AGENT, "Content-Type": "application/json"},
                timeout=timeout_sec,
            )
        except Exception as e:
            errs.append(f"osv_http_error:{e}")
            if attempt < retries - 1:
                time.sleep(backoff)
                backoff *= 2
            continue

        if r.status_code == 200:
            try:
                return r.json() or {}, errs
            except Exception as e:
                return None, errs + [f"osv_json_error:{e}"]

        # Ретраим на 429/5xx
        if r.status_code in (429, 500, 502, 503, 504) and attempt < retries - 1:
            # Поддержим Retry-After (секунды), если сервер вернул
            ra = r.headers.get("Retry-After")
            if ra:
                try:
                    sleep_s = max(float(ra), backoff)
                except Exception:
                    sleep_s = backoff
            else:
                sleep_s = backoff
            time.sleep(sleep_s)
            backoff = min(backoff * 2, 8.0)
            continue

        errs.append(f"osv_http_status:{r.status_code}")
        break

    return None, errs

def query_osv_package(name: str, ecosystem: str, version: str, *, timeout_sec: int = 15) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Запрос OSV по package+ecosystem+version.
    Возвращает (findings, errors), где findings — список объектов:
      {
        "id": <CVE|OSV id>,
        "aliases": [...],
        "summary": <str|None>,
        "cvss": <float|None>,
        "severity": <"CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|None>
      }
    """
    if not (name and ecosystem and version):
        return [], ["osv_bad_args"]

    payload = {
        "package": {"name": name, "ecosystem": ecosystem},
        "version": version
    }
    doc, errs = _request_json(_OSV_QUERY, payload, timeout_sec=timeout_sec)
    if doc is None:
        return [], errs or ["osv_no_response"]

    vulns = doc.get("vulns") or []
    out: List[Dict[str, Any]] = []
    for v in vulns:
        sev_list = v.get("severity") or []
        db_sev = None
        # Некоторые советники кладут severity строкой в database_specific
        try:
            db_sev = (v.get("database_specific") or {}).get("severity")
        except Exception:
            db_sev = None

        score, label = _sev_from_scores(sev_list, db_sev)
        out.append({
            "id": _best_id(v),
            "aliases": v.get("aliases") or [],
            "summary": v.get("summary"),
            "cvss": score,
            "severity": label,
        })
    return out, errs

def query_osv_batch(pkgs: List[Tuple[str, str, str]], *, timeout_sec: int = 25) -> Tuple[List[List[Dict[str, Any]]], List[str]]:
    """
    Batch-вариант: принимает список (name, ecosystem, version).
    Возвращает (findings_per_item, errors), где findings_per_item — список списков findings,
    выровненный по входному порядку.
    """
    items = []
    for (name, eco, ver) in pkgs:
        items.append({"package": {"name": name, "ecosystem": eco}, "version": ver})

    doc, errs = _request_json(_OSV_QUERY_BATCH, {"queries": items}, timeout_sec=timeout_sec)
    if doc is None:
        return [[] for _ in pkgs], errs or ["osv_no_response"]

    results = doc.get("results") or []
    out_all: List[List[Dict[str, Any]]] = []

    for res in results:
        vulns = (res or {}).get("vulns") or []
        bucket: List[Dict[str, Any]] = []
        for v in vulns:
            sev_list = v.get("severity") or []
            db_sev = None
            try:
                db_sev = (v.get("database_specific") or {}).get("severity")
            except Exception:
                db_sev = None
            score, label = _sev_from_scores(sev_list, db_sev)
            bucket.append({
                "id": _best_id(v),
                "aliases": v.get("aliases") or [],
                "summary": v.get("summary"),
                "cvss": score,
                "severity": label,
            })
        out_all.append(bucket)

    # Если OSV вернул меньше, чем запросили — добьём пустыми
    while len(out_all) < len(pkgs):
        out_all.append([])

    return out_all, errs
