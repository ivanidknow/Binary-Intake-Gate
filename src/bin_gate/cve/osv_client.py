from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple
import time
import requests
import json
import urllib.request
import urllib.error

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

def _normalize_osv_vuln(v: dict) -> dict:
    vid = v.get("id") or ""
    # предпочитаем CVE из aliases
    for a in v.get("aliases", []) or []:
        if a.startswith("CVE-"):
            vid = a
            break
    # лучший CVSS
    best = None
    for sev in v.get("severity", []) or []:
        try:
            if sev.get("type", "").upper().startswith("CVSS"):
                score = float(sev.get("score", "0").split("/")[0])
                best = max(best or 0.0, score)
        except Exception:
            pass
    # маппинг severity
    sev_label = None
    if best is not None:
        if best >= 9.0: sev_label = "CRITICAL"
        elif best >= 7.0: sev_label = "HIGH"
        elif best >= 4.0: sev_label = "MEDIUM"
        else: sev_label = "LOW"
    elif v.get("database_specific", {}).get("severity"):
        sev_label = v["database_specific"]["severity"]

    return {
        "id": vid or v.get("id", ""),
        "summary": v.get("summary", ""),
        "severity": sev_label,
        "cvss": best,
        "affected": v.get("affected", []),
        "references": v.get("references", []),
    }

def query_osv_batch(triples, timeout: int = 15):
    """
    triples: list[tuple[str, str, str]]  -> [(name, ecosystem, version), ...]
    returns: (list[list[vuln]], list[str]errors)
    """
    if not triples:
        return [], []

    body = {
        "queries": [
            {"package": {"name": n, "ecosystem": e}, "version": v}
            for (n, e, v) in triples
        ]
    }
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "bin-gate/1.0 (+cve-batch)"
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
    except urllib.error.HTTPError as ex:
        # мягко деградируем: пустые результаты на все запросы
        return [[] for _ in triples], [f"osv_error:batch:http:{ex.code}"]
    except Exception as ex:
        return [[] for _ in triples], [f"osv_error:batch:{type(ex).__name__}"]

    results = []
    for entry in data.get("results", []):
        vulns = []
        for v in entry.get("vulns", []) or []:
            vulns.append(_normalize_osv_vuln(v))
        results.append(vulns)

    # на случай, если OSV вернул меньше результатов, выровняем длину
    if len(results) < len(triples):
        results.extend([[] for _ in range(len(triples) - len(results))])

    return results, []
