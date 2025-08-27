from __future__ import annotations
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import json

from .osv_client import query_osv_package
from ..analyzers.elf_deps import list_elf_shared_libs
from ..analyzers.pe_deps import list_pe_imports, find_side_by_side_versions
from .mapper import map_lib_to_package, load_user_map

def _sev_buckets() -> Dict[str, int]:
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}

def _accumulate_summary(s: Dict[str, int], label: Optional[str]) -> None:
    if label:
        key = label.lower()
        if key.startswith("crit"):
            s["critical"] += 1
        elif key.startswith("high"):
            s["high"] += 1
        elif key.startswith("med"):
            s["medium"] += 1
        else:
            s["low"] += 1
    s["total"] += 1

def _load_inventory(path: Optional[Path]) -> List[Dict[str, Any]]:
    """
    Ожидаемый формат JSON:
    [
      {"ecosystem":"Debian","name":"libssl3","version":"3.0.9-1~deb12u1"},
      {"ecosystem":"Debian","name":"zlib1g","version":"1:1.2.13.dfsg-1"}
    ]
    """
    if not path:
        return []
    try:
        doc = json.loads(path.read_text(encoding="utf-8")) or []
        if isinstance(doc, list):
            return doc
        return []
    except Exception:
        return []

def _find_pkg_version(inv: List[Dict[str, Any]], ecosystem: str, pkg: str) -> Optional[str]:
    for row in inv:
        if (row.get("ecosystem") == ecosystem) and (row.get("name") == pkg):
            v = row.get("version")
            if v:
                return str(v)
    return None

def collect_cve_for_file(
    file_path: Path,
    ev: Dict[str, Any],
    *,
    ecosystem: Optional[str],
    inventory_path: Optional[Path],
    libmap_path: Optional[Path],
    osv_timeout_sec: int = 15,
) -> Dict[str, Any]:
    """
    Возвращает ev.cve-совместный dict:
      {"summary": {...}, "items":[{"package":..,"version":..,"vulns":[{id,summary,severity,cvss}], "lib":"libssl.so.3"}], "notes":[...]}
    Ничего не бросает — безопасно для pipeline.
    """
    result: Dict[str, Any] = {"summary": _sev_buckets(), "items": [], "notes": []}
    if not ecosystem:
        result["notes"].append("cve_skipped:no_ecosystem")
        return result

    inventory = _load_inventory(inventory_path)
    user_map = load_user_map(libmap_path)

    libs: List[str] = []
    notes: List[str] = []

    kind = (ev.get("kind") or ev.get("type") or "").upper()
    if kind == "ELF":
        for rec in list_elf_shared_libs(file_path):
            lib = rec.get("library")
            if lib:
                libs.append(lib)
    elif kind == "PE":
        # импортируемые DLL
        imports = list_pe_imports(file_path)
        # + версии соседних DLL (по возможности)
        _ = find_side_by_side_versions(file_path, imports)
        # для PE CVE по OSV как правило неинформативны, пропустим
        result["notes"].append("cve_pe:best_effort_skipped")
        return result
    else:
        result["notes"].append("cve_skipped:unknown_kind")
        return result

    # для каждой ELF-либы → пакет → версия → OSV
    seen_pkgs = set()
    for lib in libs:
        pkg = map_lib_to_package(lib, ecosystem=ecosystem, user_map=user_map)
        if not pkg:
            continue
        if (ecosystem, pkg) in seen_pkgs:
            continue
        seen_pkgs.add((ecosystem, pkg))
        ver = _find_pkg_version(inventory, ecosystem, pkg)
        if not ver:
            notes.append(f"no_version_for:{ecosystem}/{pkg}")
            continue
        vulns, errs = query_osv_package(pkg, ecosystem, ver, timeout_sec=osv_timeout_sec)
        for e in errs or []:
            notes.append(f"osv_error:{e}")
        if not vulns:
            continue
        item = {"package": pkg, "ecosystem": ecosystem, "version": ver, "vulns": [], "lib": lib}
        for v in vulns:
            item["vulns"].append({
                "id": v.get("id"),
                "summary": v.get("summary"),
                "severity": v.get("severity"),
                "cvss": v.get("cvss"),
            })
            _accumulate_summary(result["summary"], v.get("severity"))
        result["items"].append(item)

    # если ничего не нашли — summary останется нулевым (как и ожидалось)
    if notes:
        result["notes"].extend(notes)
    return result
