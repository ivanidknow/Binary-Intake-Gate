from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from ..analyzers.elf_deps import list_elf_needed
from ..analyzers.pe_deps import list_pe_imports_and_versions
from ..cve.mapping import load_patterns, map_dep_to_package
from ..cve.osv_client import query_osv_package
from ..cve.resolvers import resolve_file_by_ecosystem

def run_cve_scan(path: Path,
                 kind: str,
                 *,
                 ecosystem: Optional[str],
                 mapping_file: Optional[Path],
                 timeout_sec: int = 15,
                 max_per_pkg: int = 20,
                 resolve_mode: str = "auto",
                 dll_scan_depth: int = 2,
                 dll_scan_max: int = 200,
                 no_network: bool = False) -> Dict[str, Any]:
    """
    Расширенный CVE-скан:
      - ELF: DT_NEEDED → попытка резолвить пакет/версию через dpkg/rpm/apk/pacman, иначе по SONAME-паттернам
      - PE: импорт + глубокий сбор DLL рядом с exe → FileVersion; по паттернам → пакет
      - OSV запросы уважают no_network
    """
    pats = load_patterns(mapping_file)
    deps: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    if kind == "ELF":
        deps = list_elf_needed(path)
        # для каждой зависимости попробуем точный distro-resolve
        mapped = []
        for d in deps:
            # 1) точное имя/версия из ОС по реальному файлу, если он нашёлся
            resolved = d.get("resolved_path")
            eco = pkg = ver = None
            if resolved:
                eco, pkg, ver = resolve_file_by_ecosystem(Path(resolved), resolve_mode)
            if not pkg:
                # 2) fallback: SONAME → пакет (guess)
                m = map_dep_to_package(d.get("soname",""), d.get("version_guess"), pats)
                if m:
                    pkg = m["name"]; ver = m.get("version_guess")
                    eco = ecosystem or eco
            if pkg:
                mapped.append({"ecosystem": eco, "package": pkg, "version": ver, "source": d})

        if not no_network:
            for m in mapped:
                eco = m.get("ecosystem") or ecosystem
                ver = m.get("version")
                pkg = m.get("package")
                if not (eco and pkg and ver):
                    continue
                vulns, errs = query_osv_package(pkg, eco, ver, timeout_sec=timeout_sec)
                m["errors"] = errs
                if vulns:
                    findings.append({"ecosystem": eco, "package": pkg, "version": ver, "advisories": vulns[:max_per_pkg]})

    elif kind == "PE":
        deps = list_pe_imports_and_versions(
            path,
            deep_scan=True,
            scan_root=path.parent,
            max_dlls=dll_scan_max,
            max_depth=dll_scan_depth
        )
        mapped = []
        for d in deps:
            name = (d.get("dll") or "")
            m = map_dep_to_package(name, d.get("version"), pats)
            if m:
                mapped.append({"ecosystem": ecosystem, "package": m["name"], "version": m.get("version_guess") or d.get("version"), "source": d})

        if not no_network:
            for m in mapped:
                eco = m.get("ecosystem") or ecosystem
                ver = m.get("version")
                pkg = m.get("package")
                if not (eco and pkg and ver):
                    continue
                vulns, errs = query_osv_package(pkg, eco, ver, timeout_sec=timeout_sec)
                m["errors"] = errs
                if vulns:
                    findings.append({"ecosystem": eco, "package": pkg, "version": ver, "advisories": vulns[:max_per_pkg]})

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    for f in findings:
        for adv in f.get("advisories") or []:
            sev = (adv.get("severity") or "").upper()
            if sev == "CRITICAL": summary["critical"] += 1
            elif sev == "HIGH":   summary["high"] += 1
            elif sev == "MEDIUM": summary["medium"] += 1
            elif sev == "LOW":    summary["low"] += 1
            summary["total"] += 1

    return {"deps": deps, "findings": findings, "summary": summary}
