# run_one_file.py — single-file analysis for ProcessPoolExecutor worker
# Used by orchestrate: returns full evidence dict (no VT/CVE). Hard timeouts applied.
from __future__ import annotations
import time
from pathlib import Path
from typing import Dict, Any, List, Optional

# Hard timeouts (seconds) so one binary cannot block the pipeline
CAPA_TIMEOUT = int(__import__("os").getenv("CAPA_TIMEOUT_SEC", "120"))
DIE_TIMEOUT = int(__import__("os").getenv("DIE_TIMEOUT_SEC", "60"))

# v0.0.8 Advanced Malware Detection timeouts
EMULATION_TIMEOUT = int(__import__("os").getenv("BIN_GATE_EMULATION_TIMEOUT", "60"))
TI_TIMEOUT = int(__import__("os").getenv("BIN_GATE_TI_TIMEOUT", "30"))

# Aggressive gating: files > 50 MB that are not archive/MSI run only hashes, entropy, YARA
AGGRESSIVE_GATE_MB = 50
ARCHIVE_MSI_SUFFIXES = frozenset({".zip", ".msi", ".jar", ".apk", ".aab", ".7z", ".rar", ".tar", ".gz", ".tgz", ".whl", ".nupkg", ".msix", ".appx", ".vsix", ".deb", ".rpm", ".ova", ".ovf"})


def run_one_file_analysis(path: Path, kind: str, options: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run all CPU-bound and local analyzers for one file. Returns evidence-like dict
    (no vt, no cve). All subprocess calls use hard timeouts. Errors go to evidence["errors"].
    """
    path = Path(path)
    t0 = time.perf_counter()
    errors: List[str] = []
    try:
        file_size = path.stat().st_size if path.exists() else 0
    except Exception:
        file_size = 0
    is_archive_or_msi = path.suffix.lower() in ARCHIVE_MSI_SUFFIXES
    aggressive_skip = (
        file_size > AGGRESSIVE_GATE_MB * 1024 * 1024
        and not options.get("deep_scan")
        and not is_archive_or_msi
    )
    out: Dict[str, Any] = {
        "meta": {
            "path": str(path),
            "name": path.name,
            "type": kind,
            "size": path.stat().st_size if path.exists() else None,
        },
        "hashes": {},
        "entropy": {"file": None, "sections": {}},
        "pe": None,
        "elf": None,
        "macho": None,
        "capa": None,
        "yara": None,
        "strings": {},
        "strings_summary": {
            "total_cnt": 0, "static_cnt": 0, "url_cnt": 0, "ip_cnt": 0, "cmd_cnt": 0,
        },
        "die": None,
        "obfuscation": {
            "reasons": [], "score": 0, "packed_suspect": False,
            "has_dyn_api_resolve": False, "string_ratio_ascii": 0.0, "string_ratio_utf16": 0.0,
        },
        "errors": errors,
        "manifest": None,
        "docscripts": None,
        "secrets": None,
        "archive_meta": None,
        "webshell": None,
        "powershell": None,
        "source": None,
        "reputation": {"findings": [], "counts": {}, "categories": []},
    }

    def opt(key: str, default: Any = None) -> Any:
        return options.get(key, default)

    # --- Hashes ---
    try:
        from .hashes import compute_hashes
        out["hashes"] = compute_hashes(path) or {}
    except Exception as e:
        errors.append(f"hashes_error:{e}")

    # --- Entropy ---
    try:
        from .entropy import file_entropy
        out["entropy"]["file"] = file_entropy(path)
    except Exception as e:
        errors.append(f"entropy_error:{e}")

    # --- PE / ELF / Mach-O ---
    if kind == "PE":
        try:
            from .pe_hardening import analyze_pe_hardening
            from .entropy import sections_entropy_pe
            peinfo = analyze_pe_hardening(path)
            out["pe"] = {k: v for k, v in peinfo.items() if k != "errors"}
            if peinfo.get("errors"):
                errors.extend(peinfo["errors"])
            out["entropy"]["sections"] = sections_entropy_pe(path)
        except Exception as e:
            errors.append(f"pe_error:{e}")
    elif kind == "ELF":
        try:
            from .elf_checksec import analyze_elf_checksec
            from .entropy import sections_entropy_elf
            elfinfo = analyze_elf_checksec(path)
            out["elf"] = {k: v for k, v in elfinfo.items() if k != "errors"}
            if elfinfo.get("errors"):
                errors.extend(elfinfo["errors"])
            out["entropy"]["sections"] = sections_entropy_elf(path)
        except Exception as e:
            errors.append(f"elf_error:{e}")
    elif kind == "MACHO":
        try:
            from .macho_checksec import analyze as analyze_macho_checksec
            out["macho"] = analyze_macho_checksec(path)
        except Exception as e:
            errors.append(f"macho_error:{e}")

    out["entropy"].setdefault("sections", {})

    capa_sec = die_sec = yara_sec = 0.0
    yara_externals: Dict[str, Any] = {}

    if aggressive_skip:
        # Only hashes, entropy, YARA for large non-archive files
        if not opt("no_yara"):
            t_y = time.perf_counter()
            try:
                from .yara_scan import run_yara
                yara_hits = run_yara(
                    path,
                    rules_dir=opt("yara_rules"),
                    timeout_sec=int(opt("yara_timeout", 7)),
                    max_mb=int(opt("yara_max_mb", 0)),
                    max_hits=int(opt("yara_max_hits", 80)),
                    fast=bool(opt("yara_fast", True)),
                    use_builtin=not opt("yara_no_builtin"),
                    externals=yara_externals,
                )
                if yara_hits is not None:
                    out["yara"] = yara_hits
            except Exception as e:
                errors.append(f"yara_error:{e}")
            yara_sec = time.perf_counter() - t_y
        wall_sec = time.perf_counter() - t0
        out["_timing"] = {"wall_sec": wall_sec, "capa_sec": 0.0, "die_sec": 0.0, "yara_sec": yara_sec, "slowest": "yara" if yara_sec else "none", "aggressive_skip": True}
        return out

    # --- Smart gating (Trivage) ---
    skip_heavy = False
    try:
        from .smart_gate import should_skip_heavy_analysis
        skip_heavy = should_skip_heavy_analysis(
            kind,
            pe=out.get("pe"),
            elf=out.get("elf"),
            file_entropy=out["entropy"].get("file"),
        )
    except Exception:
        pass

    capa_timeout = int(opt("capa_timeout", CAPA_TIMEOUT))
    die_timeout = int(opt("die_timeout", DIE_TIMEOUT))

    # --- capa отложен до сбора YARA/DIE техник ---
    capa_prefilled_techniques: List[str] = []
    capa_prefilled_rule_hits: List[str] = []
    capa_sec = 0.0

    if skip_heavy:
        out["smart_gate_trusted"] = True  # валидная подпись + низкая энтропия → можно не тратить VT API

    # --- DIE (Detect It Easy) for packer/compiler detection ---
    if (not opt("no_die")) and kind in ("PE", "ELF", "MACHO") and not skip_heavy:
        t_die = time.perf_counter()
        try:
            from .die_scanner import run_die
            die_result, die_errs = run_die(
                path,
                timeout_sec=die_timeout,
                min_len=int(opt("die_min_len", 4)),
                max_mb=int(opt("die_max_mb", 50)),
            )
            if die_errs:
                errors.extend([f"die_{e}" for e in die_errs if "fallback" not in str(e).lower()])
            if die_result:
                out["die"] = die_result
                # Extract strings
                die_strings = die_result.get("strings") or []
                if die_strings:
                    out["strings"].setdefault("static", []).extend(die_strings[:500])
                # Update summary
                die_summary = die_result.get("strings_summary") or {}
                out["strings_summary"].update({
                    "total_cnt": int(die_summary.get("total_cnt") or len(die_strings)),
                    "static_cnt": int(die_summary.get("total_cnt") or len(die_strings)),
                    "url_cnt": int(die_summary.get("url_cnt") or 0),
                    "ip_cnt": int(die_summary.get("ip_cnt") or 0),
                    "cmd_cnt": int(die_summary.get("cmd_cnt") or 0),
                })
                # Update obfuscation from DIE
                die_packers = die_result.get("packer_families") or []
                if die_packers:
                    out["obfuscation"]["packed_suspect"] = True
                    out["obfuscation"]["packer_families"] = sorted(set(out["obfuscation"].get("packer_families", []) + die_packers))
                    out["obfuscation"]["reasons"] = list(set(out["obfuscation"].get("reasons", []) + ["die_packer_detected"]))
                    out["obfuscation"]["score"] = min(100, int(out["obfuscation"].get("score", 0)) + 25)
                die_entropy = die_result.get("entropy") or {}
                if die_entropy.get("file"):
                    out["obfuscation"]["max_section_entropy"] = die_entropy.get("file")
                # YARA externals
                total = out["strings_summary"].get("total_cnt", 0)
                yara_externals.update({
                    "die_total_cnt": total,
                    "die_has_strings": 1 if total > 0 else 0,
                    "die_packer_count": len(die_packers),
                })
        except Exception as e:
            errors.append(f"die_error:{e}")
        die_sec = time.perf_counter() - t_die

    # --- YARA ---
    if not opt("no_yara"):
        t_yara = time.perf_counter()
        try:
            from .yara_scan import run_yara
            yara_hits = run_yara(
                path,
                rules_dir=opt("yara_rules"),
                timeout_sec=int(opt("yara_timeout", 7)),
                max_mb=int(opt("yara_max_mb", 0)),
                max_hits=int(opt("yara_max_hits", 80)),
                fast=bool(opt("yara_fast", True)),
                use_builtin=not opt("yara_no_builtin"),
                externals=yara_externals,
            )
            if yara_hits is not None:
                out["yara"] = yara_hits
        except Exception as e:
            errors.append(f"yara_error:{e}")
        yara_sec = time.perf_counter() - t_yara

    # --- Packers + obfuscation ---
    try:
        from .packers_detect import detect_packers_from_yara
        packers = detect_packers_from_yara(out.get("yara") or [])
        if packers:
            out["obfuscation"]["reasons"] = list(set((out["obfuscation"].get("reasons") or []) + ["packer_signature"]))
            out["obfuscation"]["packed_suspect"] = True
            out["obfuscation"]["packer_families"] = sorted(set((out["obfuscation"].get("packer_families") or []) + packers))
            out["obfuscation"]["score"] = min(100, int(out["obfuscation"].get("score", 0)) + 30)
    except Exception as e:
        errors.append(f"packers_detect_error:{e}")

    if (not opt("no_obf")) and kind in ("PE", "ELF"):
        try:
            from .obfuscation import analyze_obfuscation
            sz = path.stat().st_size if path.exists() else 0
            obf_max_mb = int(opt("obf_max_mb", 50))
            if obf_max_mb <= 0 or (sz <= obf_max_mb * 1024 * 1024):
                obf = analyze_obfuscation(
                    path, kind,
                    pe_info=out.get("pe"),
                    elf_info=out.get("elf"),
                    die_info=out.get("die"),
                )
                if obf:
                    out["obfuscation"].update(obf)
        except Exception as e:
            errors.append(f"obf_error:{e}")

    # --- Сбор техник из YARA и DIE для capa ---
    if (not opt("no_capa")) and kind in ("PE", "ELF"):
        t_capa = time.perf_counter()
        try:
            # Извлечение техник из YARA
            if out.get("yara"):
                from .yara_scan import extract_all_techniques
                yara_techniques, yara_rule_hits = extract_all_techniques(out["yara"])
                capa_prefilled_techniques.extend(yara_techniques)
                capa_prefilled_rule_hits.extend(yara_rule_hits)

            # Извлечение техник из DIE
            if out.get("die"):
                from .die_scanner import extract_techniques_from_die
                die_techniques, die_rule_hits = extract_techniques_from_die(out["die"])
                capa_prefilled_techniques.extend(die_techniques)
                capa_prefilled_rule_hits.extend(die_rule_hits)

            # Вызов capa с предсобранными данными (быстрый режим по умолчанию)
            from .capa_analyzer import run_capa, ENABLE_DEEP_CAPA
            enable_deep = opt("deep_capa", False) or ENABLE_DEEP_CAPA

            capa_res = run_capa(
                path,
                timeout_sec=int(opt("capa_timeout", 45)),
                max_mb=int(opt("capa_max_mb", 0)),
                rules_dir=opt("capa_rules"),
                enable_deep=enable_deep,
                prefilled_techniques=list(set(capa_prefilled_techniques)),
                prefilled_rule_hits=capa_prefilled_rule_hits,
            )

            if capa_res.get("status") == "timeout":
                out["capa"] = {"status": "timeout", "techniques": capa_res.get("techniques", []), "rule_hits": capa_res.get("rule_hits", [])}
            else:
                out["capa"] = {
                    "techniques": capa_res.get("techniques", []),
                    "rule_hits": capa_res.get("rule_hits", []),
                    "source": capa_res.get("source", "unknown"),
                }

            if capa_res.get("errors"):
                errors.extend(capa_res["errors"])

        except Exception as e:
            errors.append(f"capa_error:{e}")
        capa_sec = time.perf_counter() - t_capa
    elif skip_heavy and kind in ("PE", "ELF"):
        out["capa"] = {"techniques": [], "rule_hits": [], "source": "skipped"}

    # --- Reputation ---
    if (not opt("no_reputation")) and opt("reputation_rules"):
        try:
            from .reputation_scan import run_reputation_scan
            rep = run_reputation_scan(
                path,
                rules_path=Path(opt("reputation_rules")),
                max_bytes=int(opt("reputation_max_bytes", 20971520)),
                min_str_len=int(opt("reputation_min_str", 4)),
            )
            if rep:
                out["reputation"] = rep
        except Exception as e:
            errors.append(f"reputation_error:{e}")

    # --- Light analyzers ---
    sfx = path.suffix.lower()
    base = path.name.lower()
    manifest_basenames = set(
        "requirements.txt pipfile pipfile.lock poetry.lock pyproject.toml package.json "
        "package-lock.json yarn.lock pnpm-lock.yaml go.mod go.sum cargo.toml cargo.lock "
        "pom.xml build.gradle build.gradle.kts gemfile gemfile.lock composer.json "
        "composer.lock pubspec.yaml pubspec.lock global.json nuget.config".split()
    )
    if base in manifest_basenames or sfx in (".csproj", ".vbproj", ".sln"):
        try:
            from .manifests import analyze as analyze_manifest
            out["manifest"] = analyze_manifest(path)
        except Exception as e:
            errors.append(f"manifest_error:{e}")

    try:
        from .secrets_scan import analyze as analyze_secrets
        out["secrets"] = analyze_secrets(path)
    except Exception as e:
        errors.append(f"secrets_error:{e}")

    if sfx in (".doc", ".docx", ".xlsx", ".pptx", ".pdf", ".lnk", ".ps1", ".js", ".vbs"):
        try:
            from .office_pdf_lnk import analyze as analyze_office_pdf_lnk
            out["docscripts"] = analyze_office_pdf_lnk(path)
        except Exception as e:
            errors.append(f"docscripts_error:{e}")

    if sfx in (".ps1", ".psm1", ".psd1"):
        try:
            from .powershell_analyzer import analyze as analyze_powershell
            out["powershell"] = analyze_powershell(path)
        except Exception as e:
            errors.append(f"powershell_error:{e}")

    if sfx in (".jar", ".apk", ".aab", ".whl", ".zip"):
        try:
            from .jar_apk_analyzer import analyze as analyze_jar_apk
            out["archive_meta"] = analyze_jar_apk(path)
        except Exception as e:
            errors.append(f"archive_meta_error:{e}")

    if sfx in (".php", ".asp", ".aspx", ".jsp"):
        try:
            from .webshell_scan import analyze as analyze_webshell
            out["webshell"] = analyze_webshell(path)
        except Exception as e:
            errors.append(f"webshell_error:{e}")

    # -------------------------------------------------------------------------
    # Advanced Malware Detection (v0.0.8)
    # -------------------------------------------------------------------------
    emulation_sec = 0.0
    ti_sec = 0.0
    
    # Initialize v0.0.8 fields
    out["emulation"] = None
    out["threat_intel"] = None
    out["visual"] = None
    out["script_analysis"] = None
    
    # --- Emulation (Speakeasy) ---
    if opt("emulation", False) and kind == "PE" and not skip_heavy:
        t_emu = time.perf_counter()
        try:
            from .emulation import run_emulation, merge_emulation_to_capa
            emu_timeout = int(opt("emulation_timeout", EMULATION_TIMEOUT))
            emu_max_mb = int(opt("emulation_max_mb", 50))
            
            if emu_max_mb <= 0 or (file_size <= emu_max_mb * 1024 * 1024):
                emu_result = run_emulation(
                    path,
                    timeout=emu_timeout,
                    enable=True,
                    file_type="PE",
                )
                if emu_result:
                    out["emulation"] = emu_result
                    # Merge emulation results into capa techniques
                    if out.get("capa"):
                        out["capa"] = merge_emulation_to_capa(emu_result, out["capa"])
                    # Push Speakeasy API interception results into supply_chain.dependencies
                    _emulation_deps: List[Dict[str, Any]] = []
                    import re as _re
                    for s in (emu_result.get("decoded_strings") or []):
                        if not isinstance(s, str):
                            continue
                        for m in _re.finditer(r"https?://[^\s<>\"'\]]+", s):
                            _emulation_deps.append({"type": "url", "value": m.group(0)[:500], "source": "emulation_decoded_strings"})
                    for conn in (emu_result.get("network") or []):
                        if isinstance(conn, dict):
                            for p in (conn.get("params") or [])[:3]:
                                ps = str(p).strip()
                                if _re.match(r"https?://", ps):
                                    _emulation_deps.append({"type": "url", "value": ps[:500], "source": "emulation_network"})
                    for key in ("created", "read", "written"):
                        for f in (emu_result.get("files") or {}).get(key) or []:
                            if isinstance(f, str) and f.strip():
                                _emulation_deps.append({"type": "file_ref", "value": f.strip()[:500], "source": f"emulation_files_{key}"})
                    if _emulation_deps:
                        out.setdefault("supply_chain", {}).setdefault("dependencies", []).extend(_emulation_deps)
        except Exception as e:
            errors.append(f"emulation_error:{e}")
        emulation_sec = time.perf_counter() - t_emu
    
    # --- Threat Intelligence ---
    if opt("ti", False):
        t_ti = time.perf_counter()
        try:
            from .threat_intel import analyze_threat_intel, merge_ti_to_reputation
            ti_timeout = int(opt("ti_timeout", TI_TIMEOUT))
            enable_dga = not opt("no_dga", False)
            
            # Collect strings from various sources
            all_strings: List[str] = []
            if out.get("strings") and out["strings"].get("static"):
                all_strings.extend(out["strings"]["static"][:1000])
            if out.get("die") and out["die"].get("strings"):
                all_strings.extend(out["die"]["strings"][:500])
            
            # Also add emulation network data if available
            emu_data = out.get("emulation")
            
            ti_result = analyze_threat_intel(
                strings=all_strings,
                emulation_data=emu_data,
                enable_ti=True,
                enable_dga=enable_dga,
                timeout=ti_timeout,
            )
            if ti_result:
                out["threat_intel"] = ti_result
                # Merge TI results into reputation
                if out.get("reputation"):
                    out["reputation"] = merge_ti_to_reputation(ti_result, out["reputation"])
        except Exception as e:
            errors.append(f"ti_error:{e}")
        ti_sec = time.perf_counter() - t_ti
    
    # --- Visual Analysis (PE icons) ---
    # Note: Icon extraction is already integrated into pe_hardening.py
    # We just need to populate the visual field from PE info if visual is enabled
    if opt("visual", True) and kind == "PE" and out.get("pe"):
        try:
            pe_info = out["pe"]
            visual_data: Dict[str, Any] = {
                "icon": pe_info.get("icon"),
                "resource_entropy": pe_info.get("resource_entropy"),
                "icon_mismatch": False,
                "masquerading_suspect": False,
            }
            # Check for masquerading
            icon_info = pe_info.get("icon") or {}
            if icon_info.get("masquerading"):
                visual_data["icon_mismatch"] = True
                visual_data["masquerading_suspect"] = True
                visual_data["masquerading_details"] = icon_info.get("masquerading_details")
                if "icon_masquerading" not in out["obfuscation"].get("reasons", []):
                    out["obfuscation"]["reasons"] = list(set(out["obfuscation"].get("reasons", []) + ["icon_masquerading"]))
                    out["obfuscation"]["score"] = min(100, int(out["obfuscation"].get("score", 0)) + 20)
            out["visual"] = visual_data
        except Exception as e:
            errors.append(f"visual_error:{e}")
    
    # --- Deep Script & Office Analysis ---
    if opt("deep_script", False) and sfx in (".doc", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".pdf", ".lnk", ".ps1", ".js", ".vbs", ".bat", ".cmd", ".sh"):
        try:
            from .office_pdf_lnk import analyze_deep as analyze_office_deep
            from .source_scripts import analyze_deep as analyze_script_deep
            
            script_analysis: Dict[str, Any] = {"deep_enabled": True}
            
            if sfx in (".doc", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".pdf", ".lnk"):
                deep_result = analyze_office_deep(path)
                script_analysis["office_deep"] = deep_result
                # Push referenced URLs and external resources to evidence.supply_chain.dependencies
                deps = deep_result.get("dependencies") or []
                if deps:
                    out.setdefault("supply_chain", {}).setdefault("dependencies", []).extend(deps)
                # Check for stagers
                if deep_result.get("stagers"):
                    script_analysis["stagers_detected"] = True
                    out["obfuscation"]["reasons"] = list(set(out["obfuscation"].get("reasons", []) + ["stager_detected"]))
                    out["obfuscation"]["score"] = min(100, int(out["obfuscation"].get("score", 0)) + 30)
            elif sfx in (".ps1", ".js", ".vbs", ".bat", ".cmd", ".sh"):
                deep_result = analyze_script_deep(path)
                script_analysis["script_deep"] = deep_result
                # Check for obfuscation indicators
                if deep_result.get("obfuscation", {}).get("is_obfuscated"):
                    out["obfuscation"]["reasons"] = list(set(out["obfuscation"].get("reasons", []) + ["script_obfuscation"]))
                    out["obfuscation"]["score"] = min(100, int(out["obfuscation"].get("score", 0)) + 25)
            
            out["script_analysis"] = script_analysis
        except Exception as e:
            errors.append(f"deep_script_error:{e}")

    wall_sec = time.perf_counter() - t0
    slowest = "capa" if capa_sec >= die_sec and capa_sec >= yara_sec else ("die" if die_sec >= yara_sec else "yara")
    if emulation_sec > capa_sec and emulation_sec > die_sec and emulation_sec > yara_sec:
        slowest = "emulation"
    out["_timing"] = {
        "wall_sec": wall_sec,
        "capa_sec": capa_sec,
        "die_sec": die_sec,
        "yara_sec": yara_sec,
        "emulation_sec": emulation_sec,
        "ti_sec": ti_sec,
        "slowest": slowest,
        "aggressive_skip": False,
    }
    return out
