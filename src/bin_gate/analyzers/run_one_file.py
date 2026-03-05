# run_one_file.py — single-file analysis for ProcessPoolExecutor worker
# Used by orchestrate: returns full evidence dict (no VT/CVE). Hard timeouts applied.
from __future__ import annotations
import os
import threading
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple

_emu_log_lock = threading.Lock()


def _emu_dbg(msg: str) -> None:
    """Append a line to cli_debug.log for emulation debugging (worker-safe)."""
    with _emu_log_lock:
        try:
            log_path = os.path.join(os.getcwd(), "cli_debug.log")
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass

# Hard timeouts (seconds) so one binary cannot block the pipeline
CAPA_TIMEOUT = int(__import__("os").getenv("CAPA_TIMEOUT_SEC", "120"))
DIE_TIMEOUT = int(__import__("os").getenv("DIE_TIMEOUT_SEC", "60"))

# v0.0.8 Advanced Malware Detection timeouts
EMULATION_TIMEOUT = int(__import__("os").getenv("BIN_GATE_EMULATION_TIMEOUT", "60"))
TI_TIMEOUT = int(__import__("os").getenv("BIN_GATE_TI_TIMEOUT", "30"))

# Aggressive gating: files > 50 MB that are not archive/MSI run only hashes, entropy, YARA
AGGRESSIVE_GATE_MB = 50
# v2.0: файлы > 200 МБ — бинарный padding (T1027.001), ленивый анализ без загрузки в память
GIANT_FILE_THRESHOLD_BYTES = 200 * 1024 * 1024
ARCHIVE_MSI_SUFFIXES = frozenset({".zip", ".msi", ".jar", ".apk", ".aab", ".7z", ".rar", ".tar", ".gz", ".tgz", ".whl", ".nupkg", ".msix", ".appx", ".vsix", ".deb", ".rpm", ".ova", ".ovf"})


def run_one_file_analysis(
    path: Path,
    kind: str,
    options: Dict[str, Any],
    yara_input_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Run all CPU-bound and local analyzers for one file. Returns evidence-like dict
    (no vt, no cve). All subprocess calls use hard timeouts. Errors go to evidence["errors"].
    yara_input_path: если задан (e.g. распакованный UPX), YARA запускается по нему вместо path.
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
    is_giant = file_size > GIANT_FILE_THRESHOLD_BYTES
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
    if is_giant:
        out["binary_padding"] = {
            "detected": True,
            "size_mb": round(file_size / (1024 * 1024), 2),
            "lazy_analyzed": True,
            "mitre": "T1027.001",
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
            # Кроссплатформенная проверка подписи и отзыва (osslsigncode + OCSP)
            try:
                from .signing_trust import analyze as analyze_signing_trust
                st = analyze_signing_trust(path)
                sig = out["pe"].setdefault("signature", {})
                if st.get("revoked") is not None:
                    sig["revoked"] = st["revoked"]
                if st.get("valid") is not None and sig.get("valid") is None:
                    sig["valid"] = st["valid"]
            except Exception as e2:
                errors.append(f"signing_trust_error:{e2}")
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
            _yara_path = (yara_input_path if yara_input_path and yara_input_path.exists() else path)
            try:
                from .yara_scan import run_yara
                yara_hits = run_yara(
                    _yara_path,
                    rules_dir=opt("yara_rules"),
                    timeout_sec=int(opt("yara_timeout", 7)),
                    max_mb=int(opt("yara_max_mb", 0)),
                    max_hits=int(opt("yara_max_hits", 80)),
                    fast=bool(opt("yara_fast", True)),
                    use_builtin=not opt("yara_no_builtin"),
                    externals=yara_externals,
                )
                if yara_hits is not None:
                    _seen: Set[Tuple[str, str]] = set()
                    _deduped: List[Dict[str, Any]] = []
                    for h in yara_hits:
                        if not isinstance(h, dict):
                            _deduped.append(h)
                            continue
                        _key = (str(h.get("rule", "")), str(h.get("namespace", "")))
                        if _key not in _seen:
                            _seen.add(_key)
                            _deduped.append(h)
                    out["yara"] = _deduped
            except Exception as e:
                errors.append(f"yara_error:{e}")
            yara_sec = time.perf_counter() - t_y
        # v3.0: потоковый анализ гигантских файлов — карта энтропии + YARA по островам (энтропия > 6.0)
        if is_giant:
            try:
                from .streaming_scanner import streaming_entropy_and_yara
                max_chunks = min(2048, (file_size // (1024 * 1024)) + 1) if file_size else 2048
                stream_res = streaming_entropy_and_yara(
                    path,
                    rules_dir=opt("yara_rules"),
                    max_chunks=max_chunks,
                )
                out["streaming_scan"] = stream_res
                island_hits = stream_res.get("yara_island_hits") or []
                if island_hits:
                    out.setdefault("yara", [])
                    out["yara"].extend(island_hits)
            except Exception as e:
                errors.append(f"streaming_scan_error:{e}")
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

    # --- YARA (при pre_analysis_dispatch UPX используем распакованный файл) ---
    if not opt("no_yara"):
        t_yara = time.perf_counter()
        yara_path = (yara_input_path if yara_input_path and yara_input_path.exists() else path)
        try:
            from .yara_scan import run_yara
            yara_hits = run_yara(
                yara_path,
                rules_dir=opt("yara_rules"),
                timeout_sec=int(opt("yara_timeout", 7)),
                max_mb=int(opt("yara_max_mb", 0)),
                max_hits=int(opt("yara_max_hits", 80)),
                fast=bool(opt("yara_fast", True)),
                use_builtin=not opt("yara_no_builtin"),
                externals=yara_externals,
            )
            if yara_hits is not None:
                # Дедупликация по (rule, namespace), чтобы правила вроде IsPE32 не дублировались в highlights
                seen: Set[Tuple[str, str]] = set()
                deduped: List[Dict[str, Any]] = []
                for h in yara_hits:
                    if not isinstance(h, dict):
                        deduped.append(h)
                        continue
                    key = (str(h.get("rule", "")), str(h.get("namespace", "")))
                    if key not in seen:
                        seen.add(key)
                        deduped.append(h)
                out["yara"] = deduped
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
                # Entropy trigger: > 7.2 → High Risk Obfuscated, требуется manual review
                try:
                    from .entropy import file_entropy
                    file_e = out.get("entropy", {}).get("file") or (file_entropy(path) if path.exists() else None)
                    max_sec = out.get("obfuscation", {}).get("max_section_entropy")
                    if (max_sec is not None and float(max_sec) > 7.2) or (file_e is not None and float(file_e) > 7.2):
                        out.setdefault("obfuscation", {})["manual_review_required"] = True
                except Exception:
                    pass
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
                out["capa"] = {"status": "timeout", "techniques": capa_res.get("techniques", []), "rule_hits": capa_res.get("rule_hits", []), "attck_by_tactic": capa_res.get("attck_by_tactic", {})}
            else:
                out["capa"] = {
                    "techniques": capa_res.get("techniques", []),
                    "rule_hits": capa_res.get("rule_hits", []),
                    "attck_by_tactic": capa_res.get("attck_by_tactic", {}),
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
            if out["docscripts"] and out["docscripts"].get("technique_hints"):
                out["technique_hints"] = list(out["docscripts"].get("technique_hints") or [])
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
        # v2.0 T1027.006 Tauri/WebView smuggling: assets с обфусцированным JS
        try:
            from .tauri_webview import analyze_archive_for_tauri_webview
            tw = analyze_archive_for_tauri_webview(path)
            if tw.get("detected"):
                out["tauri_webview_smuggling"] = tw
                th = out.get("technique_hints") or []
                if "T1027.006" not in th:
                    out["technique_hints"] = sorted(set(th + ["T1027.006"]))
        except Exception as e:
            errors.append(f"tauri_webview_error:{e}")

    if sfx in (".php", ".asp", ".aspx", ".jsp"):
        try:
            from .webshell_scan import analyze as analyze_webshell
            out["webshell"] = analyze_webshell(path)
        except Exception as e:
            errors.append(f"webshell_error:{e}")

    # -------------------------------------------------------------------------
    # Short-circuit: если статика уже дала критическую малварь — не запускать эмуляцию (Enterprise Fast-fail)
    # -------------------------------------------------------------------------
    def _static_critical_deny(ev: Dict[str, Any]) -> bool:
        for h in ev.get("yara") or []:
            if not isinstance(h, dict):
                continue
            ns = (h.get("namespace") or "").lower()
            meta = h.get("meta") or {}
            cat = str(meta.get("category") or meta.get("family") or "").lower()
            if "malware" in ns or "malware" in cat:
                return True
        pe = ev.get("pe") or {}
        if isinstance(pe, dict) and (pe.get("signature") or {}).get("revoked") is True:
            return True
        return False

    if _static_critical_deny(out):
        out["short_circuit_deny"] = True

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

    # --- Emulation (Speakeasy): пропуск при short_circuit_deny ---
    # Решение по эмуляции: unpacker_orchestrator (UPX/MPRESS → static; Themida/VMProtect → aggressive_emulation)
    _force_emulation_advanced = False
    _extended_protector_120 = False
    try:
        from .unpacker_orchestrator import get_unpack_decision
        decision = get_unpack_decision(path, die_info=out.get("die"), obfuscation=out.get("obfuscation"))
        if decision.get("aggressive_emulation"):
            _force_emulation_advanced = True
            families = decision.get("packer_families") or []
            if any(x in str(p).lower() for p in families for x in ("themida", "enigma", "obsidium")):
                _extended_protector_120 = True
    except Exception:
        pass
    if not _force_emulation_advanced:
        from .emulation import ADVANCED_PROTECTOR_EXTENDED_NAMES
        die = out.get("die") or {}
        for d in die.get("detects") or []:
            name = (d.get("name") or d.get("sName") or "") if isinstance(d, dict) else str(d)
            name_lower = name.lower()
            if "vmprotect" in name_lower or "themida" in name_lower or "enigma" in name_lower or "obsidium" in name_lower:
                _force_emulation_advanced = True
                if any(x in name_lower for x in ADVANCED_PROTECTOR_EXTENDED_NAMES):
                    _extended_protector_120 = True
                break
    if not _force_emulation_advanced:
        obf = out.get("obfuscation") or {}
        if isinstance(obf, dict):
            packers = obf.get("packer_families") or []
            for p in packers:
                pl = str(p).lower()
                if "vmprotect" in pl or "themida" in pl or "enigma" in pl or "obsidium" in pl:
                    _force_emulation_advanced = True
                    if any(x in pl for x in ADVANCED_PROTECTOR_EXTENDED_NAMES):
                        _extended_protector_120 = True
                    break
    # Высокая энтропия (libEngine13.so и др.) — форсируем эмуляцию для получения memory dump
    if not _force_emulation_advanced:
        _entropy_threshold = 7.2
        obf = out.get("obfuscation") or {}
        ent = out.get("entropy") or {}
        if isinstance(obf, dict) and obf.get("max_section_entropy") is not None and float(obf.get("max_section_entropy", 0)) > _entropy_threshold:
            _force_emulation_advanced = True
        elif isinstance(ent, dict) and ent.get("file") is not None and float(ent.get("file", 0)) > _entropy_threshold:
            _force_emulation_advanced = True
    BIN_GATE_ENABLE_EMULATION = os.getenv("BIN_GATE_ENABLE_EMULATION", "")
    _emu_dbg(f"[emu_dbg] Attempting emulation for {path}, enabled={BIN_GATE_ENABLE_EMULATION}, opt(emulation)={opt('emulation', False)}, kind={kind}, skip_heavy={skip_heavy}, force_advanced={_force_emulation_advanced}, extended_120={_extended_protector_120}")
    _allow_elf_for_dump = _force_emulation_advanced and kind == "ELF"
    if not out.get("short_circuit_deny") and (opt("emulation", False) or _force_emulation_advanced) and (kind == "PE" or _allow_elf_for_dump) and (not skip_heavy or _force_emulation_advanced):
        t_emu = time.perf_counter()
        _emu_dbg(f"[emu_dbg] Starting emulation for {path} (force_advanced={_force_emulation_advanced}, extended_120={_extended_protector_120})")
        try:
            from .emulation import run_emulation, merge_emulation_to_capa
            emu_timeout = int(opt("emulation_timeout", EMULATION_TIMEOUT))
            emu_max_mb = int(opt("emulation_max_mb", 50))
            if _force_emulation_advanced or emu_max_mb <= 0 or (file_size <= emu_max_mb * 1024 * 1024):
                emu_result = run_emulation(
                    path,
                    timeout=emu_timeout,
                    enable=True,
                    file_type=kind if kind in ("PE", "ELF") else "PE",
                    complex_protector=_force_emulation_advanced,
                    extended_protector=_extended_protector_120,
                )
                # Всегда сохраняем объект эмуляции (даже при пустых api_calls), чтобы репортер мог поставить [X]
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
                    # DLL names from emulation (right after emulation.run): for Grype injection when Syft returns 0
                    _dll_pat = _re.compile(r"[a-zA-Z0-9_.\-]+\.dll", _re.IGNORECASE)
                    _dll_seen: set = set()
                    for _s in list((emu_result.get("api_summary") or {}).keys()) + (emu_result.get("decoded_strings") or []):
                        if not isinstance(_s, str):
                            continue
                        for _m in _dll_pat.finditer(_s):
                            _name = _m.group(0).strip()
                            if len(_name) <= 256 and _name not in _dll_seen:
                                _dll_seen.add(_name)
                                _emulation_deps.append({"type": "dynamic_lib", "value": _name, "source": "emulation_speakeasy_strings"})
                    if _emulation_deps:
                        out.setdefault("supply_chain", {}).setdefault("dependencies", []).extend(_emulation_deps)
        except Exception as e:
            errors.append(f"emulation_error:{e}")
            # Возвращаем объект эмуляции даже при ошибке, чтобы репортер отметил этап как выполненный [X]
            out["emulation"] = {"api_calls": [], "error": str(e), "techniques": []}
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

    # --- v3.2 Deep OSINT: извлечение IoC + обогащение (AbuseIPDB/Whois) ---
    try:
        from .osint_analyzer import analyze_osint
        osint_result = analyze_osint(out, options)
        if osint_result:
            out["osint"] = osint_result
    except Exception as e:
        errors.append(f"osint_error:{e}")

    # --- v3.2 Supply Chain Guard: hash matching OSS, typosquatting ---
    try:
        from .supply_chain_guard import analyze_supply_chain_guard
        deps = (out.get("supply_chain") or {}).get("dependencies") or []
        if deps:
            guard_result = analyze_supply_chain_guard(deps)
            out["supply_chain_guard"] = guard_result
            if guard_result.get("tampering_suspected") and out.get("pe"):
                out["pe"].setdefault("behavior_hints", {})["supply_chain_tampering"] = True
    except Exception as e:
        errors.append(f"supply_chain_guard_error:{e}")

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
            # Check for masquerading (icon document + PE executable)
            icon_info = pe_info.get("icon") or {}
            if icon_info.get("masquerading") or icon_info.get("mismatch_detected"):
                visual_data["icon_mismatch"] = True
                visual_data["masquerading_suspect"] = True
                visual_data["masquerading"] = True
                visual_data["masquerading_details"] = icon_info.get("masquerading_details") or icon_info.get("mismatch_type")
                if "icon_masquerading" not in out["obfuscation"].get("reasons", []):
                    out["obfuscation"]["reasons"] = list(set(out["obfuscation"].get("reasons", []) + ["icon_masquerading"]))
                    out["obfuscation"]["score"] = min(100, int(out["obfuscation"].get("score", 0)) + 20)
            # Жёсткая проверка: расширение документа (.xlsx, .docx, .pdf, .txt), а фактический тип — PE
            doc_extensions = (".xlsx", ".docx", ".doc", ".xls", ".pptx", ".ppt", ".pdf", ".txt", ".docm", ".xlsm", ".pptm")
            if kind == "PE" and sfx.lower() in doc_extensions and not visual_data.get("masquerading_suspect"):
                visual_data["icon_mismatch"] = True
                visual_data["masquerading_suspect"] = True
                visual_data["masquerading"] = True
                visual_data["masquerading_details"] = "document_extension_pe_executable"
                if "icon_masquerading" not in out["obfuscation"].get("reasons", []):
                    out["obfuscation"]["reasons"] = list(set(out["obfuscation"].get("reasons", []) + ["icon_masquerading"]))
                    out["obfuscation"]["score"] = min(100, int(out["obfuscation"].get("score", 0)) + 20)
            out["visual"] = visual_data
            # Для Masquerading 2.0 и Визуального аудита: явно задаём icon_type и file_type
            if isinstance(visual_data, dict):
                visual_data["icon_type"] = (icon_info.get("icon_type") or icon_info.get("mismatch_type") or "").strip() or "Unknown"
                visual_data["file_type"] = "PE Executable" if kind == "PE" else (out.get("meta", {}).get("type") or "Unknown")
        except Exception as e:
            errors.append(f"visual_error:{e}")

    # --- Persistence Logic (автозагрузка: Run, RunOnce, Winlogon, Services, Task Scheduler) ---
    try:
        from .persistence_logic import analyze_persistence
        persist_strings: List[str] = []
        if out.get("strings") and out["strings"].get("static"):
            persist_strings.extend(out["strings"]["static"][:1500])
        if out.get("die") and out["die"].get("strings"):
            persist_strings.extend(out["die"]["strings"][:500])
        if out.get("emulation") and (out["emulation"].get("decoded_strings") or []):
            persist_strings.extend(out["emulation"]["decoded_strings"][:300])
        if persist_strings:
            out["persistence_analysis"] = analyze_persistence(persist_strings)
    except Exception as e:
        errors.append(f"persistence_analysis_error:{e}")

    # --- Network Profile (DoH / sneaky network) ---
    try:
        from .network_profile import analyze_network_profile
        net_strings: List[str] = []
        if out.get("strings") and out["strings"].get("static"):
            net_strings.extend(out["strings"]["static"][:1500])
        if out.get("die") and out["die"].get("strings"):
            net_strings.extend(out["die"]["strings"][:500])
        if out.get("emulation") and (out["emulation"].get("decoded_strings") or []):
            net_strings.extend(out["emulation"]["decoded_strings"][:300])
        if net_strings:
            out["network_profile"] = analyze_network_profile(net_strings, ev=out)
    except Exception as e:
        errors.append(f"network_profile_error:{e}")

    # --- verified_by_behavior: подтверждение persistence/network данными emulation ---
    try:
        emu = out.get("emulation")
        if emu:
            if out.get("persistence_analysis"):
                from .persistence_logic import merge_persistence_with_emulation
                out["persistence_analysis"] = merge_persistence_with_emulation(out["persistence_analysis"], emu)
            if out.get("network_profile"):
                from .network_profile import merge_network_with_emulation
                out["network_profile"] = merge_network_with_emulation(out["network_profile"], emu)
    except Exception as e:
        errors.append(f"persistence_network_behavior_merge_error:{e}")

    # --- Language (DIE/YARA + language_detector сигнатуры) и диспетчеризация AutoIt → ресурсы ---
    try:
        from .language_analyzer import infer_language
        lang = infer_language(die_info=out.get("die"), yara_hits=out.get("yara"))
        if lang:
            out.setdefault("meta", {})["language"] = lang
        if not out.get("meta", {}).get("language"):
            from .language_detector import get_detection_and_route
            head_data: Optional[bytes] = None
            if out.get("binary_padding", {}).get("detected"):
                try:
                    from ..streaming_reader import read_head
                    head_data = read_head(path, 512 * 1024)
                except Exception:
                    pass
            det = get_detection_and_route(path=path, die_info=out.get("die"), yara_hits=out.get("yara"), data=head_data)
            if det.get("language"):
                out.setdefault("meta", {})["language"] = det["language"]
            if det.get("route_autoit_resources"):
                out.setdefault("meta", {})["route_autoit_resources"] = True
            if det.get("route_jar_in_pe"):
                out.setdefault("meta", {})["route_jar_in_pe"] = True
                if det.get("jar_in_pe_offset") is not None:
                    out.setdefault("meta", {})["jar_in_pe_offset"] = det["jar_in_pe_offset"]
        else:
            from .language_detector import should_scan_autoit_resources
            if should_scan_autoit_resources(language=out["meta"].get("language")):
                out.setdefault("meta", {})["route_autoit_resources"] = True
        # Исключения Go/Rust: убрать из YARA хиты по рантайм-правилам (FP)
        lang = out.get("meta", {}).get("language")
        if lang and out.get("yara"):
            from .language_rules import filter_yara_fp_by_language
            out["yara"] = filter_yara_fp_by_language(out["yara"], lang)
    except Exception as e:
        errors.append(f"language_analyzer_error:{e}")

    # --- PyInstaller overlay: извлечение имён упакованных файлов (pyinstaller_extractor) ---
    try:
        lang = (out.get("meta") or {}).get("language") or ""
        has_pyi = "pyinstaller" in lang.lower() or "pyi" in lang.lower()
        if not has_pyi and isinstance(out.get("yara"), list):
            for h in out.get("yara") or []:
                if "pyinstaller" in str(h.get("rule") or "").lower() or "pyi" in str(h.get("rule") or "").lower():
                    has_pyi = True
                    break
        if has_pyi:
            from .pyinstaller_extractor import extract_from_file
            pyi_result = extract_from_file(path)
            if pyi_result.get("has_pyi") or pyi_result.get("packed_names"):
                out["pyinstaller_overlay"] = pyi_result
    except Exception as e:
        errors.append(f"pyinstaller_extractor_error:{e}")

    # --- v2.0 Steganography (T1027.003): LSB в иконках/BMP; v3.0 расширенный JPEG/PNG/IAT ---
    if kind == "PE":
        try:
            from .steganography import analyze_file_resources as analyze_steganography
            stego_result = analyze_steganography(path)
            if stego_result:
                out["steganography"] = stego_result
        except Exception as e:
            errors.append(f"steganography_error:{e}")
    try:
        from .stego_detector import analyze_advanced as stego_advanced
        adv = stego_advanced(path)
        if adv.get("suspicious_media_metadata"):
            out["suspicious_media_metadata"] = True
            out.setdefault("steganography", {})["advanced"] = adv
    except Exception as e:
        errors.append(f"stego_detector_error:{e}")

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

    # --- v3.0 Python bytecode: AST + опасные вызовы (eval/exec/os.system/subprocess) ---
    if sfx == ".pyc":
        try:
            from .python_bytecode_analyzer import analyze_python_bytecode
            pybc = analyze_python_bytecode(path)
            out["python_bytecode"] = pybc
            if pybc.get("script_eval_detected"):
                out["script_eval_detected"] = True
            if pybc.get("dynamic_assembly_detected") and pybc.get("technique_hints"):
                th = out.get("technique_hints") or []
                out["technique_hints"] = sorted(set(th + pybc["technique_hints"]))
        except Exception as e:
            errors.append(f"python_bytecode_error:{e}")

    # --- v3.0 Lua bytecode: loadlib/ffi.load и загрузка динамических библиотек ---
    if sfx in (".luac", ".lua"):
        try:
            from .lua_analyzer import analyze_lua_bytecode
            lua_data = path.read_bytes() if path.exists() else None
            if lua_data and (sfx == ".luac" or lua_data.startswith(b"\x1bLua")):
                lua_res = analyze_lua_bytecode(path, lua_data)
                out["lua_bytecode"] = lua_res
        except Exception as e:
            errors.append(f"lua_bytecode_error:{e}")

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
