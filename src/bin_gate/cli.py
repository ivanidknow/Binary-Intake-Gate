from __future__ import annotations
import sys, argparse, pathlib, os
from typing import List, Tuple, Optional

from .reporters.markdown import write_markdown_report
from .policy.loader import load_policy
from .policy.engine import evaluate_policy
from .evidence import new_evidence

from .analyzers.hashes import compute_hashes
from .analyzers.entropy import file_entropy, sections_entropy_pe, sections_entropy_elf
from .analyzers.pe_hardening import analyze_pe_hardening
from .analyzers.elf_checksec import analyze_elf_checksec
from .analyzers.capa_analyzer import run_capa, DEFAULT_TIMEOUT_SEC, DEFAULT_MAX_MB
from .analyzers.yara_scan import (
    run_yara,
    DEFAULT_TIMEOUT_SEC as YARA_DEF_TIMEOUT,
    DEFAULT_MAX_MB as YARA_DEF_MAX_MB,
    DEFAULT_MAX_HITS as YARA_DEF_MAX_HITS,
    DEFAULT_FAST_MODE as YARA_DEF_FAST,
    DEFAULT_USE_BUILTIN as YARA_DEF_BUILTIN,
)
from .reporters.sarif import write_sarif_report
from .reporters.github_checks import write_step_summary, emit_workflow_commands
from .reporters.human import write_human_report
from .cve.collector import collect_cve_for_file

# Stage 3: кэш + VT (в т.ч. upload через API/UI)
from .cache.sqlite_cache import Cache
from .integrations.virustotal import (
    vt_lookup_sha256,
    vt_upload_file_api,
    vt_poll_analysis,
    vt_extract_sha_from_analysis,
)
from .integrations.vt_full import vt_fetch_full_metrics
from .integrations.vt_playwright import vt_upload_file_ui

BINARY_EXTS = {
    ".exe", ".dll", ".sys", ".ocx", ".drv",
    ".elf", ".so", ".ko",
    ".dylib", ".bundle",
    ".bin", ".dat", ".out"
}

def sniff_magic(p: pathlib.Path) -> Tuple[bool, str]:
    # Return (is_binary, kind) where kind in {'PE','ELF','EXT','NONE'}
    try:
        with p.open("rb") as f:
            head = f.read(4)
        if len(head) >= 2 and head[0:2] == b"MZ":
            return True, "PE"
        if len(head) >= 4 and head[0:4] == b"\x7fELF":
            return True, "ELF"
    except Exception:
        return False, "NONE"
    if p.suffix.lower() in BINARY_EXTS:
        return True, "EXT"
    return False, "NONE"

def discover_files(root: pathlib.Path) -> list[pathlib.Path]:
    files: List[pathlib.Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        is_bin, _kind = sniff_magic(p)
        if is_bin:
            files.append(p)
    return files

def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    parser = argparse.ArgumentParser(
        prog="bin-gate",
        description="Binary Intake Gate — Stage 5 (Policy Engine + profiles; VT cache/upload; capa+YARA; CVE/OSV)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_scan = sub.add_parser("scan", help="Scan path and produce report + evidence.json")

    p_scan.add_argument("path", help="Path to scan (dir or file)")
    p_scan.add_argument("--policy", default=None, help="Path to policy.yaml (optional)")
    p_scan.add_argument("--out", default="report.md", help="Output Markdown report path")

    # capa knobs
    p_scan.add_argument("--no-capa", action="store_true", help="Disable capa analyzer")
    p_scan.add_argument("--capa-timeout", type=int, default=DEFAULT_TIMEOUT_SEC, help="Timeout seconds for capa (default env CAPA_TIMEOUT_SEC or 60)")
    p_scan.add_argument("--capa-max-mb", type=int, default=DEFAULT_MAX_MB, help="Skip capa if file bigger than N MB (default 0=no limit; env CAPA_MAX_MB)")
    p_scan.add_argument("--capa-rules", default=os.getenv("CAPA_RULES_DIR"), help="Path to capa rules directory (clone of capa-rules). Env: CAPA_RULES_DIR")

    # yara knobs
    p_scan.add_argument("--no-yara", action="store_true", help="Disable YARA analyzer")
    p_scan.add_argument("--yara-rules", default=os.getenv("YARA_RULES_DIR"), help="Path to directory with YARA rules (*.yar*)")
    p_scan.add_argument("--yara-timeout", type=int, default=YARA_DEF_TIMEOUT, help="YARA timeout seconds (default 7 or env YARA_TIMEOUT_SEC)")
    p_scan.add_argument("--yara-max-mb", type=int, default=YARA_DEF_MAX_MB, help="Skip YARA if file bigger than N MB (default 0=no limit; env YARA_MAX_MB)")
    p_scan.add_argument("--yara-max-hits", type=int, default=YARA_DEF_MAX_HITS, help="Cap YARA hits per file (default 80)")
    p_scan.add_argument("--yara-fast", action="store_true", default=YARA_DEF_FAST, help="YARA fast mode (stop at first match per rule)")
    p_scan.add_argument("--yara-no-builtin", action="store_true", help="Do not use builtin rules if rules dir is empty")

    # offline / cache
    p_scan.add_argument("--no-network", action="store_true", help="Disable network calls (VT UI/API); cache still used for reads")
    p_scan.add_argument("--cache-db", default=None, help="Path to cache sqlite (default: user cache dir)")

    # VT lookup/upload
    p_scan.add_argument("--no-vt", action="store_true", help="Disable VirusTotal lookups")
    p_scan.add_argument("--vt-api-key", default=os.getenv("VT_API_KEY"), help="VT API key (env VT_API_KEY)")
    p_scan.add_argument("--vt-timeout", type=int, default=20, help="VT HTTP timeout (s)")
    p_scan.add_argument("--vt-min-interval", type=float, default=15.0, help="Min seconds between VT requests")
    p_scan.add_argument("--vt-ttl-hours", type=int, default=24*7, help="Cache TTL for VT (hours)")

    p_scan.add_argument("--vt-upload", action="store_true", help="If VT hash not found, try uploading the file")
    p_scan.add_argument("--vt-upload-mode", choices=["auto","api","ui"], default="auto", help="Upload strategy: api/ui/auto")
    p_scan.add_argument("--vt-ui-browser", default="chromium", help="Playwright browser (chromium/firefox/webkit)")
    p_scan.add_argument("--vt-ui-headed", action="store_true", help="Playwright headed mode (solve captcha if shown)")
    p_scan.add_argument("--vt-ui-timeout", type=int, default=180, help="Playwright upload timeout (s)")

    # policy profile
    p_scan.add_argument("--profile", choices=["dev","staging","prod"], default=os.getenv("BIN_GATE_PROFILE","dev"),
                        help="Policy profile (dev/staging/prod). Env: BIN_GATE_PROFILE")
    p_scan.add_argument("--human-out", default=None, help="Path to human-friendly report (Markdown, RU)")
    
    # Stage 5 reporters
    p_scan.add_argument("--sarif-out", default=None, help="Write SARIF v2.1.0 report to this path (e.g., sarif.json)")
    p_scan.add_argument("--gh-summary", action="store_true", help="Append a summary to $GITHUB_STEP_SUMMARY (GitHub Actions)")
    p_scan.add_argument("--gh-annotations", action="store_true", help="Emit ::warning/::error annotations for GitHub Actions")
    p_scan.add_argument("--fail-on", choices=["none","warn","deny"], default=os.getenv("BIN_GATE_FAIL_ON","none"),
                        help="Exit non-zero if at least one file reaches this level")
    
    # CVE (Stage 9)
    # CVE knobs
    p_scan.add_argument("--no-cve", action="store_true", help="Disable CVE lookup via OSV")
    p_scan.add_argument("--cve-ecosystem", choices=["Debian","Ubuntu","Alpine","RedHat"], default=os.getenv("CVE_ECOSYSTEM"),
                        help="Target OS package ecosystem for ELF deps (e.g., Debian/Ubuntu/Alpine/RedHat)")
    p_scan.add_argument("--cve-inventory", default=os.getenv("CVE_INVENTORY"),
                        help="Path to JSON with installed packages [{ecosystem,name,version},...]")
    p_scan.add_argument("--cve-libmap", default=os.getenv("CVE_LIBMAP"),
                        help="Path to JSON with lib->package mapping overrides per ecosystem")
    p_scan.add_argument("--cve-timeout", type=int, default=15, help="OSV request timeout (s)")
    p_scan.add_argument("--cve-max-per-pkg", type=int, default=20, help="Limit advisories per package")
    p_scan.add_argument("--cve-resolve", default=os.getenv("CVE_RESOLVE","auto"),
                        choices=["auto","dpkg","rpm","apk","pacman","none"],
                        help="How to resolve ELF library to distro package")
    p_scan.add_argument("--dll-scan-depth", type=int, default=int(os.getenv("DLL_SCAN_DEPTH","2")), help="PE deep DLL scan max depth")
    p_scan.add_argument("--dll-scan-max", type=int, default=int(os.getenv("DLL_SCAN_MAX","200")), help="PE deep DLL scan max files")

    args = parser.parse_args(argv)

    if args.cmd == "scan":
        root = pathlib.Path(args.path).resolve()
        if not root.exists():
            print(f"[bin-gate] path not found: {root}", file=sys.stderr)
            return 2

        if root.is_file():
            is_bin, kind = sniff_magic(root)
            files = [root] if is_bin else []
        else:
            files = discover_files(root)

        # кэш VT
        cache = Cache(pathlib.Path(args.cache_db)) if args.cache_db else Cache()
        vt_ttl = max(0, int(args.vt_ttl_hours)) * 3600

        # policy: загрузим заранее и проставим активный профиль
        policy = load_policy(args.policy) if args.policy else {
            "version": 2,
            "profiles": {"dev": {"thresholds": {"deny": 80, "warn": 40}}},
            "rules": []
        }
        policy["profile"] = args.profile  # чтобы репортёр видел активный профиль

        evidences = []
        for fp in files:
            _, kind = sniff_magic(fp)
            ev = new_evidence(fp, kind)

            # hashes
            try:
                ev.hashes = compute_hashes(fp)
            except Exception as e:
                ev.errors.append(f"hashes_error:{e}")

            # entropy
            try:
                ev.entropy = {"file": file_entropy(fp)}
            except Exception as e:
                ev.errors.append(f"entropy_error:{e}")
                ev.entropy = {"file": None}

            # type-specific
            if kind == "PE":
                try:
                    peinfo = analyze_pe_hardening(fp)
                    ev.pe = {k: v for k, v in peinfo.items() if k not in ("errors",)}
                    if peinfo.get("errors"):
                        ev.errors.extend(peinfo["errors"])
                    ev.entropy["sections"] = sections_entropy_pe(fp)
                except Exception as e:
                    ev.errors.append(f"pe_error:{e}")
            elif kind == "ELF":
                try:
                    elfinfo = analyze_elf_checksec(fp)
                    ev.elf = {k: v for k, v in elfinfo.items() if k not in ("errors",)}
                    if elfinfo.get("errors"):
                        ev.errors.extend(elfinfo["errors"])
                    ev.entropy["sections"] = sections_entropy_elf(fp)
                except Exception as e:
                    ev.errors.append(f"elf_error:{e}")
            else:
                ev.entropy.setdefault("sections", {})

            # capa (with timeout/limits)
            if not args.no_capa and kind in ("PE", "ELF"):
                try:
                    capa_res = run_capa(fp, timeout_sec=args.capa_timeout, max_mb=args.capa_max_mb, rules_dir=args.capa_rules)
                    ev.capa = {"techniques": capa_res.get("tactics", []), "rule_hits": capa_res.get("rule_hits", [])}
                    if capa_res.get("errors"):
                        ev.errors.extend(capa_res["errors"])
                except Exception as e:
                    ev.errors.append(f"capa_error:{e}")

            # YARA
            if not args.no_yara:
                try:
                    yara_hits = run_yara(
                        fp,
                        rules_dir=args.yara_rules,
                        timeout_sec=args.yara_timeout,
                        max_mb=args.yara_max_mb,
                        max_hits=args.yara_max_hits,
                        fast=bool(args.yara_fast),
                        use_builtin=not args.yara_no_builtin,
                        externals=None,  # можно прокинуть overlay_pct и т.п. позже
                    )
                    if yara_hits is not None:
                        ev.yara = yara_hits
                except Exception as e:
                    ev.errors.append(f"yara_error:{e}")


            # ---- CVE (ELF/PE) via OSV

            if (not args.no_cve):
                try:
                    eco = args.cve_ecosystem
                    inv = pathlib.Path(args.cve_inventory).resolve() if args.cve_inventory else None
                    lmap = pathlib.Path(args.cve_libmap).resolve() if args.cve_libmap else None
                    cve_doc = collect_cve_for_file(fp, ev.to_dict(), ecosystem=eco, inventory_path=inv, libmap_path=lmap, osv_timeout_sec=int(args.cve_timeout))
                    # положим summary/items в evidence
                    if cve_doc:
                        ev.cve = {"summary": cve_doc.get("summary", {}), "items": cve_doc.get("items", [])}
                        # Примечания/ошибки не мешаем в вывод политики, но добавим в errors
                        for note in cve_doc.get("notes", []) or []:
                            ev.errors.append(f"cve_note:{note}")
                except Exception as e:
                    ev.errors.append(f"cve_error:{e}")

            # ---- VT: cache → lookup → (optional upload) → full metrics → cache
            sha256 = (ev.hashes or {}).get("sha256")
            if sha256 and not args.no_vt:
                # сперва читаем кэш полноты
                cached = cache.get("vt_full", sha256, None if vt_ttl == 0 else vt_ttl)
                if cached is not None:
                    cached["_cached"] = True
                    ev.vt = cached
                elif not args.no_network:
                    vt_data = None
                    # lookup по хэшу
                    if args.vt_api_key:
                        summary, errs = vt_lookup_sha256(
                            sha256,
                            api_key=args.vt_api_key,
                            timeout_sec=args.vt_timeout,
                            min_interval_sec=args.vt_min_interval
                        )
                        if errs:
                            ev.errors.extend(errs)
                    else:
                        summary = None
                        ev.errors.append("vt_no_api_key")

                    if summary and summary.get("found"):
                        # тянем детальные метрики
                        data, errs2 = vt_fetch_full_metrics(
                            sha256,
                            api_key=args.vt_api_key,
                            timeout_sec=args.vt_timeout,
                            min_interval_sec=args.vt_min_interval
                        )
                        if errs2:
                            ev.errors.extend(errs2)
                        vt_data = data
                    else:
                        # not found → опциональный upload
                        if args.vt_upload:
                            uploaded_sha = None
                            order = ["api", "ui"] if args.vt_upload_mode == "auto" else [args.vt_upload_mode]
                            for mode in order:
                                if mode == "api" and args.vt_api_key:
                                    analysis_id, uerrs = vt_upload_file_api(fp, api_key=args.vt_api_key, timeout_sec=max(60, args.vt_timeout))
                                    if uerrs:
                                        ev.errors.extend(uerrs)
                                    if analysis_id:
                                        adoc, perrs = vt_poll_analysis(analysis_id, api_key=args.vt_api_key, timeout_total_sec=300)
                                        if perrs:
                                            ev.errors.extend(perrs)
                                        if adoc:
                                            uploaded_sha = vt_extract_sha_from_analysis(adoc)
                                elif mode == "ui":
                                    usha, uerrs = vt_upload_file_ui(
                                        fp,
                                        browser=args.vt_ui_browser,
                                        headless=(not args.vt_ui_headed),
                                        timeout_sec=args.vt_ui_timeout
                                    )
                                    if uerrs:
                                        ev.errors.extend(uerrs)
                                    uploaded_sha = usha

                                if uploaded_sha:
                                    data, errs3 = vt_fetch_full_metrics(
                                        uploaded_sha,
                                        api_key=args.vt_api_key,
                                        timeout_sec=args.vt_timeout,
                                        min_interval_sec=args.vt_min_interval
                                    )
                                    if errs3:
                                        ev.errors.extend(errs3)
                                    vt_data = data
                                    break

                    if vt_data:
                        vt_data["_cached"] = False
                        ev.vt = vt_data
                        cache.put("vt_full", vt_data.get("sha256", sha256), vt_data)

            # --- POLICY EVALUATION (Stage 4)
            ev_dict = ev.to_dict()
            ev_dict.setdefault("meta", {})["profile"] = args.profile
            try:
                polres = evaluate_policy(ev_dict, policy or {}, profile=args.profile)
            except Exception as e:
                polres = {"decision": "allow", "score": 0, "reasons": [f"policy_engine_error:{e}"], "matched": []}
            ev_dict["policy"] = polres

            evidences.append(ev_dict)

        # Stage label -> 5
        summary = {"stage": "5", "profile": policy.get("profile", args.profile), "scanned": len(files)}

        # Markdown как раньше
        write_markdown_report(pathlib.Path(args.out), files, summary, policy, evidences=evidences)

        if args.human_out:
            try:
                write_human_report(
                    pathlib.Path(args.human_out),
                    files,
                    summary,
                    policy,
                    evidences=evidences,
                    profile=policy.get("profile", getattr(args, "profile", "dev")),
                    capa_timeout=int(getattr(args, "capa_timeout", 120)),
                )
            except Exception as e:
                print(f"[bin-gate] human report error: {e}", file=sys.stderr)

        # SARIF (если попросили)
        if args.sarif_out:
            write_sarif_report(pathlib.Path(args.sarif_out), evidences)

        # GitHub Step Summary (если в Actions)
        if args.gh_summary:
            write_step_summary(evidences, summary, profile=summary["profile"])

        # GitHub Annotations (если нужно)
        if args.gh_annotations:
            emit_workflow_commands(evidences)

        # Итоговый exit code по порогу
        exit_code = 0
        if args.fail_on != "none":
            for ev in evidences:
                dec = (ev.get("policy") or {}).get("decision")
                if args.fail_on == "deny" and dec == "deny":
                    exit_code = 1; break
                if args.fail_on == "warn" and dec in ("warn", "deny"):
                    exit_code = 1; break

        print(f"[bin-gate] Stage 5 complete: {len(files)} file(s), report -> {args.out}"
            f"{' ; sarif -> ' + args.sarif_out if args.sarif_out else ''}")
        return exit_code

    return 1
