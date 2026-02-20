# orchestrate.py — parallel scan: cache → ProcessPoolExecutor → async VT → CVE
from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
import os
import threading
import logging
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed

# Evidence cache TTL (default 7 days); use same as VT if desired
EVIDENCE_TTL_SEC = int(os.getenv("BIN_GATE_EVIDENCE_TTL_SEC", str(7 * 24 * 3600)))

# Batching: files smaller than this are grouped into batches of BATCH_SIZE
SMALL_FILE_THRESHOLD_BYTES = 100 * 1024  # 100 KB
BATCH_SIZE = 50

# Default workers count (can be overridden via env or CLI)
DEFAULT_WORKERS = int(os.getenv("BIN_GATE_WORKERS", "4"))

# Thread-safe logging lock
_log_lock = threading.Lock()


def _thread_safe_log(msg: str, log_file: str = "cli_debug.log") -> None:
    """Thread-safe logging to file."""
    with _log_lock:
        try:
            log_path = os.path.join(os.getcwd(), log_file)
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass


def _build_options(args: Any) -> Dict[str, Any]:
    """Build serializable options dict for worker from argparse namespace."""
    return {
        "deep_scan": bool(getattr(args, "deep_scan", False)),
        "capa_timeout": int(getattr(args, "capa_timeout", 120)),
        "capa_max_mb": int(getattr(args, "capa_max_mb", 0)),
        "capa_rules": getattr(args, "capa_rules", None) or os.getenv("CAPA_RULES_DIR"),
        "no_capa": bool(getattr(args, "no_capa", False)),
        "floss_timeout": int(getattr(args, "floss_timeout", 60)),
        "floss_bin": getattr(args, "floss_bin", None) or os.getenv("FLOSS_BIN"),
        "floss_min_len": int(getattr(args, "floss_min_len", 4)),
        "floss_max_mb": int(getattr(args, "floss_max_mb", 16)),
        "no_floss": bool(getattr(args, "no_floss", False)),
        "yara_rules": getattr(args, "yara_rules", None) or os.getenv("YARA_RULES_DIR"),
        "yara_timeout": int(getattr(args, "yara_timeout", 7)),
        "yara_max_mb": int(getattr(args, "yara_max_mb", 0)),
        "yara_max_hits": int(getattr(args, "yara_max_hits", 80)),
        "yara_fast": bool(getattr(args, "yara_fast", True)),
        "yara_no_builtin": bool(getattr(args, "yara_no_builtin", False)),
        "no_obf": bool(getattr(args, "no_obf", False)),
        "obf_max_mb": int(getattr(args, "obf_max_mb", 50)),
        "no_reputation": bool(getattr(args, "no_reputation", True)),
        "reputation_rules": getattr(args, "reputation_rules", None) or os.getenv("REPUTATION_RULES"),
        "reputation_max_bytes": int(getattr(args, "reputation_max_bytes", 20971520)),
        "reputation_min_str": int(getattr(args, "reputation_min_str", 4)),
        # DIE options
        "no_die": bool(getattr(args, "no_die", False)),
        "die_timeout": int(getattr(args, "die_timeout", 60)),
        "die_min_len": int(getattr(args, "die_min_len", 4)),
        "die_max_mb": int(getattr(args, "die_max_mb", 50)),
        "die_no_batch": bool(getattr(args, "die_no_batch", False)),
        # Workers
        "workers": int(getattr(args, "workers", DEFAULT_WORKERS)),
    }


def run_parallel_scan(
    files: List[Path],
    origin_of: Dict[str, List[str]],
    args: Any,
    cache: Any,
    vt_ttl_sec: int,
    *,
    evidence_ttl_sec: Optional[int] = None,
    max_workers: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    1) Quick pass: hashes + evidence cache lookup.
    2) ProcessPoolExecutor: run CPU-bound analysis for cache misses.
    3) Async batch VT lookup for all evidences.
    4) ThreadPoolExecutor: CVE for files that need it.
    Returns list of evidence dicts (with policy still to be applied in caller).
    """
    from .analyzers.hashes import compute_hashes
    from .integrations.vt_async import vt_lookup_batch_sync
    from .cve.collector import collect_cve_for_file

    evidence_ttl = evidence_ttl_sec if evidence_ttl_sec is not None else vt_ttl_sec
    if evidence_ttl <= 0:
        evidence_ttl = EVIDENCE_TTL_SEC

    evidences: List[Dict[str, Any]] = []
    todo: List[Tuple[Path, str, Dict[str, Optional[str]]]] = []  # (path, kind, hashes)

    # files: list of Path (caller already filtered by sniff_magic). We need kind per file:
    # accept either list[Path] and infer kind from path/headers, or list of (Path, kind).
    file_list: List[Tuple[Path, str]] = []
    for f in files:
        if isinstance(f, (list, tuple)) and len(f) >= 2:
            file_list.append((Path(f[0]), str(f[1])))
        else:
            p = Path(f)
            # minimal kind detection
            try:
                with p.open("rb") as h:
                    head = h.read(4)
                if len(head) >= 2 and head[:2] == b"MZ":
                    file_list.append((p, "PE"))
                elif len(head) >= 4 and head[:4] == b"\x7fELF":
                    file_list.append((p, "ELF"))
                elif p.suffix.lower() in (".py", ".sh", ".ps1", ".js", ".json", ".yaml", ".toml", ".xml", ".md", ".txt"):
                    file_list.append((p, "EXT"))
                else:
                    file_list.append((p, "EXT"))
            except Exception:
                file_list.append((p, "EXT"))

    for fp, kind in file_list:
        try:
            hashes = compute_hashes(fp) or {}
        except Exception:
            hashes = {}
        sha256 = (hashes.get("sha256") or "").strip()
        if not sha256:
            todo.append((fp, kind, hashes))
            continue
        cached = cache.get_evidence(sha256, evidence_ttl) if cache else None
        if cached is not None:
            # Restore from cache; add origin_chain if needed
            if str(fp) in origin_of:
                cached["origin_chain"] = origin_of[str(fp)]
            if cached.get("meta") and "path" not in cached["meta"]:
                cached["meta"]["path"] = str(fp)
                cached["meta"]["name"] = fp.name
            evidences.append(cached)
            continue
        todo.append((fp, kind, hashes))

    timings: List[Tuple[str, Dict[str, Any]]] = []  # (path, _timing) for profiling

    if not todo:
        # All from cache; still need VT/CVE merge below
        pass
    else:
        options = _build_options(args)
        # Workers priority: max_workers arg > --workers CLI > env BIN_GATE_WORKERS > cpu_count-1
        if max_workers is not None:
            n_workers = max_workers
        elif hasattr(args, "workers") and args.workers:
            n_workers = max(1, int(args.workers))
        else:
            n_workers = max(1, (os.cpu_count() or 2) - 1)
        
        _thread_safe_log(f"[parallel] Starting ProcessPoolExecutor with {n_workers} workers, {len(todo)} files to process")

        def _size(p: Path) -> int:
            try:
                return p.stat().st_size if p.exists() else 0
            except Exception:
                return 0

        small_todo = [(fp, kind, h) for fp, kind, h in todo if _size(fp) < SMALL_FILE_THRESHOLD_BYTES]
        large_todo = [(fp, kind, h) for fp, kind, h in todo if _size(fp) >= SMALL_FILE_THRESHOLD_BYTES]

        from .analyzers.worker import run_file_analysis, run_batch_analysis

        with ProcessPoolExecutor(max_workers=n_workers) as executor:
            try:
                futures: Dict[Any, Any] = {}

                for batch_start in range(0, len(small_todo), BATCH_SIZE):
                    batch = small_todo[batch_start : batch_start + BATCH_SIZE]
                    batch_payload = ([(str(fp), kind) for fp, kind, _ in batch], options)
                    fut = executor.submit(run_batch_analysis, batch_payload)
                    futures[fut] = ("batch", batch)

                for fp, kind, _ in large_todo:
                    t = (str(fp), kind, options)
                    fut = executor.submit(run_file_analysis, t)
                    futures[fut] = ("single", (fp, kind))

                for future in as_completed(futures):
                    tag, payload = futures[future]
                    try:
                        if tag == "batch":
                            batch = payload
                            frags = future.result()
                            for i, frag in enumerate(frags):
                                if i < len(batch):
                                    fp, kind, _ = batch[i]
                                    if str(fp) in origin_of:
                                        frag["origin_chain"] = origin_of[str(fp)]
                                timing = frag.pop("_timing", None)
                                if timing:
                                    timings.append(((frag.get("meta") or {}).get("path") or frag.get("path", ""), timing))
                                evidences.append(frag)
                        else:
                            fp, kind = payload
                            frag = future.result()
                            timing = frag.pop("_timing", None)
                            if timing:
                                timings.append((str(fp), timing))
                            if str(fp) in origin_of:
                                frag["origin_chain"] = origin_of[str(fp)]
                            evidences.append(frag)
                    except Exception as e:
                        if tag == "single":
                            fp, kind = payload
                            frag = {
                                "meta": {"path": str(fp), "name": fp.name, "type": kind, "size": fp.stat().st_size if fp.exists() else None},
                                "hashes": {},
                                "entropy": {"file": None},
                                "errors": [f"worker_error:{e}"],
                            }
                            if str(fp) in origin_of:
                                frag["origin_chain"] = origin_of[str(fp)]
                            evidences.append(frag)
                        else:
                            for fp, kind, _ in payload:
                                evidences.append({
                                    "meta": {"path": str(fp), "name": fp.name, "type": kind, "size": fp.stat().st_size if fp.exists() else None},
                                    "hashes": {},
                                    "entropy": {"file": None},
                                    "errors": [f"worker_error:{e}"],
                                })
                                if str(fp) in origin_of:
                                    evidences[-1]["origin_chain"] = origin_of[str(fp)]
            except KeyboardInterrupt:
                executor.shutdown(wait=False)
                raise

        # Progress profiling: top 10 slowest to cli_debug.log
        if timings:
            sorted_timings = sorted(timings, key=lambda x: x[1].get("wall_sec", 0.0), reverse=True)
            top10 = sorted_timings[:10]
            _log_path = os.path.join(os.getcwd(), "cli_debug.log")
            try:
                with open(_log_path, "a", encoding="utf-8") as f:
                    f.write("\n--- Top 10 slowest files (wall_sec, slowest analyzer) ---\n")
                    for path, t in top10:
                        slowest = t.get("slowest", "?")
                        wall = t.get("wall_sec", 0.0)
                        f.write(f"  {wall:.2f}s  {slowest}  {path}\n")
                    f.write("---\n")
            except Exception:
                pass

    # Batch VT: сетевые запросы только ОДИН раз на каждый уникальный хэш (Set), негативный кэш NOT_FOUND/429, при 429 — только кэш
    if not getattr(args, "no_vt", False) and getattr(args, "vt_api_key", None) and cache:
        vt_negative_ttl = 24 * 3600
        not_found_status = getattr(cache, "NOT_FOUND", "NOT_FOUND")
        sha256_to_request: List[str] = []
        for ev in evidences:
            if ev.get("smart_gate_trusted"):
                continue
            if ev.get("vt") is not None:
                continue
            h = ev.get("hashes") or {}
            s = (h.get("sha256") or "").strip()
            if not s:
                continue
            neg = cache.get_vt_negative(s, vt_negative_ttl)
            if neg:
                st = neg.get("status")
                if st in ("404", not_found_status):
                    ev["vt"] = {"found": False, "sha256": s}
                elif st == "429":
                    pass
                continue
            sha256_to_request.append(s)
        unique_hashes: Set[str] = set(sha256_to_request)
        unique_sha256 = list(unique_hashes)
        if unique_sha256:
            vt_results = vt_lookup_batch_sync(
                unique_sha256,
                getattr(args, "vt_api_key"),
                timeout_sec=int(getattr(args, "vt_timeout", 20)),
                stop_on_429=True,
            )
            for s, data in vt_results.items():
                if data is None:
                    continue
                if isinstance(data, dict) and data.get("status") == "429":
                    try:
                        cache.put_vt_negative(s, "429")
                    except Exception:
                        pass
                    data = None
                elif isinstance(data, dict) and data.get("found") is False:
                    try:
                        cache.put_vt_negative(s, not_found_status)
                    except Exception:
                        pass
                for ev in evidences:
                    sh = ((ev.get("hashes") or {}).get("sha256") or "").strip()
                    if sh == s and data is not None:
                        ev["vt"] = data
    elif not getattr(args, "no_vt", False) and getattr(args, "vt_api_key", None):
        sha256_list = []
        for ev in evidences:
            if ev.get("smart_gate_trusted") or ev.get("vt") is not None:
                continue
            s = ((ev.get("hashes") or {}).get("sha256") or "").strip()
            if s:
                sha256_list.append(s)
        unique_hashes = set(sha256_list)
        unique_sha256 = list(unique_hashes)
        if unique_sha256:
            vt_results = vt_lookup_batch_sync(
                unique_sha256,
                getattr(args, "vt_api_key"),
                timeout_sec=int(getattr(args, "vt_timeout", 20)),
                stop_on_429=True,
            )
            for ev in evidences:
                s = ((ev.get("hashes") or {}).get("sha256") or "").strip()
                if s and s in vt_results and vt_results[s] is not None:
                    data = vt_results[s]
                    if isinstance(data, dict) and data.get("status") != "429":
                        ev["vt"] = data

    # CVE in parallel (I/O, per-file)
    if not getattr(args, "no_cve", False):
        cve_max_workers = min(len(evidences), 8)
        with ThreadPoolExecutor(max_workers=cve_max_workers) as tpe:
            def do_cve(ev: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[Dict]]:
                path_str = (ev.get("meta") or {}).get("path") or ev.get("path")
                if not path_str:
                    return ev, None
                try:
                    p = Path(path_str)
                    if not p.exists():
                        return ev, None
                    inv = getattr(args, "cve_inventory", None)
                    lmap = getattr(args, "cve_libmap", None)
                    cve_doc = collect_cve_for_file(
                        p,
                        ev,
                        ecosystem=getattr(args, "cve_ecosystem", None),
                        inventory_path=Path(inv).resolve() if inv else None,
                        libmap_path=Path(lmap).resolve() if lmap else None,
                        osv_timeout_sec=int(getattr(args, "cve_timeout", 15)),
                    )
                    return ev, cve_doc
                except Exception:
                    return ev, None

            futs = [tpe.submit(do_cve, ev) for ev in evidences]
            for fut in as_completed(futs):
                try:
                    ev, cve_doc = fut.result()
                    if cve_doc:
                        ev["cve"] = {"summary": cve_doc.get("summary", {}), "items": cve_doc.get("items", [])}
                except Exception:
                    pass

    # Write back to evidence cache for next run
    for ev in evidences:
        sha = (ev.get("hashes") or {}).get("sha256")
        if sha and cache:
            try:
                cache.put_evidence(sha, ev)
            except Exception:
                pass

    return evidences
