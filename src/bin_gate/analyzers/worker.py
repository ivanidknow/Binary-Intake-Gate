# worker.py — ProcessPoolExecutor entry point (must be top-level for pickling)
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def run_file_analysis(task: Tuple[str, str, Dict[str, Any], Optional[str]]) -> Dict[str, Any]:
    """
    Run full local analysis for one file. Called in a worker process.
    task = (path_str, kind, options, yara_input_path). yara_input_path = unpacked path for YARA (e.g. UPX).
    Returns evidence dict (no vt, no cve).
    """
    if len(task) >= 4:
        path_str, kind, options, yara_input_path = task[0], task[1], task[2], task[3]
    else:
        path_str, kind, options = task[0], task[1], task[2]
        yara_input_path = None
    from .run_one_file import run_one_file_analysis
    try:
        return run_one_file_analysis(Path(path_str), kind, options, yara_input_path=Path(yara_input_path) if yara_input_path else None)
    finally:
        if yara_input_path:
            try:
                Path(yara_input_path).unlink(missing_ok=True)
            except Exception:
                pass


def run_batch_analysis(task: Tuple[List[Tuple[str, str, Optional[str]]], Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run analysis for a batch of small files in one process.
    task = ([(path_str, kind, yara_input_path), ...], options). Returns list of evidence dicts.
    """
    batch, options = task
    from .run_one_file import run_one_file_analysis
    results: List[Dict[str, Any]] = []
    for item in batch:
        path_str = item[0]
        kind = item[1]
        yara_input_path = item[2] if len(item) >= 3 else None
        try:
            ev = run_one_file_analysis(
                Path(path_str), kind, options,
                yara_input_path=Path(yara_input_path) if yara_input_path else None,
            )
            results.append(ev)
        except Exception as e:
            if yara_input_path:
                try:
                    Path(yara_input_path).unlink(missing_ok=True)
                except Exception:
                    pass
            results.append({
                "meta": {"path": path_str, "name": Path(path_str).name, "type": kind, "size": None},
                "hashes": {},
                "entropy": {"file": None},
                "errors": [f"worker_error:{e}"],
                "_timing": {"wall_sec": 0.0, "capa_sec": 0.0, "floss_sec": 0.0, "yara_sec": 0.0, "slowest": "none", "aggressive_skip": False},
            })
        finally:
            if yara_input_path:
                try:
                    Path(yara_input_path).unlink(missing_ok=True)
                except Exception:
                    pass
    return results
