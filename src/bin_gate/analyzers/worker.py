# worker.py — ProcessPoolExecutor entry point (must be top-level for pickling)
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Tuple


def run_file_analysis(task: Tuple[str, str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Run full local analysis for one file. Called in a worker process.
    task = (path_str, kind, options). Returns evidence dict (no vt, no cve).
    """
    path_str, kind, options = task
    from .run_one_file import run_one_file_analysis
    return run_one_file_analysis(Path(path_str), kind, options)


def run_batch_analysis(task: Tuple[List[Tuple[str, str]], Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run analysis for a batch of small files in one process. Reduces spawn overhead.
    task = ([(path_str, kind), ...], options). Returns list of evidence dicts.
    """
    batch, options = task
    from .run_one_file import run_one_file_analysis
    results: List[Dict[str, Any]] = []
    for path_str, kind in batch:
        try:
            ev = run_one_file_analysis(Path(path_str), kind, options)
            results.append(ev)
        except Exception as e:
            results.append({
                "meta": {"path": path_str, "name": Path(path_str).name, "type": kind, "size": None},
                "hashes": {},
                "entropy": {"file": None},
                "errors": [f"worker_error:{e}"],
                "_timing": {"wall_sec": 0.0, "capa_sec": 0.0, "floss_sec": 0.0, "yara_sec": 0.0, "slowest": "none", "aggressive_skip": False},
            })
    return results
