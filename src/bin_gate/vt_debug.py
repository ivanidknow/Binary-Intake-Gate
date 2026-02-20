# -*- coding: utf-8 -*-
"""Единый путь и запись в vt_debug.log (для exe и python)."""
from __future__ import annotations
import os
import sys
import time

def get_vt_debug_log_path() -> str:
    """Путь к vt_debug.log: рядом с exe при frozen, иначе cwd."""
    if getattr(sys, "frozen", False) and getattr(sys, "executable", None):
        base = os.path.dirname(os.path.abspath(sys.executable))
        return os.path.join(base, "vt_debug.log")
    return "vt_debug.log"

def vt_debug_log(msg: str) -> None:
    """Пишет строку в vt_debug.log (один файл для exe и для всех модулей)."""
    try:
        path = get_vt_debug_log_path()
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass
