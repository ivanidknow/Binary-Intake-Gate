# v3.0: Deep Script Analysis — Lua bytecode decompilation and dynamic library loading detection
"""
Декомпиляция Lua-байткода для обнаружения скрытых вызовов загрузки динамических библиотек
(package.loadlib, ffi.load, loadlib).
"""
from __future__ import annotations
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

LUA_SIGNATURE = b"\x1bLua"
# Паттерны загрузки DLL/библиотек в Lua
DYNLIB_PATTERNS = [
    (b"loadlib", "loadlib"),
    (b"package.loadlib", "package.loadlib"),
    (b"ffi.load", "ffi.load"),
    (b"ffi.C", "ffi.C"),
    (b"package.cpath", "package.cpath"),
]


def _is_lua_bytecode(data: bytes) -> bool:
    return data.startswith(LUA_SIGNATURE)


def _scan_bytecode_strings(data: bytes) -> List[str]:
    """Извлекает подозрительные подстроки из сырого байткода (поиск по паттернам в строках)."""
    found: List[str] = []
    for needle, name in DYNLIB_PATTERNS:
        if needle in data:
            found.append(name)
    # Дополнительно: типичные имена DLL в строках рядом с loadlib
    if b"loadlib" in data or b"ffi.load" in data:
        for m in re.finditer(rb"[a-zA-Z0-9_.\-]{3,}\.(?:dll|so|dylib)", data):
            found.append("dynlib_path:" + m.group(0).decode("utf-8", errors="replace")[:80])
    return list(dict.fromkeys(found))


def _decompile_lua(path: Path, data: Optional[bytes] = None) -> Optional[str]:
    """Попытка декомпиляции через unluac (Java) или luadec, если доступны. Возвращает исходный код или None."""
    raw = data
    if raw is None and path.exists():
        try:
            raw = path.read_bytes()
        except Exception:
            return None
    if not raw or not _is_lua_bytecode(raw):
        return None
    to_run: Optional[Path] = path
    tmp_path: Optional[Path] = None
    if data is not None:
        try:
            fd, tmp_path = tempfile.mkstemp(suffix=".luac")
            with open(fd, "wb") as f:
                f.write(raw)
            to_run = Path(tmp_path)
        except Exception:
            return None
    try:
        for args in (
            ["java", "-jar", "unluac.jar", str(to_run)],
            ["luadec", str(to_run)],
        ):
            try:
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0 and (result.stdout or "").strip():
                    return result.stdout
            except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
                continue
    finally:
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except Exception:
                pass
    return None


def analyze_lua_bytecode(path: Path, data: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Анализ Lua-байткода: поиск package.loadlib, ffi.load и путей к .dll/.so.
    При наличии декомпилятора — разбор исходного кода на те же паттерны.
    Возвращает dict для evidence: lua_bytecode.dynlib_loading, lua_bytecode.decompiled_ok.
    """
    out: Dict[str, Any] = {
        "decompiled_ok": False,
        "dynlib_loading": [],
        "suspicious": False,
        "error": None,
    }
    raw = data
    if raw is None and path.exists():
        try:
            raw = path.read_bytes()
        except Exception:
            out["error"] = "read_error"
            return out
    if not raw:
        out["error"] = "empty"
        return out
    if not _is_lua_bytecode(raw):
        out["error"] = "not_lua_bytecode"
        return out
    # Сканирование сырого байткода
    out["dynlib_loading"] = _scan_bytecode_strings(raw)
    out["suspicious"] = len(out["dynlib_loading"]) > 0
    # Декомпиляция и повторный поиск в исходнике
    source = _decompile_lua(path, data)
    if source:
        out["decompiled_ok"] = True
        for pattern, name in DYNLIB_PATTERNS:
            if pattern.decode("utf-8") in source or name in source:
                if name not in out["dynlib_loading"]:
                    out["dynlib_loading"].append(name)
        out["suspicious"] = len(out["dynlib_loading"]) > 0
    return out
