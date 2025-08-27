from __future__ import annotations
from typing import List, Dict, Any, Optional
from pathlib import Path

def _get_file_version(path: Path) -> Optional[str]:
    try:
        import pefile  # type: ignore
    except Exception:
        return None
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
        if hasattr(pe, "FileInfo"):
            for fileinfo in pe.FileInfo or []:
                for entry in fileinfo:
                    if entry.Key == b"StringFileInfo":
                        for st in entry.StringTable or []:
                            fv = st.entries.get(b"FileVersion")
                            if fv:
                                return fv.decode(errors="ignore").strip()
        # запасной путь: VS_FIXEDFILEINFO
        try:
            ffi = pe.VS_FIXEDFILEINFO[0]
            ms = ffi.FileVersionMS
            ls = ffi.FileVersionLS
            ver = f"{ms>>16}.{ms&0xffff}.{ls>>16}.{ls&0xffff}"
            return ver
        except Exception:
            return None
    except Exception:
        return None

def list_pe_imports(file_path: Path) -> List[Dict[str, str]]:
    """
    Возвращает список импортируемых DLL по именам: [{'dll':'KERNEL32.DLL'}, ...]
    """
    try:
        import pefile  # type: ignore
    except Exception:
        return []
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        pe.parse_data_directories()
        out: List[Dict[str, str]] = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT or []:
            dll = entry.dll.decode(errors="ignore") if isinstance(entry.dll, (bytes, bytearray)) else str(entry.dll)
            out.append({"dll": dll})
        return out
    except Exception:
        return []

def find_side_by_side_versions(file_path: Path, imports: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    Ищем «соседние» DLL в той же папке (best-effort) и вытаскиваем версии.
    Возвращает [{'dll':'libssl-3-x64.dll','version':'3.0.9'}, ...]
    """
    base = file_path.parent
    found: List[Dict[str, str]] = []
    seen = set()
    for imp in imports:
        name = imp.get("dll") or ""
        if not name:
            continue
        name_l = name.lower()
        # простая нормализация имени файла для поиска
        candidates = [base / name, base / name_l]
        for c in candidates:
            if c.exists() and c.is_file():
                ver = _get_file_version(c)
                key = (name_l, ver or "")
                if key in seen:
                    continue
                seen.add(key)
                found.append({"dll": name, "version": ver} if ver else {"dll": name})
                break
    return found
