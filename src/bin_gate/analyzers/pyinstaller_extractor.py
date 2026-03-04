# pyinstaller_extractor.py — базовый парсинг оверлея PyInstaller для извлечения имён упакованных файлов
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

MEI_MAGIC = b"MEI\x0c"
PYINSTALLER_MAGIC = b"PyInstaller"
PYI_ARCHIVE = b"pyi-archive"
PYZ_MAGIC = b"PYZ\x00"


def extract_packed_names(data: bytes, max_names: int = 500) -> List[str]:
    """
    Базовый парсинг оверлея PyInstaller: извлечение имён упакованных файлов (main, python*.dll, *.zip, и т.д.).
    Ищет нуль-терминированные строки после magic и разумной длины (2–200 символов).
    """
    if not data or len(data) < 20:
        return []
    names: List[str] = []
    seen: set = set()
    # Ищем зоны после PyInstaller / MEI / pyi-archive
    for magic in (PYINSTALLER_MAGIC, MEI_MAGIC, PYZ_MAGIC, PYI_ARCHIVE):
        off = 0
        while True:
            pos = data.find(magic, off)
            if pos < 0:
                break
            # Сканируем после magic: CArchive-подобные имена (null-terminated)
            scan_start = pos + len(magic)
            scan_end = min(scan_start + 8192, len(data))
            i = scan_start
            while i < scan_end and len(names) < max_names:
                if data[i] == 0:
                    i += 1
                    continue
                start = i
                while i < scan_end and data[i] != 0 and (i - start) < 200:
                    i += 1
                if i > start:
                    try:
                        raw = data[start:i]
                        if b"\x00" in raw:
                            raw = raw.split(b"\x00")[0]
                        s = raw.decode("utf-8", errors="ignore").strip()
                        if 2 <= len(s) <= 200 and s.isprintable() and s not in seen:
                            if any(c in s for c in (".", "/", "\\")) or s.endswith((".dll", ".zip", ".pyd", ".pyc", "main")):
                                seen.add(s)
                                names.append(s)
                    except Exception:
                        pass
                i += 1
            off = pos + 1
    return names


def extract_from_file(path: Path, max_bytes: int = 10 * 1024 * 1024) -> Dict[str, Any]:
    """
    Извлечение имён упакованных файлов из PE с оверлеем PyInstaller.
    Возвращает {"packed_names": [...], "has_pyi": bool, "raw_blocks": [(name, len)]}.
    """
    path = Path(path)
    result: Dict[str, Any] = {"packed_names": [], "has_pyi": False, "raw_blocks": []}
    if not path.exists() or not path.is_file():
        return result
    try:
        data = path.read_bytes()
    except Exception:
        return result
    if len(data) > max_bytes:
        data = data[:max_bytes]
    if PYINSTALLER_MAGIC in data or MEI_MAGIC in data or PYZ_MAGIC in data:
        result["has_pyi"] = True
    result["packed_names"] = extract_packed_names(data)
    # Сырые блоки для отчёта (позиция PYZ/MEI)
    off = 0
    for magic in (PYZ_MAGIC, MEI_MAGIC):
        while True:
            pos = data.find(magic, off)
            if pos < 0:
                break
            result["raw_blocks"].append((magic.decode("ascii", errors="replace"), pos))
            off = pos + 1
    return result
