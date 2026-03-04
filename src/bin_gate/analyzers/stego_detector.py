# v3.0: Advanced Stego-Scanner — JPEG/PNG metadata and IAT order (T1027.003)
"""
Расширенный анализ за пределы LSB:
- JPEG: сегменты APP0–APP15 и COM на исполняемый код / зашифрованные блоки.
- PNG: IDAT и кастомные чанки (tEXt, zTXt).
- Resource Mapping: порядок функций в IAT — нетипичный для компилятора → T1027.003.
"""
from __future__ import annotations
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Порог энтропии для «подозрительного» блока (исполняемый/шифр)
HIGH_ENTROPY_THRESHOLD = 7.0
EXECUTABLE_MAGIC = b"MZ"
PE_MAGIC = b"PE\x00\x00"


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 4)


def _jpeg_scan_segments(data: bytes) -> Dict[str, Any]:
    """Парсинг JPEG: SOI, затем сегменты (0xFF + marker). APP0–APP15 = 0xFFE0–0xFFEF, COM = 0xFFFE."""
    out: Dict[str, Any] = {"anomalies": [], "com_high_entropy": False, "app_high_entropy": []}
    if len(data) < 4 or data[0:2] != b"\xff\xd8":
        return out
    i = 2
    while i < len(data) - 4:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker == 0xD9:  # EOI
            break
        if marker == 0x00:
            i += 2
            continue
        length = int.from_bytes(data[i + 2 : i + 4], "big") if i + 4 <= len(data) else 0
        if length < 2:
            i += 2
            continue
        payload_start = i + 4
        payload_end = min(payload_start + length - 2, len(data))
        payload = data[payload_start:payload_end]
        if 0xE0 <= marker <= 0xEF:  # APP0–APP15
            ent = _shannon_entropy(payload)
            if ent >= HIGH_ENTROPY_THRESHOLD or EXECUTABLE_MAGIC in payload or PE_MAGIC in payload:
                out["anomalies"].append(f"APP{marker - 0xE0}_entropy_or_exec")
                out["app_high_entropy"].append(marker - 0xE0)
        elif marker == 0xFE:  # COM
            ent = _shannon_entropy(payload)
            if ent >= HIGH_ENTROPY_THRESHOLD or EXECUTABLE_MAGIC in payload:
                out["com_high_entropy"] = True
                out["anomalies"].append("COM_high_entropy_or_exec")
        i = payload_end
    return out


def _png_scan_chunks(data: bytes) -> Dict[str, Any]:
    """PNG: подпись 89 50 4E 47 0D 0A 1A 0A, затем чанки (4 len, 4 type, data, 4 crc). IDAT, tEXt, zTXt."""
    out: Dict[str, Any] = {"anomalies": [], "idat_high_entropy": False, "custom_suspicious": []}
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return out
    i = 8
    while i < len(data) - 12:
        length = int.from_bytes(data[i : i + 4], "big")
        chunk_type = data[i + 4 : i + 8].decode("latin-1", errors="replace")
        payload_start = i + 8
        payload_end = payload_start + length
        if payload_end > len(data):
            break
        payload = data[payload_start:payload_end]
        if chunk_type == "IDAT":
            ent = _shannon_entropy(payload)
            if ent >= HIGH_ENTROPY_THRESHOLD:
                out["idat_high_entropy"] = True
                out["anomalies"].append("IDAT_high_entropy")
        elif chunk_type in ("tEXt", "zTXt"):
            if EXECUTABLE_MAGIC in payload or _shannon_entropy(payload) >= HIGH_ENTROPY_THRESHOLD:
                out["custom_suspicious"].append(chunk_type)
                out["anomalies"].append(f"{chunk_type}_suspicious")
        i = payload_end + 4  # +4 CRC
    return out


def _pe_iat_order(path: Path, max_read: int = 2 * 1024 * 1024) -> Tuple[bool, List[str]]:
    """
    Проверка порядка импортов в IAT. Нетипичный порядок для компилятора (например, не как у MSVC) — T1027.003.
    Возвращает (atypical, list of import names in order).
    """
    try:
        import pefile  # type: ignore
        pe = pefile.PE(str(path), fast_load=True)
        imports_order: List[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = getattr(entry, "dll", b"").decode("utf-8", errors="replace")
                for imp in getattr(entry, "imports", []) or []:
                    name = getattr(imp, "name", None)
                    if name:
                        imports_order.append(f"{dll}!{name.decode('utf-8', errors='replace')}")
                    else:
                        ordinal = getattr(imp, "ordinal", None)
                        imports_order.append(f"{dll}!#{ordinal}")
        pe.close()
        # Эвристика: типичный порядок MSVC — kernel32.dll идут раньше многих других; если порядок сильно перепутан (например, редкие DLL первыми без kernel32) — atypical
        if len(imports_order) < 3:
            return False, imports_order
        dll_order = []
        seen = set()
        for s in imports_order:
            dll = s.split("!")[0].lower()
            if dll not in seen:
                seen.add(dll)
                dll_order.append(dll)
        # Считаем нетипичным, если kernel32 не в первой тройке DLL (часто первый или второй)
        kernel32_pos = next((i for i, d in enumerate(dll_order) if "kernel32" in d), None)
        atypical = kernel32_pos is not None and kernel32_pos > 2 and len(dll_order) > 4
        return atypical, imports_order
    except Exception:
        return False, []


def analyze_advanced(path: Path, data: Optional[bytes] = None, max_read: int = 4 * 1024 * 1024) -> Dict[str, Any]:
    """
    Расширенный стего/метаданные: JPEG APP/COM, PNG IDAT/tEXt/zTXt, порядок IAT в PE.
    Устанавливает suspicious_media_metadata=True при аномалиях (для scoring RISK_SUSPICIOUS_MEDIA_METADATA).
    """
    result: Dict[str, Any] = {
        "suspicious_media_metadata": False,
        "jpeg": {},
        "png": {},
        "iat_atypical_order": False,
        "mitre": "T1027.003",
    }
    raw = data
    if raw is None:
        try:
            raw = path.read_bytes() if path.stat().st_size <= max_read else path.open("rb").read(max_read)
        except Exception:
            return result
    if not raw:
        return result
    # JPEG
    if raw[:2] == b"\xff\xd8":
        jpeg = _jpeg_scan_segments(raw)
        result["jpeg"] = jpeg
        if jpeg.get("anomalies"):
            result["suspicious_media_metadata"] = True
    # PNG
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        png = _png_scan_chunks(raw)
        result["png"] = png
        if png.get("anomalies"):
            result["suspicious_media_metadata"] = True
    # PE IAT order (для любого PE)
    if raw[:2] == EXECUTABLE_MAGIC and len(raw) > 0x40:
        iat_atypical, _ = _pe_iat_order(path)
        result["iat_atypical_order"] = iat_atypical
        if iat_atypical:
            result["suspicious_media_metadata"] = True
    return result
