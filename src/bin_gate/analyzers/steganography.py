# steganography.py — T1027.003: анализ LSB в иконках/BMP на высокую энтропию (признак скрытых данных)

from __future__ import annotations
import math
from pathlib import Path
from typing import Dict, Any, List, Optional

# BMP magic
BMP_MAGIC = b"BM"
# Минимальный размер заголовка BMP (DIB header может быть 40, 108, 124 байт)
BMP_HEADER_MIN = 54
# Максимум байт пиксельных данных для анализа (чтобы не грузить огромные картинки)
MAX_PIXEL_BYTES = 2 * 1024 * 1024


def _shannon_entropy_bits(bits: List[int]) -> float:
    """Энтропия последовательности 0/1."""
    if not bits:
        return 0.0
    n0 = sum(1 for b in bits if b == 0)
    n1 = len(bits) - n0
    total = len(bits)
    ent = 0.0
    for c in (n0, n1):
        if c == 0:
            continue
        p = c / total
        ent -= p * math.log2(p)
    return round(ent, 4)


def _lsb_entropy_from_bytes(data: bytes, max_bytes: int = MAX_PIXEL_BYTES) -> Optional[float]:
    """
    Из байт пиксельных данных берём LSB каждого байта, строим битовую последовательность,
    считаем энтропию. Высокая энтропия (~1.0) — признак стего.
    """
    if not data or len(data) < 64:
        return None
    sample = data[:max_bytes]
    bits = [b & 1 for b in sample]
    return _shannon_entropy_bits(bits)


def _extract_bmp_pixel_data(data: bytes) -> Optional[bytes]:
    """Из сырых BMP данных возвращает кусок пиксельных данных (после заголовка)."""
    if len(data) < BMP_HEADER_MIN or data[:2] != BMP_MAGIC:
        return None
    # Offset to pixel array at 0x0A
    try:
        offset = int.from_bytes(data[10:14], "little")
        if offset < BMP_HEADER_MIN or offset > len(data):
            return None
        return data[offset:]
    except Exception:
        return None


def _icon_group_or_rt_icon_chunks(data: bytes) -> List[bytes]:
    """
    Упрощённо: ищем в данных подпоследовательности, похожие на BMP (BM...) или
    маленькие иконки (после заголовка ICO). ICO: 6 byte header + 16 byte entries,
    затем идут изображения (каждое может быть BMP или PNG).
    Возвращаем список кусков для проверки LSB.
    """
    out: List[bytes] = []
    i = 0
    while i < len(data) - 4:
        if data[i : i + 2] == BMP_MAGIC and i + BMP_HEADER_MIN <= len(data):
            # Может быть вложенный BMP
            rest = data[i:]
            pixel = _extract_bmp_pixel_data(rest)
            if pixel:
                out.append(pixel)
            # Сдвигаемся за этот BMP по размеру из заголовка (0x02)
            try:
                size = int.from_bytes(rest[2:6], "little")
                if size > 0 and size < 50 * 1024 * 1024:
                    i += size
                else:
                    i += 1
            except Exception:
                i += 1
            continue
        i += 1
    return out


def analyze_lsb_entropy(data: bytes) -> Dict[str, Any]:
    """
    Анализ блока данных: ищем BMP/иконки, извлекаем пиксельные данные,
    считаем LSB-энтропию. Если хотя бы один блок даёт высокую энтропию — стего-подозрение.
    """
    result: Dict[str, Any] = {
        "detected": False,
        "lsb_high_entropy": False,
        "details": [],
        "mitre": "T1027.003",
    }
    chunks: List[bytes] = []
    # Один цельный BMP
    pixel = _extract_bmp_pixel_data(data)
    if pixel:
        chunks.append(pixel)
    # Несколько BMP внутри (например в ресурсах)
    for c in _icon_group_or_rt_icon_chunks(data):
        if c and c not in chunks:
            chunks.append(c)
    # Если ничего не нашли, считаем LSB по всему блоку (эвристика для «сырых» пикселей)
    if not chunks and len(data) >= 256:
        chunks.append(data)
    high_entropy_threshold = 0.95
    for blob in chunks[:20]:
        ent = _lsb_entropy_from_bytes(blob)
        if ent is not None:
            result["details"].append({"entropy": ent, "size": len(blob)})
            if ent >= high_entropy_threshold:
                result["lsb_high_entropy"] = True
                result["detected"] = True
    return result


def analyze_file_resources(
    path: Path,
    max_read: int = 4 * 1024 * 1024,
    giant_file_threshold: int = 200 * 1024 * 1024,
) -> Dict[str, Any]:
    """
    Проверяет файл на стеганографию: ресурсы PE (иконки, BMP) или сырой контент.
    Для PE по возможности извлекает ресурсы типа RT_ICON, RT_GROUP_ICON, затем LSB-анализ.
    Для файлов > giant_file_threshold (200 МБ) не загружает PE в память — только head для LSB.
    """
    result = analyze_lsb_entropy(b"")
    result["detected"] = False
    result["lsb_high_entropy"] = False
    result["details"] = []
    try:
        file_size = path.stat().st_size
        data = path.read_bytes() if file_size <= max_read else _read_head(path, max_read)
    except Exception:
        return result
    is_giant = file_size > giant_file_threshold
    # Пробуем PE ресурсы (для гигантских файлов пропускаем — pefile может загрузить весь файл → OOM)
    resources_data = b""
    if not is_giant:
        try:
            import pefile  # type: ignore
            pe = pefile.PE(str(path), fast_load=True)
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for res_type in getattr(pe, "DIRECTORY_ENTRY_RESOURCE", []).entries or []:
                    name = getattr(res_type, "name", None) or getattr(res_type, "id", None)
                    if name is None:
                        continue
                    if str(name).isdigit():
                        rid = int(name)
                        if rid in (3, 14):  # RT_ICON, RT_GROUP_ICON
                            for entry in getattr(res_type, "directory", {}).entries or []:
                                for item in getattr(entry, "directory", {}).entries or []:
                                    try:
                                        off = item.data.struct.OffsetToData
                                        size = item.data.struct.Size
                                        if 0 <= off < len(data) and size > 0 and off + size <= len(data):
                                            resources_data += data[off : off + size]
                                    except Exception:
                                        pass
                    elif isinstance(name, (bytes, str)) and "icon" in str(name).lower():
                        for entry in getattr(res_type, "directory", {}).entries or []:
                            for item in getattr(entry, "directory", {}).entries or []:
                                try:
                                    off = item.data.struct.OffsetToData
                                    size = item.data.struct.Size
                                    if 0 <= off < len(data) and size > 0 and off + size <= len(data):
                                        resources_data += data[off : off + size]
                                except Exception:
                                    pass
            pe.close()
        except Exception:
            pass
    if resources_data:
        result = analyze_lsb_entropy(resources_data)
    else:
        result = analyze_lsb_entropy(data)
    return result


def _read_head(path: Path, size: int) -> bytes:
    with path.open("rb") as f:
        return f.read(size)
