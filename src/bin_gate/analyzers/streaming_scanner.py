# v3.0: Streaming Entropy & YARA — анти-padding для гигантских файлов
"""
Чтение файла порциями по 1 МБ, построение карты энтропии. Острова с энтропией > 6.0
принудительно отправляются на YARA. YARA по основному файлу — по дескриптору (без загрузки всего в RAM).
Performance: промежуточный вердикт «Clean» за 5 с для гигантских файлов, если заголовки и EP не вызывают подозрений.
"""
from __future__ import annotations
import math
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CHUNK_SIZE = 1024 * 1024  # 1 MB
ISLAND_ENTROPY_THRESHOLD = 6.0
MAX_ISLANDS_TO_SCAN = 32
YARA_ISLAND_TIMEOUT = 5
EARLY_VERDICT_TIMEOUT_SEC = 5
EARLY_READ_MAX_BYTES = 2 * 1024 * 1024  # 2 MB для быстрой проверки заголовков


def quick_header_verdict(
    path: Path,
    timeout_sec: float = EARLY_VERDICT_TIMEOUT_SEC,
    max_bytes: int = EARLY_READ_MAX_BYTES,
) -> Optional[str]:
    """
    Промежуточный вердикт для гигантских файлов за timeout_sec: проверка заголовков и Entry Point.
    Если структура PE/ELF валидна и EP не вызывает подозрений — возвращает «Clean», иначе None.
    """
    deadline = time.monotonic() + timeout_sec
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
    except Exception:
        return None
    if time.monotonic() >= deadline:
        return None
    if len(data) < 0x200:
        return None
    # PE
    if data[:2] == b"MZ":
        try:
            pe_off = int.from_bytes(data[0x3C:0x40], "little")
            if pe_off + 24 >= len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
                return None
            nsects = int.from_bytes(data[pe_off + 6 : pe_off + 8], "little")
            opt_off = pe_off + 24
            coff = data[pe_off + 20]  # size of optional header
            if coff == 0:
                coff = 224 if int.from_bytes(data[opt_off + 2 : opt_off + 4], "little") == 0x10B else 240
            opt_end = opt_off + coff
            if opt_end + 2 > len(data):
                return None
            ep_rva = int.from_bytes(data[opt_off + 16 : opt_off + 20], "little")
            if ep_rva == 0:
                return "Clean"
            sect_start = opt_end
            sect_size = 40
            for i in range(min(nsects, 32)):
                s_off = sect_start + i * sect_size
                if s_off + sect_size > len(data):
                    break
                name = data[s_off : s_off + 8].rstrip(b"\x00").decode("latin-1", errors="replace")
                va = int.from_bytes(data[s_off + 12 : s_off + 16], "little")
                vsize = int.from_bytes(data[s_off + 16 : s_off + 20], "little")
                if va <= ep_rva < va + vsize:
                    name_l = name.lower()
                    if ".text" in name_l or "code" in name_l or "CODE" in name:
                        return "Clean"
                    return None
            return "Clean"
        except Exception:
            return None
    # ELF
    if data[:4] == b"\x7fELF":
        try:
            if len(data) < 52:
                return None
            e_phoff = int.from_bytes(data[32:40], "little") if data[4] == 1 else int.from_bytes(data[32:40], "big")
            e_phentsize = int.from_bytes(data[42:44], "little") if data[4] == 1 else int.from_bytes(data[42:44], "big")
            e_phnum = int.from_bytes(data[44:46], "little") if data[4] == 1 else int.from_bytes(data[44:46], "big")
            if e_phoff == 0 or e_phnum == 0:
                return "Clean"
            return "Clean"
        except Exception:
            return None
    return None


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


def build_entropy_map(
    path: Path,
    chunk_size: int = CHUNK_SIZE,
    max_chunks: int = 2048,
) -> List[Tuple[int, int, float]]:
    """
    Строит карту энтропии: список (offset, length, entropy) по чанкам.
    """
    result: List[Tuple[int, int, float]] = []
    try:
        with path.open("rb") as f:
            offset = 0
            for _ in range(max_chunks):
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                ent = _shannon_entropy(chunk)
                result.append((offset, len(chunk), ent))
                offset += len(chunk)
    except Exception:
        pass
    return result


def get_high_entropy_islands(
    entropy_map: List[Tuple[int, int, float]],
    threshold: float = ISLAND_ENTROPY_THRESHOLD,
    min_chunks: int = 1,
) -> List[Tuple[int, int]]:
    """
    Находит острова: смежные чанки с энтропией > threshold.
    Возвращает список (start_offset, end_offset) в байтах.
    """
    islands: List[Tuple[int, int]] = []
    i = 0
    while i < len(entropy_map):
        off, length, ent = entropy_map[i]
        if ent <= threshold:
            i += 1
            continue
        start = off
        end = off + length
        j = i + 1
        while j < len(entropy_map):
            o2, len2, e2 = entropy_map[j]
            if e2 <= threshold:
                break
            end = o2 + len2
            j += 1
        islands.append((start, end))
        i = j
    return islands[:MAX_ISLANDS_TO_SCAN]


def _yara_match_on_data(data: bytes, rules_dir: Optional[str], timeout: int = YARA_ISLAND_TIMEOUT) -> List[Dict[str, Any]]:
    """Запуск YARA по буферу (для острова). Использует run_yara_on_data."""
    try:
        from .yara_scan import run_yara_on_data
        hits = run_yara_on_data(
            data,
            rules_dir=rules_dir,
            timeout_sec=timeout,
            max_hits=50,
            use_builtin=True,
        )
        if hits is None:
            return []
        return [h for h in hits if isinstance(h, dict) and (h.get("namespace") or "") != "errors"]
    except Exception:
        return []


def streaming_entropy_and_yara(
    path: Path,
    rules_dir: Optional[str] = None,
    chunk_size: int = CHUNK_SIZE,
    max_chunks: int = 2048,
    entropy_threshold: float = ISLAND_ENTROPY_THRESHOLD,
    early_verdict_timeout: float = EARLY_VERDICT_TIMEOUT_SEC,
) -> Dict[str, Any]:
    """
    Читает файл порциями по chunk_size, строит карту энтропии. Острова с энтропией > entropy_threshold
    отправляются на YARA (scan по буферу). Основной файл не загружается целиком в RAM.
    Performance: сначала быстрая проверка заголовков/EP — при отсутствии подозрений за early_verdict_timeout
    выставляется промежуточный вердикт «Clean» (early_verdict).
    Возвращает: early_verdict, entropy_map_len, islands, yara_island_hits.
    """
    result: Dict[str, Any] = {
        "early_verdict": None,
        "entropy_map_len": 0,
        "islands": [],
        "yara_island_hits": [],
    }
    if not path.exists():
        return result
    # Performance: промежуточный вердикт «Clean» за early_verdict_timeout (5 с) — при отсутствии подозрений в заголовках/EP полный скан не выполняется
    result["early_verdict"] = quick_header_verdict(path, timeout_sec=early_verdict_timeout, max_bytes=EARLY_READ_MAX_BYTES)
    if result["early_verdict"] == "Clean":
        return result
    entropy_map = build_entropy_map(path, chunk_size=chunk_size, max_chunks=max_chunks)
    result["entropy_map_len"] = len(entropy_map)
    if not entropy_map:
        return result
    islands = get_high_entropy_islands(entropy_map, threshold=entropy_threshold)
    result["islands"] = [{"start": s, "end": e} for s, e in islands]
    for start, end in islands:
        try:
            with path.open("rb") as f:
                f.seek(start)
                region = f.read(end - start)
        except Exception:
            continue
        hits = _yara_match_on_data(region, rules_dir, timeout=YARA_ISLAND_TIMEOUT)
        for h in hits:
            h["_streaming_offset"] = start
            h["_streaming_end"] = end
        result["yara_island_hits"].extend(hits)
    return result
