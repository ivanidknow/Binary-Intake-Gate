from __future__ import annotations
from pathlib import Path
from typing import Dict, Any
import math

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    ln2 = math.log(2)
    total = len(data)
    for c in freq:
        if c == 0:
            continue
        p = c / total
        entropy -= p * (math.log(p) / ln2)
    return round(entropy, 3)

def file_entropy(path: Path, max_read: int = 5 * 1024 * 1024) -> float:
    with path.open("rb") as f:
        data = f.read(max_read)
    return shannon_entropy(data)

def sections_entropy_pe(path: Path) -> Dict[str, float]:
    try:
        import pefile  # type: ignore
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
        out: Dict[str, float] = {}
        for s in getattr(pe, "sections", []):
            name = s.Name.decode(errors="ignore").strip("\x00") if isinstance(s.Name, (bytes, bytearray)) else str(s.Name)
            try:
                ent = round(s.get_entropy(), 3)
            except Exception:
                ent = 0.0
            out[name] = ent
        return out
    except Exception:
        return {}

def sections_entropy_elf(path: Path) -> Dict[str, float]:
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore
        out: Dict[str, float] = {}
        with path.open("rb") as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                try:
                    data = sec.data()
                    out[sec.name] = shannon_entropy(data)
                except Exception:
                    continue
        return out
    except Exception:
        return {}
