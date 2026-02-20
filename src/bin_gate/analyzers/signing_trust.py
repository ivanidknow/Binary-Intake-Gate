from __future__ import annotations
from pathlib import Path
import struct

def _u32le(b: bytes, off: int) -> int: return struct.unpack_from("<I", b, off)[0]

def analyze(path: Path) -> dict:
    """Лёгкая проверка наличия таблицы подписи (Authenticode) в PE."""
    p = Path(path)
    try:
        with p.open("rb") as f:
            if f.read(2) != b"MZ": return {"error":"not_pe"}
            f.seek(0x3C); peoff = _u32le(f.read(4), 0)
            f.seek(peoff); 
            if f.read(4) != b"PE\x00\x00": return {"error":"bad_pe_sig"}
            f.seek(peoff + 4 + 20)  # Optional header
            hdr = f.read(240)
            is_plus = hdr[:2] == b"\x0b\x02"
            dd_off = 96 if not is_plus else 112
            sec_va = _u32le(hdr, dd_off + 4*8)      # IMAGE_DIRECTORY_ENTRY_SECURITY (VA)
            sec_sz = _u32le(hdr, dd_off + 4*8 + 4)  # Size
            return {"signed": bool(sec_va and sec_sz), "cert_table_size": int(sec_sz)}
    except Exception as e:
        return {"error": str(e)}
