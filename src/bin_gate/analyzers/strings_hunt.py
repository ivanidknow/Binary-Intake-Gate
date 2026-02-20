# src/bin_gate/analyzers/strings_hunt.py
from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
import base64, re, string

PRINTABLE = set(bytes(string.printable, "ascii"))

def _extract_ascii_runs(data: bytes, *, min_len: int = 6) -> List[str]:
    out: List[str] = []
    cur: bytearray = bytearray()
    for b in data:
        if b in PRINTABLE and b not in (0x0b,):  # no VT
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", errors="ignore"))
            cur.clear()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", errors="ignore"))
    return out

def _extract_utf16le_ascii_runs(data: bytes, *, min_len: int = 6) -> List[str]:
    out: List[str] = []
    cur: List[int] = []
    i, n = 0, len(data)
    while i + 1 < n:
        c, z = data[i], data[i+1]
        if (c in PRINTABLE and c not in (0x0b,)) and z == 0x00:
            cur.append(c)
            i += 2
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur).decode("ascii", errors="ignore"))
            cur = []
            i += 1
    if len(cur) >= min_len:
        out.append(bytes(cur).decode("ascii", errors="ignore"))
    return out

def _rot13_ascii(s: str) -> str:
    def r(ch: str) -> str:
        o = ord(ch)
        if 65 <= o <= 90:
            return chr((o - 65 + 13) % 26 + 65)
        if 97 <= o <= 122:
            return chr((o - 97 + 13) % 26 + 97)
        return ch
    return "".join(r(c) for c in s)

_B64_RE = re.compile(rb"(?:[A-Za-z0-9+/]{16,}={0,2})")

def _try_b64_decode(chunk: bytes) -> Optional[bytes]:
    # выровняем padding
    pad = (-len(chunk)) % 4
    try:
        return base64.b64decode(chunk + b"=" * pad, validate=False)
    except Exception:
        return None

def recover_strings(
    path: Path,
    *,
    blob: Optional[bytes] = None,
    limit_bytes: int = 2 * 1024 * 1024,
    min_len: int = 6,
    max_samples: int = 10,
) -> Dict[str, Any]:
    """
    Вытаскивает скрытые строки простыми методами:
      - XOR-однобайтовый (несколько популярных ключей)
      - ROT13 для ASCII-строк
      - Base64 фрагменты
      - UTF-16LE ASCII-последовательности
    Возвращает: { total_found, methods, samples }
    """
    try:
        data = blob if blob is not None else path.read_bytes()
    except Exception:
        data = b""
    if limit_bytes and len(data) > limit_bytes:
        data = data[:limit_bytes]

    # baseline (не хотим дублировать явно читаемые строки)
    base_ascii = set(_extract_ascii_runs(data, min_len=min_len))
    base_u16   = set(_extract_utf16le_ascii_runs(data, min_len=min_len))
    baseline: Set[str] = base_ascii | base_u16

    out_samples: List[str] = []
    methods: Dict[str, int] = {"xor": 0, "rot13": 0, "b64": 0, "utf16": 0}
    total = 0

    # UTF-16LE «обычные» — это не «скрытые», но полезно показывать как извлечённые
    if base_u16:
        methods["utf16"] = len(base_u16)
        for s in list(base_u16)[:max_samples]:
            if s not in out_samples:
                out_samples.append(s)
        total += len(base_u16)

    # ROT13 по базовым ASCII
    for s in list(base_ascii)[:200]:
        rs = _rot13_ascii(s)
        if rs != s and len(rs) >= min_len and rs not in baseline:
            total += 1
            methods["rot13"] += 1
            if len(out_samples) < max_samples:
                out_samples.append(rs)

    # Base64 фрагменты
    for m in _B64_RE.finditer(data):
        dec = _try_b64_decode(m.group(0))
        if not dec:
            continue
        # из декодированного вытащим ascii-ран
        for ss in _extract_ascii_runs(dec, min_len=min_len):
            if ss not in baseline:
                total += 1
                methods["b64"] += 1
                if len(out_samples) < max_samples:
                    out_samples.append(ss)

    # XOR-однобайтовый
    xor_keys = [1, 2, 3, 5, 0x10, 0x20, 0x40, 0xAA, 0xFF]
    for k in xor_keys:
        try:
            x = bytes(b ^ k for b in data)
            for ss in _extract_ascii_runs(x, min_len=min_len):
                if ss not in baseline:
                    total += 1
                    methods["xor"] += 1
                    if len(out_samples) < max_samples:
                        out_samples.append(ss)
        except Exception:
            continue

    return {
        "total_found": int(total),
        "methods": methods,
        "samples": out_samples,
    }
