# smart_gate.py — Trivage: skip heavy FLOSS/capa when file looks trusted
from __future__ import annotations
from typing import Dict, Any, Optional

# Порог энтропии: ниже = «нормальный» код без обфускации
ENTROPY_TRUSTED_MAX = 7.0

# Категории импортов PE, наличие которых отключает пропуск тяжёлого скана
SUSPICIOUS_IMPORT_CATEGORIES = frozenset({
    "loader",       # GetProcAddress, LoadLibrary
    "memory",       # VirtualProtect, VirtualAlloc, WriteProcessMemory
    "proc_thread",  # CreateRemoteThread, OpenProcess
    "debug_sym",    # SymInitialize, MiniDump
})


def should_skip_heavy_analysis(
    kind: str,
    pe: Optional[Dict[str, Any]] = None,
    elf: Optional[Dict[str, Any]] = None,
    file_entropy: Optional[float] = None,
) -> bool:
    """
    Smart gating (Trivage): skip FLOSS and deep capa when:
    - PE: valid digital signature + low entropy + no suspicious imports;
    - ELF: low entropy only (no signature concept in same way).
    Returns True = skip heavy tools.
    """
    if file_entropy is not None and file_entropy > ENTROPY_TRUSTED_MAX:
        return False

    if kind == "PE" and pe:
        sig = (pe.get("signature") or {})
        if not sig.get("present"):
            return False
        # valid/chain_ok can be None on non-Windows; treat present as enough if entropy low
        if sig.get("valid") is False or sig.get("chain_ok") is False:
            return False
        summary = (pe.get("imports_summary") or {})
        for cat in SUSPICIOUS_IMPORT_CATEGORIES:
            if summary.get(cat):
                return False
        return True

    if kind == "ELF" and elf is not None:
        # ELF: only low entropy; no RELRO/textrel abuse as simple proxy
        h = (elf.get("hardening") or {})
        if h.get("textrel") is True:
            return False
        return True

    return False
