from __future__ import annotations
from pathlib import Path
from typing import Dict, Any

def analyze(p: Path) -> Dict[str, Any]:
    data = p.read_bytes()
    # очень грубо: признаки наличия подписи/entitlements
    has_codesig = b"LC_CODE_SIGNATURE" in data or b"CodeResources" in data
    has_ent = b"com.apple.security" in data or b"entitlements" in data
    # грубо: PAGEZERO/SEGMENT в текстовом виде (символы в бинаре часто присутствуют)
    has_pagezero = b"__PAGEZERO" in data
    # RWX эвристика проверить сложно без парсера LC; оставим флажок "unknown"
    return {
        "present": True,
        "codesign": {"present": has_codesig},
        "entitlements": {"present": has_ent},
        "pagezero": has_pagezero,
        "notes": "lightweight Mach-O check (no full LC parsing)",
    }
