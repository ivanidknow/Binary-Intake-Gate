from __future__ import annotations
from typing import List, Dict
import re

# аккуратный маппинг из meta и имени правила → нормализованное название packer’a
_FAMILY_HINTS = {
    "upx": "upx",
    "vmprotect": "vmprotect",
    "themida": "themida",
    "mpress": "mpress",
    "aspack": "aspack",
    "enigma": "enigma",
    "petite": "petite",
    "fsg": "fsg",
    "molebox": "molebox",
    "yoda": "yoda",
    "telock": "telock",
    "pecompact": "pecompact",
    "obsidium": "obsidium",
    "dotfuscator": "dotfuscator",
    "confuser": "confuser",
}

_NAME_RE = re.compile(r"(upx|vmprotect|themida|mpress|aspack|enigma|petite|fsg|molebox|yoda|telock|pecompact|obsidium|dotfuscator|confuser)", re.I)

def detect_packers_from_yara(yara_hits: List[Dict]) -> List[str]:
    families = set()
    for h in (yara_hits or []):
        meta = (h.get("meta") or {})
        # приоритет — meta.family / meta.packer
        for k in ("family", "packer", "group"):
            v = str(meta.get(k) or "").strip().lower()
            if v:
                for key, norm in _FAMILY_HINTS.items():
                    if key in v:
                        families.add(norm)
        # fallback — имя правила
        rname = str(h.get("rule") or "").lower()
        m = _NAME_RE.search(rname)
        if m:
            families.add(_FAMILY_HINTS.get(m.group(1).lower(), m.group(1).lower()))
    return sorted(families)
