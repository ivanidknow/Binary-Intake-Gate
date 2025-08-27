from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional
from pathlib import Path

@dataclass
class Evidence:
    meta: Dict[str, Any] = field(default_factory=dict)
    pe: Optional[Dict[str, Any]] = None
    elf: Optional[Dict[str, Any]] = None
    hashes: Dict[str, Optional[str]] = field(default_factory=dict)
    entropy: Dict[str, Any] = field(default_factory=dict)
    capa: Optional[Dict[str, Any]] = None
    yara: Optional[List[Dict[str, Any]]] = None
    vt: Optional[Dict[str, Any]] = None
    kes: Optional[Dict[str, Any]] = None
    libs: Optional[Dict[str, Any]] = None
    score: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def new_evidence(path: Path, filetype: str) -> Evidence:
    ev = Evidence()
    ev.meta = {
        "path": str(path),
        "name": path.name,
        "type": filetype,  # 'PE', 'ELF', 'EXT', 'NONE'
        "size": path.stat().st_size if path.exists() else None,
    }
    return ev
