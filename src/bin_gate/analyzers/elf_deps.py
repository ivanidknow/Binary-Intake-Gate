from __future__ import annotations
from typing import List, Dict, Any
from pathlib import Path

def _with_pyelftools(p: Path) -> List[Dict[str, str]]:
    try:
        from elftools.elf.elffile import ELFFile
    except Exception:
        return []
    out: List[Dict[str, str]] = []
    try:
        with p.open("rb") as f:
            ef = ELFFile(f)
            dyn = ef.get_section_by_name(".dynamic")
            if not dyn:
                return out
            soname = None
            needed: List[str] = []
            for tag in dyn.iter_tags():
                if tag.entry.d_tag == "DT_SONAME":
                    soname = str(tag.soname)
                elif tag.entry.d_tag == "DT_NEEDED":
                    needed.append(str(tag.needed))
            # складываем SONAME тоже как «lib»
            if soname:
                out.append({"library": soname, "source": "SONAME"})
            for n in needed:
                out.append({"library": n, "source": "NEEDED"})
    except Exception:
        return []
    return out

def list_elf_shared_libs(file_path: Path) -> List[Dict[str, str]]:
    """
    Возвращает [{library:'libssl.so.3', source:'NEEDED|SONAME'}, ...] или [].
    Без внешних утилит; использует pyelftools при наличии.
    """
    return _with_pyelftools(file_path)
