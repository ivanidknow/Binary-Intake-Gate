from __future__ import annotations
from pathlib import Path
from typing import Dict, Any

def analyze_elf_checksec(path: Path) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "hardening": {"pie": None, "nx": None, "relro": None, "canary": None, "rpath": None, "runpath": None, "textrel": None},
        "setuid_setgid": None,
        "errors": []
    }
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore
        from elftools.elf.dynamic import DynamicSegment  # type: ignore
    except Exception as e:
        info["errors"].append(f"elftools_import_error:{e}")
        return info

    try:
        with path.open("rb") as f:
            elf = ELFFile(f)

            # PIE: ET_DYN
            e_type = elf.header["e_type"]
            info["hardening"]["pie"] = (e_type == "ET_DYN")

            # RELRO, RUNPATH/RPATH, TEXTREL, NX
            has_gnu_relro = False
            bind_now = False
            rpath = None
            runpath = None
            textrel = False
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_GNU_STACK":
                    flags = seg.header.p_flags  # PF_X=1
                    exec_on_stack = bool(flags & 1)
                    info["hardening"]["nx"] = not exec_on_stack
                if seg.header.p_type == "PT_GNU_RELRO":
                    has_gnu_relro = True
                if isinstance(seg, DynamicSegment):
                    for tag in seg.iter_tags():
                        if tag.entry.d_tag == "DT_BIND_NOW":
                            bind_now = True
                        elif tag.entry.d_tag == "DT_RPATH":
                            rpath = tag.rpath
                        elif tag.entry.d_tag == "DT_RUNPATH":
                            runpath = tag.runpath
                        elif tag.entry.d_tag == "DT_TEXTREL":
                            textrel = True

            if has_gnu_relro and bind_now:
                relro = "full"
            elif has_gnu_relro:
                relro = "partial"
            else:
                relro = "none"
            info["hardening"]["relro"] = relro
            info["hardening"]["rpath"] = bool(rpath)
            info["hardening"]["runpath"] = bool(runpath)
            info["hardening"]["textrel"] = bool(textrel)

            # Canary: символ __stack_chk_fail в .dynsym
            has_canary = False
            try:
                dynsym = elf.get_section_by_name(".dynsym")
                if dynsym:
                    for sym in dynsym.iter_symbols():
                        if sym.name == "__stack_chk_fail":
                            has_canary = True
                            break
            except Exception:
                pass
            info["hardening"]["canary"] = has_canary

            # SUID/SGID (по битам на FS)
            try:
                st = path.stat()
                info["setuid_setgid"] = bool(st.st_mode & 0o4000 or st.st_mode & 0o2000)
            except Exception:
                info["setuid_setgid"] = None

    except Exception as e:
        info["errors"].append(f"elf_parse_error:{e}")
    return info
