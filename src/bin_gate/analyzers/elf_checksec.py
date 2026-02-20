from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Optional
import struct

# DT_FLAGS_1 bits
DF_1_NOW = 0x00000001
DF_1_PIE = 0x08000000

# DT_FLAGS bits
DF_BIND_NOW = 0x00000008
DF_TEXTREL = 0x00000004

# GNU Property Types for CET/BTI
GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002
GNU_PROPERTY_X86_FEATURE_1_IBT = 0x00000001
GNU_PROPERTY_X86_FEATURE_1_SHSTK = 0x00000002
GNU_PROPERTY_X86_ISA_1_NEEDED = 0xc0000000

# AArch64 GNU Property for BTI
GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xc0000000
GNU_PROPERTY_AARCH64_FEATURE_1_BTI = 0x00000001
GNU_PROPERTY_AARCH64_FEATURE_1_PAC = 0x00000002

def _split_pathlist(val: Optional[str]) -> List[str]:
    if not val:
        return []
    return [p for p in str(val).split(":") if p is not None]

def _rpath_risky(paths: List[str]) -> bool:
    for p in paths:
        if p == "" or p == ".":
            return True
        if p.startswith("./") or p.startswith("../"):
            return True
        # относительный без $ORIGIN
        if not (p.startswith("/") or p.startswith("$ORIGIN")):
            return True
    return False


def _parse_gnu_property_note(data: bytes, is_64bit: bool, is_arm: bool) -> dict:
    """
    Parse .note.gnu.property section to extract CET (IBT/SHSTK) and ARM BTI/PAC flags.
    
    Note format:
    - 4 bytes: n_namesz
    - 4 bytes: n_descsz  
    - 4 bytes: n_type
    - n_namesz bytes: name (padded to 4/8 byte boundary)
    - n_descsz bytes: descriptor containing property entries
    
    Property entry format:
    - 4 bytes: pr_type
    - 4 bytes: pr_datasz
    - pr_datasz bytes: pr_data (padded to 4/8 byte boundary)
    """
    result = {
        "ibt": False,
        "shstk": False,
        "bti": False,
        "pac": False,
    }
    
    if not data or len(data) < 12:
        return result
    
    try:
        offset = 0
        align = 8 if is_64bit else 4
        
        while offset + 12 <= len(data):
            n_namesz, n_descsz, n_type = struct.unpack_from("<III", data, offset)
            offset += 12
            
            # Align name size
            name_aligned = (n_namesz + (align - 1)) & ~(align - 1)
            if offset + name_aligned > len(data):
                break
                
            name = data[offset:offset + n_namesz].rstrip(b'\x00')
            offset += name_aligned
            
            # Check if this is a GNU note
            if name != b"GNU":
                desc_aligned = (n_descsz + (align - 1)) & ~(align - 1)
                offset += desc_aligned
                continue
            
            # Parse property entries in descriptor
            desc_end = offset + n_descsz
            while offset + 8 <= desc_end:
                pr_type, pr_datasz = struct.unpack_from("<II", data, offset)
                offset += 8
                
                if pr_datasz > 0 and offset + pr_datasz <= len(data):
                    pr_data = data[offset:offset + pr_datasz]
                    
                    # x86/x64 CET features
                    if pr_type == GNU_PROPERTY_X86_FEATURE_1_AND and len(pr_data) >= 4:
                        features = struct.unpack("<I", pr_data[:4])[0]
                        result["ibt"] = bool(features & GNU_PROPERTY_X86_FEATURE_1_IBT)
                        result["shstk"] = bool(features & GNU_PROPERTY_X86_FEATURE_1_SHSTK)
                    
                    # AArch64 BTI/PAC features
                    if is_arm and pr_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND and len(pr_data) >= 4:
                        features = struct.unpack("<I", pr_data[:4])[0]
                        result["bti"] = bool(features & GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
                        result["pac"] = bool(features & GNU_PROPERTY_AARCH64_FEATURE_1_PAC)
                
                # Align to next property
                pr_aligned = (pr_datasz + (align - 1)) & ~(align - 1)
                offset += pr_aligned
            
            # Align descriptor
            desc_aligned = (n_descsz + (align - 1)) & ~(align - 1)
            offset = (offset - n_descsz) + desc_aligned + n_descsz
            
    except Exception:
        pass
    
    return result

def analyze_elf_checksec(path: Path) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "hardening": {
            "pie": None,       # bool|None
            "nx": None,        # bool|None
            "relro": None,     # "full"/"partial"/"none"
            "relro_full": None,   # bool - explicitly True only for Full RELRO
            "canary": None,    # bool
            "rpath": None,     # str|None
            "runpath": None,   # str|None
            "textrel": None,   # bool|None
            "w_x_segments": False,  # есть ли RWX LOAD-сегменты
            "rpath_risky": None,    # bool|None
            # Enterprise ARM checks
            "bti": None,       # bool - ARM Branch Target Identification
            "pac": None,       # bool - ARM Pointer Authentication Code
        },
        "interp": None,          # динамический линкер (PT_INTERP)
        "build_id": None,        # из .note.gnu.build-id
        "soname": None,          # DT_SONAME
        "needed": [],            # DT_NEEDED[]
        "static_linked": None,   # bool
        "stripped": None,        # bool (нет .symtab)
        "fortify": {"used": None, "count": 0},
        "cet": {"ibt": None, "shstk": None},  # x86/x64 CET
        "setuid_setgid": None,
        "arch": None,  # "x86", "x64", "arm", "arm64", etc.
        "errors": []
    }
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore
        from elftools.elf.dynamic import DynamicSegment  # type: ignore
        from elftools.elf.sections import NoteSection  # type: ignore
    except Exception as e:
        info["errors"].append(f"elftools_import_error:{e}")
        return info

    try:
        with path.open("rb") as f:
            elf = ELFFile(f)

            # --- Базовые заголовки/инфо
            e_type = elf.header.get("e_type")
            e_machine = elf.header.get("e_machine")
            is_64bit = elf.elfclass == 64
            
            # Determine architecture
            arch_map = {
                "EM_386": "x86",
                "EM_X86_64": "x64",
                "EM_ARM": "arm",
                "EM_AARCH64": "arm64",
                "EM_MIPS": "mips",
                "EM_PPC": "ppc",
                "EM_PPC64": "ppc64",
                "EM_RISCV": "riscv",
            }
            info["arch"] = arch_map.get(e_machine, str(e_machine) if e_machine else None)
            is_arm = e_machine in ("EM_ARM", "EM_AARCH64")
            # INTERP (динамический линкер)
            interp = None
            try:
                for seg in elf.iter_segments():
                    if seg.header.p_type == "PT_INTERP":
                        # у InterpSegment есть get_interp_name()
                        try:
                            interp = seg.get_interp_name()
                        except Exception:
                            data = seg.data()
                            interp = data.split(b"\x00")[0].decode(errors="ignore") if data else None
                        break
            except Exception:
                pass
            info["interp"] = interp
            info["static_linked"] = (interp is None)

            # PIE: ET_DYN с интерпретатором (исполняемый PIE) или DF_1_PIE
            pie = (e_type == "ET_DYN" and interp is not None)
            info["hardening"]["pie"] = bool(pie)

            # --- Сегменты: NX (PT_GNU_STACK), RELRO, RPATH/RUNPATH, TEXTREL, W^X, DT_NEEDED/SONAME/FLAGS
            has_gnu_relro = False
            bind_now = False
            flags_1 = 0
            flags_0 = 0
            rpath_val: Optional[str] = None
            runpath_val: Optional[str] = None
            textrel = False
            needed: List[str] = []
            soname: Optional[str] = None

            # Для NX: будем считать только если PT_GNU_STACK найден
            nx: Optional[bool] = None

            for seg in elf.iter_segments():
                ptype = seg.header.p_type

                # NX: PT_GNU_STACK → NX = not exec_on_stack
                if ptype == "PT_GNU_STACK":
                    flags = int(seg.header.p_flags or 0)  # PF_X = 0x1
                    exec_on_stack = bool(flags & 0x1)
                    nx = (not exec_on_stack)

                # RWX LOAD-сегменты
                if ptype == "PT_LOAD":
                    fl = int(seg.header.p_flags or 0)
                    has_wx = bool((fl & 0x2) and (fl & 0x1))  # PF_W=0x2, PF_X=0x1
                    if has_wx:
                        info["hardening"]["w_x_segments"] = True

                if ptype == "PT_GNU_RELRO":
                    has_gnu_relro = True

                if isinstance(seg, DynamicSegment):
                    for tag in seg.iter_tags():
                        dtag = tag.entry.d_tag
                        if dtag == "DT_BIND_NOW":
                            bind_now = True
                        elif dtag == "DT_FLAGS_1":
                            flags_1 = int(tag.entry.d_val or 0)
                        elif dtag == "DT_FLAGS":
                            flags_0 = int(tag.entry.d_val or 0)
                        elif dtag == "DT_RPATH":
                            rpath_val = str(getattr(tag, "rpath", "") or "")
                        elif dtag == "DT_RUNPATH":
                            runpath_val = str(getattr(tag, "runpath", "") or "")
                        elif dtag == "DT_TEXTREL":
                            textrel = True
                        elif dtag == "DT_NEEDED":
                            try:
                                needed.append(str(tag.needed))
                            except Exception:
                                pass
                        elif dtag == "DT_SONAME":
                            try:
                                soname = str(tag.soname)
                            except Exception:
                                pass

            info["hardening"]["nx"] = nx  # None, если PT_GNU_STACK не найден

            # RELRO: full = PT_GNU_RELRO + (DT_BIND_NOW || DF_1_NOW || DF_BIND_NOW in DT_FLAGS)
            # Strict check: DF_1_NOW in DT_FLAGS_1 OR DF_BIND_NOW in DT_FLAGS OR DT_BIND_NOW tag
            now_flag = bind_now or bool(flags_1 & DF_1_NOW) or bool(flags_0 & DF_BIND_NOW)
            if has_gnu_relro and now_flag:
                relro = "full"
                info["hardening"]["relro_full"] = True
            elif has_gnu_relro:
                relro = "partial"
                info["hardening"]["relro_full"] = False
            else:
                relro = "none"
                info["hardening"]["relro_full"] = False
            info["hardening"]["relro"] = relro

            # TEXTREL: также через DF_TEXTREL
            if not textrel and (flags_0 & DF_TEXTREL):
                textrel = True
            info["hardening"]["textrel"] = bool(textrel)

            # RPATH/RUNPATH + риск-оценка
            info["hardening"]["rpath"] = rpath_val
            info["hardening"]["runpath"] = runpath_val
            paths = _split_pathlist(runpath_val or rpath_val)
            info["hardening"]["rpath_risky"] = (None if not paths else _rpath_risky(paths))

            info["soname"] = soname
            info["needed"] = needed

            # Canary: ищем в dynsym и symtab
            has_canary = False
            try:
                for secname in (".dynsym", ".symtab"):
                    sec = elf.get_section_by_name(secname)
                    if sec is None:
                        continue
                    for sym in sec.iter_symbols():
                        if sym.name == "__stack_chk_fail":
                            has_canary = True
                            break
                    if has_canary:
                        break
            except Exception:
                pass
            info["hardening"]["canary"] = has_canary

            # FORTIFY: наличие *_chk символов
            fortify_cnt = 0
            try:
                chk_names = {
                    "__memcpy_chk","__memmove_chk","__mempcpy_chk","__strcpy_chk",
                    "__strncpy_chk","__sprintf_chk","__snprintf_chk","__vsprintf_chk",
                    "__vsnprintf_chk","__read_chk","__recv_chk","__gets_chk"
                }
                for secname in (".dynsym", ".symtab"):
                    sec = elf.get_section_by_name(secname)
                    if sec is None:
                        continue
                    for sym in sec.iter_symbols():
                        if sym.name in chk_names:
                            fortify_cnt += 1
                if fortify_cnt > 0:
                    info["fortify"]["used"] = True
                    info["fortify"]["count"] = fortify_cnt
                else:
                    info["fortify"]["used"] = False
            except Exception:
                info["fortify"]["used"] = None

            # Build-ID: из .note.gnu.build-id (если есть)
            try:
                nsec = elf.get_section_by_name(".note.gnu.build-id")
                if isinstance(nsec, NoteSection):
                    for note in nsec.iter_notes():
                        if (note["n_type"] == "NT_GNU_BUILD_ID") or (str(note["n_type"]).endswith("BUILD_ID")):
                            desc = note["n_desc"]
                            if isinstance(desc, (bytes, bytearray)):
                                info["build_id"] = desc.hex()
                            else:
                                # pyelftools иногда даёт bytes уже
                                try:
                                    info["build_id"] = bytes(desc).hex()
                                except Exception:
                                    pass
            except Exception:
                pass

            # CET (IBT/SHSTK) and ARM BTI/PAC — proper .note.gnu.property parsing
            try:
                psec = elf.get_section_by_name(".note.gnu.property")
                if psec is not None:
                    blob = psec.data() or b""
                    props = _parse_gnu_property_note(blob, is_64bit, is_arm)
                    
                    # x86/x64 CET
                    info["cet"]["ibt"] = props.get("ibt", False)
                    info["cet"]["shstk"] = props.get("shstk", False)
                    
                    # ARM BTI/PAC
                    if is_arm:
                        info["hardening"]["bti"] = props.get("bti", False)
                        info["hardening"]["pac"] = props.get("pac", False)
                else:
                    # No .note.gnu.property section - CET/BTI not enabled
                    info["cet"]["ibt"] = False
                    info["cet"]["shstk"] = False
                    if is_arm:
                        info["hardening"]["bti"] = False
                        info["hardening"]["pac"] = False
            except Exception as e:
                info["errors"].append(f"gnu_property_parse_error:{e}")

            # SUID/SGID (по битам на FS)
            try:
                st = path.stat()
                info["setuid_setgid"] = bool(st.st_mode & 0o4000 or st.st_mode & 0o2000)
            except Exception:
                info["setuid_setgid"] = None

            # stripped: нет .symtab
            try:
                info["stripped"] = (elf.get_section_by_name(".symtab") is None)
            except Exception:
                info["stripped"] = None

    except Exception as e:
        info["errors"].append(f"elf_parse_error:{e}")
    return info
