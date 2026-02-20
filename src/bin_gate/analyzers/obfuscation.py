# src/bin_gate/analyzers/obfuscation.py
from __future__ import annotations
from typing import Dict, Any, Tuple, Optional, Set
from pathlib import Path
import string
from .strings_hunt import recover_strings

# локальные утилиты
from .entropy import sections_entropy_pe, sections_entropy_elf, file_entropy

# внешние — опционально
try:
    import pefile  # type: ignore
except Exception:
    pefile = None

try:
    from elftools.elf.elffile import ELFFile  # type: ignore
    from elftools.elf.sections import SymbolTableSection  # type: ignore
except Exception:
    ELFFile = None  # type: ignore

PRINTABLE = set(bytes(string.printable, "ascii"))
MIN_STR_LEN = 4

PACKER_SECTION_HINTS = (
    b".upx", b"upx", b".vmp", b"vmprotect", b".themida", b"mpress", b"aspack",
)

ANTI_DEBUG_STRINGS = (
    b"isdebuggerpresent", b"checkremotedebuggerpresent",
    b"ntqueryinformationprocess", b"outputdebugstringa", b"outputdebugstringw",
    b"debuggerdetected", b"__wine_dbg", b"ptrace", b"tracerpid",
    b"pr_set_dumpable", b"prctl",
)

ANTI_VM_STRINGS = (
    b"vbox", b"virtualbox", b"vmware", b"qemu", b"virtualpc",
    b"parallels", b"xen", b"hyper-v", b"kvm",
)

DYN_RESOLVE_STRINGS_PE  = (b"loadlibrarya", b"loadlibraryw", b"getprocaddress")
DYN_RESOLVE_STRINGS_ELF = (b"dlopen", b"dlsym")

INJECTION_APIS = (b"writeprocessmemory", b"createremotethread")
MEM_PROTECT_APIS = (b"virtualprotect", b"mprotect")


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except Exception:
        return 0


def _ascii_strings_ratio_and_count(path: Path, min_len: int = MIN_STR_LEN) -> Tuple[float, int]:
    size = _file_size(path)
    if size <= 0:
        return 0.0, 0
    data = path.read_bytes()
    total_len = 0
    count = 0
    cur = 0
    for b in data:
        if b in PRINTABLE and b not in (0x0b,):
            cur += 1
        else:
            if cur >= min_len:
                total_len += cur
                count += 1
            cur = 0
    if cur >= min_len:
        total_len += cur
        count += 1
    ratio = float(total_len) / float(size) if size else 0.0
    return ratio, count


def _utf16le_strings_ratio(path: Path, min_len: int = MIN_STR_LEN) -> float:
    """Очень грубо: последовательности вида ASCII_char 00 ASCII_char 00 ..."""
    size = _file_size(path)
    if size <= 0:
        return 0.0
    data = path.read_bytes()
    total_pairs = 0
    run = 0
    i = 0
    n = len(data)
    while i + 1 < n:
        c = data[i]
        z = data[i+1]
        if (c in PRINTABLE and c not in (0x0b,)) and z == 0x00:
            run += 1
            i += 2
        else:
            if run >= min_len:
                total_pairs += run
            run = 0
            i += 1
    if run >= min_len:
        total_pairs += run
    # «символ» = 2 байта, но для простоты считаем отношение байт в таких последовательностях к размеру
    total_bytes = total_pairs * 2
    return float(total_bytes) / float(size) if size else 0.0


def _pe_imports_exports_tls(path: Path) -> Tuple[Set[str], int, int]:
    """Возвращает (imports_lower, export_count, tls_callback_count)."""
    imps: Set[str] = set()
    exp_count = 0
    tls_count = 0
    if pefile is None:
        return imps, exp_count, tls_count
    try:
        pe = pefile.PE(str(path), fast_load=True)
        # IMPORTS
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT or []:
                    for imp in entry.imports or []:
                        nb = (imp.name or b"")
                        if nb:
                            imps.add(nb.decode(errors="ignore").strip().lower())
        except Exception:
            pass
        # EXPORTS
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
                exp_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols or [])
        except Exception:
            pass
        # TLS callbacks
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]])
            if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
                cbs = getattr(pe.DIRECTORY_ENTRY_TLS.struct, "AddressOfCallBacks", 0) or 0
                # приблизительно: если адрес есть — считаем как ≥1
                if cbs:
                    tls_count = 1
        except Exception:
            pass
    except Exception:
        return imps, exp_count, tls_count
    return imps, exp_count, tls_count


def _elf_symbols_flags(path: Path) -> Tuple[Set[str], int, bool, bool]:
    """
    Возвращает (imports_lower, export_count, stripped, has_init_array).
    imports_lower ~ имена из .dynsym (как "импортируемые/используемые"),
    export_count ~= число глобальных символов из .dynsym,
    stripped = нет .symtab,
    has_init_array = секция существует.
    """
    imps: Set[str] = set()
    exp_count = 0
    stripped = False
    has_init_array = False
    if ELFFile is None:
        return imps, exp_count, stripped, has_init_array
    try:
        with path.open("rb") as f:
            elf = ELFFile(f)
            # .symtab отсутствует → вероятно stripped
            stripped = (elf.get_section_by_name(".symtab") is None)
            has_init_array = (elf.get_section_by_name(".init_array") is not None)
            dynsym = elf.get_section_by_name(".dynsym")
            if isinstance(dynsym, SymbolTableSection):
                for sym in dynsym.iter_symbols():
                    n = (sym.name or "").strip()
                    if n:
                        imps.add(n.lower())
                        # приблизительно считаем экспортируемыми глобальные FUNC/OBJECT
                        bind = sym['st_info']['bind']
                        typ = sym['st_info']['type']
                        if bind == 'STB_GLOBAL' and typ in ('STT_FUNC', 'STT_OBJECT'):
                            exp_count += 1
    except Exception:
        return imps, exp_count, stripped, has_init_array
    return imps, exp_count, stripped, has_init_array


def _byte_search_any(data_lower: bytes, needles: Tuple[bytes, ...]) -> bool:
    try:
        for n in needles:
            if n and data_lower.find(n) != -1:
                return True
    except Exception:
        pass
    return False


def analyze_obfuscation(
    path: Path,
    kind: str,
    *,
    pe_info: Optional[Dict[str, Any]] = None,
    elf_info: Optional[Dict[str, Any]] = None,
    die_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Быстрые эвристики «обфускация/анти-анализ» (без дизассемблера).
    Если передан die_info — интегрирует данные от Detect It Easy.
    """
    kind = (kind or "").upper()
    out: Dict[str, Any] = {
        "score": 0,
        # строки
        "string_ratio_ascii": None,
        "string_ratio_utf16": None,
        "string_count": None,
        # энтропия
        "num_high_entropy_sections": None,
        "max_section_entropy": None,
        # импорты/экспорты
        "import_count": None,
        "export_count": None,
        # прочее
        "stripped": None,           # ELF
        "has_init_array": None,     # ELF
        "tls_callback_count": None, # PE
        "has_dyn_api_resolve": False,
        "dyn_import_ratio": 0.0,
        # индикаторы API
        "uses_virtualprotect": False,
        "uses_mprotect": False,
        "uses_writeprocessmemory": False,
        "uses_createremotethread": False,
        # агрегаты
        "packed_suspect": False,
        "packer_families": [],
        "reasons": [],
    }

    size = _file_size(path)
    # читаем не более 4МБ для строк/поиска сигнатур
    data: bytes = b""
    try:
        cap = min(size, 4 * 1024 * 1024) if size > 0 else 0
        data = path.read_bytes()[:cap] if cap else b""
    except Exception:
        data = b""
    data_l = data.lower()

    # 1) строки
    try:
        r_ascii, cnt = _ascii_strings_ratio_and_count(path)
    except Exception:
        r_ascii, cnt = 0.0, 0
    try:
        r_u16 = _utf16le_strings_ratio(path)
    except Exception:
        r_u16 = 0.0

    out["string_ratio_ascii"] = r_ascii
    out["string_ratio_utf16"] = r_u16
    out["string_count"] = cnt

    # stringless + высокая общая энтропия
    try:
        if (r_ascii + r_u16) < 0.004 and file_entropy(path) >= 7.0:
            out["reasons"].append("stringless_high_entropy")
            out["score"] += 20
    except Exception:
        pass

    # 2) секции/энтропия → packer suspicion
    num_high = 0
    max_ent = 0.0
    try:
        if kind == "PE":
            ent = sections_entropy_pe(path) or {}
        elif kind == "ELF":
            ent = sections_entropy_elf(path) or {}
        else:
            ent = {}
        for _, val in (ent.items() if isinstance(ent, dict) else []):
            try:
                v = float(val or 0)
                if v >= 7.2:
                    num_high += 1
                if v > max_ent:
                    max_ent = v
            except Exception:
                continue
    except Exception:
        pass
    out["num_high_entropy_sections"] = num_high
    out["max_section_entropy"] = max_ent if max_ent > 0 else None

    # 3) imports/exports + dynamic resolve
    imports: Set[str] = set()
    export_count = 0
    tls_cb = None
    stripped = None
    has_init_array = None

    try:
        if kind == "PE":
            imports, export_count, tls_cb = _pe_imports_exports_tls(path)
            out["import_count"] = len(imports)
            out["export_count"] = export_count
            out["tls_callback_count"] = tls_cb
            # имена секций/подсказки packer
            if _byte_search_any(data_l, tuple(n for n in PACKER_SECTION_HINTS)):
                out["packed_suspect"] = True
                out["reasons"].append("packer_section_hint")
                out["score"] += 15
            # overlay сигнал уже лучше брать из pe_info, но в этом этапе опционально
        elif kind == "ELF":
            imports, export_count, stripped, has_init_array = _elf_symbols_flags(path)
            out["import_count"] = len(imports)
            out["export_count"] = export_count
            out["stripped"] = stripped
            out["has_init_array"] = has_init_array
    except Exception:
        pass

    # динамическая резольвация API
    try:
        if kind == "PE":
            has_dyn = (any(s.decode() in imports for s in DYN_RESOLVE_STRINGS_PE)
                       or _byte_search_any(data_l, DYN_RESOLVE_STRINGS_PE))
        elif kind == "ELF":
            has_dyn = (any(s.decode() in imports for s in DYN_RESOLVE_STRINGS_ELF)
                       or _byte_search_any(data_l, DYN_RESOLVE_STRINGS_ELF))
        else:
            has_dyn = False
        if has_dyn:
            out["has_dyn_api_resolve"] = True
            out["reasons"].append("dynamic_api_resolve")
            out["score"] += 20
    except Exception:
        pass

    # грубая dyn_import_ratio
    try:
        ic = int(out.get("import_count") or 0)
        out["dyn_import_ratio"] = (1.0 / (ic + 1)) if out["has_dyn_api_resolve"] else 0.0
    except Exception:
        out["dyn_import_ratio"] = 0.0

    # 4) anti-debug / anti-VM / mem-protect / injection
    try:
        if _byte_search_any(data_l, ANTI_DEBUG_STRINGS):
            out["reasons"].append("anti_debug")
            out["score"] += 15
        if _byte_search_any(data_l, ANTI_VM_STRINGS):
            out["reasons"].append("anti_vm")
            out["score"] += 10
        if _byte_search_any(data_l, (b"virtualprotect",)):
            out["uses_virtualprotect"] = True
            out["reasons"].append("vprotect_usage")
            out["score"] += 10
        if _byte_search_any(data_l, (b"mprotect",)):
            out["uses_mprotect"] = True
            out["reasons"].append("mprotect_usage")
            out["score"] += 10
        if _byte_search_any(data_l, (b"writeprocessmemory",)):
            out["uses_writeprocessmemory"] = True
            out["reasons"].append("wpm_usage")
            out["score"] += 20
        if _byte_search_any(data_l, (b"createremotethread",)):
            out["uses_createremotethread"] = True
            out["reasons"].append("crt_usage")
            out["score"] += 20
    except Exception:
        pass

    # 5) подозрение на packer: высокая энтропия секций, подсказки
    try:
        if num_high >= 1:
            out["packed_suspect"] = True
            out["reasons"].append("packed_suspect_sections")
            out["score"] += 25
    except Exception:
        pass

    # 6) попытка восстановить скрытые строки (XOR/ROT13/Base64/UTF-16)
    try:
        rec = recover_strings(path, blob=data, limit_bytes=2*1024*1024, min_len=6, max_samples=8)
    except Exception:
        rec = None

    if isinstance(rec, dict):
        out["recovered_strings_count"] = int(rec.get("total_found") or 0)
        out["recovered_strings_samples"] = list(rec.get("samples") or [])
        out["recovered_strings_methods"] = dict(rec.get("methods") or {})
        if out["recovered_strings_count"] >= 5:
            out["reasons"].append("obf_strings_recovered")
            out["score"] += min(20, out["recovered_strings_count"] * 2)

    # 7) Интеграция DIE (Detect It Easy) если передано
    if die_info and isinstance(die_info, dict):
        try:
            # Packer families from DIE
            die_packers = die_info.get("packer_families") or []
            if die_packers:
                out["packed_suspect"] = True
                out["packer_families"] = list(set(out.get("packer_families", []) + die_packers))
                if "die_packer_detected" not in out["reasons"]:
                    out["reasons"].append("die_packer_detected")
                    out["score"] += 25

            # Protector detection
            if die_info.get("protector"):
                out["reasons"].append(f"die_protector:{die_info['protector']}")
                out["score"] += 30

            # Entropy from DIE
            die_entropy = die_info.get("entropy") or {}
            if isinstance(die_entropy, dict):
                die_file_ent = die_entropy.get("file")
                if die_file_ent and (out.get("max_section_entropy") is None or die_file_ent > out["max_section_entropy"]):
                    out["max_section_entropy"] = die_file_ent
                # Count high entropy sections
                die_sections = die_entropy.get("sections") or {}
                if isinstance(die_sections, dict):
                    high_ent = sum(1 for v in die_sections.values() if isinstance(v, (int, float)) and v >= 7.2)
                    if high_ent > (out.get("num_high_entropy_sections") or 0):
                        out["num_high_entropy_sections"] = high_ent

            # Merge DIE reasons
            die_reasons = die_info.get("reasons") or []
            for r in die_reasons:
                if r and r not in out["reasons"]:
                    out["reasons"].append(r)

            # Add DIE score (avoid double counting)
            die_score = die_info.get("score") or 0
            if die_score > 0 and "die_packer_detected" not in out["reasons"]:
                out["score"] += min(die_score, 30)

        except Exception:
            pass

    # усечём score
    if out["score"] > 100:
        out["score"] = 100
    return out
