# language_detector.py — сигнатуры Nim, Delphi, AutoIt для детекции по контенту; диспетчеризация AutoIt → поиск скрипта в ресурсах
from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

# Сигнатуры по байтам (подстроки в файле)
NIM_SIGNATURES = (
    b"nimrtl",
    b"NimMain",
    b"nimFrame",
    b"raiseException",
    b"system.nim",
    b"nimZeroMem",
)
DELPHI_SIGNATURES = (
    b"TApplication",
    b"TForm",
    b"Borland",
    b"Delphi",
    b"VCL",
    b".tls",
    b"Pascal",
)
AUTOIT_SIGNATURES = (
    b"AutoIt",
    b"AutoIt3",
    b"AU3!",
    b"AutoItScript",
    b"#AutoIt3Script",
)
# v2.0 Exotic: Ruby/Lua embedded, Swift
RUBY_SIGNATURES = (
    b"ruby\x00",
    b"RUBY\x00",
    b"mri_embed",
    b"RString",
    b"rb_enc",
)
LUA_SIGNATURES = (
    b"lua_\x00",
    b"LUA\x00",
    b"luaL_",
    b"lua_state",
    b"luaopen_",
)
SWIFT_SIGNATURES = (
    b"swiftCore",
    b"$s",
    b"Swift\x00",
    b"swift_retain",
    b"swift_release",
)
# JAR-in-EXE (Launch4j): PK\x03\x04 внутри PE
JAR_IN_PE_MAGIC = b"PK\x03\x04"
LAUNCH4J_HINT = b"Launch4j"

# Legacy/Exotic: Haskell, D, Fortran
HASKELL_SIGNATURES = (
    b"ghc-prim",
    b"base:GHC",
    b"GHC.Base",
    b"ghcversion",
    b"base_Prelude",
)
D_SIGNATURES = (
    b"_Dmain",
    b"_d_run_main",
    b"object.d",
    b"core.thread",
)
FORTRAN_SIGNATURES = (
    b"for_main",
    b"_gfortran",
    b"libgfortran",
    b"GFORTRAN",
)
# Perl-to-EXE (PAR/pp): оверлей содержит PAR-архив
PAR_OVERLAY_SIGNATURES = (b"PAR\x00", b"par-", b"PAR.pm", b"pp.bat", b"perl5lib")

# Go: runtime, itab, build ID (для test_language_recognition и Evidence.meta.language)
GO_SIGNATURES = (
    b"runtime.main",
    b"go.itab.",
    b"Go build ID",
    b"runtime.morestack",
    b"go.string.",
    b"go.func.",
    b"runtime.",
    b"go.buildid",
    b"type..importpath",
)
# Rust: mangled symbols, ABI, cargo paths (без общих core::/std:: чтобы не путать с C++)
RUST_SIGNATURES = (
    b"_ZN4rust",
    b"__rust_abi",
    b".cargo/registry",
    b"rust_alloc",
    b"rust_eh_personality",
    b"__rust_",
    b"lang_start",
)


def detect_from_content(data: bytes, max_scan: int = 512 * 1024) -> Optional[str]:
    """
    Определяет язык по сигнатурам (Nim, Delphi, AutoIt, Ruby, Lua, Swift, Haskell, D, Fortran).
    Возвращает соответствующий идентификатор языка или None.
    """
    if not data:
        return None
    scan = data[:max_scan] if len(data) > max_scan else data
    if any(s in scan for s in NIM_SIGNATURES):
        return "Nim"
    if any(s in scan for s in DELPHI_SIGNATURES):
        return "Delphi"
    if any(s in scan for s in AUTOIT_SIGNATURES):
        return "AutoIt"
    if any(s in scan for s in RUBY_SIGNATURES):
        return "Ruby"
    if any(s in scan for s in LUA_SIGNATURES):
        return "Lua"
    if any(s in scan for s in SWIFT_SIGNATURES):
        return "Swift"
    if any(s in scan for s in HASKELL_SIGNATURES):
        return "Haskell"
    if any(s in scan for s in D_SIGNATURES):
        return "D"
    if any(s in scan for s in FORTRAN_SIGNATURES):
        return "Fortran"
    if any(s in scan for s in GO_SIGNATURES):
        return "Go"
    if any(s in scan for s in RUST_SIGNATURES):
        return "Rust"
    return None


def find_jar_in_pe(data: bytes, max_scan: int = 50 * 1024 * 1024) -> Optional[int]:
    """
    Поиск заголовка PK\\x03\\x04 (ZIP/JAR) внутри PE (типично Launch4j).
    Возвращает смещение первого вхождения или None. Анализ только в оверлее (после последней секции).
    """
    if not data or len(data) < 64:
        return None
    scan = data[:max_scan] if len(data) > max_scan else data
    pos = scan.find(JAR_IN_PE_MAGIC)
    if pos >= 0:
        return pos
    return None


def find_perl_par_in_pe(data: bytes, overlay_start: Optional[int] = None, max_tail: int = 4 * 1024 * 1024) -> bool:
    """
    Детект Perl-to-EXE (PAR/pp): ищет сигнатуры PAR в оверлее (после overlay_start или в хвосте файла).
    Если overlay_start не задан, сканирует последние max_tail байт.
    """
    if not data or len(data) < 256:
        return False
    if overlay_start is not None:
        region = data[overlay_start : overlay_start + max_tail]
    else:
        region = data[-max_tail:] if len(data) > max_tail else data
    return any(sig in region for sig in PAR_OVERLAY_SIGNATURES)


def detect_language_from_file(path: Path, max_bytes: int = 512 * 1024) -> Optional[str]:
    """Детекция языка по файлу (сигнатуры Nim, Delphi, AutoIt)."""
    path = Path(path)
    if not path.exists() or not path.is_file():
        return None
    try:
        data = path.read_bytes()
    except Exception:
        return None
    return detect_from_content(data, max_scan=max_bytes)


def should_scan_autoit_resources(
    language: Optional[str],
    die_info: Optional[Dict[str, Any]] = None,
    yara_hits: Optional[List[Dict[str, Any]]] = None,
) -> bool:
    """
    Если обнаружен AutoIt — вернуть True, чтобы направить файл на поиск скрытого скрипта в ресурсах.
    """
    if language and isinstance(language, str):
        if "autoit" in language.lower() or "autohotkey" in language.lower():
            return True
    if die_info and isinstance(die_info, dict):
        for d in die_info.get("detects") or []:
            name = (d.get("name") or d.get("sName") or "") if isinstance(d, dict) else str(d)
            if "autoit" in name.lower() or "autohotkey" in name.lower():
                return True
    if yara_hits:
        for h in yara_hits:
            if not isinstance(h, dict):
                continue
            rule = (h.get("rule") or "").lower()
            ns = (h.get("namespace") or "").lower()
            if "autoit" in rule or "autoit" in ns or "autohotkey" in rule or "autohotkey" in ns:
                return True
    return False


def detect_and_route(
    path: Path,
    die_info: Optional[Dict[str, Any]] = None,
    yara_hits: Optional[List[Dict[str, Any]]] = None,
    data: Optional[bytes] = None,
) -> Tuple[Optional[str], Dict[str, Any]]:
    """
    Детекция языка по файлу + DIE/YARA; рекомендации по диспетчеризации.
    Возвращает (language, options). options: scan_autoit_resources, route_jar_in_pe, jar_in_pe_offset.
    data: опционально уже прочитанные байты (для больших файлов — только заголовки).
    """
    if data is None:
        lang_from_content = detect_language_from_file(path)
    else:
        lang_from_content = detect_from_content(data)
    lang_from_die_yara = None
    try:
        from .language_analyzer import infer_language
        lang_from_die_yara = infer_language(die_info=die_info, yara_hits=yara_hits)
    except Exception:
        pass
    language = lang_from_die_yara or lang_from_content
    options: Dict[str, Any] = {}
    options["scan_autoit_resources"] = should_scan_autoit_resources(language, die_info, yara_hits)
    # JAR-in-EXE (Launch4j): перенаправление на анализ байт-кода
    file_data = data
    if file_data is None and path.exists():
        try:
            file_data = path.read_bytes()
        except Exception:
            file_data = None
    if file_data and len(file_data) >= 64 and file_data[:2] == b"MZ":
        jar_offset = find_jar_in_pe(file_data)
        if jar_offset is not None:
            options["route_jar_in_pe"] = True
            options["jar_in_pe_offset"] = jar_offset
            if not language:
                language = "Java"
        if find_perl_par_in_pe(file_data):
            options["route_perl_par"] = True
            if not language:
                language = "Perl"
    return (language, options)


def get_detection_and_route(
    path: Path,
    die_info: Optional[Dict[str, Any]] = None,
    yara_hits: Optional[List[Dict[str, Any]]] = None,
    data: Optional[bytes] = None,
) -> Dict[str, Any]:
    """
    Удобный формат для пайплайна: language, route_autoit_resources, route_jar_in_pe, jar_in_pe_offset.
    """
    lang, options = detect_and_route(path, die_info=die_info, yara_hits=yara_hits, data=data)
    return {
        "language": lang,
        "route_autoit_resources": options.get("scan_autoit_resources", False),
        "route_jar_in_pe": options.get("route_jar_in_pe", False),
        "jar_in_pe_offset": options.get("jar_in_pe_offset"),
        "route_perl_par": options.get("route_perl_par", False),
    }
