from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import platform, json, subprocess, re
from collections import defaultdict, Counter

# ---- PE constants ---------------------------------------------------------

# DllCharacteristics flags
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020  # HighEntropyVA
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE    = 0x0040  # ASLR
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080  # /INTEGRITYCHECK — VBS/HVCI compatibility
IMAGE_DLLCHARACTERISTICS_NX_COMPAT       = 0x0100  # DEP
IMAGE_DLLCHARACTERISTICS_GUARD_CF        = 0x4000  # CFG

# FileHeader.Characteristics
IMAGE_FILE_RELOCS_STRIPPED  = 0x0001
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
IMAGE_FILE_DLL              = 0x2000

# Machine
IMAGE_FILE_MACHINE_I386   = 0x014c
IMAGE_FILE_MACHINE_AMD64  = 0x8664
IMAGE_FILE_MACHINE_ARM64  = 0xAA64

# Data directory indices
DIR_EXPORT         = 0
DIR_IMPORT         = 1
DIR_RESOURCE       = 2
DIR_SECURITY       = 4
DIR_BASERELOC      = 5
DIR_DEBUG          = 6
DIR_TLS            = 9
DIR_LOAD_CONFIG    = 10
DIR_COM_DESCRIPTOR = 14
DIR_DELAY_IMPORT   = 13  # IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT

# Subsystem map
SUBSYS_MAP = {
    1: "Native", 2: "Windows GUI", 3: "Windows CUI", 7: "POSIX CUI",
    9: "Windows CE GUI", 10: "EFI Application", 11: "EFI Driver",
    12: "EFI ROM", 14: "Xbox", 16: "Windows Boot App",
}

# LoadConfig.GuardFlags (подмножество)
IMAGE_GUARD_CF_INSTRUMENTED             = 0x00000100
IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT   = 0x00000400
IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO  = 0x00004000
IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT   = 0x00010000
# CET / Return Flow (IBT) биты (современные тулчейны)
IMAGE_GUARD_RF_INSTRUMENTED             = 0x00000200  # Return-Flow (инструментация)
IMAGE_GUARD_RF_ENABLE                   = 0x00040000  # IBT enable
IMAGE_GUARD_RF_STRICT                   = 0x00080000  # IBT strict

# Extended DLL Characteristics (IMAGE_DLLCHARACTERISTICS_EX)
IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT         = 0x0001  # CET Shadow Stack compatible
IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT  = 0x0002  # CET strict mode

# Process Mitigation Policy flags (LoadConfig)
PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE                      = 0x00000001
PROCESS_CREATION_MITIGATION_POLICY_ASLR_HIGH_ENTROPY               = 0x00000020
PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE           = 0x00001000  # ACG
PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ENABLE       = 0x00100000
PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_STRICT       = 0x00200000
PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES    = 0x00010000
PROCESS_CREATION_MITIGATION_POLICY_CET_USER_SHADOW_STACKS          = 0x01000000

# Entropy threshold for suspicious overlay
OVERLAY_ENTROPY_SUSPICIOUS_THRESHOLD = 7.0

# Небезопасные CRT-API (минимальный список)
UNSAFE_CRT = {
    "strcpy","wcscpy","strcat","wcscat","gets","scanf","wscanf","sscanf","swscanf",
    "sprintf","swprintf","vsprintf","vswprintf","strncpy","strncat","strtok"
}

# Категории по регуляркам (низкий шум, высокая полезность)
_IMP_CATS: dict[str, list[str]] = {
    "loader":      [r"^LoadLibrary", r"^GetProcAddress$", r"^GetModuleHandle"],
    "memory":      [r"^VirtualProtect$", r"^VirtualAlloc(Ex)?$", r"^VirtualFree(Ex)?$", r"^MapViewOfFile(Ex)?$",
                    r"^Nt(Protect|Allocate|Free)VirtualMemory$"],
    "proc_thread": [r"^CreateRemoteThread(Ex)?$", r"^OpenProcess$", r"^CreateProcess", r"^TerminateProcess$",
                    r"^SuspendThread$", r"^ResumeThread$", r"^Nt(Open|Create|Query)Process"],
    "debug_sym":   [r"^Sym", r"^StackWalk", r"^MiniDump", r"^RtlCaptureStackBackTrace$"],
    "psapi":       [r"^EnumProcess", r"^EnumProcessModules(Ex)?$", r"^GetModuleInformation$", r"^GetProcessMemoryInfo$"],
    "file_io":     [r"^CreateFile", r"^ReadFile$", r"^WriteFile$", r"^SetFilePointer(Ex)?$", r"^GetFileSize(Ex)?$"],
    "registry":    [r"^Reg(Create|Open|Set|Query|Delete)"],
    "network":     [r"^(Internet|Http|WinHttp|WinInet|URL|WSA|socket|connect|send|recv)"],
    "services":    [r"^OpenSCManager", r"^CreateService", r"^StartService", r"^ChangeServiceConfig"],
    "crypto":      [r"^(Crypt|BCrypt|NCrypt|CryptProtect|CryptUnprotect)"],
    "ui":          [r"^MessageBox", r"^CreateWindow", r"^SetWindow", r"^GetMessage"],
}

# Подсказки для «динамического резолва» (ищем в строках, которых нет в IAT)
_DYNAMIC_HINTS = [
    "VirtualProtect", "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
    "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "OpenProcess",
    "SymInitialize", "SymFromAddr", "StackWalk64", "EnumProcessModules", "GetModuleInformation",
    "WinHttpOpen", "InternetOpenA", "WSASocketA", "connect", "CryptEncrypt", "CreateServiceA"
]

# Опасные API при резолве по ординалу (скрытый импорт)
DANGEROUS_ORDINAL_APIS = frozenset({
    "VirtualAllocEx", "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "OpenProcess", "CreateProcessW", "CreateProcessA",
})

# Минимальная база ординалов для kernel32.dll, ntdll.dll, user32.dll (примеры; ординалы зависят от версии ОС)
# Формат: (dll_lower, ordinal) -> name. Источник: экспорт DLL на типичной Windows 10 x64.
_ORDINAL_BASE: Dict[Tuple[str, int], str] = {}
for _dll, _ords in [
    ("kernel32.dll", {
        165: "CreateRemoteThread", 376: "VirtualAllocEx", 508: "WriteProcessMemory",
        158: "CreateRemoteThreadEx", 375: "VirtualAlloc", 268: "OpenProcess",
        100: "CreateProcessW", 99: "CreateProcessA",
    }),
    ("ntdll.dll", {
        263: "NtAllocateVirtualMemory", 50: "NtProtectVirtualMemory",
    }),
]:
    for _ord, _name in _ords.items():
        _ORDINAL_BASE[(_dll.lower(), _ord)] = _name


def _resolve_ordinal_import(dll_name: str, ordinal_val: int) -> Optional[str]:
    """Резолв имени API по ординалу для kernel32.dll, ntdll.dll, user32.dll."""
    if not dll_name:
        return None
    key = (dll_name.lower().strip(), int(ordinal_val))
    return _ORDINAL_BASE.get(key)

# ---- helpers --------------------------------------------------------------

def _extract_cn(subject_str: str | None) -> Optional[str]:
    if not subject_str:
        return None
    parts = [p.strip() for p in subject_str.split(",")]
    for it in parts:
        if it.upper().startswith("CN="):
            return it[3:].strip()
    return subject_str

def _ps_quote_single(s: str) -> str:
    return s.replace("'", "''")

def _get_authenticode_via_powershell(path: Path) -> Optional[dict]:
    """Windows-only: возвращает объект с полями:
       Status, StatusCode, StatusMessage, SignerCertificate, TimeStamperCertificate.
    """
    if platform.system().lower() != "windows":
        return None
    cmd = [
        "powershell", "-NoProfile", "-NonInteractive",
        "-Command",
        (
            f"$p='{_ps_quote_single(str(path))}'; "
            "$sig = Get-AuthenticodeSignature -FilePath $p; "
            "$out = [PSCustomObject]@{ "
            "  Status = $sig.Status.ToString(); "
            "  StatusCode = [int]$sig.Status; "
            "  StatusMessage = $sig.StatusMessage; "
            "  SignerCertificate = $sig.SignerCertificate; "
            "  TimeStamperCertificate = $sig.TimeStamperCertificate "
            "}; "
            "$out | ConvertTo-Json -Depth 10"
        )
    ]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if cp.returncode != 0:
            return None
        data = cp.stdout.strip()
        if not data:
            return None
        return json.loads(data)
    except Exception:
        return None

def _read_resource_manifest(pe) -> Optional[str]:
    """Вытащить RT_MANIFEST (тип 24) как текст (UTF-8/UTF-16/ANSI), если есть."""
    try:
        pe.parse_data_directories(directories=[DIR_RESOURCE])
        rt = getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None)
        if not rt:
            return None
        for entry in rt.entries or []:
            typ = entry.id if hasattr(entry, 'id') else getattr(entry, 'name', None)
            if typ == 24 or str(typ).lower() == 'rt_manifest':
                for e2 in (entry.directory.entries or []):
                    for e3 in (e2.directory.entries or []):
                        data = pe.get_data(e3.data.struct.OffsetToData, e3.data.struct.Size)
                        if not data:
                            continue
                        for enc in ('utf-8-sig', 'utf-16-le', 'utf-16-be', 'cp1252'):
                            try:
                                return data.decode(enc, errors='ignore')
                            except Exception:
                                pass
        return None
    except Exception:
        return None

def _uac_from_manifest(xml_text: str) -> dict:
    """Парсим requestedExecutionLevel level=... + autoElevate=true/false."""
    res = {"uac_level": None, "uac_auto_elevate": None}
    if not xml_text:
        return res
    m = re.search(r'requestedExecutionLevel[^>]*level\s*=\s*"(.*?)"', xml_text, re.IGNORECASE)
    if m:
        lvl = m.group(1).strip().lower()
        if 'require' in lvl:  res["uac_level"] = "requireAdministrator"
        elif 'highest' in lvl: res["uac_level"] = "highestAvailable"
        elif 'asinvoker' in lvl: res["uac_level"] = "asInvoker"
        else: res["uac_level"] = lvl
    m2 = re.search(r'autoElevate\s*=\s*"(true|false)"', xml_text, re.IGNORECASE)
    if m2:
        res["uac_auto_elevate"] = (m2.group(1).lower() == "true")
    return res

def _get_version_info(pe) -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {
        "CompanyName": None, "FileDescription": None, "FileVersion": None,
        "ProductName": None, "ProductVersion": None, "OriginalFilename": None
    }
    try:
        for fileinfo in getattr(pe, 'FileInfo', []) or []:
            if getattr(fileinfo, "Key", b"") == b"StringFileInfo":
                for st in getattr(fileinfo, "StringTable", []) or []:
                    for k, v in (getattr(st, "entries", {}) or {}).items():
                        k = k.decode(errors="ignore") if isinstance(k, (bytes, bytearray)) else str(k)
                        v = v.decode(errors="ignore") if isinstance(v, (bytes, bytearray)) else str(v)
                        if k in out:
                            out[k] = v
    except Exception:
        pass
    return out

def _arch_from_machine(m: int) -> str:
    if m == IMAGE_FILE_MACHINE_AMD64: return "x64"
    if m == IMAGE_FILE_MACHINE_I386:  return "x86"
    if m == IMAGE_FILE_MACHINE_ARM64: return "ARM64"
    try:
        return hex(int(m))
    except Exception:
        return str(m)

def _ascii_strings(b: bytes, min_len: int = 5) -> list[str]:
    out, buf = [], []
    for ch in b:
        if 32 <= ch < 127:
            buf.append(chr(ch))
        else:
            if len(buf) >= min_len:
                out.append("".join(buf))
            buf = []
    if len(buf) >= min_len:
        out.append("".join(buf))
    return out


def _calc_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    import math
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _parse_load_config_extended(pe, lc) -> dict:
    """
    Parse extended Load Config fields for Enterprise hardening checks.
    Returns dict with CET, ACG, SafeSEH details.
    """
    result = {
        "cet_shadow_stack": None,
        "cet_strict": None,
        "acg_enabled": None,  # Arbitrary Code Guard
        "policy_flags": None,
        "safeseh_count": None,
        "safeseh_table_rva": None,
        "security_cookie": None,
        "guard_cf_check_function": None,
        "guard_cf_dispatch_function": None,
        "enclave_config": None,
        "volatile_metadata": None,
    }
    
    if not lc or not hasattr(lc, "struct"):
        return result
    
    struct = lc.struct
    
    # Security Cookie (GS)
    cookie = getattr(struct, "SecurityCookie", 0) or 0
    result["security_cookie"] = hex(cookie) if cookie else None
    
    # SafeSEH (x86 only)
    seh_table = getattr(struct, "SEHandlerTable", 0) or 0
    seh_count = getattr(struct, "SEHandlerCount", 0) or 0
    result["safeseh_table_rva"] = hex(seh_table) if seh_table else None
    result["safeseh_count"] = int(seh_count) if seh_count else None
    
    # Guard CF
    guard_check = getattr(struct, "GuardCFCheckFunctionPointer", 0) or 0
    guard_dispatch = getattr(struct, "GuardCFDispatchFunctionPointer", 0) or 0
    result["guard_cf_check_function"] = hex(guard_check) if guard_check else None
    result["guard_cf_dispatch_function"] = hex(guard_dispatch) if guard_dispatch else None
    
    # DynamicValueRelocTableOffset для CET
    # GuardFlags уже парсятся отдельно
    
    # Extended DLL Characteristics (для CET Shadow Stack)
    # Находится в структуре Load Config начиная с PE32+ версии 0x94+
    try:
        ext_chars = getattr(struct, "ExtendedDllCharacteristics", 0) or 0
        if not ext_chars:
            # Альтернативное поле в новых версиях
            ext_chars = getattr(struct, "DllCharacteristicsEx", 0) or 0
        
        if ext_chars:
            result["cet_shadow_stack"] = bool(ext_chars & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT)
            result["cet_strict"] = bool(ext_chars & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT)
    except Exception:
        pass
    
    # Process Creation Mitigation Policy (если есть)
    try:
        # Это поле появилось в версии Load Config 0x70+
        process_policy = getattr(struct, "ProcessCreationMitigationPolicy", 0) or 0
        if process_policy:
            result["policy_flags"] = hex(process_policy)
            result["acg_enabled"] = bool(process_policy & PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE)
    except Exception:
        pass
    
    # Enclave config
    try:
        enclave = getattr(struct, "EnclaveConfigurationPointer", 0) or 0
        result["enclave_config"] = hex(enclave) if enclave else None
    except Exception:
        pass
    
    # Volatile metadata
    try:
        volatile = getattr(struct, "VolatileMetadataPointer", 0) or 0
        result["volatile_metadata"] = hex(volatile) if volatile else None
    except Exception:
        pass
    
    return result

# ---- Recursive import / dependency scanning (for analysis queue) -----------

def get_imported_dlls_quick(path: Path) -> List[str]:
    """
    Lightweight PE import scan: returns list of imported DLL names only.
    Use for dependency discovery without full analyze_pe_hardening.
    Returns [] on non-PE or error.
    """
    try:
        import pefile  # type: ignore
    except ImportError:
        return []
    dlls: List[str] = []
    try:
        with path.open("rb") as f:
            pe = pefile.PE(data=f.read(), fast_load=True)
        pe.parse_data_directories(directories=[DIR_IMPORT])
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            try:
                dll_name = entry.dll.decode(errors="ignore") if isinstance(entry.dll, (bytes, bytearray)) else str(entry.dll)
            except Exception:
                dll_name = None
            if dll_name:
                dlls.append(dll_name)
        try:
            pe.parse_data_directories(directories=[DIR_DELAY_IMPORT])
            for entry in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []) or []:
                d_dll = entry.dll.decode(errors="ignore") if isinstance(entry.dll, (bytes, bytearray)) else str(entry.dll)
                if d_dll:
                    dlls.append(d_dll)
        except Exception:
            pass
    except Exception:
        return []
    return list(dict.fromkeys(dlls))  # preserve order, dedupe


def recursive_import_scanner(
    scanned_file_path: Path,
    imported_names: List[str],
    kind: str = "PE",
) -> List[Tuple[Path, str]]:
    """
    Find linked .dll (PE) or .so (ELF) files in the same directory as the scanned file.
    Returns list of (path, tag) with tag "origin_dependency" for adding to the analysis queue.
    """
    if not imported_names:
        return []
    same_dir = scanned_file_path.parent
    if not same_dir.is_dir():
        return []
    suffix_lower = ".dll" if kind.upper() == "PE" else ".so"
    want_set: set = set()
    for n in imported_names:
        nlow = n.lower().strip()
        want_set.add(nlow)
        if nlow.endswith(suffix_lower):
            want_set.add(nlow[: -len(suffix_lower)] + suffix_lower)
        else:
            want_set.add(nlow + suffix_lower)
    seen: set = set()
    out: List[Tuple[Path, str]] = []
    for child in same_dir.iterdir():
        if not child.is_file():
            continue
        name_lower = child.name.lower()
        if name_lower in seen:
            continue
        if name_lower.endswith(suffix_lower) and name_lower in want_set:
            seen.add(name_lower)
            out.append((child.resolve(), "origin_dependency"))
    return out


# ---- main analyzer --------------------------------------------------------

def analyze_pe_hardening(path: Path) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "signature": {
            "present": None, "valid": None, "chain_ok": None,
            "publisher": None, "issuer": None, "thumbprint": None,
            "timestamp_present": None, "timestamp_time": None,
            "raw_status": None, "raw_status_code": None
        },
        "hardening": {
            "aslr": None, "aslr_effective": None, "dep": None, "cfg": None,
            "cfg_table": None, "gs_cookie": None,
            "safeseh": None, "safeseh_count": None, "high_entropy_va": None, "large_address_aware": None,
            "cet_ibt": None, "cet_shstk": None, "cet_strict": None, "sehop_hint": None,
            # VBS/HVCI compatibility
            "integrity_check": None,   # /INTEGRITYCHECK (IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
            "hvci_compatible": None,  # True if integrity_check + no W^X violations + relocs
            # Enterprise-level checks
            "acg": None,  # Arbitrary Code Guard
            "policy_flags": None,  # Process Creation Mitigation Policy
            "enclave_config": None,  # SGX Enclave
        },
        "imports": [],                  # red-flag набор (совместимость с прежним форматом)
        "imports_count": None,
        "imported_dlls": [],
        "imports_summary": {},          # новый агрегат
        "ordinal_imports": [],
        "dangerous_ordinal_imports": [],
        "has_ordinal_imports": False,
        "exports_count": None,
        "sections": {
            "has_rwx": None, "has_wx": None, "overlay_pct": None,
            "unusual_names": [], "relocs_present": None,
            "wx_violations": [],  # [{"name": ".section", "r": True, "w": True, "x": True}] — W^X violations
            "hidden_attributes_referenced": None,  # True if FILE_ATTRIBUTE_HIDDEN/SetFileAttributes in strings (T1564.001)
        },
        # AppLocker/WDAC bypass detection
        "wdac_bypass": {
            "lolbins_detected": [],   # Names/metadata matching known LOLBins (certutil, mshta, rundll32, etc.)
            "loader_heuristics": [],  # Code-section patterns typical of custom loaders
            "suspect": None,          # True if bypass indicators found
        },
        "behavior_hints": {
            "crypto_usage": False,       # BCrypt + file search (ransomware) or Stratum + high entropy (miner)
            "sensitive_data_access": False,  # SetWindowsHookEx + browser profile paths (keylogger/spyware)
            "discovery_activity": False,     # Mass file/process discovery (T1083, T1057)
            "screen_capture": False,         # GDI BitBlt/GetDC (T1113)
            "native_api_usage": False,       # ntdll NtCreateSection etc. (T1106)
            "uac_bypass_attempt": False,   # T1548.002 (fodhelper/eventvwr + registry)
            "defender_disable_attempt": False,  # T1112 (Policies\\Windows Defender)
            "anti_sandbox_stall": False,     # T1124 (GetTickCount/GetSystemTime loops)
            "sensitive_storage_access": False,  # T1005/T1114/T1539 — пароли, почта, куки
            "data_staging": False,            # T1074.001 — скрытые хранилища в AppData
            "cloud_exfiltration_strings": False,  # T1567.002 — Telegram/Discord/Mega в коде
            "defense_disabled": False,   # T1562 — отключение Firewall/AV
            "log_clear_attempt": False,  # T1070.001 — очистка журналов
            "ifeo_injection": False,     # T1546.012 — Image File Execution Options
            "internal_network_scan": False,   # T1018, T1046 — сканирование внутренней сети
            "domain_enumeration": False,      # T1087.002 — запросы к AD
            "lateral_transfer_attempt": False,  # T1570 — копирование на сетевые шары
            "supply_chain_tampering": False,   # T1195.002 — модификация системных DLL
            "uncommon_port": False,            # T1048.003 — нестандартные порты
            "hosts_modification": False,       # T1562.006 — правка hosts
            "wmi_subscription": False,        # T1546.003 — WMI Event Subscription
        },
        "technique_hints": [],  # MITRE IDs inferred from strings (T1120, T1012, ...)
        "anti_analysis": {
            "debug_api_strings": [],  # IsDebuggerPresent, CheckRemoteDebuggerPresent, etc.
            "detected": False,
        },
        # Enterprise Overlay Analysis
        "overlay": {
            "present": None,
            "size": None,
            "entropy": None,
            "suspicious": None,  # True if entropy > 7.0
            "pct_of_file": None,
        },
        "pdb_path": None,
        "incremental": None,
        "dotnet": {"present": None, "flags": None, "strong_name": None, "anti_tamper_suspect": None},
        "resources": {
            "has_manifest": None, "uac_level": None, "uac_auto_elevate": None,
            "uac_admin_required": None,  # Easy flag for policy
            "has_version_info": None, "version": {}
        },
        "subsystem": None,
        "driver_like": None,
        "arch": None,
        "machine": None,
        "timestamp_linker": None,   # из FileHeader.TimeDateStamp
        "tls_callbacks": None,
        "rich_header": {"present": None, "hash": None},
        "load_config_extended": {},  # Enterprise Load Config details
        "errors": [],
        # Legacy packers (Upack): нулевые размеры секций — не отбрасывать файл как битый
        "malformed_pe": False,
        "malformed_header_upack_suspect": False,
    }

    try:
        import pefile  # type: ignore
    except Exception as e:
        info["errors"].append(f"pefile_import_error:{e}")
        return info

    try:
        pe = pefile.PE(str(path), fast_load=False)

        # --- Подпись (SECURITY dir + PowerShell-валидация)
        present_by_dir = False
        try:
            dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[DIR_SECURITY]
            present_by_dir = bool(getattr(dd, "Size", 0))
        except Exception:
            present_by_dir = False

        ps_sig = _get_authenticode_via_powershell(path)
        signer, timestamper = {}, {}
        status_str = None
        if isinstance(ps_sig, dict):
            status_str = (ps_sig.get("Status") or "") or (ps_sig.get("StatusMessage") or "")
            info["signature"]["raw_status"] = status_str
            info["signature"]["raw_status_code"] = ps_sig.get("StatusCode")
            signer = ps_sig.get("SignerCertificate") or {}
            timestamper = ps_sig.get("TimeStamperCertificate") or {}

        subj = signer.get("Subject"); issuer = signer.get("Issuer"); thumb = signer.get("Thumbprint")
        if subj:   info["signature"]["publisher"] = _extract_cn(subj)
        if issuer: info["signature"]["issuer"]    = _extract_cn(issuer)
        if thumb:  info["signature"]["thumbprint"]= thumb
        info["signature"]["timestamp_present"] = bool(timestamper) or None
        # v3.2: Publisher Reputation & Stolen Cert Detection
        try:
            from .signing_trust import is_publisher_known, check_stolen_thumbprint
            info["signature"]["uncertain_publisher"] = not is_publisher_known(info["signature"].get("publisher"))
            info["signature"]["stolen_cert_detected"] = check_stolen_thumbprint(info["signature"].get("thumbprint"))
        except Exception:
            info["signature"]["uncertain_publisher"] = None
            info["signature"]["stolen_cert_detected"] = False

        present_ps = bool(signer)
        info["signature"]["present"] = bool(present_by_dir or present_ps)
        if status_str:
            s = status_str.lower()
            if s == "valid":
                info["signature"]["valid"] = True
                info["signature"]["chain_ok"] = True
            elif s == "notsigned":
                info["signature"]["valid"] = False
                info["signature"]["chain_ok"] = False
                if not present_by_dir:
                    info["signature"]["present"] = False
            else:
                info["signature"]["valid"] = False
                info["signature"]["chain_ok"] = False

        # --- Общие метаданные
        try:
            m = pe.FILE_HEADER.Machine
            info["machine"] = int(m)
            info["arch"] = _arch_from_machine(m)
        except Exception:
            pass
        try:
            ss = pe.OPTIONAL_HEADER.Subsystem
            info["subsystem"] = SUBSYS_MAP.get(int(ss), str(int(ss)))
        except Exception:
            pass
        try:
            info["timestamp_linker"] = int(pe.FILE_HEADER.TimeDateStamp)
        except Exception:
            pass

        # --- DllCharacteristics → ASLR/DEP/CFG/HighEntropy/INTEGRITYCHECK (VBS/HVCI)
        try:
            dc = pe.OPTIONAL_HEADER.DllCharacteristics
            info["hardening"]["aslr"] = bool(dc & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
            info["hardening"]["dep"]  = bool(dc & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
            info["hardening"]["cfg"]  = bool(dc & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
            info["hardening"]["high_entropy_va"] = bool(dc & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
            info["hardening"]["integrity_check"] = bool(dc & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
        except Exception:
            pass

        # --- LargeAddressAware
        try:
            fhc = pe.FILE_HEADER.Characteristics
            info["hardening"]["large_address_aware"] = bool(fhc & IMAGE_FILE_LARGE_ADDRESS_AWARE)
        except Exception:
            pass

        # --- Load Config: SafeSEH (x86), GS-cookie, CFG GuardFlags/таблица, CET(IBT), ACG
        try:
            pe.parse_data_directories(directories=[DIR_LOAD_CONFIG])
            lc = getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
            
            # SafeSEH (x86 only) with count
            if pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_I386:
                seh_table = getattr(lc.struct, "SEHandlerTable", 0) if lc else 0
                seh_count = getattr(lc.struct, "SEHandlerCount", 0) if lc else 0
                info["hardening"]["safeseh"] = bool(seh_table)
                info["hardening"]["safeseh_count"] = int(seh_count) if seh_count else None
            else:
                info["hardening"]["safeseh"] = None
                info["hardening"]["safeseh_count"] = None
            
            # GS Cookie (/GS)
            info["hardening"]["gs_cookie"] = bool(lc and getattr(lc.struct, "SecurityCookie", 0))
            
            # CFG GuardFlags
            gf = int(getattr(getattr(lc, "struct", None), "GuardFlags", 0) or 0)
            has_cfg_tbl = bool(gf & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT)
            instr_cfg   = bool(gf & IMAGE_GUARD_CF_INSTRUMENTED)
            info["hardening"]["cfg_table"] = True if (has_cfg_tbl or instr_cfg) else (False if info["hardening"]["cfg"] else None)
            
            # CET (IBT) — по GuardFlags
            cet_ibt = bool(gf & (IMAGE_GUARD_RF_INSTRUMENTED | IMAGE_GUARD_RF_ENABLE | IMAGE_GUARD_RF_STRICT))
            info["hardening"]["cet_ibt"] = cet_ibt
            
            # Extended Load Config parsing for Enterprise checks
            ext_lc = _parse_load_config_extended(pe, lc)
            info["load_config_extended"] = ext_lc
            
            # CET Shadow Stack from Extended DLL Characteristics
            info["hardening"]["cet_shstk"] = ext_lc.get("cet_shadow_stack")
            info["hardening"]["cet_strict"] = ext_lc.get("cet_strict")
            
            # ACG (Arbitrary Code Guard)
            info["hardening"]["acg"] = ext_lc.get("acg_enabled")
            info["hardening"]["policy_flags"] = ext_lc.get("policy_flags")
            info["hardening"]["enclave_config"] = ext_lc.get("enclave_config")
            
        except Exception as e:
            info["errors"].append(f"load_config_parse_error:{e}")

        # --- Импорты (все) + delay-imports + категоризация + red-flags/unsafe CRT
        red = {"CreateRemoteThread","WriteProcessMemory","VirtualAllocEx",
               "NtQueryInformationProcess","RegSetValueExA","RegSetValueExW"}
        red_imps = set()
        dlls: list[str] = []
        imports_list: list[tuple[str,str]] = []
        delay_list: list[tuple[str,str]] = []
        ordinal_imports: list[dict] = []   # {"dll": str, "ordinal": int, "resolved": str|None}
        dangerous_ordinal_imports: list[dict] = []
        imp_count = 0
        unsafe_crt_cnt = 0

        def _process_ordinal(dll: str, nm: str, ord_val: int) -> str:
            """Резолв ординала; при совпадении с опасным API добавляет в red_imps и dangerous_ordinal_imports."""
            resolved = _resolve_ordinal_import(dll, ord_val)
            rec = {"dll": dll, "ordinal": ord_val, "resolved": resolved}
            ordinal_imports.append(rec)
            if resolved:
                if resolved in DANGEROUS_ORDINAL_APIS:
                    red_imps.add(resolved)
                    dangerous_ordinal_imports.append({**rec, "api": resolved})
                return resolved
            return nm

        try:
            # Обычные импорты
            pe.parse_data_directories(directories=[DIR_IMPORT])
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                try:
                    dll_name = entry.dll.decode(errors="ignore") if isinstance(entry.dll, (bytes, bytearray)) else str(entry.dll)
                except Exception:
                    dll_name = None
                if dll_name:
                    dlls.append(dll_name.lower())
                for imp in getattr(entry, "imports", []) or []:
                    if getattr(imp, "name", None):
                        try:
                            nm = imp.name.decode() if isinstance(imp.name, (bytes, bytearray)) else str(imp.name)
                        except Exception:
                            nm = str(imp.name)
                    else:
                        ord_val = getattr(imp, "ordinal", None)
                        try:
                            ord_val = int(ord_val) if ord_val is not None else 0
                        except (TypeError, ValueError):
                            ord_val = 0
                        nm = f"ord_{ord_val}"
                        nm = _process_ordinal(dll_name or "", nm, ord_val)
                    if dll_name and nm:
                        imports_list.append((dll_name, nm))
                        imp_count += 1
                        base = nm.split("@",1)[0]
                        if base in UNSAFE_CRT:
                            unsafe_crt_cnt += 1
                        if nm in red:
                            red_imps.add(nm)

            # Delay-imports (если есть)
            try:
                pe.parse_data_directories(directories=[DIR_DELAY_IMPORT])
                for entry in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []) or []:
                    d_dll = entry.dll.decode(errors="ignore") if isinstance(entry.dll, (bytes, bytearray)) else str(entry.dll)
                    for imp in getattr(entry, "imports", []) or []:
                        if getattr(imp, "name", None):
                            name = imp.name.decode(errors="ignore")
                        else:
                            ord_val = getattr(imp, "ordinal", None)
                            try:
                                ord_val = int(ord_val) if ord_val is not None else 0
                            except (TypeError, ValueError):
                                ord_val = 0
                            name = _process_ordinal(d_dll, f"ord_{ord_val}", ord_val)
                        delay_list.append((d_dll, name))
                        base = name.split("@",1)[0]
                        if base in UNSAFE_CRT:
                            unsafe_crt_cnt += 1
            except Exception:
                pass

        except Exception:
            pass

        info["imports"] = sorted(red_imps)              # совместимость
        info["imports_count"] = imp_count
        info["imported_dlls"] = sorted(set(dlls))
        info["ordinal_imports"] = ordinal_imports
        info["dangerous_ordinal_imports"] = dangerous_ordinal_imports
        info["has_ordinal_imports"] = bool(ordinal_imports)

        # --- Свод по импортам: топ DLL, категории, delay, динамический резолв
        try:
            cat_count: dict[str,int] = defaultdict(int)
            cat_examples: dict[str,set[str]] = defaultdict(set)
            for _, func in imports_list:
                for c in _IMP_CATS:
                    if any(re.search(p, func, re.IGNORECASE) for p in _IMP_CATS[c]):
                        cat_count[c] += 1
                        if len(cat_examples[c]) < 5:
                            cat_examples[c].add(func)
                if "other" not in _IMP_CATS:
                    pass  # «other» не считаем

            dll_top = Counter([d for d,_ in imports_list]).most_common(5)

            # Динамические API по строкам (те, что не в IAT)
            file_bytes = Path(path).read_bytes()
            strs = _ascii_strings(file_bytes, min_len=5)
            iat_funcs = {f for _, f in imports_list}
            dyn_hits = sorted({s for s in strs for hint in _DYNAMIC_HINTS if hint in s and s not in iat_funcs})

            red_groups = {
                "network":  bool(cat_count.get("network", 0)),
                "services": bool(cat_count.get("services", 0)),
                "crypto":   bool(cat_count.get("crypto", 0)),
            }

            info["imports_summary"] = {
                "dlls_top": [f"{d}({n})" for d,n in dll_top],
                "by_category": {k: {"count": cat_count.get(k,0), "examples": sorted(list(cat_examples.get(k, set())))}
                                for k in ["loader","memory","proc_thread","debug_sym","psapi","file_io","registry","network","services","crypto","ui"]
                                if cat_count.get(k,0) > 0},
                "delay_imports": {
                    "present": bool(delay_list),
                    "dlls": sorted(list({d for d,_ in delay_list}))[:10],
                    "count": len(delay_list)
                },
                "stats": {
                    "unsafe_crt_cnt": int(unsafe_crt_cnt),
                    "delay_imports_cnt": int(len(delay_list)),
                },
                "dynamic_api_strings": dyn_hits[:12],
                "red_groups": red_groups
            }
        except Exception as e:
            info["errors"].append(f"imports_summary_error:{e}")

        # --- Экспорты (кол-во)
        try:
            pe.parse_data_directories(directories=[DIR_EXPORT])
            exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
            info["exports_count"] = len(getattr(exp, "symbols", []) or []) if exp else 0
        except Exception:
            info["exports_count"] = None

        # --- TLS callbacks
        try:
            pe.parse_data_directories(directories=[DIR_TLS])
            tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
            cnt = 0
            if tls and getattr(tls.struct, "AddressOfCallBacks", 0):
                cbs = getattr(tls, "callbacks", None)
                if isinstance(cbs, list):
                    cnt = len([x for x in cbs if x])
                else:
                    cnt = 1
            info["tls_callbacks"] = cnt if cnt > 0 else 0
        except Exception:
            info["tls_callbacks"] = None

        # --- .reloc наличие → relocs_present и aslr_effective
        try:
            relocs_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[DIR_BASERELOC]
            relocs_size = int(getattr(relocs_dir, "Size", 0) or 0)
            relocs_stripped = bool(pe.FILE_HEADER.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
            relocs_present = (relocs_size > 0) and not relocs_stripped
            info["sections"]["relocs_present"] = relocs_present
            if info["hardening"]["aslr"] is not None:
                if pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_I386:
                    info["hardening"]["aslr_effective"] = bool(info["hardening"]["aslr"] and relocs_present)
                else:
                    info["hardening"]["aslr_effective"] = bool(info["hardening"]["aslr"] and not relocs_stripped)
        except Exception:
            pass

        # --- Секции: RWX/WX + W^X violations (исполняемая+записываемая) + необычные имена
        try:
            has_rwx = False
            has_wx  = False
            unusual: List[str] = []
            wx_violations: List[Dict[str, Any]] = []
            for s in getattr(pe, "sections", []) or []:
                try:
                    name = s.Name.rstrip(b'\x00').decode(errors="ignore").strip()
                except Exception:
                    name = ""
                ch = s.Characteristics
                is_r = bool(ch & 0x40000000)
                is_w = bool(ch & 0x80000000)
                is_x = bool(ch & 0x20000000)
                if is_r and is_w and is_x:
                    has_rwx = True
                if is_w and is_x:
                    has_wx = True
                    wx_violations.append({"name": name or "(unnamed)", "r": is_r, "w": is_w, "x": is_x})
                low = name.lower()
                if low and low not in ('.text','.rdata','.data','.pdata','.tls','.rsrc','.idata','.edata','.reloc'):
                    unusual.append(name)
            info["sections"]["has_rwx"] = has_rwx
            info["sections"]["has_wx"]  = has_wx
            info["sections"]["wx_violations"] = wx_violations
            info["sections"]["unusual_names"] = sorted(set(unusual))
        except Exception:
            pass

        # --- HVCI compatible: /INTEGRITYCHECK + no W^X + relocs (for ASLR)
        try:
            integrity = info["hardening"].get("integrity_check")
            relocs = info["sections"].get("relocs_present")
            no_wx = not (info["sections"].get("has_wx") or info["sections"].get("has_rwx"))
            info["hardening"]["hvci_compatible"] = bool(integrity and no_wx and (relocs is not False))
        except Exception:
            pass

        # --- AppLocker/WDAC bypass: LOLBins по именам/метаданным + эвристики загрузчиков
        try:
            lolbins_names = {
                "certutil", "mshta", "rundll32", "regsvr32", "msiexec", "wscript", "cscript",
                "bitsadmin", "cmstp", "installutil", "msbuild", "presentationhost", "pcalua",
                "forfiles", "wmic", "odbcconf", "regasm", "regsvcs", "msxsl", "signedbinary",
            }
            version = _get_version_info(pe)
            all_strings = []
            for v in (version or {}).values():
                if v and isinstance(v, str):
                    all_strings.append(v.lower())
            try:
                file_bytes = Path(path).read_bytes()
                all_strings.extend(_ascii_strings(file_bytes, min_len=4))
            except Exception:
                pass
            lolbins_detected: List[str] = []
            for lb in lolbins_names:
                for s in all_strings:
                    if lb in s and lb not in lolbins_detected:
                        lolbins_detected.append(lb)
                        break
            loader_heuristics: List[str] = []
            imp_summary = info.get("imports_summary") or {}
            dyn = (imp_summary.get("dynamic_api_strings") or []) + (imp_summary.get("by_category", {}).get("loader", {}).get("examples") or [])
            if any("VirtualAlloc" in x or "VirtualProtect" in x for x in dyn):
                if any("WriteProcessMemory" in x or "CreateRemoteThread" in x for x in (info.get("imports") or [])):
                    loader_heuristics.append("loader_memory_remote_thread")
            # Цепочка Process Hollowing по строкам (CreateProcessA + VirtualAllocEx + WriteProcessMemory + SetThreadContext + ResumeThread)
            hollowing_apis = ("createprocessa", "virtualallocex", "writeprocessmemory", "setthreadcontext", "resumethread")
            all_low = [s.lower() for s in all_strings if isinstance(s, str)]
            if all(any(api in x for x in all_low) for api in hollowing_apis):
                loader_heuristics.append("loader_process_hollowing_chain")
            if info.get("ordinal_imports") and (info.get("dangerous_ordinal_imports") or []):
                loader_heuristics.append("ordinal_imports_hidden_api")
            info["wdac_bypass"]["lolbins_detected"] = lolbins_detected
            info["wdac_bypass"]["loader_heuristics"] = loader_heuristics
            info["wdac_bypass"]["suspect"] = bool(lolbins_detected or loader_heuristics)
            # behavior_hints: ransomware (BCrypt + file search), miner (Stratum), keylogger (hook + browser paths)
            all_low = [s.lower() for s in all_strings if isinstance(s, str)]
            bcrypt_apis = ("bcryptencrypt", "bcryptdecrypt", "bcryptgeneratesymmetrickey", "bcrypt")
            file_search = any("findfirstfile" in x or "findnextfile" in x for x in all_low)
            crypto_api = any(any(api in x for x in all_low) for api in bcrypt_apis)
            stratum_hint = any("stratum" in x or "mining.submit" in x or "mining.notify" in x for x in all_low)
            info["behavior_hints"]["crypto_usage"] = (file_search and crypto_api) or stratum_hint
            hook_api = any("setwindowshookex" in x for x in all_low)
            browser_paths = (
                "chrome\\user data", "firefox\\profiles", "edge\\user data",
                "brave-browser", "login data", "cookies", "web data",
            )
            has_browser_path = any(any(bp in x for x in all_low) for bp in browser_paths)
            info["behavior_hints"]["sensitive_data_access"] = bool(hook_api and has_browser_path)
            # technique_hints: MITRE IDs from string patterns (10 APT-style techniques)
            technique_hints: List[str] = []
            if any("setupdigetclassdevs" in x for x in all_low):
                technique_hints.append("T1120")
            if any("currentversion" in x and ("regopenkeyex" in x or "regqueryvalueex" in x or "windows nt" in x) for x in all_low) or (any("regqueryvalueex" in x for x in all_low) and any("currentversion" in x for x in all_low)):
                technique_hints.append("T1012")
            if (any("findfirstfile" in x or "findnextfile" in x for x in all_low) and
                any("*.docx" in x or "*.pdf" in x or "*.key" in x or "docx" in x for x in all_low)):
                technique_hints.append("T1083")
            if any("bitblt" in x or "getdc" in x for x in all_low):
                technique_hints.append("T1113")
            if any("createtoolhelp32snapshot" in x or "process32first" in x or "process32next" in x for x in all_low):
                technique_hints.append("T1057")
            if any("ntcreatesection" in x or "ntmapviewofsection" in x or "ntdll" in x for x in all_low):
                technique_hints.append("T1106")
            if any("getadaptersinfo" in x or "getadaptersaddresses" in x for x in all_low):
                technique_hints.append("T1016")
            if any("gettcptable" in x or "getextendedtcptable" in x for x in all_low):
                technique_hints.append("T1049")
            if any("createservicea" in x or "openscmanagera" in x for x in all_low):
                technique_hints.append("T1543.003")
            if any("rtldecompressbuffer" in x for x in all_low) or (any("xor" in x for x in all_low) and any("decode" in x for x in all_low)):
                technique_hints.append("T1140")
            # 10 techniques: UAC Bypass, Modify Registry, File Deletion, etc.
            if any("fodhelper" in x or "eventvwr" in x for x in all_low) and any("regsetvalueex" in x or "ms-settings" in x for x in all_low):
                technique_hints.append("T1548.002")
            if any("disableantispyware" in x for x in all_low) or any(("windows defender" in x and "policies" in x) for x in all_low):
                technique_hints.append("T1112")
            if any("movefileex" in x or "delay_until_reboot" in x for x in all_low) or (any("cmd" in x and "del " in x for x in all_low)):
                technique_hints.append("T1070.004")
            if any("getsystemtime" in x or "gettickcount" in x for x in all_low):
                technique_hints.append("T1124")
            if any("getcomputername" in x or "getversionex" in x for x in all_low):
                technique_hints.append("T1082")
            if any("chacha20" in x or "aes-256-gcm" in x for x in all_low) and any("internetopen" in x or "winhttp" in x for x in all_low):
                technique_hints.append("T1573")
            if any("%appdata%" in x or "%temp%" in x for x in all_low) and any("telegram" in x or "signal" in x or "tdata" in x for x in all_low):
                technique_hints.append("T1005")
            if any("windows defender" in x or "mpcmdrun" in x or "wbemclient" in x for x in all_low):
                technique_hints.append("T1518.001")
            if any("internetsetoption" in x and "proxy" in x for x in all_low) or any("internet_option_proxy" in x for x in all_low):
                technique_hints.append("T1090")
            if any("rundll32" in x for x in all_low) and any("createprocess" in x or "control_rundll" in x for x in all_low):
                technique_hints.append("T1218.011")
            # 10 techniques: sensitive storage, cookie steal, CLI capture, email, staging, DNS, cloud, encoding, uninstall, winlogon
            if any(".kdbx" in x or ".ovpn" in x for x in all_low) or (any(".zip" in x or ".7z" in x for x in all_low) and any("keepass" in x or "openvpn" in x for x in all_low)):
                technique_hints.append("T1005")
            if any("login data" in x or "cookies" in x for x in all_low) and any("chrome" in x or "edge" in x or "firefox" in x for x in all_low):
                technique_hints.append("T1539")
            if any("ntqueryinformationprocess" in x for x in all_low) and any("commandline" in x or "win32_process" in x for x in all_low):
                technique_hints.append("T1056.004")
            if any(".pst" in x or ".ost" in x for x in all_low) and any("outlook" in x or "thunderbird" in x for x in all_low):
                technique_hints.append("T1114.001")
            if any("localappdata" in x for x in all_low) and any("file_attribute_hidden" in x or "createdirectory" in x for x in all_low):
                technique_hints.append("T1074.001")
            if any("dnsquery" in x for x in all_low) and any("dnsapi" in x for x in all_low):
                technique_hints.append("T1071.004")
            if any("mega.nz" in x or "api.telegram.org" in x or "discord.com/api/webhooks" in x for x in all_low):
                technique_hints.append("T1567.002")
            if any("base64" in x for x in all_low) and any("frombase64string" in x or "decode" in x or "hex" in x for x in all_low):
                technique_hints.append("T1132.001")
            if any("uninstall" in x for x in all_low) and any("regenumkey" in x or "displayname" in x for x in all_low):
                technique_hints.append("T1012")
            if any("winlogon" in x for x in all_low) and any("shell" in x or "userinit" in x for x in all_low):
                technique_hints.append("T1547.004")
            # 10 techniques: Impair Defenses, Firewall, Event Log Clear, IFEO, Security Center, Hidden, Hidden Window, Indirect Exec, Root Cert, Phishing UI
            if any("msmpeng" in x or "terminateprocess" in x for x in all_low) and any("openprocess" in x or "edr" in x for x in all_low):
                technique_hints.append("T1562.001")
            if any("advfirewall" in x or "allprofiles state off" in x for x in all_low) or any("inetfwpolicy" in x for x in all_low):
                technique_hints.append("T1562.004")
            if any("cleareventlog" in x or "wevtutil cl" in x for x in all_low):
                technique_hints.append("T1070.001")
            if any("image file execution options" in x for x in all_low) and any("debugger" in x for x in all_low):
                technique_hints.append("T1546.012")
            if any("security center" in x or "notificationsdisabled" in x for x in all_low) or (any("zonemap" in x or "1806" in x for x in all_low) and any("regsetvalue" in x for x in all_low)):
                technique_hints.append("T1112")
            if any("setfileattributes" in x for x in all_low) and any("file_attribute_hidden" in x or "0x02" in x for x in all_low):
                technique_hints.append("T1564.001")
            if any("create_no_window" in x or "sw_hide" in x for x in all_low):
                technique_hints.append("T1564.003")
            if any("pcalua" in x or "conhost" in x for x in all_low):
                technique_hints.append("T1202")
            if any("certaddcertificatecontexttostore" in x for x in all_low) and any("root" in x or "local_machine" in x for x in all_low):
                technique_hints.append("T1553.004")
            if any("createwindowex" in x for x in all_low) and any("password" in x or "log in" in x for x in all_low) and any("getwindowtext" in x for x in all_low):
                technique_hints.append("T1056.002")
            # v0.1.6 Lateral Movement & Network Discovery
            if any("netserverenum" in x or "getipnettable" in x for x in all_low):
                technique_hints.append("T1018")
            if any("netuserenum" in x for x in all_low) or any("/etc/passwd" in x or "getpwent" in x for x in all_low):
                technique_hints.append("T1087.001")
            if any("adsi" in x or "netgetdisplayinformationindex" in x or "directorysearcher" in x for x in all_low):
                technique_hints.append("T1087.002")
            if any("3389" in x or "445" in x for x in all_low) and any("connect" in x or "192.168" in x or "10." in x for x in all_low):
                technique_hints.append("T1046")
            if any("netlocalgroupenum" in x for x in all_low):
                technique_hints.append("T1069.001")
            if any("mstscax" in x or "rdp" in x for x in all_low) and any("3389" in x for x in all_low):
                technique_hints.append("T1021.001")
            if any("netuseadd" in x for x in all_low) and any("c$" in x or "admin$" in x or "named pipe" in x for x in all_low):
                technique_hints.append("T1021.002")
            if any("sccm" in x or "pdq deploy" in x or "ccmsetup" in x or "ccmexec" in x for x in all_low):
                technique_hints.append("T1072")
            if any("copyfileex" in x for x in all_low) and any("\\\\" in x and "c$" in x for x in all_low):
                technique_hints.append("T1570")
            if any("bluetoothfindfirstdevice" in x or "bthprops" in x for x in all_low):
                technique_hints.append("T1011.001")
            # Final 11 techniques (matrix 75)
            if any("zlib.dll" in x or "libssl.dll" in x for x in all_low) and any("malicious" in x or "hook" in x or "export" in x for x in all_low):
                technique_hints.append("T1195.002")
            if any("expired certificate" in x or "authenticode" in x for x in all_low) and any("code signing" in x or "signtool" in x for x in all_low):
                technique_hints.append("T1553.002")
            if any("wnetaddconnection" in x or "netuseadd" in x for x in all_low) and any("password" in x or "p@ssw0rd" in x or "svc_" in x for x in all_low):
                technique_hints.append("T1078")
            if any("addins" in x or "xlstart" in x or "wll" in x for x in all_low) and any("startup" in x or "word" in x for x in all_low):
                technique_hints.append("T1137")
            if any("scrnsave.exe" in x for x in all_low) and any("control panel" in x or "desktop" in x for x in all_low):
                technique_hints.append("T1546.002")
            if any("1337" in x or "4444" in x or "666" in x for x in all_low) and any("connect" in x or "wsaconnect" in x for x in all_low):
                technique_hints.append("T1048.003")
            if any(("hosts" in x and ("etc" in x or "drivers" in x)) or "definition.microsoft" in x or "update.microsoft" in x for x in all_low):
                technique_hints.append("T1562.006")
            if any("pastebin.com" in x or "gist.githubusercontent" in x or "docs.google.com" in x for x in all_low):
                technique_hints.append("T1102")
            if any("keservicedescriptortable" in x or "ssdt" in x for x in all_low) and any("ntquerysysteminformation" in x or ".sys" in x for x in all_low):
                technique_hints.append("T1014")
            if any("payload.vbs" in x or ".vbs" in x for x in all_low) and any("wscript.shell" in x or "expandarchive" in x or ".zip" in x for x in all_low):
                technique_hints.append("T1204.002")
            if any("systemparametersinfo" in x or "spi_setdeskwallpaper" in x for x in all_low):
                technique_hints.append("T1491")
            # Top-20 sub-techniques
            if any("__eventfilter" in x or "commandlineeventconsumer" in x for x in all_low) and any("iwbemservices" in x or "putinstance" in x for x in all_low):
                technique_hints.append("T1546.003")
            if any("start menu" in x for x in all_low) and any("shelllink" in x or "ipersistfile" in x for x in all_low) and any(".lnk" in x for x in all_low):
                technique_hints.append("T1547.009")
            if any("netsh" in x for x in all_low) and any("add helper" in x or "inetcfg" in x for x in all_low):
                technique_hints.append("T1546.007")
            if any("createremotethread" in x for x in all_low) and any("loadlibrary" in x for x in all_low):
                technique_hints.append("T1055.002")
            if any("suspendthread" in x for x in all_low) and any("setthreadcontext" in x or "getthreadcontext" in x for x in all_low):
                technique_hints.append("T1055.003")
            if any("setfiletime" in x or "getfiletime" in x for x in all_low) and any("standard_information" in x or "$i30" in x for x in all_low):
                technique_hints.append("T1070.006")
            if any("bcdedit" in x or "testsigning" in x for x in all_low) and any("nointegritychecks" in x or "disable_integrity" in x for x in all_low):
                technique_hints.append("T1562.010")
            if any("mshta" in x for x in all_low) and any("vbscript:" in x or ".hta" in x for x in all_low):
                technique_hints.append("T1218.005")
            if any("regsvr32" in x for x in all_low) and any("scrobj.dll" in x or "/i:http" in x for x in all_low):
                technique_hints.append("T1218.010")
            if any("compress2" in x or "bz2_bzcompress" in x for x in all_low) and any("zlib" in x or "deflate" in x for x in all_low):
                technique_hints.append("T1560.001")
            if any(".env" in x or "appsettings.xml" in x or "web.config" in x for x in all_low) and any("findfirstfile" in x or ".config" in x for x in all_low):
                technique_hints.append("T1005.001")
            if any("getasynckeystate" in x for x in all_low) and any("wh_keyboard" in x or "keyboard" in x for x in all_low):
                technique_hints.append("T1056.001")
            if any("iex" in x or "frombase64string" in x for x in all_low) and any("powershell" in x or "-enc" in x for x in all_low):
                technique_hints.append("T1059.001")
            if any("cmd.exe" in x for x in all_low) and any(" && " in x or " || " in x for x in all_low):
                technique_hints.append("T1059.003")
            if any("wmic" in x for x in all_low) and any("cpu get name" in x or "os get caption" in x for x in all_low):
                technique_hints.append("T1082")
            if any("getipforwardtable" in x for x in all_low) or (any("iphlpapi" in x for x in all_low) and any("route" in x for x in all_low)):
                technique_hints.append("T1016.001")
            if any("netgroupenum" in x for x in all_low):
                technique_hints.append("T1069.002")
            if any("ntmapviewofsection" in x for x in all_low):
                technique_hints.append("T1106")
            if any("custom unpack" in x or "vmprotect" in x for x in all_low) and any("upx0" in x or "!.text" in x for x in all_low):
                technique_hints.append("T1027.002")
            # v0.1.9: 10 новых техник Credentials & Impact
            if any("lsass" in x for x in all_low) and any("minidumpwritedump" in x for x in all_low) and any("openprocess" in x or "process32first" in x for x in all_low):
                technique_hints.append("T1003.001")
            if any("password=" in x or "login=" in x or "apikey=" in x for x in all_low) and any(".env" in x or ".config" in x or ".xml" in x for x in all_low):
                technique_hints.append("T1552.001")
            if any("regsavekey" in x or "reg.exe save" in x for x in all_low) and any("sam" in x or "system" in x or "security" in x for x in all_low):
                technique_hints.append("T1003.002")
            if any("controlservice" in x for x in all_low) and any("openservice" in x or "openscmanager" in x for x in all_low) and any("eventlog" in x or "windefend" in x for x in all_low):
                technique_hints.append("T1489")
            if any("vssadmin" in x for x in all_low) and any("delete shadows" in x for x in all_low) or any("wbadmin" in x for x in all_low):
                technique_hints.append("T1490")
            if any(".locked" in x or ".crypted" in x for x in all_low) and any("cryptencrypt" in x or "findfirstfile" in x for x in all_low):
                technique_hints.append("T1486")
            if any("netuserdel" in x for x in all_low) or any("net user" in x and "delete" in x for x in all_low):
                technique_hints.append("T1531")
            if any("createprocess" in x for x in all_low) and any("getdiskfreespaceex" in x or "setendoffile" in x for x in all_low):
                technique_hints.append("T1499")
            if any("httpsendrequest" in x or "winhttpsendrequest" in x for x in all_low) and any("post" in x for x in all_low) and any("zip" in x or "exfil" in x for x in all_low):
                technique_hints.append("T1020")
            if any("netlocalgroupaddmembers" in x for x in all_low) and any("administrators" in x for x in all_low):
                technique_hints.append("T1098")
            # Deep Coverage: T1055.004 APC, T1055.005 TLS, T1055.011 EWMI, T1546.009/010, T1547.005/014, T1562.009/002, T1027.003, T1021.003
            if any("queueuserapc" in x or "ntqueueapcthread" in x for x in all_low):
                technique_hints.append("T1055.004")
            if any("tlsalloc" in x or "tlssetvalue" in x for x in all_low) and any("__tls_used" in x or "tlsgetvalue" in x for x in all_low):
                technique_hints.append("T1055.005")
            if any("setwindowlongptr" in x for x in all_low) and any("gwlp_wndproc" in x or "wndproc" in x for x in all_low):
                technique_hints.append("T1055.011")
            if any("appcertdlls" in x for x in all_low) and any("session manager" in x or "regsetvalueex" in x for x in all_low):
                technique_hints.append("T1546.009")
            if any("appinit_dlls" in x or "loadappinit_dlls" in x for x in all_low):
                technique_hints.append("T1546.010")
            if any("security support provider" in x or "security packages" in x for x in all_low) and any("lsa" in x or "currentcontrolset" in x for x in all_low):
                technique_hints.append("T1547.005")
            if any("active setup" in x for x in all_low) and any("installed components" in x or "stubpath" in x for x in all_low):
                technique_hints.append("T1547.014")
            if any("safeboot" in x for x in all_low) and any("bcdedit" in x or "boot.ini" in x for x in all_low):
                technique_hints.append("T1562.009")
            if any("steganography" in x or "lsb" in x for x in all_low) and any("bitmap" in x or "rt_icon" in x or "embed" in x for x in all_low):
                technique_hints.append("T1027.003")
            if any("etweventwrite" in x for x in all_low) and any("ntdll" in x or "event tracing" in x for x in all_low):
                technique_hints.append("T1562.002")
            if any("coinitializeex" in x or "cocreateinstanceex" in x for x in all_low) and any("dcom" in x or "mmc20" in x for x in all_low):
                technique_hints.append("T1021.003")
            # v2.0 T1027.013 Custom Cryptors: GetVolumeInformation -> XOR -> VirtualAlloc (hardware-based key)
            get_vol = any("getvolumeinformation" in x for x in all_low)
            virt = any("virtualalloc" in x for x in all_low)
            xor_hint = any("xor" in x for x in all_low)
            if get_vol and virt and xor_hint:
                technique_hints.append("T1027.013")
            info["technique_hints"] = sorted(set(technique_hints))
            info["behavior_hints"]["discovery_activity"] = "T1083" in technique_hints or "T1057" in technique_hints
            info["behavior_hints"]["screen_capture"] = "T1113" in technique_hints
            info["behavior_hints"]["native_api_usage"] = "T1106" in technique_hints
            info["behavior_hints"]["uac_bypass_attempt"] = "T1548.002" in technique_hints
            info["behavior_hints"]["defender_disable_attempt"] = "T1112" in technique_hints
            info["behavior_hints"]["anti_sandbox_stall"] = "T1124" in technique_hints
            info["behavior_hints"]["sensitive_storage_access"] = "T1005" in technique_hints or "T1114.001" in technique_hints or "T1539" in technique_hints
            info["behavior_hints"]["data_staging"] = "T1074.001" in technique_hints
            info["behavior_hints"]["cloud_exfiltration_strings"] = "T1567.002" in technique_hints
            info["behavior_hints"]["defense_disabled"] = "T1562.001" in technique_hints or "T1562.004" in technique_hints
            info["behavior_hints"]["log_clear_attempt"] = "T1070.001" in technique_hints
            info["behavior_hints"]["ifeo_injection"] = "T1546.012" in technique_hints
            info["behavior_hints"]["internal_network_scan"] = "T1018" in technique_hints or "T1046" in technique_hints
            info["behavior_hints"]["domain_enumeration"] = "T1087.002" in technique_hints
            info["behavior_hints"]["lateral_transfer_attempt"] = "T1570" in technique_hints
            info["behavior_hints"]["supply_chain_tampering"] = "T1195.002" in technique_hints
            info["behavior_hints"]["uncommon_port"] = "T1048.003" in technique_hints
            info["behavior_hints"]["hosts_modification"] = "T1562.006" in technique_hints
            info["behavior_hints"]["wmi_subscription"] = "T1546.003" in technique_hints
            if "T1564.001" in technique_hints:
                info["sections"]["hidden_attributes_referenced"] = True
        except Exception as e:
            info["errors"].append(f"wdac_bypass_error:{e}")

        # --- Anti-Analysis / Evasion: отладочные API в строках (IsDebuggerPresent и др.)
        try:
            debug_api_names = (
                "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
                "debugactiveprocess", "outputdebugstring", "isdebuggerpresent",
            )
            anti_strings: List[str] = []
            try:
                file_bytes = Path(path).read_bytes()
                anti_strings = _ascii_strings(file_bytes, min_len=4)
            except Exception:
                pass
            debug_found: List[str] = []
            for name in debug_api_names:
                for s in anti_strings:
                    if name in s.lower() and name not in debug_found:
                        debug_found.append(name)
                        break
            info["anti_analysis"]["debug_api_strings"] = debug_found
            info["anti_analysis"]["detected"] = bool(debug_found)
        except Exception as e:
            info["anti_analysis"]["detected"] = False
            info["errors"].append(f"anti_analysis_error:{e}")

        # --- Overlay analysis (Enterprise). Upack: секции могут иметь SizeOfRawData=0 — не отбрасывать
        try:
            last_end = max([(s.PointerToRawData + getattr(s, "SizeOfRawData", 0)) for s in pe.sections]) if pe.sections else 0
            # Признак Upack: все секции с нулевым SizeOfRawData в заголовке
            if pe.sections and all(getattr(s, "SizeOfRawData", 0) == 0 for s in pe.sections):
                info["malformed_header_upack_suspect"] = True
            file_size = Path(path).stat().st_size
            overlay_size = max(0, file_size - last_end)
            info["sections"]["overlay_pct"] = round(100.0 * overlay_size / file_size, 3) if file_size else 0.0
            
            # Enterprise Overlay Analysis
            if overlay_size > 0:
                info["overlay"]["present"] = True
                info["overlay"]["size"] = overlay_size
                info["overlay"]["pct_of_file"] = round(100.0 * overlay_size / file_size, 2) if file_size else 0.0
                
                # Calculate overlay entropy (limit to 10MB for performance)
                try:
                    with open(path, "rb") as f:
                        f.seek(last_end)
                        overlay_data = f.read(min(overlay_size, 10 * 1024 * 1024))
                    overlay_entropy = _calc_entropy(overlay_data)
                    info["overlay"]["entropy"] = overlay_entropy
                    info["overlay"]["suspicious"] = overlay_entropy >= OVERLAY_ENTROPY_SUSPICIOUS_THRESHOLD
                except Exception as e:
                    info["errors"].append(f"overlay_entropy_error:{e}")
                    info["overlay"]["entropy"] = None
                    info["overlay"]["suspicious"] = None
            else:
                info["overlay"]["present"] = False
                info["overlay"]["size"] = 0
                info["overlay"]["entropy"] = None
                info["overlay"]["suspicious"] = False
                info["overlay"]["pct_of_file"] = 0.0
                
        except Exception as e:
            info["sections"]["overlay_pct"] = None
            info["errors"].append(f"overlay_analysis_error:{e}")

        # Legacy Upack: нулевые размеры секций уже помечены в malformed_header_upack_suspect выше

        # --- Rich header
        try:
            rh = pe.parse_rich_header()
            if rh:
                info["rich_header"]["present"] = True
                chk = None
                if isinstance(rh, dict):
                    chk = rh.get("checksum") or rh.get("clearsum") or rh.get("hash")
                elif isinstance(rh, (list, tuple)) and len(rh) >= 2:
                    chk = rh[1]
                if isinstance(chk, int):
                    info["rich_header"]["hash"] = hex(chk)
                elif chk:
                    info["rich_header"]["hash"] = str(chk)
            else:
                info["rich_header"]["present"] = False
        except Exception:
            info["rich_header"]["present"] = None

        # --- PDB (debug)
        try:
            pdb = None
            pe.parse_data_directories(directories=[DIR_DEBUG])
            for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
                data = pe.parse_debug_directory(entry.struct)
                for dbg in data:
                    if hasattr(dbg, "PdbFileName") and dbg.PdbFileName:
                        pdb = dbg.PdbFileName.decode(errors="ignore") if isinstance(dbg.PdbFileName, (bytes, bytearray)) else str(dbg.PdbFileName)
            info["pdb_path"] = pdb
        except Exception:
            info["pdb_path"] = None

        # --- Инкрементальная линковка (грубо)
        try:
            info["incremental"] = bool(pe.OPTIONAL_HEADER.LoaderFlags)
        except Exception:
            info["incremental"] = None

        # --- .NET/CLR
        try:
            dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[DIR_COM_DESCRIPTOR]
            present = bool(getattr(dd, "Size", 0))
            info["dotnet"]["present"] = present
            if present:
                try:
                    com_desc = getattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR", None)
                    flags = None
                    if com_desc and hasattr(com_desc.struct, "Flags"):
                        flags = int(com_desc.struct.Flags)
                    info["dotnet"]["flags"] = flags
                except Exception:
                    pass
        except Exception:
            pass

        # --- Ресурсы: манифест + UAC, версия
        try:
            man = _read_resource_manifest(pe)
            info["resources"]["has_manifest"] = bool(man)
            uac = _uac_from_manifest(man) if man else {"uac_level": None, "uac_auto_elevate": None}
            info["resources"]["uac_level"] = uac["uac_level"]
            info["resources"]["uac_auto_elevate"] = uac["uac_auto_elevate"]
            # Easy policy flag: True if requireAdministrator
            info["resources"]["uac_admin_required"] = (uac["uac_level"] == "requireAdministrator")
        except Exception:
            pass

        try:
            ver = _get_version_info(pe)
            info["resources"]["version"] = ver
            info["resources"]["has_version_info"] = any(v for v in ver.values())
        except Exception:
            pass

        # --- driver-like эвристика
        try:
            is_sys = path.suffix.lower() == ".sys"
            is_native = (info.get("subsystem") == "Native")
            is_dll = bool(pe.FILE_HEADER.Characteristics & IMAGE_FILE_DLL)
            info["driver_like"] = bool(is_sys or (is_native and not is_dll))
        except Exception:
            info["driver_like"] = None

        # --- SEHOP hint (по SafeSEH на x86 лишь косвенно)
        try:
            safe_seh = info.get("hardening", {}).get("safeseh")
            if safe_seh is not None and info.get("arch","").startswith("x86"):
                info["hardening"]["sehop_hint"] = ("compatible" if safe_seh else "unknown")
            else:
                info["hardening"]["sehop_hint"] = None
        except Exception:
            pass

        # --- Visual Analysis: Icon extraction and hash (v0.0.8)
        try:
            icon_info = _extract_icon_analysis(pe, path)
            info["icon"] = icon_info
        except Exception as e:
            info["errors"].append(f"icon_analysis_error:{e}")
            info["icon"] = {"present": False, "error": str(e)[:100]}

        # --- Resource Entropy Analysis (v0.0.8)
        try:
            resource_entropy = _analyze_resource_entropy(pe)
            info["resource_entropy"] = resource_entropy
        except Exception as e:
            info["errors"].append(f"resource_entropy_error:{e}")
            info["resource_entropy"] = {"error": str(e)[:100]}

    except Exception as e:
        info["errors"].append(f"pe_parse_error:{e}")
        # Legacy packers (Upack): не отбрасывать файл — помечаем как malformed, YARA/остальной пайплайн обработают
        info["malformed_pe"] = True
        try:
            with path.open("rb") as f:
                head = f.read(64)
            if len(head) >= 64 and head[:2] == b"MZ":
                pe_off = int.from_bytes(head[0x3C:0x40], "little")
                if pe_off < len(head) - 4 and head[pe_off:pe_off+4] == b"PE\x00\x00":
                    info["meta"] = {"type": "PE", "malformed": True}
        except Exception:
            pass
    return info


# ----- Visual Analysis Functions (v0.0.8) -----

# Known icon hashes for masquerading detection
# These are dhash values of common document/media icons
KNOWN_ICON_HASHES = {
    # PDF icons (various sizes/versions)
    "pdf": [
        "0000000000000000",  # Placeholder - calculate actual hashes
        "ff00000000000000",
    ],
    # Word document icons
    "doc": [
        "0101010101010101",
    ],
    # Excel icons  
    "xls": [
        "0202020202020202",
    ],
    # Folder icons
    "folder": [
        "0303030303030303",
    ],
    # Image icons
    "image": [
        "0404040404040404",
    ],
}

# Extensions that should NOT have document-like icons
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".com", ".pif"}

# Extensions that SHOULD have document-like icons
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}


def _calc_dhash(data: bytes, hash_size: int = 8) -> Optional[str]:
    """
    Calculate difference hash (dHash) of image data.
    This is a perceptual hash that is robust to small changes.
    """
    try:
        from PIL import Image
        import io
        
        # Load image
        img = Image.open(io.BytesIO(data))
        
        # Convert to grayscale and resize
        img = img.convert('L')
        img = img.resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
        
        # Calculate difference
        pixels = list(img.getdata())
        diff = []
        for row in range(hash_size):
            for col in range(hash_size):
                left = pixels[row * (hash_size + 1) + col]
                right = pixels[row * (hash_size + 1) + col + 1]
                diff.append(1 if left > right else 0)
        
        # Convert to hex
        hex_str = ""
        for i in range(0, len(diff), 4):
            nibble = diff[i:i+4]
            val = sum(b << (3-j) for j, b in enumerate(nibble))
            hex_str += format(val, 'x')
        
        return hex_str
        
    except ImportError:
        return None
    except Exception:
        return None


def _calc_simple_icon_hash(data: bytes) -> str:
    """Simple hash for icon data when PIL is not available."""
    import hashlib
    return hashlib.md5(data).hexdigest()[:16]


def _extract_icon_from_pe(pe) -> Optional[bytes]:
    """
    Extract the main icon from PE resources.
    Returns raw icon data or None.
    """
    try:
        pe.parse_data_directories(directories=[DIR_RESOURCE])
        rt = getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None)
        if not rt:
            return None
        
        # RT_GROUP_ICON = 14, RT_ICON = 3
        icon_group_data = None
        icon_entries = {}
        
        for entry in rt.entries or []:
            resource_type = entry.id if hasattr(entry, 'id') else None
            
            # Find RT_GROUP_ICON (14)
            if resource_type == 14:
                for e2 in (entry.directory.entries or []):
                    for e3 in (e2.directory.entries or []):
                        try:
                            data = pe.get_data(e3.data.struct.OffsetToData, e3.data.struct.Size)
                            icon_group_data = data
                            break
                        except Exception:
                            pass
                    if icon_group_data:
                        break
            
            # Find RT_ICON (3) entries
            if resource_type == 3:
                for e2 in (entry.directory.entries or []):
                    icon_id = e2.id if hasattr(e2, 'id') else 0
                    for e3 in (e2.directory.entries or []):
                        try:
                            data = pe.get_data(e3.data.struct.OffsetToData, e3.data.struct.Size)
                            icon_entries[icon_id] = data
                        except Exception:
                            pass
        
        # Return largest icon
        if icon_entries:
            largest = max(icon_entries.values(), key=len)
            return largest
        
        return None
        
    except Exception:
        return None


def _extract_icon_analysis(pe, path: Path) -> Dict[str, Any]:
    """
    Extract and analyze PE icon for masquerading detection.
    """
    result = {
        "present": False,
        "size": 0,
        "dhash": None,
        "md5": None,
        "mismatch_detected": False,
        "mismatch_type": None,
        "entropy": None,
    }
    
    # Extract icon
    icon_data = _extract_icon_from_pe(pe)
    if not icon_data:
        return result
    
    result["present"] = True
    result["size"] = len(icon_data)
    
    # Calculate hashes
    result["dhash"] = _calc_dhash(icon_data)
    result["md5"] = _calc_simple_icon_hash(icon_data)
    
    # Calculate icon entropy
    result["entropy"] = _calc_entropy(icon_data)
    
    # Check for masquerading (icon mismatch)
    filename = path.name.lower()
    extension = path.suffix.lower()

    # Жёсткая проверка: расширение документа (.xlsx, .docx, .pdf, .txt), а файл — PE (исполняемый)
    if extension in DOCUMENT_EXTENSIONS:
        result["mismatch_detected"] = True
        result["mismatch_type"] = "document_extension_pe_executable"
        result["masquerading"] = True

    # Check if executable has document-like name but suspicious icon
    has_doc_in_name = any(ext in filename for ext in [".pdf", ".doc", ".xls", ".ppt", ".jpg", ".png"])
    is_executable = extension in EXECUTABLE_EXTENSIONS

    if is_executable and has_doc_in_name:
        result["mismatch_detected"] = True
        result["mismatch_type"] = result.get("mismatch_type") or "executable_with_document_name"

    # Additional: Check if icon hash matches known document icons
    # (This would require building a database of known icon hashes)
    if result["dhash"]:
        for icon_type, hashes in KNOWN_ICON_HASHES.items():
            if result["dhash"] in hashes:
                if is_executable and icon_type in ("pdf", "doc", "xls", "folder"):
                    result["mismatch_detected"] = True
                    result["mismatch_type"] = f"executable_with_{icon_type}_icon"
                break
    
    return result


def _analyze_resource_entropy(pe) -> Dict[str, Any]:
    """
    Analyze entropy of specific PE resources.
    High entropy in resources can indicate embedded encrypted/compressed payloads.
    """
    result = {
        "rcdata_count": 0,
        "rcdata_high_entropy": [],
        "version_entropy": None,
        "max_resource_entropy": 0.0,
        "total_resource_size": 0,
        "suspicious": False,
    }
    
    try:
        pe.parse_data_directories(directories=[DIR_RESOURCE])
        rt = getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None)
        if not rt:
            return result
        
        # RT_RCDATA = 10, RT_VERSION = 16
        for entry in rt.entries or []:
            resource_type = entry.id if hasattr(entry, 'id') else None
            
            # RT_RCDATA (10) - often used to hide payloads
            if resource_type == 10:
                for e2 in (entry.directory.entries or []):
                    for e3 in (e2.directory.entries or []):
                        try:
                            data = pe.get_data(e3.data.struct.OffsetToData, e3.data.struct.Size)
                            if data and len(data) > 100:
                                result["rcdata_count"] += 1
                                result["total_resource_size"] += len(data)
                                entropy = _calc_entropy(data)
                                result["max_resource_entropy"] = max(result["max_resource_entropy"], entropy)
                                
                                if entropy > 7.0:
                                    result["rcdata_high_entropy"].append({
                                        "size": len(data),
                                        "entropy": entropy,
                                    })
                        except Exception:
                            pass
            
            # RT_VERSION (16)
            if resource_type == 16:
                for e2 in (entry.directory.entries or []):
                    for e3 in (e2.directory.entries or []):
                        try:
                            data = pe.get_data(e3.data.struct.OffsetToData, e3.data.struct.Size)
                            if data:
                                result["version_entropy"] = _calc_entropy(data)
                        except Exception:
                            pass
        
        # Flag as suspicious if high entropy resources found
        if result["rcdata_high_entropy"]:
            result["suspicious"] = True
        
    except Exception:
        pass
    
    return result
