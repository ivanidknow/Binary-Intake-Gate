"""
Emulation Layer using Speakeasy for PE/ELF analysis.

Speakeasy is a Windows kernel and user mode emulation framework.
It provides in-memory unpacking and API tracing without execution.

Usage:
    result = run_emulation(path, timeout=60, enable=True)
    
Results merged into evidence.emulation and evidence.capa.
"""
from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
import os
import sys
import json
import tempfile
import hashlib
import threading
import time

_emu_log_lock = threading.Lock()
_last_dump_reason: str = ""


def get_last_dump_reason() -> str:
    """Return the last dump failure reason (for CLI to log when no dump path)."""
    return _last_dump_reason


def _emu_log(msg: str) -> None:
    """Append one line to cli_debug.log (file only so it works from any process/thread)."""
    line = f"[emu_dbg] {msg}\n"
    with _emu_log_lock:
        # Try multiple path candidates so log is written even if cwd differs
        candidates = []
        if os.environ.get("BIN_GATE_DEBUG_LOG"):
            candidates.append(os.path.abspath(os.environ["BIN_GATE_DEBUG_LOG"]))
        candidates.append(os.path.abspath("cli_debug.log"))
        candidates.append(os.path.join(os.getcwd(), "cli_debug.log"))
        try:
            if getattr(sys, "frozen", False):
                candidates.append(os.path.join(os.path.dirname(sys.executable), "cli_debug.log"))
        except Exception:
            pass
        for log_path in candidates:
            try:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                return
            except Exception:
                continue
        try:
            out = getattr(sys, "stdout", None)
            if out is not None and getattr(out, "write", None):
                out.write(line)
                out.flush()
        except Exception:
            pass


# Emulation timeout (seconds)
EMULATION_TIMEOUT_SEC = int(os.getenv("BIN_GATE_EMULATION_TIMEOUT", "60"))
EMULATION_MAX_INSTRUCTIONS = int(os.getenv("BIN_GATE_EMULATION_MAX_INSTR", "10000000"))
EMULATION_MAX_FILE_SIZE_MB = int(os.getenv("BIN_GATE_EMULATION_MAX_MB", "50"))
# v3.1: лимит одновременных контейнеров эмуляции (должны быть до _emulation_slot_acquire)
EMULATION_MAX_CONCURRENT = int(os.getenv("BIN_GATE_EMULATION_MAX_CONCURRENT", "2"))
EMULATION_SLOT_WAIT_TIMEOUT = int(os.getenv("BIN_GATE_EMULATION_SLOT_TIMEOUT", "300"))


@dataclass
class EmulationResult:
    """Result of Speakeasy emulation."""
    success: bool = False
    error: str = ""
    
    # API calls captured during emulation
    api_calls: List[Dict[str, Any]] = field(default_factory=list)
    api_summary: Dict[str, int] = field(default_factory=dict)
    
    # Artifacts
    mutexes: List[str] = field(default_factory=list)
    files_created: List[str] = field(default_factory=list)
    files_read: List[str] = field(default_factory=list)
    files_written: List[str] = field(default_factory=list)
    registry_keys: List[Dict[str, str]] = field(default_factory=list)
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    
    # Extracted strings (post-unpack)
    decoded_strings: List[str] = field(default_factory=list)
    
    # Techniques detected
    techniques: List[str] = field(default_factory=list)
    
    # Shellcode detection
    shellcode_detected: bool = False
    shellcode_info: Dict[str, Any] = field(default_factory=dict)
    
    # Memory dump path (image base + mapped pages written to .dmp for CVE/SBOM)
    memory_dump_path: Optional[str] = None
    # When memory_dump_path is None, reason for failure (for logging)
    dump_failure_reason: str = ""

    # Статус эмуляции: "load_failed" при сбое load_module (UC_ERR_WRITE_UNMAPPED и т.д.)
    emulation_status: str = ""

    # Loaded modules (LDR list) from Docker JSON report
    modules: List[str] = field(default_factory=list)

    # Per-module version/hash from !!!MODULE_INFO!!! (LIEF fingerprinting in container)
    module_details: List[Dict[str, str]] = field(default_factory=list)
    detailed_modules: List[Dict[str, Any]] = field(default_factory=list)

    # Docker raw stdout length (for orchestrate: emulation_insufficient_data when < 1000)
    docker_stdout_length: int = 0

    # Timing
    elapsed_ms: int = 0
    instructions_executed: int = 0


# Suspicious API categories for technique mapping
SUSPICIOUS_APIS = {
    "process_injection": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
        "NtQueueApcThread", "SetThreadContext", "NtSetContextThread",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    ],
    "process_hollowing": [
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "SetThreadContext", "ResumeThread",
    ],
    "code_injection": [
        "VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory",
        "WriteProcessMemory", "NtWriteVirtualMemory",
    ],
    "persistence": [
        "RegSetValueEx", "RegCreateKeyEx", "CreateService",
        "ChangeServiceConfig", "SetWindowsHookEx",
        "schtasks", "at.exe",
    ],
    "defense_evasion": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugString",
        "GetTickCount", "QueryPerformanceCounter",
        "NtSetInformationThread", "NtQuerySystemInformation",
    ],
    "credential_access": [
        "CredEnumerate", "CryptUnprotectData", "LsaEnumerateLogonSessions",
        "SamEnumerateUsersInDomain", "NetUserEnum",
    ],
    "discovery": [
        "GetComputerName", "GetUserName", "GetSystemInfo",
        "GetVersionEx", "GetLocaleInfo", "GetKeyboardLayout",
        "EnumProcesses", "CreateToolhelp32Snapshot",
        "Process32First", "Process32Next",
        "FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW",
    ],
    "peripheral_discovery": ["SetupDiGetClassDevsA", "SetupDiGetClassDevsW", "SetupDiEnumDeviceInfo"],
    "registry_query": ["RegOpenKeyExA", "RegOpenKeyExW", "RegQueryValueExA", "RegQueryValueExW", "RegEnumKeyExA"],
    "screen_capture": ["BitBlt", "GetDC", "CreateCompatibleDC", "GetDesktopWindow"],
    "native_api": ["NtCreateSection", "NtMapViewOfSection", "ZwQuerySystemInformation", "LdrLoadDll"],
    "network_config": ["GetAdaptersInfo", "GetAdaptersAddresses"],
    "network_connections": ["GetTcpTable", "GetExtendedTcpTable"],
    "network": [
        "InternetOpen", "InternetConnect", "HttpOpenRequest",
        "HttpSendRequest", "URLDownloadToFile", "WinHttpOpen",
        "socket", "connect", "send", "recv", "WSAStartup",
    ],
    "file_operations": [
        "CreateFile", "WriteFile", "ReadFile", "DeleteFile",
        "CopyFile", "MoveFile", "SetFileAttributes",
    ],
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
        "CryptImportKey", "CryptAcquireContext",
        "BCryptEncrypt", "BCryptDecrypt",
    ],
}

# ATT&CK technique mapping
API_TO_TECHNIQUE = {
    "VirtualAllocEx": ["T1055", "process-injection"],
    "WriteProcessMemory": ["T1055", "process-injection"],
    "CreateRemoteThread": ["T1055.001", "process-injection"],
    "NtUnmapViewOfSection": ["T1055.012", "process-hollowing"],
    "SetThreadContext": ["T1055.012", "process-hollowing"],
    "RegSetValueEx": ["T1547.001", "persistence"],
    "CreateService": ["T1543.003", "persistence"],
    "CreateServiceA": ["T1543.003", "persistence"],
    "CreateServiceW": ["T1543.003", "persistence"],
    "IsDebuggerPresent": ["T1497.001", "defense-evasion"],
    "CheckRemoteDebuggerPresent": ["T1497.001", "defense-evasion"],
    "GetTickCount": ["T1497.003", "defense-evasion"],
    "InternetOpen": ["T1071", "command-and-control"],
    "URLDownloadToFile": ["T1105", "ingress-tool-transfer"],
    "CryptEncrypt": ["T1027", "defense-evasion"],
    "CryptDecrypt": ["T1140", "deobfuscation"],
    # 10 new APT-style techniques
    "SetupDiGetClassDevsA": ["T1120", "peripheral-device-discovery"],
    "SetupDiGetClassDevsW": ["T1120", "peripheral-device-discovery"],
    "SetupDiEnumDeviceInfo": ["T1120", "peripheral-device-discovery"],
    "RegOpenKeyExA": ["T1012", "query-registry"],
    "RegOpenKeyExW": ["T1012", "query-registry"],
    "RegQueryValueExA": ["T1012", "query-registry"],
    "RegQueryValueExW": ["T1012", "query-registry"],
    "RegEnumKeyExA": ["T1012", "query-registry"],
    "FindFirstFileA": ["T1083", "file-directory-discovery"],
    "FindFirstFileW": ["T1083", "file-directory-discovery"],
    "FindNextFileA": ["T1083", "file-directory-discovery"],
    "FindNextFileW": ["T1083", "file-directory-discovery"],
    "BitBlt": ["T1113", "screen-capture"],
    "GetDC": ["T1113", "screen-capture"],
    "CreateCompatibleDC": ["T1113", "screen-capture"],
    "GetDesktopWindow": ["T1113", "screen-capture"],
    "CreateToolhelp32Snapshot": ["T1057", "process-discovery"],
    "Process32First": ["T1057", "process-discovery"],
    "Process32Next": ["T1057", "process-discovery"],
    "NtCreateSection": ["T1106", "native-api"],
    "NtMapViewOfSection": ["T1106", "native-api"],
    "ZwQuerySystemInformation": ["T1106", "native-api"],
    "LdrLoadDll": ["T1106", "native-api"],
    "GetAdaptersInfo": ["T1016", "network-config-discovery"],
    "GetAdaptersAddresses": ["T1016", "network-config-discovery"],
    "GetTcpTable": ["T1049", "network-connections-discovery"],
    "GetExtendedTcpTable": ["T1049", "network-connections-discovery"],
    "OpenSCManagerA": ["T1543.003", "persistence"],
    "OpenSCManagerW": ["T1543.003", "persistence"],
    "ChangeServiceConfigA": ["T1543.003", "persistence"],
    "ChangeServiceConfigW": ["T1543.003", "persistence"],
    "RtlDecompressBuffer": ["T1140", "deobfuscation"],
    # 10 techniques: UAC Bypass, Modify Registry, File Deletion, etc.
    "DeleteFileA": ["T1070.004", "file-deletion"],
    "DeleteFileW": ["T1070.004", "file-deletion"],
    "MoveFileExA": ["T1070.004", "file-deletion"],
    "MoveFileExW": ["T1070.004", "file-deletion"],
    "GetSystemTime": ["T1124", "system-time-discovery"],
    "GetTickCount": ["T1124", "system-time-discovery"],
    "GetTickCount64": ["T1124", "system-time-discovery"],
    "GetSystemTimeAsFileTime": ["T1124", "system-time-discovery"],
    "GetComputerNameA": ["T1082", "system-info-discovery"],
    "GetComputerNameW": ["T1082", "system-info-discovery"],
    "GetVersionExA": ["T1082", "system-info-discovery"],
    "GetVersionExW": ["T1082", "system-info-discovery"],
    "GetUserNameA": ["T1082", "system-info-discovery"],
    "GetUserNameW": ["T1082", "system-info-discovery"],
    "InternetSetOptionA": ["T1090", "proxy"],
    "InternetSetOptionW": ["T1090", "proxy"],
    # Impair Defenses, Event Log Clear, IFEO, Hidden, Root Cert, Phishing
    "ClearEventLogA": ["T1070.001", "indicator-removal"],
    "ClearEventLogW": ["T1070.001", "indicator-removal"],
    "TerminateProcess": ["T1562.001", "impair-defenses"],
    "SetFileAttributesA": ["T1564.001", "hidden-files"],
    "SetFileAttributesW": ["T1564.001", "hidden-files"],
    "ShowWindow": ["T1564.003", "hidden-window"],
    "CertAddCertificateContextToStore": ["T1553.004", "subvert-trust"],
    "CreateWindowExA": ["T1056.002", "input-capture"],
    "GetWindowTextW": ["T1056.002", "input-capture"],
    # v0.1.6 Lateral Movement & Network Discovery (NetAPI32, iphlpapi, etc.)
    "NetServerEnum": ["T1018", "remote-system-discovery"],
    "NetServerEnumEx": ["T1018", "remote-system-discovery"],
    "GetIpNetTable": ["T1018", "remote-system-discovery"],
    "NetUserEnum": ["T1087.001", "account-discovery"],
    "NetGetDisplayInformationIndex": ["T1087.002", "domain-account-discovery"],
    "NetLocalGroupEnum": ["T1069.001", "permission-groups-discovery"],
    "NetUseAdd": ["T1021.002", "remote-services-smb"],
    "CopyFileExW": ["T1570", "lateral-tool-transfer"],
    "CopyFileExA": ["T1570", "lateral-tool-transfer"],
    "BluetoothFindFirstDevice": ["T1011.001", "exfiltration-bluetooth"],
    "BluetoothFindNextDevice": ["T1011.001", "exfiltration-bluetooth"],
    # Top-20 sub-techniques: injection variants, timestomp, WMI, LOLBins
    "LoadLibraryA": ["T1055.002", "dll-injection"],
    "LoadLibraryW": ["T1055.002", "dll-injection"],
    "SuspendThread": ["T1055.003", "thread-hijacking"],
    "GetThreadContext": ["T1055.003", "thread-hijacking"],
    "SetFileTime": ["T1070.006", "timestomp"],
    "GetFileTime": ["T1070.006", "timestomp"],
    "IWbemServices_PutInstance": ["T1546.003", "wmi-subscription"],
    "IWbemServices_ExecMethod": ["T1546.003", "wmi-subscription"],
    "IWbemClassObject": ["T1546.003", "wmi-subscription"],
    "GetIpForwardTable": ["T1016.001", "network-config-discovery"],
    "NetGroupEnum": ["T1069.002", "domain-groups-discovery"],
    # Deep Coverage: APC, TLS, EWMI, Event Logging, DCOM
    "QueueUserAPC": ["T1055.004", "process-injection"],
    "NtQueueApcThread": ["T1055.004", "process-injection"],
    "TlsAlloc": ["T1055.005", "process-injection"],
    "TlsSetValue": ["T1055.005", "process-injection"],
    "SetWindowLongPtrA": ["T1055.011", "process-injection"],
    "SetWindowLongPtrW": ["T1055.011", "process-injection"],
    "EtwEventWrite": ["T1562.002", "impair-defenses"],
    "CoInitializeEx": ["T1021.003", "lateral-movement"],
    "CoCreateInstanceEx": ["T1021.003", "lateral-movement"],
    # DNS API (Payload-as-Code / T1071.004)
    "DnsQuery_A": ["T1071.004", "dns-protocol"],
    "DnsQuery_W": ["T1071.004", "dns-protocol"],
    "DnsQuery_UTF8": ["T1071.004", "dns-protocol"],
    "DnsRecordListFree": ["T1071.004", "dns-protocol"],
    # WMI (Payload-as-Code / T1546.003) — IWbemServices::ExecMethod and related
    "IWbemLocator_ConnectServer": ["T1546.003", "wmi-subscription"],
    "IWbemServices_ConnectServer": ["T1546.003", "wmi-subscription"],
}


def _check_file_size(path: Path) -> bool:
    """Check if file is within size limit for emulation."""
    try:
        size_mb = path.stat().st_size / (1024 * 1024)
        return size_mb <= EMULATION_MAX_FILE_SIZE_MB
    except Exception:
        return False


def _detect_sequential_techniques(api_calls: List[Dict[str, Any]]) -> List[str]:
    """
    Маппинг последовательных вызовов API в сложные техники.
    Например: VirtualAllocEx + WriteProcessMemory + (CreateRemoteThread или SetThreadContext+ResumeThread)
    → T1055 (Process Injection) / T1055.012 (Process Hollowing).
    """
    added: Set[str] = set()
    names = [c.get("api", "") for c in api_calls if isinstance(c, dict)]
    if not names:
        return []
    # Alloc + Write + Execute → Process Injection
    alloc = any("VirtualAlloc" in n or "NtAllocateVirtualMemory" in n for n in names)
    write = any("WriteProcessMemory" in n or "NtWriteVirtualMemory" in n for n in names)
    remote_thread = any("CreateRemoteThread" in n or "NtCreateThreadEx" in n or "RtlCreateUserThread" in n for n in names)
    set_ctx = any("SetThreadContext" in n or "NtSetContextThread" in n for n in names)
    resume = any("ResumeThread" in n for n in names)
    hollow = any("NtUnmapViewOfSection" in n or "ZwUnmapViewOfSection" in n for n in names)
    if alloc and write and (remote_thread or (set_ctx and resume)):
        added.add("T1055")
        added.add("process-injection")
    if hollow and (set_ctx or "SetThreadContext" in names) and (resume or "ResumeThread" in names):
        added.add("T1055.012")
        added.add("process-hollowing")
    load_lib = any("LoadLibrary" in n for n in names)
    if remote_thread and load_lib:
        added.add("T1055.002")
        added.add("dll-injection")
    if any("SuspendThread" in n for n in names) and set_ctx and not hollow:
        added.add("T1055.003")
        added.add("thread-hijacking")
    # APC injection: QueueUserAPC / NtQueueApcThread + alloc
    apc = any("QueueUserAPC" in n or "NtQueueApcThread" in n for n in names)
    if apc and alloc:
        added.add("T1055.004")
        added.add("process-injection")
    # TLS injection
    if any("TlsAlloc" in n or "TlsSetValue" in n for n in names):
        added.add("T1055.005")
    # EWMI: SetWindowLongPtr
    if any("SetWindowLongPtr" in n for n in names):
        added.add("T1055.011")
    # Disable Event Logging (EtwEventWrite patch)
    if any("EtwEventWrite" in n for n in names):
        added.add("T1562.002")
    # DCOM lateral
    if any("CoInitializeEx" in n or "CoCreateInstanceEx" in n for n in names):
        added.add("T1021.003")
    if any("SetFileTime" in n for n in names):
        added.add("T1070.006")
        added.add("timestomp")
    # Self-Deletion: DeleteFile or MoveFileEx (T1070.004)
    if any("DeleteFile" in n or "MoveFileEx" in n for n in names):
        added.add("T1070.004")
        added.add("file-deletion")
    # UAC Bypass pattern: RegSetValueEx + registry key creation (T1548.002)
    reg_set = any("RegSetValueEx" in n or "RegSetValueExA" in n or "RegSetValueExW" in n for n in names)
    reg_create = any("RegCreateKeyEx" in n or "RegOpenKeyEx" in n for n in names)
    if reg_set and reg_create:
        added.add("T1548.002")
        added.add("uac-bypass")
    # T1564.003 Hidden Window: ShowWindow(hwnd, nCmdShow) with nCmdShow == 0 (SW_HIDE)
    for c in api_calls:
        if not isinstance(c, dict):
            continue
        if c.get("api") == "ShowWindow":
            args = c.get("args") or []
            if len(args) >= 2:
                n_cmd = args[1]
                if n_cmd == 0 or str(n_cmd).strip() in ("0", "0x0") or "sw_hide" in str(n_cmd).lower():
                    added.add("T1564.003")
                    added.add("hidden-window")
                    break
    # CreateProcessA/CreateProcessW with CREATE_NO_WINDOW (0x08000000) or SW_HIDE in args
    create_proc = any("CreateProcess" in n for n in names)
    if create_proc:
        for c in api_calls:
            if not isinstance(c, dict):
                continue
            args = c.get("args") or []
            args_str = " ".join(str(a) for a in args).lower()
            if "0x08000000" in args_str or "create_no_window" in args_str or "sw_hide" in args_str:
                added.add("T1564.003")
                added.add("hidden-window")
                break
            if len(args) >= 6:
                dw_creation = args[5] if len(args) > 5 else None
                if dw_creation == 0x08000000 or dw_creation == 134217728 or str(dw_creation) == "0x08000000":
                    added.add("T1564.003")
                    added.add("hidden-window")
                    break
    return sorted(added)


def _extract_techniques(api_calls: List[Dict[str, Any]]) -> List[str]:
    """Extract ATT&CK techniques from API calls (single-call + sequential chains)."""
    techniques: Set[str] = set()
    
    for call in api_calls:
        api_name = call.get("api", "")
        if api_name in API_TO_TECHNIQUE:
            techniques.update(API_TO_TECHNIQUE[api_name])
        
        # Category-based detection
        for category, apis in SUSPICIOUS_APIS.items():
            if api_name in apis:
                techniques.add(category)
    
    # Sequential chain: Alloc + Write + Execute → T1055 / Process Hollowing
    techniques.update(_detect_sequential_techniques(api_calls))
    
    return sorted(techniques)


def _summarize_api_calls(api_calls: List[Dict[str, Any]]) -> Dict[str, int]:
    """Summarize API calls by name."""
    summary: Dict[str, int] = {}
    for call in api_calls:
        api_name = call.get("api", "unknown")
        summary[api_name] = summary.get(api_name, 0) + 1
    return dict(sorted(summary.items(), key=lambda x: -x[1])[:50])


def _set_dump_reason(reason: str) -> None:
    global _last_dump_reason
    _last_dump_reason = reason
    _emu_log(f"dump: reason={reason}")


def _dump_emulated_memory_to_file(se: Any, source_path: Path) -> Optional[str]:
    """
    Dump emulated process memory to a temporary .dmp file.
    Tries: 1) get_memory_dumps() generator; 2) get_mem_maps() + mem_read() (required if 1 is empty).
    Returns path to the .dmp file or None on failure. Sets _last_dump_reason on failure for CLI.
    """
    global _last_dump_reason
    _last_dump_reason = ""
    dmp_path: Optional[str] = None
    try:
        _emu_log("dump: starting extraction.")
        # 1) Speakeasy: get_memory_dumps() -> generator of (tag, base, size, is_free, proc, data)
        get_dumps = getattr(se, "get_memory_dumps", None)
        _emu_log(f"dump: get_memory_dumps present={callable(get_dumps)}")
        if callable(get_dumps):
            dumps = get_dumps()
            fd, dmp_path = tempfile.mkstemp(suffix=".dmp", prefix="bin_gate_emu_")
            try:
                with os.fdopen(fd, "wb") as f:
                    written = 0
                    blocks = 0
                    for block in dumps:
                        blocks += 1
                        if isinstance(block, (list, tuple)) and len(block) >= 1:
                            data = block[-1] if len(block) >= 3 else (block[0] if len(block) == 1 else None)
                            if isinstance(data, (bytes, bytearray)):
                                f.write(data)
                                written += len(data)
                        elif isinstance(block, (bytes, bytearray)):
                            f.write(block)
                            written += len(block)
                    _emu_log(f"dump: get_memory_dumps blocks={blocks} written={written} path={dmp_path}")
                    if written > 0:
                        _emu_log(f"dump: bytes written: {written}.")
                if written == 0:
                    _set_dump_reason(f"get_memory_dumps empty (blocks={blocks} written=0)")
                    try:
                        os.unlink(dmp_path)
                    except Exception:
                        pass
                    dmp_path = None
                else:
                    return dmp_path
            except Exception as e:
                _set_dump_reason(f"get_memory_dumps error: {e}")
                _emu_log(f"dump: get_memory_dumps error={e}")
                try:
                    if dmp_path:
                        os.unlink(dmp_path)
                except Exception:
                    pass
                dmp_path = None
        else:
            _set_dump_reason("get_memory_dumps not available")

        # 2) If get_memory_dumps() was empty, MUST use get_mem_maps(): all regions, mem_read, concatenate, write
        if dmp_path is None and hasattr(se, "get_mem_maps") and hasattr(se, "mem_read"):
            get_maps = getattr(se, "get_mem_maps", None)
            mem_read = getattr(se, "mem_read", None)
            if callable(get_maps) and callable(mem_read):
                _emu_log("dump: fallback get_mem_maps + mem_read")
                try:
                    maps = get_maps()
                    if not maps:
                        _set_dump_reason((_last_dump_reason + "; " if _last_dump_reason else "") + "get_mem_maps returned empty list")
                        _emu_log("dump: get_mem_maps returned empty")
                    else:
                        total_data = bytearray()
                        regions_ok = 0
                        regions_fail = 0
                        for region in maps:
                            base = region.get_base() if hasattr(region, "get_base") else getattr(region, "base", None)
                            size = region.get_size() if hasattr(region, "get_size") else getattr(region, "size", None)
                            if base is None or size is None or size <= 0:
                                continue
                            try:
                                data = mem_read(base, size)
                                if data:
                                    total_data.extend(data)
                                    regions_ok += 1
                            except Exception as e:
                                regions_fail += 1
                                _emu_log(f"dump: mem_read region base={base} size={size} failed: {e}")
                        _emu_log(f"dump: get_mem_maps regions_ok={regions_ok} regions_fail={regions_fail} bytes={len(total_data)}")
                        if len(total_data) == 0:
                            _set_dump_reason((_last_dump_reason + "; " if _last_dump_reason else "") + f"get_mem_maps read 0 bytes (regions_ok={regions_ok} regions_fail={regions_fail})")
                            dmp_path = None
                        else:
                            _emu_log(f"dump: bytes written: {len(total_data)}.")
                            fd, dmp_path = tempfile.mkstemp(suffix=".dmp", prefix="bin_gate_emu_")
                            try:
                                with os.fdopen(fd, "wb") as f:
                                    f.write(total_data)
                                return dmp_path
                            except Exception as e:
                                _set_dump_reason((_last_dump_reason + "; " if _last_dump_reason else "") + f"get_mem_maps write error: {e}")
                                _emu_log(f"dump: get_mem_maps write error={e}")
                                try:
                                    os.unlink(dmp_path)
                                except Exception:
                                    pass
                                dmp_path = None
                except Exception as e:
                    _set_dump_reason((_last_dump_reason + "; " if _last_dump_reason else "") + f"get_mem_maps error: {e}")
                    _emu_log(f"dump: get_mem_maps error={e}")
            else:
                _set_dump_reason((_last_dump_reason + "; " if _last_dump_reason else "") + "get_mem_maps/mem_read not callable")

        if dmp_path is None and not _last_dump_reason:
            _set_dump_reason("no method produced a dump")
    except Exception as e:
        _set_dump_reason(f"exception: {e}")
        _emu_log(f"dump: exception={e}")
    return None


def _add_mem_invalid_hook(se: Any) -> None:
    """
    Регистрирует обработчик неразмеченной памяти через se.add_mem_invalid_hook (если API есть).
    При UC_MEM_WRITE_UNMAPPED вызывается se.mem_map(address & ~0xfff, 0x1000), возврат True — выполнение продолжается.
    """
    PAGE_SIZE = 0x1000

    def _hook_mem_invalid(*args: Any) -> bool:
        # API может вызывать (address, size, access) или (emu, address, size, access)
        address = args[0] if args else 0
        if not isinstance(address, int) and len(args) >= 2:
            address = args[1]
        base = int(address) & ~0xFFF
        try:
            mem_map = getattr(se, "mem_map", None)
            if callable(mem_map):
                mem_map(base, PAGE_SIZE)
        except Exception:
            pass
        try:
            uc = getattr(se, "emu", None) or getattr(se, "_emu", None) or getattr(se, "uc", None)
            if uc is None and callable(getattr(se, "get_emu", None)):
                uc = se.get_emu()
            if uc is not None:
                uc.mem_map(base, PAGE_SIZE)
        except Exception:
            pass
        return True

    try:
        add_hook = getattr(se, "add_mem_invalid_hook", None)
        if callable(add_hook):
            add_hook(_hook_mem_invalid)
    except Exception:
        pass


def _install_unmapped_write_hook(se: Any) -> None:
    """
    Хук на ошибку записи/чтения неразмеченной памяти (UC_ERR_WRITE_UNMAPPED): при записи в неразмеченную
    страницу вызываем se.mem_map(addr, size) или uc.mem_map() для этого региона, возвращаем True —
    инструкция повторится, распаковщик завершит работу, дамп создаётся (оживляет test_unpacking_success).
    Сначала пробуем se.mem_map(base, PAGE_SIZE) — нативный API Speakeasy; иначе Unicorn uc.mem_map().
    """
    PAGE_SIZE = 0x1000
    PAGE_MASK = ~(PAGE_SIZE - 1)
    se_mem_map = getattr(se, "mem_map", None) if se else None
    se_mem_map_callable = callable(se_mem_map)

    def _do_map(base: int) -> None:
        try:
            if se_mem_map_callable:
                se_mem_map(base, PAGE_SIZE)
                return
        except Exception:
            pass
        try:
            uc = getattr(se, "emu", None) or getattr(se, "_emu", None) or getattr(se, "uc", None)
            if uc is None and callable(getattr(se, "get_emu", None)):
                uc = se.get_emu()
            if uc is not None:
                uc.mem_map(base, PAGE_SIZE)
        except Exception:
            pass

    try:
        uc = getattr(se, "emu", None) or getattr(se, "_emu", None) or getattr(se, "uc", None)
        if uc is None and callable(getattr(se, "get_emu", None)):
            uc = se.get_emu()
        if uc is None:
            return
        from unicorn import UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_READ_UNMAPPED

        def _hook_unmapped(uc_eng, access, address, size, value, user_data):
            base = address & PAGE_MASK
            _do_map(base)
            return True  # доступ обработан — инструкция повторится, эмуляция продолжается

        try:
            uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, _hook_unmapped)
        except Exception:
            pass
        try:
            uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, _hook_unmapped)
        except Exception:
            pass
    except Exception:
        pass


def _run_speakeasy_emulation(path: Path, timeout: int) -> EmulationResult:
    """
    Run Speakeasy emulation on a PE file.
    
    Speakeasy provides:
    - Windows kernel/usermode emulation
    - API hooking and logging
    - Memory analysis
    - Shellcode detection
    """
    result = EmulationResult()
    
    try:
        import speakeasy
        from speakeasy import Speakeasy
    except ImportError as e:
        err = str(e).strip()
        result.error = f"speakeasy_import_error: {err}"
        if "dynamic library" in err.lower() or "dll" in err.lower():
            result.error += " (hint: on Windows install VC++ Redistributable; ensure Python and pip are same arch 64-bit)"
        return result
    
    import time
    start_time = time.time()
    
    try:
        # Initialize Speakeasy: снижение UC_ERR_WRITE_UNMAPPED при распаковке (запись в динамически выделенную память)
        config = {
            "keep_memory_on_free": True,
            "memory_tracing": False,
            "allow_unmapped_access": True,  # при записи в неразмеченную область — не падать; эмулятор может промапить страницу
        }
        try:
            se = Speakeasy(config=config)
        except TypeError:
            # Старые версии Speakeasy не принимают allow_unmapped_access
            config_legacy = {k: v for k, v in config.items() if k != "allow_unmapped_access"}
            try:
                se = Speakeasy(config=config_legacy)
            except TypeError:
                se = Speakeasy()

        # Обработчик неразмеченной памяти: при UC_MEM_WRITE_UNMAPPED мапим страницу 4КБ, продолжаем выполнение (дамп создаётся)
        _add_mem_invalid_hook(se)

        # Load the module (критический сбой загрузчика UC_ERR_WRITE_UNMAPPED и др. — не роняем весь процесс)
        try:
            module = se.load_module(str(path))
        except Exception as load_err:
            result.emulation_status = "load_failed"
            result.error = f"load_failed:{str(load_err)[:300]}"
            result.elapsed_ms = int((time.time() - start_time) * 1000)
            return result
        
        # После load_module: хук UC_MEM_WRITE_UNMAPPED + авто-мапирование страницы (если Speakeasy даёт доступ к Unicorn)
        _install_unmapped_write_hook(se)
        
        # Set up hooks for interesting APIs
        api_calls = []
        mutexes = []
        files_created = []
        files_read = []
        files_written = []
        registry_keys = []
        network_ops = []
        
        def generic_hook(emu, api_name, func, params):
            """Generic API hook to capture calls."""
            call_info = {
                "api": api_name,
                "params": [str(p)[:200] for p in params] if params else [],
                "return": None,
            }
            api_calls.append(call_info)
            
            # Extract specific artifacts
            if "Mutex" in api_name and params:
                mutexes.append(str(params[-1])[:200] if params else "")
            elif api_name in ("CreateFileA", "CreateFileW") and params:
                files_created.append(str(params[0])[:500])
            elif api_name in ("ReadFile",) and params:
                files_read.append(str(params[0])[:500])
            elif api_name in ("WriteFile",) and params:
                files_written.append(str(params[0])[:500])
            elif "Reg" in api_name and params:
                registry_keys.append({
                    "operation": api_name,
                    "key": str(params[0])[:500] if params else "",
                })
            elif api_name in ("connect", "send", "recv", "InternetConnect") and params:
                network_ops.append({
                    "api": api_name,
                    "params": [str(p)[:100] for p in params[:3]] if params else [],
                })
            
            return None  # Continue execution
        
        # Install hooks for suspicious APIs
        for category, apis in SUSPICIOUS_APIS.items():
            for api_name in apis:
                try:
                    se.add_api_hook(generic_hook, module_name="*", api_name=api_name)
                except Exception:
                    pass  # API may not exist
        
        # Run emulation with timeout
        se.run_module(
            module,
            timeout=timeout,
            max_instructions=EMULATION_MAX_INSTRUCTIONS,
        )
        
        # Collect results
        result.api_calls = api_calls[:1000]  # Limit stored calls
        result.api_summary = _summarize_api_calls(api_calls)
        result.mutexes = list(set(mutexes))[:50]
        result.files_created = list(set(files_created))[:100]
        result.files_read = list(set(files_read))[:100]
        result.files_written = list(set(files_written))[:100]
        result.registry_keys = registry_keys[:100]
        result.network_connections = network_ops[:50]
        
        # Extract techniques
        result.techniques = _extract_techniques(api_calls)
        
        # Get decoded strings from memory
        try:
            mem_strings = se.get_strings()
            result.decoded_strings = [s[:500] for s in mem_strings[:200]]
        except Exception:
            pass
        
        # Check for shellcode
        try:
            sc_info = se.get_shellcode_info()
            if sc_info:
                result.shellcode_detected = True
                result.shellcode_info = {
                    "type": sc_info.get("type", "unknown"),
                    "entry": hex(sc_info.get("entry", 0)),
                }
        except Exception:
            pass
        
        result.instructions_executed = se.get_instruction_count() if hasattr(se, 'get_instruction_count') else 0
        result.success = True

        # Dump emulated memory (image base + mapped pages) for CVE/SBOM on unpacked content
        if result.success:
            _emu_log("dump: calling _dump_emulated_memory_to_file")
            result.memory_dump_path = _dump_emulated_memory_to_file(se, path)
            if not result.memory_dump_path:
                result.dump_failure_reason = get_last_dump_reason()
            _emu_log(f"dump: result path={result.memory_dump_path}")
        
    except Exception as e:
        result.error = f"speakeasy_error:{str(e)[:200]}"
        if not result.memory_dump_path:
            result.dump_failure_reason = get_last_dump_reason() or f"exception_before_or_during_dump: {e!r}"

    result.elapsed_ms = int((time.time() - start_time) * 1000)
    return result


def _run_unicorn_shellcode_emulation(data: bytes, arch: str = "x86") -> EmulationResult:
    """
    Fallback: Basic shellcode emulation using Unicorn Engine.
    Used when Speakeasy is not available or for raw shellcode.
    """
    result = EmulationResult()
    
    try:
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64
        from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_RIP
    except ImportError:
        result.error = "unicorn_not_installed"
        return result
    
    import time
    start_time = time.time()
    
    try:
        # Initialize Unicorn
        if arch == "x64":
            uc = Uc(UC_ARCH_X86, UC_MODE_64)
            ip_reg = UC_X86_REG_RIP
        else:
            uc = Uc(UC_ARCH_X86, UC_MODE_32)
            ip_reg = UC_X86_REG_EIP
        
        # Map memory
        base_addr = 0x400000
        stack_addr = 0x100000
        uc.mem_map(base_addr, 2 * 1024 * 1024)
        uc.mem_map(stack_addr, 1024 * 1024)
        
        # Write shellcode
        uc.mem_write(base_addr, data[:0x100000])
        
        # Set up stack
        if arch == "x64":
            uc.reg_write(UC_X86_REG_RIP, base_addr)
        else:
            uc.reg_write(UC_X86_REG_EIP, base_addr)
        
        # Emulate limited instructions
        instructions = 0
        max_instr = min(10000, EMULATION_MAX_INSTRUCTIONS)
        
        def hook_code(uc, address, size, user_data):
            nonlocal instructions
            instructions += 1
            if instructions >= max_instr:
                uc.emu_stop()
        
        uc.hook_add(1, hook_code)  # UC_HOOK_CODE
        
        try:
            uc.emu_start(base_addr, base_addr + len(data), timeout=5000000)
        except Exception:
            pass  # Expected to fail on syscalls
        
        result.instructions_executed = instructions
        result.shellcode_detected = instructions > 100
        result.success = True
        
    except Exception as e:
        result.error = f"unicorn_error:{str(e)[:200]}"
    
    result.elapsed_ms = int((time.time() - start_time) * 1000)
    return result


def _emulation_slot_acquire(timeout_sec: int = EMULATION_SLOT_WAIT_TIMEOUT):
    """v3.1: захват слота для ограничения одновременных контейнеров эмуляции. Возвращает путь к файлу слота или None."""
    slot_dir = Path(tempfile.gettempdir()) / "bin_gate_emulation_slots"
    slot_dir.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        for i in range(EMULATION_MAX_CONCURRENT):
            slot_path = slot_dir / f"slot_{i}"
            try:
                fd = os.open(str(slot_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
                return slot_path
            except FileExistsError:
                continue
        time.sleep(1.0)
    return None


def _emulation_slot_release(slot_path) -> None:
    """v3.1: освобождение слота."""
    if slot_path:
        try:
            Path(slot_path).unlink(missing_ok=True)
        except Exception:
            pass


def _run_speakeasy_emulation_via_docker(path: Path, timeout: int, max_api_calls: int = 1000) -> EmulationResult:
    """
    Run Speakeasy emulation inside Docker (Linux image; use when local import fails e.g. on Windows).
    v3.1: лимит одновременных контейнеров через слоты (EMULATION_MAX_CONCURRENT).
    Returns EmulationResult with memory_dump_path set if dump was produced.
    """
    result = EmulationResult()
    try:
        from ..docker_utils import (
            check_docker_available,
            image_exists,
            build_emulation_image,
            run_emulation_container,
            EMULATION_IMAGE,
        )
    except ImportError:
        result.error = "docker_utils_unavailable"
        return result

    if not check_docker_available(raise_on_fail=False).available:
        result.error = "docker_unavailable"
        return result

    if not image_exists(EMULATION_IMAGE):
        _emu_log("emulation docker: building image (first run)...")
        ok, err = build_emulation_image()
        if not ok:
            result.error = f"emulation_image_build_failed: {err}"
            return result

    slot = _emulation_slot_acquire()
    if slot is None:
        result.error = "emulation_slot_timeout"
        return result
    try:
        rc, stdout, stderr, report_dict = run_emulation_container(path, timeout=timeout, max_api_calls=max_api_calls)
    finally:
        _emulation_slot_release(slot)
    result.docker_stdout_length = len(stdout)

    # Parse Base64 dump even on non-zero exit (container may dump memory on run_module failure)
    import base64
    start_m = "DUMP_BASE64_START"
    end_m = "DUMP_BASE64_END"
    if start_m in stdout and end_m in stdout:
        try:
            i = stdout.index(start_m) + len(start_m)
            j = stdout.index(end_m)
            b64 = stdout[i:j].strip().replace("\n", "").replace("\r", "")
            dump_bytes = base64.b64decode(b64)
            if dump_bytes:
                fd, stable_path = tempfile.mkstemp(suffix=".dmp", prefix="bin_gate_emu_")
                try:
                    os.write(fd, dump_bytes)
                    result.memory_dump_path = stable_path
                    result.success = True
                    _emu_log(f"emulation docker: dump {len(dump_bytes)} bytes -> {stable_path}")
                finally:
                    os.close(fd)
        except Exception as e:
            if not result.memory_dump_path:
                result.dump_failure_reason = f"emulation_docker_decode: {e}"

    if rc != 0:
        result.error = f"emulation_docker_exit_{rc}"
        if stderr:
            result.error += f": {stderr[:200].strip()}"
        # Критический сбой загрузчика (UC_ERR_WRITE_UNMAPPED и т.д.) — фиксируем для тестов/пайплайна
        stderr_lower = (stderr or "").lower()
        if "uc_err" in stderr_lower or "write_unmapped" in stderr_lower or "load_module" in stderr_lower:
            result.emulation_status = "load_failed"
        # If we got a dump despite exit != 0, caller can still use memory_dump_path
        if not result.memory_dump_path:
            return result

    _emu_log(f"Docker RAW output length: {result.docker_stdout_length}. Looking for modules...")

    # Parse JSON report from container (docker_utils uses r"!!!MODULE_LOADED!!!:.*?([\w\-. ]+\.dll)" for DLLs with weird separators): fill api_summary, decoded_strings, modules
    if report_dict:
        result.modules = list(report_dict.get("modules", [])) if isinstance(report_dict.get("modules"), list) else []
        if report_dict.get("decoded_strings"):
            result.decoded_strings = list(report_dict["decoded_strings"])[:500]
        if isinstance(report_dict.get("api_summary"), dict):
            result.api_summary = dict(report_dict["api_summary"])
        result.module_details = list(report_dict.get("module_details") or [])
        result.detailed_modules = list(report_dict.get("detailed_modules") or report_dict.get("module_details") or [])
        n_strings = len(result.decoded_strings)
        n_apis = len(result.api_summary) if isinstance(result.api_summary, dict) else 0
        _emu_log(f"Docker report parsed: found {n_strings} strings and {n_apis} API calls.")

    # Dump already parsed above (including on rc != 0). If no dump yet, treat report as success.
    if not result.success and report_dict:
        # Structured JSON output only (no Base64): success = report + modules
        result.success = True
        _emu_log("emulation docker: no dump; success from !!!JSON_REPORT_START!!! / !!!MODULE_LOADED!!!")
    if not result.success:
        result.error = "emulation_docker_no_dump_in_stdout"
        if stderr:
            result.error += f": {stderr[:150].strip()}"

    return result


# Themida/Enigma/Obsidium — усиленный профиль: timeout 120s (v1.2)
ADVANCED_PROTECTOR_EXTENDED_NAMES = frozenset({"themida", "enigma", "obsidium"})

# v3.0: adaptive_timeout — жёсткий предел и шаги для коммерческих протекторов (VMProtect/Themida)
ADAPTIVE_MAX_API_CALLS_HARD_LIMIT = int(os.getenv("BIN_GATE_EMU_API_HARD_LIMIT", "15000"))
ADAPTIVE_MAX_API_CALLS_MULTIPLIER = 2

def run_emulation(
    path: Path,
    timeout: int = EMULATION_TIMEOUT_SEC,
    enable: bool = False,
    file_type: str = "PE",
    complex_protector: bool = False,
    extended_protector: bool = False,
) -> Dict[str, Any]:
    """
    Run emulation analysis on a binary file.
    complex_protector=True (VMProtect): timeout=60, max_api_calls=5000.
    extended_protector=True (Themida/Enigma/Obsidium): timeout=120, max_api_calls=5000.

    Args:
        path: Path to the file
        timeout: Emulation timeout in seconds
        enable: Whether emulation is enabled (--emulation flag)
        file_type: "PE" or "ELF"
        complex_protector: True для VMProtect/сложных протекторов — больше API вызовов
        extended_protector: True для Themida/Enigma/Obsidium — timeout 120s

    Returns:
        Dict with emulation results for Evidence.emulation
    """
    result_dict: Dict[str, Any] = {
        "enabled": enable,
        "success": False,
        "error": None,
        "api_calls": [],
        "api_summary": {},
        "mutexes": [],
        "files": {"created": [], "read": [], "written": []},
        "registry": [],
        "network": [],
        "decoded_strings": [],
        "techniques": [],
        "shellcode": {"detected": False, "info": {}},
        "stats": {"elapsed_ms": 0, "instructions": 0},
        "memory_dump_path": None,
    }
    
    if not enable:
        result_dict["error"] = "emulation_disabled"
        return result_dict
    
    if not path.exists():
        result_dict["error"] = "file_not_found"
        return result_dict
    
    if not _check_file_size(path):
        result_dict["error"] = f"file_too_large_max_{EMULATION_MAX_FILE_SIZE_MB}MB"
        return result_dict
    
    # Only support PE for now (Speakeasy is Windows-focused)
    if file_type not in ("PE",):
        result_dict["error"] = f"unsupported_type:{file_type}"
        return result_dict

    if complex_protector or extended_protector:
        max_api_calls = 5000
        timeout = 120 if extended_protector else 60
    else:
        max_api_calls = 1000

    # v3.0: adaptive_timeout — для коммерческих протекторов увеличиваем max_api_calls до дампа/OEP или жёсткого предела
    use_adaptive = complex_protector or extended_protector
    emu_result = _run_speakeasy_emulation_via_docker(path, timeout, max_api_calls=max_api_calls)
    while use_adaptive and not emu_result.memory_dump_path and not (emu_result.success and getattr(emu_result, "api_summary", None)):
        next_limit = min(max_api_calls * ADAPTIVE_MAX_API_CALLS_MULTIPLIER, ADAPTIVE_MAX_API_CALLS_HARD_LIMIT)
        if next_limit <= max_api_calls:
            break
        max_api_calls = next_limit
        _emu_log(f"adaptive_timeout: retry with max_api_calls={max_api_calls} (no dump yet)")
        emu_result = _run_speakeasy_emulation_via_docker(path, timeout, max_api_calls=max_api_calls)

    # Convert to dict format
    result_dict["success"] = emu_result.success
    result_dict["error"] = emu_result.error if emu_result.error else None
    result_dict["api_calls"] = emu_result.api_calls[:100]  # Limit for JSON
    result_dict["api_summary"] = emu_result.api_summary
    result_dict["mutexes"] = emu_result.mutexes
    result_dict["files"] = {
        "created": emu_result.files_created,
        "read": emu_result.files_read,
        "written": emu_result.files_written,
    }
    result_dict["registry"] = emu_result.registry_keys
    result_dict["network"] = emu_result.network_connections
    result_dict["decoded_strings"] = emu_result.decoded_strings
    result_dict["techniques"] = emu_result.techniques
    result_dict["shellcode"] = {
        "detected": emu_result.shellcode_detected,
        "info": emu_result.shellcode_info,
    }
    result_dict["stats"] = {
        "elapsed_ms": emu_result.elapsed_ms,
        "instructions": emu_result.instructions_executed,
    }
    if emu_result.memory_dump_path:
        result_dict["memory_dump_path"] = emu_result.memory_dump_path
    if getattr(emu_result, "modules", None):
        result_dict["modules"] = list(emu_result.modules)
    else:
        result_dict["modules"] = []
    result_dict["module_details"] = list(getattr(emu_result, "module_details", None) or [])
    result_dict["detailed_modules"] = list(getattr(emu_result, "detailed_modules", None) or [])
    result_dict["docker_stdout_length"] = getattr(emu_result, "docker_stdout_length", 0) or 0
    # When no dump, always set a reason (from dataclass, global, or error before dump)
    if not result_dict.get("memory_dump_path"):
        result_dict["dump_failure_reason"] = (
            getattr(emu_result, "dump_failure_reason", None)
            or get_last_dump_reason()
            or (f"emulation_error_before_dump: {emu_result.error}" if getattr(emu_result, "error", None) else "dump_emulated_memory_to_file did not set reason")
        )
    # Статус загрузки модуля (load_failed при UC_ERR и т.д.) для корректной обработки в тестах/пайплайне
    result_dict["emulation_status"] = getattr(emu_result, "emulation_status", "") or (
        "load_failed" if (getattr(emu_result, "error", "") or "").strip().startswith("load_failed:") else ""
    )

    return result_dict


def merge_emulation_to_capa(emulation: Dict[str, Any], capa: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Merge emulation techniques into capa results.
    
    Args:
        emulation: Emulation result dict
        capa: Existing capa dict (may be None)
        
    Returns:
        Updated capa dict
    """
    if capa is None:
        capa = {
            "techniques": [],
            "rule_hits": [],
            "source": "emulation",
        }
    
    existing_techniques = set(capa.get("techniques", []))
    existing_hits = set(capa.get("rule_hits", []))
    
    # Add emulation techniques
    for tech in emulation.get("techniques", []):
        existing_techniques.add(tech)
        existing_hits.add(f"EMU:{tech}")
    
    # Add mutex-based detections
    for mutex in emulation.get("mutexes", []):
        if any(m in mutex.lower() for m in ["global\\", "local\\", "basenamed"]):
            existing_hits.add(f"EMU:mutex:{mutex[:50]}")
    
    # Add shellcode detection
    if emulation.get("shellcode", {}).get("detected"):
        existing_techniques.add("shellcode-execution")
        existing_hits.add("EMU:shellcode_detected")
    
    capa["techniques"] = sorted(existing_techniques)
    capa["rule_hits"] = sorted(existing_hits)
    
    # Update source
    if capa.get("source") not in ("capa", "yara_die"):
        capa["source"] = "emulation"
    else:
        capa["source"] = f"{capa['source']}+emulation"
    
    return capa
