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
    ],
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
    "IsDebuggerPresent": ["T1497.001", "defense-evasion"],
    "CheckRemoteDebuggerPresent": ["T1497.001", "defense-evasion"],
    "GetTickCount": ["T1497.003", "defense-evasion"],
    "InternetOpen": ["T1071", "command-and-control"],
    "URLDownloadToFile": ["T1105", "ingress-tool-transfer"],
    "CryptEncrypt": ["T1027", "defense-evasion"],
    "CryptDecrypt": ["T1140", "deobfuscation"],
}


def _check_file_size(path: Path) -> bool:
    """Check if file is within size limit for emulation."""
    try:
        size_mb = path.stat().st_size / (1024 * 1024)
        return size_mb <= EMULATION_MAX_FILE_SIZE_MB
    except Exception:
        return False


def _extract_techniques(api_calls: List[Dict[str, Any]]) -> List[str]:
    """Extract ATT&CK techniques from API calls."""
    techniques: Set[str] = set()
    
    for call in api_calls:
        api_name = call.get("api", "")
        if api_name in API_TO_TECHNIQUE:
            techniques.update(API_TO_TECHNIQUE[api_name])
        
        # Category-based detection
        for category, apis in SUSPICIOUS_APIS.items():
            if api_name in apis:
                techniques.add(category)
    
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
        # Initialize Speakeasy
        se = Speakeasy()
        
        # Load the module
        module = se.load_module(str(path))
        
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


def _run_speakeasy_emulation_via_docker(path: Path, timeout: int) -> EmulationResult:
    """
    Run Speakeasy emulation inside Docker (Linux image; use when local import fails e.g. on Windows).
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

    rc, stdout, stderr, report_dict = run_emulation_container(path, timeout=timeout)
    if rc != 0:
        result.error = f"emulation_docker_exit_{rc}"
        if stderr:
            result.error += f": {stderr[:200].strip()}"
        return result

    result.docker_stdout_length = len(stdout)
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

    # Optional: parse Base64 dump if present (DUMP_BASE64_START/END). If no dump, success = having report/modules.
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
                    result.success = True
                    result.memory_dump_path = stable_path
                    _emu_log(f"emulation docker: dump {len(dump_bytes)} bytes -> {stable_path}")
                finally:
                    os.close(fd)
        except Exception as e:
            result.error = f"emulation_docker_decode: {e}"
    if not result.success and report_dict:
        # Structured JSON output only (no Base64): success = report + modules
        result.success = True
        _emu_log("emulation docker: no dump; success from !!!JSON_REPORT_START!!! / !!!MODULE_LOADED!!!")
    if not result.success:
        result.error = "emulation_docker_no_dump_in_stdout"
        if stderr:
            result.error += f": {stderr[:150].strip()}"

    return result


def run_emulation(
    path: Path,
    timeout: int = EMULATION_TIMEOUT_SEC,
    enable: bool = False,
    file_type: str = "PE",
) -> Dict[str, Any]:
    """
    Run emulation analysis on a binary file.
    
    Args:
        path: Path to the file
        timeout: Emulation timeout in seconds
        enable: Whether emulation is enabled (--emulation flag)
        file_type: "PE" or "ELF"
        
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

    # Docker-only: no local Speakeasy fallback; container outputs JSON report + dump
    emu_result = _run_speakeasy_emulation_via_docker(path, timeout)

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
