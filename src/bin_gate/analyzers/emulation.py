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
import json
import tempfile
import hashlib


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
    except ImportError:
        result.error = "speakeasy_not_installed"
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
        
    except Exception as e:
        result.error = f"speakeasy_error:{str(e)[:200]}"
    
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
    
    # Run Speakeasy emulation
    emu_result = _run_speakeasy_emulation(path, timeout)
    
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
