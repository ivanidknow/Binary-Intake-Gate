"""
.NET Assembly Intelligence Analyzer (Enterprise-level)

Analyzes .NET binaries for:
- Strong Name signature presence and validity
- Authenticode (code signing) signature
- Anti-tamper/packer detection via entropy and section analysis
- P/Invoke detection for native code calls
- Mixed-mode assembly detection
- Obfuscator signatures
"""
from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, Optional, List
import struct
import math
import subprocess
import platform
import json


# Known .NET obfuscator/packer signatures in metadata
KNOWN_OBFUSCATORS = {
    "ConfuserEx": [b"ConfuserEx", b"Confuser.Core"],
    "Dotfuscator": [b"Dotfuscator", b"PreEmptive"],
    "SmartAssembly": [b"SmartAssembly", b"{SmartAssembly}", b"SmartAssembly.Resource", b"Red Gate", b"SmartAssembly.Attribute", b"SmartAssembly.StringEncoding"],
    "Eazfuscator": [b"Eazfuscator", b"EazObfuscator"],
    ".NET Reactor": [b".NET Reactor", b"Eziriz", b"__reactor__"],
    "Agile.NET": [b"Agile.NET", b"CliSecure"],
    "Crypto Obfuscator": [b"CryptoObfuscator", b"LogicNP"],
    "Babel.NET": [b"Babel.NET", b"babelfor.net"],
    "Goliath.NET": [b"Goliath.NET"],
    "MaxtoCode": [b"MaxtoCode"],
    "CodeVeil": [b"CodeVeil", b"Xheo"],
    "Themida/.NET": [b"Themida", b"Oreans"],
    "VMProtect": [b"VMProtect"],
    "Xenocode": [b"Xenocode"],
    "DeepSea": [b"DeepSea"],
    "ILProtector": [b"ILProtector"],
    "Skater.NET": [b"Skater.NET"],
    "NETGuard": [b"NETGuard", b"netguard"],
    "Obfuscar": [b"Obfuscar"],
    # v2.0 APT: Boxed App (virtualization/packer), Eazfuscator (already listed above; ensure coverage)
    "Boxed App": [b"BoxedApp", b"BoxedAppPacker", b"BxILMerge", b"BoxedApp.SDK"],
    "Eazfuscator": [b"Eazfuscator", b"EazObfuscator", b"Eazfuscator.NET"],  # explicit v2.0
}

# Suspicious .NET section names (common with packers/protectors)
SUSPICIOUS_SECTION_NAMES = {
    ".vmp0", ".vmp1", ".vmp2",  # VMProtect
    ".themida", ".oreans",      # Themida
    ".enigma1", ".enigma2",     # Enigma
    ".perplex",                 # Perplex
    ".crypt", ".crypted",       # Generic encryption
    ".packed", ".pack",         # Generic packing
    ".netshrink",              # .NET Shrink
    ".reactor",                # .NET Reactor
    ".sdata",                  # Suspicious data
    ".aspack", ".adata",       # ASPack
}

# High entropy threshold
HIGH_ENTROPY_THRESHOLD = 7.2


def _calc_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
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


def _find_pe_offset(data: bytes) -> Optional[int]:
    """Find PE header offset from DOS header."""
    if len(data) < 64:
        return None
    if data[:2] != b"MZ":
        return None
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset < len(data) - 4 and data[pe_offset:pe_offset+4] == b"PE\x00\x00":
            return pe_offset
    except Exception:
        pass
    return None


def _parse_pe_sections(data: bytes, pe_offset: int) -> List[Dict[str, Any]]:
    """Parse PE section headers."""
    sections = []
    try:
        # COFF header starts at pe_offset + 4
        coff_offset = pe_offset + 4
        machine = struct.unpack_from("<H", data, coff_offset)[0]
        num_sections = struct.unpack_from("<H", data, coff_offset + 2)[0]
        optional_header_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
        
        # Section headers start after optional header
        section_table_offset = coff_offset + 20 + optional_header_size
        
        for i in range(min(num_sections, 96)):  # Sanity limit
            section_offset = section_table_offset + (i * 40)
            if section_offset + 40 > len(data):
                break
            
            name = data[section_offset:section_offset + 8].rstrip(b'\x00').decode('utf-8', errors='replace')
            virtual_size = struct.unpack_from("<I", data, section_offset + 8)[0]
            virtual_addr = struct.unpack_from("<I", data, section_offset + 12)[0]
            raw_size = struct.unpack_from("<I", data, section_offset + 16)[0]
            raw_offset = struct.unpack_from("<I", data, section_offset + 20)[0]
            characteristics = struct.unpack_from("<I", data, section_offset + 36)[0]
            
            sections.append({
                "name": name,
                "virtual_size": virtual_size,
                "virtual_addr": virtual_addr,
                "raw_size": raw_size,
                "raw_offset": raw_offset,
                "characteristics": characteristics,
            })
    except Exception:
        pass
    return sections


def _find_clr_header(data: bytes, pe_offset: int) -> Optional[Dict[str, Any]]:
    """Find and parse CLR header (COM descriptor)."""
    try:
        # Parse optional header to find CLR directory
        coff_offset = pe_offset + 4
        optional_header_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
        
        # Check if PE32 or PE32+
        opt_offset = coff_offset + 20
        magic = struct.unpack_from("<H", data, opt_offset)[0]
        is_pe32_plus = (magic == 0x20b)
        
        # CLR header is at index 14 in data directories
        if is_pe32_plus:
            dir_offset = opt_offset + 112 + (14 * 8)  # PE32+ base + dir index
        else:
            dir_offset = opt_offset + 96 + (14 * 8)   # PE32 base + dir index
        
        if dir_offset + 8 > len(data):
            return None
        
        clr_rva = struct.unpack_from("<I", data, dir_offset)[0]
        clr_size = struct.unpack_from("<I", data, dir_offset + 4)[0]
        
        if clr_rva == 0 or clr_size == 0:
            return None
        
        return {
            "rva": clr_rva,
            "size": clr_size,
        }
    except Exception:
        return None


def _check_strong_name(data: bytes, clr_info: Dict[str, Any], sections: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Check for Strong Name signature in CLR header."""
    result = {
        "present": False,
        "signed": False,
        "delay_signed": False,
        "public_key_token": None,
    }
    
    try:
        # Convert CLR RVA to file offset
        clr_rva = clr_info["rva"]
        file_offset = None
        
        for sec in sections:
            if sec["virtual_addr"] <= clr_rva < sec["virtual_addr"] + sec["virtual_size"]:
                file_offset = sec["raw_offset"] + (clr_rva - sec["virtual_addr"])
                break
        
        if file_offset is None or file_offset + 72 > len(data):
            return result
        
        # CLR header structure (IMAGE_COR20_HEADER)
        # Offset 8: Flags
        # Offset 32: StrongNameSignature RVA
        # Offset 36: StrongNameSignature Size
        
        flags = struct.unpack_from("<I", data, file_offset + 16)[0]
        sn_rva = struct.unpack_from("<I", data, file_offset + 32)[0]
        sn_size = struct.unpack_from("<I", data, file_offset + 36)[0]
        
        # Flag bits
        COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008
        
        result["present"] = (sn_rva != 0 and sn_size != 0)
        result["signed"] = bool(flags & COMIMAGE_FLAGS_STRONGNAMESIGNED)
        result["delay_signed"] = result["present"] and not result["signed"]
        
    except Exception:
        pass
    
    return result


def _check_authenticode_powershell(path: Path) -> Dict[str, Any]:
    """Check Authenticode signature using PowerShell (Windows only)."""
    result = {
        "present": False,
        "valid": False,
        "publisher": None,
        "status": None,
    }
    
    if platform.system().lower() != "windows":
        return result
    
    try:
        cmd = [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            f"$sig = Get-AuthenticodeSignature -LiteralPath '{str(path).replace(chr(39), chr(39)+chr(39))}'; "
            f"[PSCustomObject]@{{Status=$sig.Status.ToString();SignerCN=$sig.SignerCertificate.Subject}} | ConvertTo-Json"
        ]
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if cp.returncode == 0 and cp.stdout.strip():
            data = json.loads(cp.stdout)
            status = data.get("Status", "")
            signer = data.get("SignerCN", "")
            
            result["status"] = status
            result["present"] = (status != "NotSigned")
            result["valid"] = (status == "Valid")
            
            if signer:
                # Extract CN from subject
                for part in str(signer).split(","):
                    if part.strip().upper().startswith("CN="):
                        result["publisher"] = part.strip()[3:]
                        break
    except Exception:
        pass
    
    return result


def _detect_obfuscators(data: bytes) -> List[str]:
    """Detect known obfuscators by signature."""
    detected = []
    data_lower = data.lower()
    
    for name, signatures in KNOWN_OBFUSCATORS.items():
        for sig in signatures:
            if sig.lower() in data_lower:
                detected.append(name)
                break
    
    return detected


def _analyze_sections_for_packing(sections: List[Dict[str, Any]], data: bytes) -> Dict[str, Any]:
    """Analyze sections for signs of packing/protection."""
    result = {
        "suspicious_sections": [],
        "high_entropy_sections": [],
        "rwx_sections": [],
        "overall_suspicious": False,
        "max_entropy": 0.0,
    }
    
    for sec in sections:
        name_lower = sec["name"].lower()
        
        # Check for suspicious section names
        if name_lower in SUSPICIOUS_SECTION_NAMES:
            result["suspicious_sections"].append(sec["name"])
        
        # Check section characteristics for RWX
        # IMAGE_SCN_MEM_EXECUTE = 0x20000000
        # IMAGE_SCN_MEM_READ = 0x40000000
        # IMAGE_SCN_MEM_WRITE = 0x80000000
        chars = sec["characteristics"]
        if (chars & 0x20000000) and (chars & 0x40000000) and (chars & 0x80000000):
            result["rwx_sections"].append(sec["name"])
        
        # Calculate section entropy
        if sec["raw_size"] > 0 and sec["raw_offset"] + sec["raw_size"] <= len(data):
            section_data = data[sec["raw_offset"]:sec["raw_offset"] + min(sec["raw_size"], 1024*1024)]
            entropy = _calc_entropy(section_data)
            result["max_entropy"] = max(result["max_entropy"], entropy)
            
            if entropy >= HIGH_ENTROPY_THRESHOLD:
                result["high_entropy_sections"].append({
                    "name": sec["name"],
                    "entropy": entropy,
                })
    
    result["overall_suspicious"] = bool(
        result["suspicious_sections"] or 
        result["rwx_sections"] or 
        len(result["high_entropy_sections"]) > 1
    )
    
    return result


def analyze_dotnet(path: Path, max_bytes: int = 20*1024*1024) -> Dict[str, Any]:
    """
    Comprehensive .NET assembly analysis.
    
    Returns:
        Dict with keys:
        - is_dotnet: bool - True if file is a .NET assembly
        - strong_name: dict - Strong Name signature info
        - authenticode: dict - Code signing info
        - anti_tamper: dict - Packer/obfuscator detection
        - p_invoke: list - Native DLLs called via P/Invoke
        - mixed_mode: bool - Contains native code alongside managed
        - obfuscators: list - Detected obfuscator names
        - metadata_version: str - CLR version string
        - errors: list
    """
    info: Dict[str, Any] = {
        "is_dotnet": False,
        "strong_name": {
            "present": False,
            "signed": False,
            "delay_signed": False,
            "public_key_token": None,
        },
        "authenticode": {
            "present": None,
            "valid": None,
            "publisher": None,
            "status": None,
        },
        "anti_tamper": {
            "suspected": False,
            "packer_detected": False,
            "obfuscator_detected": False,
            "high_entropy": False,
            "suspicious_sections": [],
            "max_entropy": 0.0,
        },
        "p_invoke": [],
        "mixed_mode": False,
        "obfuscators": [],
        "metadata_version": None,
        "flags": None,
        "errors": [],
    }
    
    p = Path(path)
    try:
        data = p.read_bytes()[:max_bytes]
    except Exception as e:
        info["errors"].append(f"read_error:{e}")
        return info
    
    # Quick .NET detection
    is_managed = (b"BSJB" in data or b"mscoree.dll" in data or b"CorExeMain" in data)
    if not is_managed:
        return info
    
    info["is_dotnet"] = True
    
    # Parse PE structure
    pe_offset = _find_pe_offset(data)
    if pe_offset is None:
        info["errors"].append("invalid_pe_header")
        return info
    
    sections = _parse_pe_sections(data, pe_offset)
    clr_info = _find_clr_header(data, pe_offset)
    
    if clr_info is None:
        info["errors"].append("clr_header_not_found")
        return info
    
    # Strong Name analysis
    try:
        sn_result = _check_strong_name(data, clr_info, sections)
        info["strong_name"] = sn_result
    except Exception as e:
        info["errors"].append(f"strong_name_error:{e}")
    
    # Authenticode analysis
    try:
        auth_result = _check_authenticode_powershell(p)
        info["authenticode"] = auth_result
    except Exception as e:
        info["errors"].append(f"authenticode_error:{e}")
    
    # Obfuscator detection
    try:
        info["obfuscators"] = _detect_obfuscators(data)
        info["anti_tamper"]["obfuscator_detected"] = bool(info["obfuscators"])
    except Exception as e:
        info["errors"].append(f"obfuscator_detection_error:{e}")
    
    # Section analysis for packing
    try:
        section_analysis = _analyze_sections_for_packing(sections, data)
        info["anti_tamper"]["suspicious_sections"] = section_analysis["suspicious_sections"]
        info["anti_tamper"]["high_entropy"] = len(section_analysis["high_entropy_sections"]) > 0
        info["anti_tamper"]["max_entropy"] = section_analysis["max_entropy"]
        info["anti_tamper"]["packer_detected"] = section_analysis["overall_suspicious"]
        info["anti_tamper"]["suspected"] = (
            section_analysis["overall_suspicious"] or 
            info["anti_tamper"]["obfuscator_detected"]
        )
    except Exception as e:
        info["errors"].append(f"section_analysis_error:{e}")
    
    # P/Invoke detection
    try:
        pinvoke_dlls = []
        native_markers = [
            b"kernel32.dll", b"user32.dll", b"advapi32.dll", b"ntdll.dll",
            b"gdi32.dll", b"shell32.dll", b"ole32.dll", b"oleaut32.dll",
            b"ws2_32.dll", b"wininet.dll", b"crypt32.dll", b"netapi32.dll",
        ]
        for dll in native_markers:
            if dll.lower() in data.lower():
                pinvoke_dlls.append(dll.decode())
        info["p_invoke"] = pinvoke_dlls
        
        # Mixed-mode detection: both managed and significant native imports
        info["mixed_mode"] = len(pinvoke_dlls) >= 3
    except Exception as e:
        info["errors"].append(f"pinvoke_error:{e}")
    
    # Extract metadata version (runtime version)
    try:
        # Look for version string after BSJB signature
        bsjb_pos = data.find(b"BSJB")
        if bsjb_pos != -1 and bsjb_pos + 16 < len(data):
            # Metadata header: BSJB + major + minor + reserved + length + version_string
            # Skip to version string (12 bytes after BSJB)
            version_len = struct.unpack_from("<I", data, bsjb_pos + 12)[0]
            if version_len > 0 and version_len < 256:
                version_str = data[bsjb_pos + 16:bsjb_pos + 16 + version_len]
                info["metadata_version"] = version_str.rstrip(b'\x00').decode('utf-8', errors='replace')
    except Exception:
        pass
    
    return info


# Backwards compatibility alias
def analyze(path: Path, max_bytes: int = 10*1024*1024) -> dict:
    """Legacy function for backwards compatibility."""
    result = analyze_dotnet(path, max_bytes)
    
    # Convert to old format
    return {
        "managed_hint": result["is_dotnet"],
        "p_invoke": result["p_invoke"],
        "suspicious": result["anti_tamper"]["suspected"],
        "score": 5 * len(result["p_invoke"]) + (10 if result["anti_tamper"]["suspected"] else 0),
        # New fields
        "strong_name": result["strong_name"],
        "authenticode": result["authenticode"],
        "anti_tamper": result["anti_tamper"],
        "obfuscators": result["obfuscators"],
    }
