"""
Deep Script & Office Analysis Module (v0.0.8)

Features:
- oletools (olevba) integration for VBA macro deobfuscation
- Robust LNK parser with Base64/Hex payload extraction
- Stager detection (powershell -enc, certutil, etc.)
- PDF JavaScript analysis
- Office macro analysis

Usage:
    result = analyze(path)
    deep_result = analyze_deep(path, enable_deobfuscation=True)
"""
from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import re
import struct
import base64
import binascii
import os


# Signature patterns for detection
PS_SIGNATURES = (
    b"-enc ", b"-encodedcommand", b"FromBase64String", b"IEX ", b"Invoke-Expression",
    b"Add-MpPreference", b"Bypass", b"downloadstring", b"webclient",
    b"Net.WebClient", b"DownloadFile", b"Start-Process", b"hidden",
    b"-nop", b"-noni", b"-w hidden", b"bitstransfer",
)
PDF_SIGNATURES = (
    b"/JavaScript", b"/OpenAction", b"/AA", b"/Launch", b"/SubmitForm",
    b"/EmbeddedFile", b"/ObjStm", b"/XFA", b"/AcroForm", b"/RichMedia",
    b"/GoTo", b"/GoToR", b"/GoToE", b"/URI",
)
OFFICE_SIGNATURES = (
    b"DDEAUTO", b"Excel 4.0 Macros", b"Auto_Open", b"AutoOpen", b"Document_Open",
    b"vbaProject.bin", b"msoffcrypto", b"Workbook_Open", b"AutoExec",
    b"Shell(", b"CreateObject", b"WScript.Shell", b"PowerShell",
    b"cmd /c", b"cmd.exe", b"regsvr32", b"mshta",
)
JS_SIGNATURES = (
    b"ActiveXObject", b"WScript.Shell", b"new XMLHttpRequest", b"eval(",
    b"document.write", b"unescape(", b"String.fromCharCode", b"setTimeout",
    b"setInterval", b".Run(", b".Exec(",
)
VBS_SIGNATURES = (
    b"CreateObject(\"Wscript.Shell\")", b"Execute(", b"GetObject(",
    b"Shell.Application", b"WScript.Run", b"Shell(", b"ExecuteGlobal",
    b"ScriptControl", b"Scripting.FileSystemObject",
)

# Stager patterns for command line payloads
STAGER_PATTERNS = [
    # PowerShell encoded commands
    (r'powershell[^\n]*-e(?:nc(?:odedcommand)?)?[\s]+([A-Za-z0-9+/=]{20,})', 'powershell_encoded'),
    # PowerShell download cradles
    (r'powershell[^\n]*(?:downloadstring|downloadfile|webclient|iwr|invoke-webrequest)[^\n]*https?://[^\s"\']+', 'powershell_download'),
    # Certutil download
    (r'certutil[^\n]*-urlcache[^\n]*https?://[^\s"\']+', 'certutil_download'),
    (r'certutil[^\n]*-decode[^\n]+', 'certutil_decode'),
    # Bitsadmin
    (r'bitsadmin[^\n]*/transfer[^\n]*https?://[^\s"\']+', 'bitsadmin_transfer'),
    # Mshta
    (r'mshta[^\n]*(?:vbscript:|javascript:|https?://)[^\s"\']+', 'mshta_execution'),
    # Rundll32
    (r'rundll32[^\n]*(?:javascript:|shell32|url\.dll)', 'rundll32_execution'),
    # Regsvr32
    (r'regsvr32[^\n]*/(?:s|u|i)[^\n]*(?:scrobj|https?://)', 'regsvr32_execution'),
    # WMIC
    (r'wmic[^\n]*(?:process\s+call|os\s+get)[^\n]+', 'wmic_execution'),
    # Cscript/Wscript
    (r'(?:cscript|wscript)[^\n]*(?:\.vbs|\.js|//e:)[^\n]+', 'script_execution'),
]


# ----- LNK Parser -----

def _parse_lnk_file(data: bytes) -> Dict[str, Any]:
    """
    Parse Windows LNK (shortcut) file structure.
    
    LNK format:
    - Header (76 bytes)
    - Shell Link Header
    - Link Target ID List (optional)
    - Link Info (optional)
    - String Data (optional)
    - Extra Data (optional)
    """
    result = {
        "valid": False,
        "target_path": None,
        "arguments": None,
        "working_dir": None,
        "icon_location": None,
        "description": None,
        "command_line": None,
        "payloads": [],
        "decoded_payloads": [],
        "suspicious_patterns": [],
    }
    
    # Check magic
    if len(data) < 76:
        return result
    
    # LNK magic: 4C 00 00 00
    if data[:4] != b'\x4c\x00\x00\x00':
        return result
    
    result["valid"] = True
    
    try:
        # Parse header flags
        flags = struct.unpack_from('<I', data, 20)[0]
        has_target_id_list = bool(flags & 0x01)
        has_link_info = bool(flags & 0x02)
        has_name = bool(flags & 0x04)
        has_relative_path = bool(flags & 0x08)
        has_working_dir = bool(flags & 0x10)
        has_arguments = bool(flags & 0x20)
        has_icon_location = bool(flags & 0x40)
        
        offset = 76  # After header
        
        # Skip Link Target ID List
        if has_target_id_list:
            if offset + 2 <= len(data):
                id_list_size = struct.unpack_from('<H', data, offset)[0]
                offset += 2 + id_list_size
        
        # Skip Link Info
        if has_link_info:
            if offset + 4 <= len(data):
                link_info_size = struct.unpack_from('<I', data, offset)[0]
                offset += link_info_size
        
        # Parse String Data
        def read_string(data: bytes, offset: int) -> Tuple[str, int]:
            if offset + 2 > len(data):
                return "", offset
            strlen = struct.unpack_from('<H', data, offset)[0]
            offset += 2
            # Unicode string (2 bytes per char)
            if offset + strlen * 2 <= len(data):
                try:
                    s = data[offset:offset + strlen * 2].decode('utf-16-le', errors='replace')
                    return s, offset + strlen * 2
                except Exception:
                    pass
            return "", offset + strlen * 2
        
        if has_name:
            result["description"], offset = read_string(data, offset)
        if has_relative_path:
            result["target_path"], offset = read_string(data, offset)
        if has_working_dir:
            result["working_dir"], offset = read_string(data, offset)
        if has_arguments:
            result["arguments"], offset = read_string(data, offset)
        if has_icon_location:
            result["icon_location"], offset = read_string(data, offset)
        
        # Build command line
        parts = []
        if result["target_path"]:
            parts.append(result["target_path"])
        if result["arguments"]:
            parts.append(result["arguments"])
        result["command_line"] = " ".join(parts)
        
    except Exception:
        pass
    
    # Extract payloads from command line
    if result["command_line"]:
        cmd = result["command_line"]
        
        # Look for Base64 encoded payloads
        b64_pattern = re.compile(r'([A-Za-z0-9+/]{40,}={0,2})')
        for match in b64_pattern.finditer(cmd):
            b64_str = match.group(1)
            try:
                decoded = base64.b64decode(b64_str)
                # Check if it's valid text or binary
                if decoded:
                    result["payloads"].append({
                        "type": "base64",
                        "encoded": b64_str[:100] + "..." if len(b64_str) > 100 else b64_str,
                        "length": len(b64_str),
                    })
                    # Try to decode as UTF-16 (PowerShell)
                    try:
                        decoded_text = decoded.decode('utf-16-le', errors='replace')
                        if decoded_text and len(decoded_text) > 10:
                            result["decoded_payloads"].append({
                                "type": "base64_utf16",
                                "content": decoded_text[:500],
                            })
                    except Exception:
                        pass
            except Exception:
                pass
        
        # Look for Hex encoded payloads
        hex_pattern = re.compile(r'(?:0x)?([0-9A-Fa-f]{40,})')
        for match in hex_pattern.finditer(cmd):
            hex_str = match.group(1)
            try:
                decoded = binascii.unhexlify(hex_str)
                if decoded:
                    result["payloads"].append({
                        "type": "hex",
                        "encoded": hex_str[:100] + "..." if len(hex_str) > 100 else hex_str,
                        "length": len(hex_str),
                    })
            except Exception:
                pass
        
        # Detect stager patterns
        cmd_lower = cmd.lower()
        for pattern, stager_type in STAGER_PATTERNS:
            if re.search(pattern, cmd_lower, re.IGNORECASE):
                result["suspicious_patterns"].append(stager_type)
    
    return result


# ----- OLE/VBA Analysis -----

def _analyze_ole_vba(path: Path) -> Dict[str, Any]:
    """
    Analyze Office document for VBA macros using oletools.
    
    Requires: oletools (pip install oletools)
    """
    result = {
        "has_macros": False,
        "macro_count": 0,
        "auto_exec": False,
        "suspicious": False,
        "vba_code": [],
        "iocs": [],
        "obfuscation_score": 0,
        "deobfuscated": [],
        "analysis_type": [],
        "error": None,
    }
    
    try:
        from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML
    except ImportError:
        result["error"] = "oletools_not_installed"
        return result
    
    try:
        vba_parser = VBA_Parser(str(path))
        
        if vba_parser.detect_vba_macros():
            result["has_macros"] = True
            result["analysis_type"].append(vba_parser.type)
            
            # Extract macros
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                result["macro_count"] += 1
                
                # Store code snippet
                if vba_code:
                    result["vba_code"].append({
                        "filename": vba_filename,
                        "stream": stream_path,
                        "code_preview": vba_code[:2000] if len(vba_code) > 2000 else vba_code,
                        "code_length": len(vba_code),
                    })
                    
                    # Check for auto-execution
                    auto_triggers = [
                        "Auto_Open", "AutoOpen", "Document_Open", "DocumentOpen",
                        "Auto_Close", "AutoClose", "Workbook_Open", "AutoExec",
                        "Document_Close", "Workbook_Close",
                    ]
                    for trigger in auto_triggers:
                        if trigger.lower() in vba_code.lower():
                            result["auto_exec"] = True
                            break
            
            # Analyze for suspicious patterns
            try:
                analysis_results = vba_parser.analyze_macros()
                for kw_type, keyword, description in analysis_results:
                    if kw_type in ('Suspicious', 'IOC', 'AutoExec'):
                        result["suspicious"] = True
                        result["iocs"].append({
                            "type": kw_type,
                            "keyword": keyword,
                            "description": description[:200] if description else "",
                        })
                        
                        if kw_type == 'AutoExec':
                            result["auto_exec"] = True
            except Exception:
                pass
            
            # Calculate obfuscation indicators
            try:
                all_code = " ".join([m.get("code_preview", "") for m in result["vba_code"]])
                
                # Check for obfuscation patterns
                obf_score = 0
                
                # Chr() concatenation
                if all_code.count("Chr(") > 10:
                    obf_score += 2
                
                # String concatenation abuse
                if all_code.count("& \"") > 20 or all_code.count("+ \"") > 20:
                    obf_score += 2
                
                # Unusual variable names
                short_vars = re.findall(r'\b[a-z]{1,2}\d*\b', all_code, re.IGNORECASE)
                if len(short_vars) > 50:
                    obf_score += 1
                
                # Base64/Hex strings
                if re.search(r'[A-Za-z0-9+/]{50,}={0,2}', all_code):
                    obf_score += 2
                
                # Shell/Run calls
                shell_calls = len(re.findall(r'\b(?:Shell|Run|Exec|CreateObject)\s*\(', all_code, re.IGNORECASE))
                if shell_calls > 0:
                    obf_score += shell_calls
                
                result["obfuscation_score"] = min(obf_score, 10)
                
            except Exception:
                pass
        
        vba_parser.close()
        
    except Exception as e:
        result["error"] = f"vba_analysis_error:{str(e)[:100]}"
    
    return result


def _analyze_pdf_javascript(data: bytes) -> Dict[str, Any]:
    """
    Analyze PDF for embedded JavaScript.
    """
    result = {
        "has_javascript": False,
        "js_count": 0,
        "auto_actions": [],
        "suspicious_objects": [],
        "urls": [],
        "suspicious": False,
    }
    
    # Check for JavaScript streams
    js_count = data.count(b'/JavaScript')
    result["js_count"] = js_count
    result["has_javascript"] = js_count > 0
    
    # Check for auto-execution triggers
    triggers = {
        b'/OpenAction': 'open_action',
        b'/AA': 'additional_actions',
        b'/Launch': 'launch_action',
        b'/SubmitForm': 'submit_form',
        b'/ImportData': 'import_data',
        b'/GoTo': 'goto_action',
        b'/GoToR': 'goto_remote',
        b'/GoToE': 'goto_embedded',
    }
    
    for trigger, name in triggers.items():
        if trigger in data:
            result["auto_actions"].append(name)
    
    # Check for suspicious objects
    suspicious = {
        b'/EmbeddedFile': 'embedded_file',
        b'/ObjStm': 'object_stream',
        b'/XFA': 'xfa_form',
        b'/RichMedia': 'rich_media',
        b'/AcroForm': 'acro_form',
    }
    
    for obj, name in suspicious.items():
        if obj in data:
            result["suspicious_objects"].append(name)
    
    # Extract URLs
    url_pattern = re.compile(rb'https?://[^\s<>"\')\]]+')
    urls = url_pattern.findall(data)
    result["urls"] = [u.decode('utf-8', errors='replace')[:200] for u in urls[:20]]
    
    result["suspicious"] = bool(result["auto_actions"] or result["suspicious_objects"] or result["js_count"] > 2)
    
    return result


# ----- Main Analysis Functions -----

def analyze(path: Path, max_bytes: int = 5*1024*1024) -> dict:
    """
    Basic analysis for Office documents, PDFs, and scripts.
    Backward compatible with original function.
    """
    p = Path(path)
    sfx = p.suffix.lower()
    
    try:
        data = p.read_bytes()[:max_bytes]
    except Exception as e:
        return {"error": str(e)}
    
    res = {"type": None, "triggers": [], "suspicious": False, "score": 0}
    
    if sfx in (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".docm", ".xlsm", ".pptm"):
        res["type"] = "office"
        src = OFFICE_SIGNATURES
        mult = 5
    elif sfx == ".pdf":
        res["type"] = "pdf"
        src = PDF_SIGNATURES
        mult = 4
    elif sfx == ".ps1":
        res["type"] = "powershell"
        src = PS_SIGNATURES
        mult = 3
    elif sfx == ".js":
        res["type"] = "js"
        src = JS_SIGNATURES
        mult = 3
    elif sfx == ".vbs":
        res["type"] = "vbs"
        src = VBS_SIGNATURES
        mult = 3
    elif sfx == ".lnk":
        res["type"] = "lnk"
        src = tuple()
        mult = 6
    else:
        return res
    
    if res["type"] == "lnk":
        payload_hits = sum(
            1 for k in (b"cmd.exe /c", b"powershell", b"mshta", b"wscript.exe", b"cscript.exe", b"rundll32")
            if k in data.lower()
        )
        res["triggers"] = [f"payload_hits={payload_hits}"]
        res["suspicious"] = payload_hits > 0
        res["score"] = mult * payload_hits
    else:
        for t in src:
            if t.lower() in data.lower():
                try:
                    res["triggers"].append(t.decode())
                except Exception:
                    res["triggers"].append(str(t))
        res["suspicious"] = bool(res["triggers"])
        res["score"] = mult * len(res["triggers"])
    
    return res


def analyze_deep(
    path: Path,
    max_bytes: int = 10*1024*1024,
    enable_deobfuscation: bool = True,
) -> Dict[str, Any]:
    """
    Deep analysis with oletools, LNK parsing, and deobfuscation.
    
    Args:
        path: Path to the file
        max_bytes: Maximum bytes to read
        enable_deobfuscation: Enable VBA deobfuscation (requires oletools)
        
    Returns:
        Dict with comprehensive analysis results
    """
    p = Path(path)
    sfx = p.suffix.lower()
    
    result = {
        "type": None,
        "basic": {},
        "deep": {},
        "lnk": None,
        "vba": None,
        "pdf": None,
        "stagers": [],
        "iocs": [],
        "suspicious": False,
        "risk_score": 0,
        "errors": [],
    }
    
    try:
        data = p.read_bytes()[:max_bytes]
    except Exception as e:
        result["errors"].append(f"read_error:{e}")
        return result
    
    # Run basic analysis
    result["basic"] = analyze(path, max_bytes)
    result["type"] = result["basic"].get("type")
    
    # Deep analysis based on type
    try:
        if sfx == ".lnk":
            lnk_result = _parse_lnk_file(data)
            result["lnk"] = lnk_result
            result["stagers"] = lnk_result.get("suspicious_patterns", [])
            
            # Update suspicion
            if lnk_result.get("payloads") or lnk_result.get("suspicious_patterns"):
                result["suspicious"] = True
                result["risk_score"] += len(lnk_result.get("payloads", [])) * 3
                result["risk_score"] += len(lnk_result.get("suspicious_patterns", [])) * 5
        
        elif sfx in (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".docm", ".xlsm", ".pptm"):
            if enable_deobfuscation:
                vba_result = _analyze_ole_vba(path)
                result["vba"] = vba_result
                
                if vba_result.get("has_macros"):
                    result["suspicious"] = True
                    result["risk_score"] += 5
                    
                    if vba_result.get("auto_exec"):
                        result["risk_score"] += 5
                    
                    if vba_result.get("suspicious"):
                        result["risk_score"] += 10
                    
                    result["risk_score"] += vba_result.get("obfuscation_score", 0)
                    
                    # Collect IOCs
                    for ioc in vba_result.get("iocs", []):
                        result["iocs"].append({
                            "type": ioc.get("type"),
                            "value": ioc.get("keyword"),
                            "source": "vba_analysis",
                        })
        
        elif sfx == ".pdf":
            pdf_result = _analyze_pdf_javascript(data)
            result["pdf"] = pdf_result
            
            if pdf_result.get("has_javascript"):
                result["suspicious"] = True
                result["risk_score"] += pdf_result.get("js_count", 0) * 2
            
            if pdf_result.get("auto_actions"):
                result["risk_score"] += len(pdf_result["auto_actions"]) * 3
            
            if pdf_result.get("suspicious_objects"):
                result["risk_score"] += len(pdf_result["suspicious_objects"]) * 2
            
            # Add URLs as IOCs
            for url in pdf_result.get("urls", []):
                result["iocs"].append({
                    "type": "url",
                    "value": url,
                    "source": "pdf_analysis",
                })
        
        elif sfx in (".ps1", ".vbs", ".js", ".bat", ".cmd"):
            # Analyze script content for stagers
            content = data.decode('utf-8', errors='replace').lower()
            
            for pattern, stager_type in STAGER_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    result["stagers"].append(stager_type)
                    result["risk_score"] += 5
            
            if result["stagers"]:
                result["suspicious"] = True
        
    except Exception as e:
        result["errors"].append(f"deep_analysis_error:{e}")
    
    # Cap risk score
    result["risk_score"] = min(result["risk_score"], 100)
    
    return result


def detect_stagers(command_line: str) -> List[Dict[str, Any]]:
    """
    Detect common stagers/downloaders in a command line string.
    
    Args:
        command_line: Command line to analyze
        
    Returns:
        List of detected stagers with details
    """
    stagers = []
    cmd_lower = command_line.lower()
    
    for pattern, stager_type in STAGER_PATTERNS:
        matches = re.finditer(pattern, cmd_lower, re.IGNORECASE)
        for match in matches:
            stagers.append({
                "type": stager_type,
                "matched_text": match.group(0)[:200],
                "position": match.start(),
            })
    
    return stagers
