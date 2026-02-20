"""
Source Script Analysis Module (v0.0.8)

Features:
- Multi-language script analysis (Python, PowerShell, Bash, Batch, VBS, JS)
- Deep pattern matching for malicious constructs
- Obfuscation detection
- Stager/downloader detection
- IOC extraction (URLs, IPs, domains, emails)

Usage:
    result = analyze(path)
    deep_result = analyze_deep(path)
"""
from __future__ import annotations
from pathlib import Path
import re
import base64
import math
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import Counter


# IOC extraction patterns
URL_RE = re.compile(r'(?i)\bhttps?://[^\s\'"<>]+')
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
DOM_RE = re.compile(r'(?i)\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b')
EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
B64_RE = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
HEX_RE = re.compile(r'(?:0x)?[0-9A-Fa-f]{32,}')

# Common malicious pattern tokens
TOKENS = {
    # Code execution
    "eval": re.compile(r'(?i)\beval\s*\('),
    "exec": re.compile(r'(?i)\b(exec|os\.system|subprocess\.(?:Popen|call|run)|system|popen)\b'),
    "exec_shell": re.compile(r'(?i)\b(shell_exec|passthru|proc_open)\b'),
    
    # Encoding/obfuscation
    "b64": re.compile(r'(?i)(base64\.b64decode|FromBase64String|atob\s*\(|\-enc(?:odedcommand)?|[System\.Convert]::FromBase64)'),
    "chr_concat": re.compile(r'(?i)(Chr\s*\(\s*\d+\s*\)|String\.fromCharCode|\\x[0-9a-f]{2})'),
    "string_reverse": re.compile(r'(?i)(\.reverse\(\)|strrev|ReverseString|-join\s*\[\s*char\s*\])'),
    
    # File operations
    "writerun": re.compile(r'(?i)(chmod\s+\+x|WriteAllBytes|WriteAllText|mktemp|>[/\\\w\.\-]+;?\s*(?:chmod|sh|bash|\.\/))'),
    "file_write": re.compile(r'(?i)(open\s*\([^)]*[\'"]w[\'"]|fwrite|file_put_contents|Out-File|Set-Content)'),
    
    # Network operations
    "net_dl": re.compile(r'(?i)(curl|wget|Invoke\-WebRequest|Invoke\-RestMethod|Net\.WebClient|requests\.(?:get|post)|urllib|httplib|fetch\s*\()'),
    "net_socket": re.compile(r'(?i)(socket\s*\(|fsockopen|stream_socket_client|TcpClient|UdpClient)'),
    
    # Command execution
    "cmd_run": re.compile(r'(?i)\b(start\s+|cmd\s*/c|powershell\s+(?:-enc|-nop|-w\s+hidden))'),
    "shell_spawn": re.compile(r'(?i)(\/bin\/(?:ba)?sh|cmd\.exe|command\.com|wscript\.exe|cscript\.exe)'),
    
    # Shell pipe
    "pipe_sh": re.compile(r'(?i)\|\s*(sh|bash|sudo|python[23]?)\b'),
    
    # Registry/persistence
    "registry": re.compile(r'(?i)(HKLM|HKCU|HKEY_|reg\s+add|New-ItemProperty|Set-ItemProperty)'),
    "startup": re.compile(r'(?i)(Startup|Run|RunOnce|CurrentVersion\\\\Run|crontab|systemctl\s+enable)'),
    
    # Credential theft
    "creds": re.compile(r'(?i)(mimikatz|sekurlsa|lsass|SAM|hashdump|Get-Credential|ConvertTo-SecureString)'),
    
    # Anti-analysis
    "anti_debug": re.compile(r'(?i)(IsDebuggerPresent|CheckRemoteDebuggerPresent|ptrace|anti_debug|VM_DETECT)'),
    "anti_vm": re.compile(r'(?i)(vmware|virtualbox|vbox|qemu|hyperv|sandbox)'),
    
    # PowerShell specific
    "ps_download": re.compile(r'(?i)(DownloadString|DownloadFile|DownloadData|WebRequest)'),
    "ps_bypass": re.compile(r'(?i)(-ExecutionPolicy\s+Bypass|Set-ExecutionPolicy|Unrestricted)'),
    "ps_reflection": re.compile(r'(?i)(\.GetMethod|\.Invoke|Add-Type|Reflection\.Assembly)'),
    
    # Python specific
    "py_import": re.compile(r'(?i)(__import__|importlib|exec\s*\(\s*compile)'),
    "py_marshal": re.compile(r'(?i)(marshal\.loads|pickle\.loads|dill\.loads)'),
    
    # JavaScript/Node specific
    "js_require": re.compile(r'(?i)(require\s*\(\s*[\'"]child_process|vm\.runInNewContext|vm\.createContext)'),
}

# Suspicious string patterns for scoring
SUSPICIOUS_STRINGS = [
    (r'password', 1),
    (r'credential', 1),
    (r'secret', 1),
    (r'api[_-]?key', 2),
    (r'authorization', 1),
    (r'bearer\s+[a-zA-Z0-9_-]+', 3),
    (r'AWS[A-Z0-9]{16,}', 4),
    (r'[0-9a-f]{32}', 2),  # MD5-like
    (r'\\x[0-9a-f]{2}{4,}', 2),  # Hex escape sequences
    (r'shellcode', 5),
    (r'payload', 2),
    (r'exploit', 3),
    (r'backdoor', 5),
    (r'keylogger', 5),
    (r'ransomware', 5),
]


def _read_text(fp: Path) -> str:
    """Read file with multiple encoding fallbacks."""
    data = fp.read_bytes()
    for enc in ("utf-8", "utf-8-sig", "utf-16", "cp1251", "latin-1"):
        try:
            return data.decode(enc, errors="strict")
        except Exception:
            continue
    return data.decode("latin-1", errors="ignore")


def _calc_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _detect_obfuscation(content: str) -> Dict[str, Any]:
    """
    Detect various obfuscation techniques.
    """
    result = {
        "score": 0,
        "techniques": [],
        "entropy": 0.0,
    }
    
    # Calculate string entropy
    result["entropy"] = _calc_entropy(content)
    if result["entropy"] > 5.5:
        result["score"] += 2
        result["techniques"].append("high_entropy")
    
    # Check for excessive character encoding
    chr_count = len(re.findall(r'(?i)Chr\s*\(\s*\d+\s*\)', content))
    if chr_count > 10:
        result["score"] += min(chr_count // 5, 5)
        result["techniques"].append(f"chr_encoding:{chr_count}")
    
    # Check for Base64 blocks
    b64_matches = B64_RE.findall(content)
    if b64_matches:
        result["score"] += min(len(b64_matches), 3)
        result["techniques"].append(f"base64_blocks:{len(b64_matches)}")
        
        # Try to decode and check if it's code
        for b64 in b64_matches[:3]:
            try:
                decoded = base64.b64decode(b64)
                if b'powershell' in decoded.lower() or b'cmd' in decoded.lower():
                    result["score"] += 3
                    result["techniques"].append("encoded_command")
            except Exception:
                pass
    
    # Check for hex strings
    hex_matches = HEX_RE.findall(content)
    if hex_matches:
        result["score"] += min(len(hex_matches), 3)
        result["techniques"].append(f"hex_strings:{len(hex_matches)}")
    
    # Check for string concatenation abuse
    concat_count = content.count('+ "') + content.count("+ '") + content.count('& "')
    if concat_count > 20:
        result["score"] += min(concat_count // 10, 5)
        result["techniques"].append(f"string_concat:{concat_count}")
    
    # Check for variable name obfuscation (very short names)
    short_vars = re.findall(r'\$[a-z]{1,2}\b|\b[a-z]{1,2}\s*=', content, re.IGNORECASE)
    if len(short_vars) > 30:
        result["score"] += 2
        result["techniques"].append("short_variable_names")
    
    # Check for character array joins
    if re.search(r'-join\s*\[', content, re.IGNORECASE):
        result["score"] += 2
        result["techniques"].append("char_array_join")
    
    # Check for reflection/dynamic invocation
    if re.search(r'\.Invoke\(|Invoke-Expression|IEX\s', content, re.IGNORECASE):
        result["score"] += 3
        result["techniques"].append("dynamic_invocation")
    
    result["score"] = min(result["score"], 20)
    return result


def _extract_decoded_payloads(content: str) -> List[Dict[str, Any]]:
    """
    Try to extract and decode obfuscated payloads.
    """
    payloads = []
    
    # Find Base64 encoded content
    for b64_match in B64_RE.finditer(content):
        b64_str = b64_match.group()
        try:
            decoded = base64.b64decode(b64_str)
            
            # Try UTF-16 (PowerShell encoded commands)
            try:
                text = decoded.decode('utf-16-le', errors='strict')
                if len(text) > 10 and text.isprintable():
                    payloads.append({
                        "type": "base64_utf16",
                        "decoded": text[:500],
                        "position": b64_match.start(),
                    })
                    continue
            except Exception:
                pass
            
            # Try UTF-8
            try:
                text = decoded.decode('utf-8', errors='strict')
                if len(text) > 10 and any(c.isalpha() for c in text):
                    payloads.append({
                        "type": "base64_utf8",
                        "decoded": text[:500],
                        "position": b64_match.start(),
                    })
            except Exception:
                pass
                
        except Exception:
            pass
    
    return payloads[:10]  # Limit results


def analyze(fp: Path) -> Dict[str, Any]:
    """
    Basic analysis for source scripts.
    Backward compatible with original function.
    """
    txt = _read_text(Path(fp))
    # Remove simple comments
    no_comments = re.sub(r'(?m)^[ \t]*([#;].*)$', '', txt)
    s = no_comments

    externals = {}
    flags = {}
    for k, rx in TOKENS.items():
        cnt = len(rx.findall(s))
        externals[k + "_cnt"] = cnt
        if k in ("eval", "b64", "net_dl", "exec", "creds") and cnt > 0:
            flags[k] = True

    urls = list(dict.fromkeys(URL_RE.findall(s)))
    ips = [x for x in IP_RE.findall(s) if not x.startswith(("127.", "0.0.0.0", "255.", "10.", "192.168.", "172."))]
    doms = []
    for d in DOM_RE.findall(s):
        dl = d.lower()
        if dl not in ("localhost", "localdomain", "example.com"):
            doms.append(dl)
    doms = list(dict.fromkeys(doms))

    return {
        "meta": {"lines": len(s.splitlines()), "size": len(txt)},
        "externals": externals,
        "flags": flags,
        "iocs": {"urls": urls[:50], "ips": ips[:50], "domains": doms[:50]},
    }


def analyze_deep(
    fp: Path,
    extract_payloads: bool = True,
) -> Dict[str, Any]:
    """
    Deep analysis with obfuscation detection and payload extraction.
    
    Args:
        fp: Path to the script file
        extract_payloads: Whether to extract and decode payloads
        
    Returns:
        Dict with comprehensive analysis results
    """
    result = {
        "basic": {},
        "obfuscation": {},
        "decoded_payloads": [],
        "suspicious_strings": [],
        "risk_score": 0,
        "risk_level": "low",
        "errors": [],
    }
    
    try:
        txt = _read_text(Path(fp))
    except Exception as e:
        result["errors"].append(f"read_error:{e}")
        return result
    
    # Run basic analysis
    result["basic"] = analyze(fp)
    
    # Detect obfuscation
    result["obfuscation"] = _detect_obfuscation(txt)
    
    # Extract payloads
    if extract_payloads:
        result["decoded_payloads"] = _extract_decoded_payloads(txt)
    
    # Check for suspicious strings
    txt_lower = txt.lower()
    for pattern, score in SUSPICIOUS_STRINGS:
        matches = re.findall(pattern, txt_lower, re.IGNORECASE)
        if matches:
            result["suspicious_strings"].append({
                "pattern": pattern,
                "count": len(matches),
                "score": score,
            })
            result["risk_score"] += score * min(len(matches), 3)
    
    # Calculate total risk score
    basic = result["basic"]
    externals = basic.get("externals", {})
    
    # Add score from pattern matches
    high_risk_patterns = ["exec_cnt", "creds_cnt", "anti_debug_cnt", "ps_reflection_cnt"]
    medium_risk_patterns = ["eval_cnt", "b64_cnt", "net_dl_cnt", "cmd_run_cnt"]
    
    for p in high_risk_patterns:
        if externals.get(p, 0) > 0:
            result["risk_score"] += externals[p] * 3
    
    for p in medium_risk_patterns:
        if externals.get(p, 0) > 0:
            result["risk_score"] += externals[p] * 2
    
    # Add obfuscation score
    result["risk_score"] += result["obfuscation"].get("score", 0)
    
    # Add payload score
    result["risk_score"] += len(result["decoded_payloads"]) * 3
    
    # Cap and determine level
    result["risk_score"] = min(result["risk_score"], 100)
    
    if result["risk_score"] >= 30:
        result["risk_level"] = "critical"
    elif result["risk_score"] >= 20:
        result["risk_level"] = "high"
    elif result["risk_score"] >= 10:
        result["risk_level"] = "medium"
    else:
        result["risk_level"] = "low"
    
    return result
