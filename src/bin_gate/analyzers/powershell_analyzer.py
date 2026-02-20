from __future__ import annotations
from pathlib import Path
import re
from typing import Dict, Any

URL_RE = re.compile(r'(?i)\bhttps?://[^\s\'"]+')
IP_RE  = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOM_RE = re.compile(r'(?i)\b([a-z0-9-]+\.)+[a-z]{2,}\b')

TOKENS = {
    "iex": re.compile(r'(?i)\b(?:iex|invoke-expression)\b'),
    "iwr": re.compile(r'(?i)\b(?:iwr|invoke-webrequest)\b'),
    "irm": re.compile(r'(?i)\b(?:irm|invoke-restmethod)\b'),
    "webclient": re.compile(r'(?i)new-object\s+system\.net\.webclient'),
    "add_type": re.compile(r'(?i)\badd-type\b|\[ref\]|\[type\]::gettype'),
    "encoded_cmd": re.compile(r'(?i)(?:-enc|-encodedcommand)\s+[a-z0-9/+=]{8,}'),
    "from_base64": re.compile(r'(?i)frombase64string\('),
    "gzipstream": re.compile(r'(?i)system\.io\.compression\.gzipstream'),
    "amsi_bypass": re.compile(r'(?is)(amsiutils?\.amsiscanbuffer|amsiinitfailed|amsienable)\s*=\s*(?:\$true|1)|(?:(?:amsi|anti\-malware)\s*bypass)'),
    "etw_bypass": re.compile(r'(?i)(etw|etwprovider|eventtrace)'),
    "downloadstring": re.compile(r'(?i)downloadstring\('),
    "start_process": re.compile(r'(?i)\bstart\-process\b'),
    "invoke_item": re.compile(r'(?i)\binvoke\-item\b'),
    "dllimport": re.compile(r'(?i)\[dllimport\(|Add\-Type\s+-MemberDefinition'),
    "reflections": re.compile(r'(?i)system\.reflection'),
    "xor_op": re.compile(r'(?i)(bxor\b|\^[\w\'"])'),
    "replace_chain": re.compile(r'(?i)(?:-replace\s+["\'][^"\']+["\']\s*){3,}'),
    "concat_chain": re.compile(r'["\'][^"\']*["\']\s*\+\s*["\'][^"\']*["\']'),
}

def _read_text(fp: Path) -> str:
    data = fp.read_bytes()
    for enc in ("utf-8", "cp1251", "latin-1"):
        try:
            return data.decode(enc, errors="ignore")
        except Exception:
            continue
    return data.decode("latin-1", errors="ignore")

def analyze(fp: Path) -> Dict[str, Any]:
    txt = _read_text(Path(fp))
    no_comments = re.sub(r'(?m)^[ \t]*#.*$', '', txt)

    externals, flags = {}, {}
    for k, rx in TOKENS.items():
        cnt = len(rx.findall(no_comments))
        externals[f"{k}_cnt"] = cnt
        if k in ("amsi_bypass", "encoded_cmd") and cnt > 0:
            flags[k] = True

    urls = list(dict.fromkeys(URL_RE.findall(no_comments)))
    ips  = [x for x in IP_RE.findall(no_comments) if not x.startswith(("127.","0.0.0.0"))]
    doms = []
    for d in DOM_RE.findall(no_comments):
        if d.lower() not in ("localhost","localdomain"):
            doms.append(d.lower())
    doms = list(dict.fromkeys(doms))

    return {
        "meta": {"lines": len(no_comments.splitlines()), "size": len(txt)},
        "externals": externals,
        "flags": flags,
        "iocs": {"urls": urls, "ips": ips, "domains": doms},
    }
