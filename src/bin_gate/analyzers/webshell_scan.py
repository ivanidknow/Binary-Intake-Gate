from __future__ import annotations
from pathlib import Path
import re

PHP = [re.compile(rb"<\?php", re.I),
       re.compile(rb"(eval|assert|system|passthru|shell_exec|popen)\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*", re.I),
       re.compile(rb"base64_decode\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*", re.I)]
ASP = [re.compile(rb"Execute\(", re.I),
       re.compile(rb"Server\.CreateObject\(['\"]Scripting\.FileSystemObject['\"]\)", re.I)]
JSP = [re.compile(rb"<%@", re.I), re.compile(rb"Runtime\.getRuntime\(\)\.exec\(", re.I)]

def analyze(path: Path, max_bytes: int = 2*1024*1024) -> dict:
    p = Path(path); sfx = p.suffix.lower()
    try:
        data = p.read_bytes()[:max_bytes]
    except Exception as e:
        return {"error": str(e)}
    res = {"type": sfx, "suspicious": False, "score": 0, "matches": []}
    pats = PHP if sfx==".php" else ASP if sfx in (".asp",".aspx") else JSP if sfx==".jsp" else []
    for rx in pats:
        if rx.search(data): res["matches"].append(rx.pattern.decode(errors="ignore")[:60])
    res["suspicious"] = bool(res["matches"]); res["score"] = 8 if res["suspicious"] else 0
    return res
