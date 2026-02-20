from __future__ import annotations
from pathlib import Path
import re

REGEXES = {
    "aws_access_key_id": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "aws_secret_access_key": re.compile(rb"(?i)aws_secret_access_key\s*[:=]\s*([A-Za-z0-9/+=]{32,})"),
    "github_token": re.compile(rb"ghp_[A-Za-z0-9]{36}"),
    "slack_token": re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,48}"),
    "discord_webhook": re.compile(rb"https?://(?:canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{6,}/[A-Za-z0-9_\-]{20,}"),
    "telegram_token": re.compile(rb"https?://api\.telegram\.org/bot[0-9]{8,10}:[A-Za-z0-9_\-]{35,}"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"),
}

def analyze(path: Path, max_bytes: int = 5*1024*1024) -> dict:
    p = Path(path); out = {"hits": {}, "suspicious": False, "score": 0}
    try:
        data = p.read_bytes()[:max_bytes]
    except Exception as e:
        return {"error": str(e)}
    for name, rx in REGEXES.items():
        hits = [m.group(0).decode(errors="ignore")[:120] for m in rx.finditer(data)]
        if hits: out["hits"][name] = hits[:5]
    out["suspicious"] = bool(out["hits"])
    out["score"] = 5 * len(out["hits"])
    return out
