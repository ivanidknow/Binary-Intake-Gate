from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Set
import os, json, shutil, subprocess

# По умолчанию таймаут 60с, лимит размера выключен (0 = нет лимита)
DEFAULT_TIMEOUT_SEC = int(os.getenv("CAPA_TIMEOUT_SEC", "120"))
DEFAULT_MAX_MB      = int(os.getenv("CAPA_MAX_MB", "0"))

# Грубый маппинг названий правил в тактики ATT&CK (ярлыки для отчёта)
KEYWORDS_TO_TACTICS = {
    "persistence": "persistence",
    "credential": "credential-access",
    "creds": "credential-access",
    "injection": "defense-evasion",
    "evasion": "defense-evasion",
    "discovery": "discovery",
    "lateral": "lateral-movement",
    "c2": "command-and-control",
    "command and control": "command-and-control",
    "exfil": "exfiltration",
    "keylog": "collection",
}

def _which_capa() -> str | None:
    ex = os.getenv("CAPA_EXE")
    if ex and Path(ex).exists():
        return ex
    for cand in ("capa", "capa.exe"):
        w = shutil.which(cand)
        if w:
            return w
    return None

def _too_big(path: Path, max_mb: int) -> bool:
    if max_mb is None or max_mb <= 0:
        return False
    try:
        return (path.stat().st_size / (1024*1024)) > max_mb
    except Exception:
        return False

def _extract_tactics_from_rule(rule: dict) -> List[str]:
    tactics: Set[str] = set()
    meta = rule.get("meta", {})
    atk = meta.get("att&ck") or meta.get("attack") or []
    if isinstance(atk, list):
        for item in atk:
            if isinstance(item, dict):
                t = (item.get("tactic") or "").strip().lower()
                if t:
                    tactics.add(t.replace(" ", "-"))
    name = (meta.get("name") or rule.get("name") or "").lower()
    for k, v in KEYWORDS_TO_TACTICS.items():
        if k in name:
            tactics.add(v)
    return sorted(tactics)

def run_capa(path: Path, timeout_sec: int = DEFAULT_TIMEOUT_SEC, max_mb: int = DEFAULT_MAX_MB, rules_dir: str | None = None) -> Dict[str, Any]:
    """
    Возвращает:
      { "rule_hits":[...], "tactics":[...], "errors":[...] }
    """
    out: Dict[str, Any] = {"rule_hits": [], "tactics": [], "errors": []}

    if _too_big(path, max_mb):
        out["errors"].append(f"capa_skipped_large_file(size_mb>{max_mb})")
        return out

    exe = _which_capa()
    if not exe:
        out["errors"].append("capa_not_found")
        return out

    cmd = [exe, "-j", "--quiet"]
    # правила: из параметра, иначе из ENV
    rules_dir = rules_dir or os.getenv("CAPA_RULES_DIR")
    if rules_dir:
        rp = Path(rules_dir)
        if rp.exists():
            cmd += ["-r", str(rp)]
        else:
            out["errors"].append(f"capa_rules_missing:{rules_dir}")

    cmd.append(str(path))
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        out["errors"].append(f"capa_timeout({timeout_sec}s)")
        return out
    except Exception as e:
        out["errors"].append(f"capa_exec_error:{e}")
        return out

    # capa может вернуть rc=1 для "no matches" — это не ошибка
    if cp.returncode not in (0, 1) and not cp.stdout:
        out["errors"].append(f"capa_rc:{cp.returncode}:{(cp.stderr or '').strip()[:200]}")
        return out

    # парс JSON
    data = {}
    if cp.stdout:
        try:
            data = json.loads(cp.stdout)
        except Exception as e:
            out["errors"].append(f"capa_json_error:{e}")
            return out

    rules = []
    if isinstance(data.get("rules"), list):
        rules = data["rules"]
    elif isinstance(data.get("rules"), dict):
        rules = list(data["rules"].values())

    hits: List[str] = []
    tactics: Set[str] = set()
    for r in rules:
        meta = r.get("meta", {})
        name = meta.get("name") or r.get("name")
        if name:
            hits.append(str(name))
        for t in _extract_tactics_from_rule(r):
            tactics.add(t)

    out["rule_hits"] = sorted(hits)[:25]
    out["tactics"] = sorted(tactics)
    return out
