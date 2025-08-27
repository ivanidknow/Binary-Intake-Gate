from __future__ import annotations
from typing import Dict, Any, Optional, Tuple
import json
import re
from pathlib import Path

# Базовый маппинг «имя либы → пакет» по экосистемам.
# Можно дополнять через --cve-libmap (JSON).
_DEFAULT_MAP = {
    "Debian": {
        r"^libssl\.so\.(?P<maj>\d+)$":        "libssl{maj}",
        r"^libcrypto\.so\.(?P<maj>\d+)$":     "libcrypto{maj}",
        r"^libz\.so\.\d+$":                   "zlib1g",
        r"^libcurl\.so\.\d+$":                "libcurl4",
        r"^libxml2\.so\.\d+$":                "libxml2",
    },
    "Ubuntu": {
        r"^libssl\.so\.(?P<maj>\d+)$":        "libssl{maj}",
        r"^libcrypto\.so\.(?P<maj>\d+)$":     "libcrypto{maj}",
        r"^libz\.so\.\d+$":                   "zlib1g",
        r"^libcurl\.so\.\d+$":                "libcurl4",
        r"^libxml2\.so\.\d+$":                "libxml2",
    },
    "Alpine": {
        r"^libssl\.so\.\d+$":                 "openssl",
        r"^libcrypto\.so\.\d+$":              "openssl",
        r"^libz\.so\.\d+$":                   "zlib",
        r"^libcurl\.so\.\d+$":                "curl",      # иногда curl-libs, но в OSV чаще «curl»
        r"^libxml2\.so\.\d+$":                "libxml2",
    },
    "RedHat": {
        r"^libssl\.so\.\d+$":                 "openssl-libs",
        r"^libcrypto\.so\.\d+$":              "openssl-libs",
        r"^libz\.so\.\d+$":                   "zlib",
        r"^libcurl\.so\.\d+$":                "libcurl",
        r"^libxml2\.so\.\d+$":                "libxml2",
    }
}

def load_user_map(path: Optional[Path]) -> Dict[str, Dict[str, str]]:
    if not path:
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}

def _apply_rules(libname: str, rules: Dict[str, str]) -> Optional[str]:
    for pat, tmpl in rules.items():
        m = re.match(pat, libname)
        if not m:
            continue
        if "{maj}" in tmpl:
            maj = m.groupdict().get("maj", "")
            return tmpl.format(maj=maj)
        return tmpl
    return None

def map_lib_to_package(libname: str, *, ecosystem: str, user_map: Optional[Dict[str, Dict[str, str]]] = None) -> Optional[str]:
    """
    Возвращает имя пакета экосистемы для данного SONAME/libname или None.
    """
    user_rules = (user_map or {}).get(ecosystem, {})
    if user_rules:
        got = _apply_rules(libname, user_rules)
        if got:
            return got
    base_rules = _DEFAULT_MAP.get(ecosystem, {})
    if base_rules:
        got = _apply_rules(libname, base_rules)
        if got:
            return got
    return None
