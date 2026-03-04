# supply_chain_guard.py — Open Source cross-check: hash matching, typosquatting (v3.2)
"""
Hash Matching: сравнение хэша файла/библиотеки с известными релизами OSS (локальная БД).
Typosquatting: проверка имён импортируемых библиотек на подмену (requests vs requesst).
"""
from __future__ import annotations
import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple

# Популярные библиотеки для проверки на опечатку (имя -> норма)
KNOWN_OSS_NAMES: Set[str] = {
    "kernel32", "ntdll", "user32", "advapi32", "ws2_32", "msvcrt",
    "zlib", "zlib1", "libssl", "libcrypto", "libcurl", "libpng", "libjpeg",
    "requests", "urllib3", "numpy", "pandas", "pyarrow", "cryptography",
    "sqlite3", "lua51", "liblua", "vcruntime", "msvcp", "api-ms-win",
}
# Типичные опечатки/варианты (typosquatting)
TYPO_PATTERNS: List[Tuple[str, str]] = [
    ("requesst", "requests"), ("requestts", "requests"), ("numpys", "numpy"),
    ("pandass", "pandas"), ("cryptographyy", "cryptography"), ("urllib3", "urllib3"),
]


def _load_known_hashes_db(path: Optional[Path] = None) -> Dict[str, Dict[str, str]]:
    """Загружает JSON: { "zlib1.dll": { "sha256": "...", "source": "zlib.net" }, ... }. Env: BIN_GATE_OSS_HASHES_JSON."""
    if path is None:
        path = os.getenv("BIN_GATE_OSS_HASHES_JSON")
        path = Path(path) if path else None
    if not path or not Path(path).exists():
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="ignore"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def check_oss_hash_match(name: str, sha256: str, db: Optional[Dict[str, Dict[str, str]]] = None) -> Dict[str, Any]:
    """
    Если имя совпадает с известной OSS-библиотекой — сравнить хэш с официальным.
    Возвращает: { "matched": bool, "expected_hash": str?, "tampering_suspected": bool }
    """
    out: Dict[str, Any] = {"matched": False, "expected_hash": None, "tampering_suspected": False}
    if not name or not sha256:
        return out
    db = db if db is not None else _load_known_hashes_db()
    name_norm = name.lower().strip().replace(" ", "")
    for key, val in db.items():
        if not isinstance(val, dict):
            continue
        key_norm = key.lower().replace(" ", "")
        if key_norm != name_norm and name_norm not in key_norm and key_norm not in name_norm:
            continue
        expected = (val.get("sha256") or val.get("sha256_hex") or "").strip().lower().replace(" ", "")
        if not expected:
            continue
        if sha256.strip().lower().replace(" ", "") == expected:
            out["matched"] = True
            out["expected_hash"] = expected
            return out
        out["tampering_suspected"] = True
        out["expected_hash"] = expected
        return out
    return out


def detect_typosquatting(dependency_names: List[str]) -> List[Dict[str, Any]]:
    """
    Проверка имён на подмену (typosquatting). Возвращает список { "name": str, "suggested": str, "typosquat": True }.
    """
    results: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for raw in dependency_names:
        if not isinstance(raw, str):
            continue
        name = raw.strip()
        if not name or name in seen:
            continue
        seen.add(name)
        name_lower = name.lower()
        # Точное совпадение с известным — не типосквот
        if name_lower in KNOWN_OSS_NAMES:
            continue
        # Проверка по списку типичных опечаток
        for typo, correct in TYPO_PATTERNS:
            if typo in name_lower or name_lower == typo:
                results.append({"name": name, "suggested": correct, "typosquat": True})
                break
        # Эвристика: очень похоже на известное имя (длина ±1, одна буква разница)
        for known in KNOWN_OSS_NAMES:
            if len(name_lower) >= 4 and known in name_lower and name_lower != known:
                if abs(len(name_lower) - len(known)) <= 2:
                    results.append({"name": name, "suggested": known, "typosquat": True})
                    break
    return results


def analyze_supply_chain_guard(
    dependencies: List[Dict[str, Any]],
    hashes_by_name: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Анализ supply_chain.dependencies: hash matching для OSS, typosquatting по именам.
    dependencies: список { "type": "dynamic_lib", "value": "zlib1.dll", ... }.
    hashes_by_name: опционально { "zlib1.dll": "sha256..." } (если есть хэши по файлам).
    """
    out: Dict[str, Any] = {
        "hash_mismatch": [],
        "typosquat": [],
        "tampering_suspected": False,
    }
    names = []
    for d in dependencies or []:
        if isinstance(d, dict) and d.get("type") in ("dynamic_lib", "file_ref", "library"):
            v = d.get("value") or d.get("name")
            if isinstance(v, str) and v.strip():
                names.append(v.strip())
    if not names:
        return out
    db = _load_known_hashes_db()
    for name in names:
        sha = (hashes_by_name or {}).get(name) or ""
        if sha:
            res = check_oss_hash_match(name, sha, db)
            if res.get("tampering_suspected"):
                out["hash_mismatch"].append({"name": name, "expected_hash": res.get("expected_hash")})
                out["tampering_suspected"] = True
    typos = detect_typosquatting(names)
    out["typosquat"] = typos
    if typos:
        out["tampering_suspected"] = True
    return out
