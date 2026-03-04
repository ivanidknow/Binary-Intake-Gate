# language_rules.py — наборы исключений для Go и Rust, чтобы статические YARA не давали FP на рантайм-функции
from __future__ import annotations
from typing import Any, Dict, List, Optional, Set

# Правила YARA (имена или подстроки), которые часто дают ложные срабатывания на легитимный Go runtime
GO_YARA_EXCEPTIONS: Set[str] = {
    "go_", "golang", "go.buildid", "runtime.main", "runtime.morestack",
    "type..eq", "type..hash", "go.string", "go.func", "go.map",
    "crypto_", "encoding_", "net.http", "os_", "sync.",
    "internal_", "vendor_", "main.init", "main.main",
}

# Правила YARA (имена или подстроки), которые часто дают ложные срабатывания на легитимный Rust runtime
RUST_YARA_EXCEPTIONS: Set[str] = {
    "rust", "rustc", "core::", "std::", "alloc::", "panic", "unwrap",
    "lang_start", "rust_alloc", "rust_dealloc", "rust_realloc",
    "drop_in_place", "memcpy", "memmove", "memset",
    "eh_personality", "rust_eh", "begin_unwind",
}


def _normalize_language(lang: Optional[str]) -> Optional[str]:
    if not lang or not isinstance(lang, str):
        return None
    return lang.strip().lower()


def _rule_matches_exception(rule_name: str, exceptions: Set[str]) -> bool:
    r = (rule_name or "").strip().lower()
    for ex in exceptions:
        if ex.lower() in r or r in ex.lower():
            return True
    return False


def filter_yara_fp_by_language(
    yara_hits: Optional[List[Dict[str, Any]]],
    language: Optional[str],
) -> List[Dict[str, Any]]:
    """
    Убирает из yara_hits те правила, что входят в исключения для данного языка (Go/Rust),
    чтобы снизить ложные срабатывания на стандартные рантайм-функции.
    """
    if not yara_hits:
        return []
    lang = _normalize_language(language)
    if not lang:
        return list(yara_hits)
    if "go" in lang or "golang" in lang:
        exceptions = GO_YARA_EXCEPTIONS
    elif "rust" in lang:
        exceptions = RUST_YARA_EXCEPTIONS
    else:
        return list(yara_hits)
    out: List[Dict[str, Any]] = []
    for h in yara_hits:
        if not isinstance(h, dict):
            out.append(h)
            continue
        rule = h.get("rule") or h.get("name") or ""
        if _rule_matches_exception(rule, exceptions):
            continue
        out.append(h)
    return out
