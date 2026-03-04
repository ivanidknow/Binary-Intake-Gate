# profiles.py — Enterprise Analysis Profiles (Fast / Balanced / Deep)
"""
Интенсивность проверки: Fast (CI/PR <15s), Balanced (30–60s), Deep (Release/Audit).
Управление: ANALYSIS_PROFILE или --analysis-profile.
"""
from __future__ import annotations
import os
from typing import Any, Dict

PROFILE_FAST = "fast"
PROFILE_BALANCED = "balanced"
PROFILE_DEEP = "deep"

ANALYSIS_PROFILE_ENV = "ANALYSIS_PROFILE"
DEFAULT_PROFILE = PROFILE_BALANCED

# Глубина профиля для кэша: можно использовать результат более глубокого профиля для более быстрого
PROFILE_DEPTH = {PROFILE_FAST: 0, PROFILE_BALANCED: 1, PROFILE_DEEP: 2}


def get_analysis_profile(args: Any) -> str:
    """Профиль из args.analysis_profile или env ANALYSIS_PROFILE. По умолчанию balanced."""
    if args is not None and getattr(args, "analysis_profile", None):
        p = (getattr(args, "analysis_profile") or "").strip().lower()
        if p in (PROFILE_FAST, PROFILE_BALANCED, PROFILE_DEEP):
            return p
    p = (os.getenv(ANALYSIS_PROFILE_ENV) or "").strip().lower()
    if p in (PROFILE_FAST, PROFILE_BALANCED, PROFILE_DEEP):
        return p
    return DEFAULT_PROFILE


def profile_depth(profile: str) -> int:
    """Числовая глубина профиля (0=fast, 1=balanced, 2=deep)."""
    return PROFILE_DEPTH.get((profile or "").lower(), 1)


def is_profile_deeper_or_equal(cached_profile: str, requested_profile: str) -> bool:
    """True если кэш с cached_profile подходит для запроса requested_profile (кэш не менее глубокий)."""
    return profile_depth(cached_profile) >= profile_depth(requested_profile)


def apply_analysis_profile_to_options(options: Dict[str, Any], profile: str) -> Dict[str, Any]:
    """
    Переопределяет options в зависимости от профиля.
    Fast: без эмуляции, без CVE, без рекурсивной распаковки, минимальные таймауты.
    Deep: полная рекурсия, макс. таймаут эмуляции, глубокий стего.
    """
    opts = dict(options)
    opts["analysis_profile"] = profile
    if profile == PROFILE_FAST:
        opts["emulation"] = False
        opts["recursive_unpack_max"] = 0
        opts["no_capa"] = opts.get("no_capa", True)  # Fast: без capa по умолчанию
        opts["yara_timeout"] = min(opts.get("yara_timeout", 7), 5)
        opts["die_timeout"] = min(opts.get("die_timeout", 60), 30)
    elif profile == PROFILE_DEEP:
        opts["emulation"] = True
        opts["recursive_unpack_max"] = int(os.getenv("BIN_GATE_RECURSIVE_UNPACK_MAX", "5"))
        opts["emulation_timeout"] = max(opts.get("emulation_timeout", 60), 120)
        opts["deep_scan"] = True
        opts["deep_stego"] = True
    else:
        # Balanced
        opts["recursive_unpack_max"] = int(os.getenv("BIN_GATE_RECURSIVE_UNPACK_MAX", "3"))
    return opts


def recursive_unpack_max_for_profile(profile: str, default_max: int = 3) -> int:
    """Максимальная глубина рекурсивной распаковки для профиля."""
    if profile == PROFILE_FAST:
        return 0
    if profile == PROFILE_DEEP:
        return int(os.getenv("BIN_GATE_RECURSIVE_UNPACK_MAX", "5"))
    return default_max


def should_run_cve_for_profile(profile: str, no_cve_flag: bool = False) -> bool:
    """Запускать ли CVE (Syft/Grype) при данном профиле."""
    if no_cve_flag:
        return False
    return profile != PROFILE_FAST
