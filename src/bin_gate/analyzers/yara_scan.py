from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import os, sys, hashlib, json, time

# ======== РАЗУМНЫЕ ДЕФОЛТЫ (можно переопределять флагами/ENV) ========
DEFAULT_TIMEOUT_SEC = int(os.getenv("YARA_TIMEOUT_SEC", "7"))
DEFAULT_MAX_MB      = int(os.getenv("YARA_MAX_MB", "0"))
DEFAULT_MAX_HITS    = int(os.getenv("YARA_MAX_HITS", "80"))
DEFAULT_FAST_MODE   = bool(int(os.getenv("YARA_FAST", "1")))     # 1=fast (останавливает правило на первом совпадении)
DEFAULT_USE_BUILTIN = bool(int(os.getenv("YARA_USE_BUILTIN", "1")))
CACHE_DIR_ENV       = os.getenv("YARA_CACHE_DIR")                # куда складывать .yarac

# ======== ВСТРОЕННЫЕ «БЕЗОПАСНЫЕ» ПРАВИЛА (минимум FP) ========
# Строгие гейты по магии/структуре (модуль pe обязателен)
BUILTIN_PACKERS = r"""
import "pe"

/* --- PE packers --- */
rule PACKER_UPX_PE {
    meta: author="builtin" family="packers" target="pe" severity="medium"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upxS = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and  // 'MZ'
        (
          for any i in (0..pe.number_of_sections-1): ( pe.sections[i].name matches /UPX\d?/
        ) or
          2 of ($upx*)
        )
}

rule PACKER_MPRESS_PE {
    meta: author="builtin" family="packers" target="pe" severity="high"
    strings:
        $m = "MPRESS" nocase ascii
    condition:
        uint16(0) == 0x5A4D and
        $m and
        for any i in (0..pe.number_of_sections-1):
            ( pe.sections[i].name == ".MPRESS1" or pe.sections[i].name == ".MPRESS2" )
}

rule PACKER_ASPACK_PE {
    meta: author="builtin" family="packers" target="pe" severity="medium"
    strings:
        $a = "ASPack" nocase ascii
    condition:
        uint16(0) == 0x5A4D and
        $a and
        for any i in (0..pe.number_of_sections-1):
            ( pe.sections[i].name == ".aspack" or pe.sections[i].name == ".adata" )
}

/* --- ELF packers --- */
rule PACKER_UPX_ELF {
    meta: author="builtin" family="packers" target="elf" severity="medium"
    strings:
        $u1 = "UPX!" ascii
        $u2 = "UPX0" ascii
        $u3 = "UPX1" ascii
    condition:
        uint32(0) == 0x464C457F and 2 of ($u*)
}
"""

# ======== УТИЛИТЫ ========
def _is_pe(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(2) == b"MZ"
    except Exception:
        return False

def _is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False

def _file_size_mb(path: Path) -> float:
    try:
        return path.stat().st_size / (1024.0 * 1024.0)
    except Exception:
        return 0.0

def _cache_base_dir() -> Path:
    if CACHE_DIR_ENV:
        return Path(CACHE_DIR_ENV)
    # кросс-платформенный кеш
    if os.name == "nt":
        base = os.getenv("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
        return Path(base) / "bin-gate" / "yara-cache"
    return Path(os.path.expanduser("~/.cache")) / "bin-gate" / "yara"

def _fingerprint_rules_dir(rules_dir: Path) -> str:
    """
    Хеш-фингерпринт содержимого каталога правил (пути+mtime+размер).
    Меняется — инвалидация кэша .yarac.
    """
    h = hashlib.sha256()
    count = 0
    for p in sorted(rules_dir.rglob("*.yar*")):
        try:
            st = p.stat()
            h.update(str(p).encode("utf-8"))
            h.update(str(int(st.st_mtime)).encode("ascii"))
            h.update(str(st.st_size).encode("ascii"))
            count += 1
        except Exception:
            continue
    h.update(str(count).encode("ascii"))
    return h.hexdigest()

def _compile_from_dir(yara, rules_dir: Path):
    """
    Компилируем из файлов, чтобы работали include/namespace.
    """
    filepaths = {}
    for p in rules_dir.rglob("*.yar*"):
        filepaths[str(p)] = str(p)
    if not filepaths:
        return None
    return yara.compile(filepaths=filepaths)

def _load_or_compile_rules(rules_dir: Optional[Path], use_builtin: bool) -> Tuple[Optional[Any], List[str]]:
    """
    Возвращает (rules, errors). При наличии rules_dir — кэшируем в .yarac.
    Иначе — компилируем встроенные правила.
    """
    errors: List[str] = []
    try:
        import yara  # type: ignore
    except Exception as e:
        return None, [f"yara_not_installed:{e}"]

    # Ветка с внешними правилами
    if rules_dir and rules_dir.exists():
        try:
            fp = _fingerprint_rules_dir(rules_dir)
            cache_dir = _cache_base_dir()
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file = cache_dir / f"rules_{fp}.yarac"

            # если есть кэш — грузим, иначе компилим и пишем
            if cache_file.exists():
                try:
                    rules = yara.load(str(cache_file))
                    return rules, errors
                except Exception as e:
                    errors.append(f"yara_cache_load_error:{e}")
                    # упадём в перекомпиляцию

            rules = _compile_from_dir(yara, rules_dir)
            if rules is None:
                # пустая директория — fallback
                if use_builtin:
                    return yara.compile(sources={"builtin-packers": BUILTIN_PACKERS}), errors
                else:
                    return None, ["yara_no_sources"]
            try:
                rules.save(str(cache_file))
            except Exception as e:
                errors.append(f"yara_cache_save_error:{e}")
            return rules, errors
        except Exception as e:
            errors.append(f"yara_compile_error:{e}")
            # попробуем builtin если разрешено
            if use_builtin:
                try:
                    return yara.compile(sources={"builtin-packers": BUILTIN_PACKERS}), errors
                except Exception as e2:
                    errors.append(f"yara_builtin_compile_error:{e2}")
                    return None, errors
            return None, errors

    # Ветка без внешних правил — builtin/ничего
    if use_builtin:
        try:
            import yara  # reimport ok
            return yara.compile(sources={"builtin-packers": BUILTIN_PACKERS}), errors
        except Exception as e:
            return None, [f"yara_builtin_compile_error:{e}"]
    return None, ["yara_no_sources"]

def _norm_severity(meta: Dict[str, Any]) -> str:
    # нормализуем severity из meta (строка/число)
    val = (meta.get("severity") or meta.get("sev") or "").strip().lower() if isinstance(meta.get("severity") or meta.get("sev"), str) else meta.get("severity")
    if isinstance(val, str):
        m = {
            "critical": "critical", "crit": "critical", "4": "critical",
            "high": "high", "3": "high",
            "medium": "medium", "med": "medium", "2": "medium",
            "low": "low", "1": "low",
        }
        return m.get(val, "medium")
    if isinstance(val, (int, float)):
        if val >= 4: return "critical"
        if val >= 3: return "high"
        if val >= 2: return "medium"
        return "low"
    # дефолт: packers → medium, остальное → low
    fam = str(meta.get("family") or "").lower()
    return "medium" if "packer" in fam or fam == "packers" else "low"

def _too_big(path: Path, max_mb: int) -> bool:
    if max_mb is None or max_mb <= 0:
        return False  # лимит отключён
    try:
        return (path.stat().st_size / (1024*1024)) > max_mb
    except Exception:
        return False

# ======== ПУБЛИЧНОЕ API ========
def run_yara(
    path: Path,
    rules_dir: str | None = None,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_mb: int = DEFAULT_MAX_MB,
    max_hits: int = DEFAULT_MAX_HITS,
    fast: bool = DEFAULT_FAST_MODE,
    use_builtin: bool = DEFAULT_USE_BUILTIN,
    externals: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]] | None:
    """
    Продакшен-скан YARA: кэш .yarac, строгие гейты по типу файла, таймаут,
    лимит размера, нормализация severity. Возвращает список "хитов" или None
    (если нет yara). Ошибки возвращаем как псевдо-хиты (namespace=errors).
    """
    # Лимит размера — без чтения всего файла
    if _too_big(path, max_mb):
        return [{"rule": "yara_skipped_large_file", "namespace": "errors",
                 "meta": {"size_mb": round(_file_size_mb(path), 2), "limit_mb": max_mb}}]

    try:
        import yara  # type: ignore
    except Exception:
        return None  # нет yara — тихо

    rules, errs = _load_or_compile_rules(Path(rules_dir) if rules_dir else None, use_builtin)
    if rules is None:
        return [{"rule": "yara_error", "namespace": "errors", "meta": {"errors": errs}}]

    # Внешние переменные для правил (можно использовать в собственных .yar)
    ext = {
        "is_pe": int(_is_pe(path)),
        "is_elf": int(_is_elf(path)),
        "file_size": int(path.stat().st_size) if path.exists() else 0,
    }
    if externals:
        for k, v in externals.items():
            # yara принимает int/float/str/bool
            if isinstance(v, (int, float, str, bool)):
                ext[k] = v

    # Скан
    try:
        matches = rules.match(
            str(path),
            externals=ext,
            timeout=timeout_sec,
            fast=fast
        )
    except Exception as e:
        return [{"rule": "yara_match_error", "namespace": "errors", "meta": {"error": str(e)[:400]}}]

    # Нормализация и сортировка по severity → затем по имени
    out: List[Dict[str, Any]] = []
    for m in matches:
        meta = dict(m.meta) if hasattr(m, "meta") else {}
        sev = _norm_severity(meta)
        out.append({
            "rule": m.rule,
            "namespace": m.namespace,
            "meta": meta,
            "severity": sev,
            "tags": list(getattr(m, "tags", []) or []),
        })

    sev_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    out.sort(key=lambda x: (sev_order.get(x.get("severity","medium"), 1), str(x.get("rule"))), reverse=True)
    if len(out) > max_hits:
        out = out[:max_hits]
        out.append({"rule": "yara_truncated", "namespace": "meta", "meta": {"max_hits": max_hits}})
    return out
