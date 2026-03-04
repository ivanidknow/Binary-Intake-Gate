from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set
import os, sys, re, hashlib, json, time

# MITRE ID pattern: T + digits + optional .digits (e.g. T1055, T1055.012) — raw string to avoid SyntaxWarning
_MITRE_ID_PATTERN = re.compile(r"T\d+(\.\d+)?", re.IGNORECASE)
# Примечание: max_strings_per_rule — опция только CLI YARA; в yara-python при too many matches используем fast=True и max_hits

# ======== РАЗУМНЫЕ ДЕФОЛТЫ (можно переопределять флагами/ENV) ========
DEFAULT_TIMEOUT_SEC = int(os.getenv("YARA_TIMEOUT_SEC", "7"))
DEFAULT_MAX_MB      = int(os.getenv("YARA_MAX_MB", "0"))
DEFAULT_MAX_HITS    = int(os.getenv("YARA_MAX_HITS", "80"))
DEFAULT_FAST_MODE   = bool(int(os.getenv("YARA_FAST", "1")))     # 1=fast (останавливает правило на первом совпадении)
DEFAULT_USE_BUILTIN = bool(int(os.getenv("YARA_USE_BUILTIN", "1")))
CACHE_DIR_ENV       = os.getenv("YARA_CACHE_DIR")                # куда складывать .yarac

# ======== МАППИНГ ТЕХНИК ATT&CK ИЗ YARA МЕТАДАННЫХ ========
# Ключевые слова для извлечения техник из имён правил и meta полей
TECHNIQUE_KEYWORDS = {
    # Persistence
    "persistence": "persistence",
    "startup": "persistence",
    "autorun": "persistence",
    "service": "persistence",
    "scheduled": "persistence",
    "registry_run": "persistence",
    # Defense Evasion
    "evasion": "defense-evasion",
    "injection": "defense-evasion",
    "obfuscat": "defense-evasion",
    "packer": "defense-evasion",
    "anti_debug": "defense-evasion",
    "anti_vm": "defense-evasion",
    "anti_analysis": "defense-evasion",
    "hollowing": "defense-evasion",
    # Credential Access
    "credential": "credential-access",
    "mimikatz": "credential-access",
    "password": "credential-access",
    "keylog": "credential-access",
    "dump_lsass": "credential-access",
    # Discovery
    "discovery": "discovery",
    "enum": "discovery",
    "recon": "discovery",
    "systeminfo": "discovery",
    # Lateral Movement
    "lateral": "lateral-movement",
    "psexec": "lateral-movement",
    "wmi_exec": "lateral-movement",
    "rdp": "lateral-movement",
    # Command and Control
    "c2": "command-and-control",
    "beacon": "command-and-control",
    "cobalt": "command-and-control",
    "backdoor": "command-and-control",
    "rat": "command-and-control",
    "reverse_shell": "command-and-control",
    # Exfiltration
    "exfil": "exfiltration",
    "data_theft": "exfiltration",
    "upload": "exfiltration",
    # Collection
    "collection": "collection",
    "screen_capture": "collection",
    "clipboard": "collection",
    "keylogger": "collection",
    # Execution
    "execution": "execution",
    "shellcode": "execution",
    "powershell": "execution",
    "script": "execution",
    # Impact
    "ransomware": "impact",
    "wiper": "impact",
    "encrypt": "impact",
    "destruct": "impact",
}

# Маппинг имён правил/категорий в MITRE ID (для meta без technique/mitre/attack)
RULE_MITRE_MAP = {
    "antivirus": "T1562",           # Impair Defenses (отключение AV)
    "win_files_operation": "T1570", # Lateral Tool Transfer
}

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


def _get_external_rules_dir() -> Optional[Path]:
    """Директория rules/external/ (внешние базы Yara-Rules, Neo23x0)."""
    try:
        from ..rules import get_external_rules_dir
        d = get_external_rules_dir()
        return d if d.exists() else None
    except Exception:
        return None


def _compile_external_dir(yara, external_dir: Path) -> Tuple[List[Tuple[Any, str]], List[str]]:
    """
    Компиляция всех .yar из external (рекурсивно). При ошибке «всего сразу» — по файлам (пропуск сломанных).
    Возвращает ([(rules_obj, namespace)], errors).
    """
    errors: List[str] = []
    files = sorted(external_dir.rglob("*.yar*"))
    filepaths = {str(p): str(p) for p in files if p.is_file()}
    if not filepaths:
        return [], errors
    # Сначала пробуем скомпилировать всё
    try:
        rules = yara.compile(filepaths=filepaths)
        ns = external_dir.name
        return [(rules, ns)], errors
    except Exception as e:
        errors.append(f"external_compile_all:{e}")
    # Пофайлово: компилируем каждый, сломанные пропускаем
    result: List[Tuple[Any, str]] = []
    for p in files:
        if not p.is_file():
            continue
        try:
            r = yara.compile(filepath=str(p))
            ns = str(p.relative_to(external_dir).parent).replace("\\", "/") or p.parent.name
            result.append((r, ns))
        except Exception as e:
            errors.append(f"skip {p.name}: {e}")
    return result, errors


def _load_external_rules() -> Tuple[List[Tuple[Any, str]], List[str]]:
    """
    Загрузка/компиляция правил из rules/external/. Кэш .yarac по fingerprint директории.
    Возвращает ([(rules, namespace)], errors).
    """
    external_dir = _get_external_rules_dir()
    if not external_dir or not external_dir.exists():
        return [], []
    try:
        import yara  # type: ignore
    except Exception:
        return [], []
    errors: List[str] = []
    fp = _fingerprint_rules_dir(external_dir)
    cache_dir = _cache_base_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / f"external_{fp}.yarac"
    if cache_file.exists():
        try:
            rules = yara.load(str(cache_file))
            return [(rules, "external")], errors
        except Exception as e:
            errors.append(f"external_cache_load:{e}")
    rules_list, compile_errs = _compile_external_dir(yara, external_dir)
    errors.extend(compile_errs)
    if len(rules_list) == 1:
        try:
            rules_list[0][0].save(str(cache_file))
        except Exception as e:
            errors.append(f"external_cache_save:{e}")
    return rules_list, errors

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


def _extract_techniques_from_match(rule_name: str, meta: Dict[str, Any], tags: List[str]) -> Set[str]:
    """
    Извлекает техники ATT&CK из YARA match метаданных.
    Поддерживает поля: meta.technique, meta.attack, meta.mitre, meta.tactic, meta.os
    А также keyword-based detection из имени правила и тегов.
    """
    techniques: Set[str] = set()

    # 1. Прямые поля техник в meta
    for field in ("technique", "techniques", "attack", "mitre", "mitre_attack", "att&ck", "attck"):
        val = meta.get(field)
        if val:
            if isinstance(val, str):
                # Может быть "T1055, T1059" или "defense-evasion"
                for part in val.replace(",", " ").split():
                    part = part.strip().lower()
                    if part:
                        techniques.add(part)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        techniques.add(item.strip().lower())
                    elif isinstance(item, dict):
                        # CAPE/YARA-CTI format: {"tactic": "...", "technique": "..."}
                        tactic = (item.get("tactic") or "").strip().lower()
                        tech = (item.get("technique") or item.get("id") or "").strip()
                        if tactic:
                            techniques.add(tactic.replace(" ", "-"))
                        if tech:
                            techniques.add(tech.upper())

    # 2. Поле tactic напрямую
    tactic = meta.get("tactic") or meta.get("tactics")
    if tactic:
        if isinstance(tactic, str):
            techniques.add(tactic.strip().lower().replace(" ", "-"))
        elif isinstance(tactic, list):
            for t in tactic:
                if isinstance(t, str):
                    techniques.add(t.strip().lower().replace(" ", "-"))

    # 3. Поле capability (CAPE rules)
    capability = meta.get("capability") or meta.get("capabilities")
    if capability:
        if isinstance(capability, str):
            techniques.add(f"capability:{capability.strip().lower()}")
        elif isinstance(capability, list):
            for c in capability:
                if isinstance(c, str):
                    techniques.add(f"capability:{c.strip().lower()}")

    # 4. Keyword-based detection из имени правила
    rule_lower = rule_name.lower()
    for keyword, technique in TECHNIQUE_KEYWORDS.items():
        if keyword in rule_lower:
            techniques.add(technique)
    # 4b. Прямой маппинг правила -> MITRE ID (Antivirus -> T1562, win_files_operation -> T1570)
    for rule_key, mitre_id in RULE_MITRE_MAP.items():
        if rule_key in rule_lower:
            techniques.add(mitre_id.upper())

    # 5. Из тегов
    for tag in tags:
        tag_lower = tag.lower()
        for keyword, technique in TECHNIQUE_KEYWORDS.items():
            if keyword in tag_lower:
                techniques.add(technique)
        # Прямые теги-тактики
        if tag_lower in ("persistence", "evasion", "execution", "collection", "exfiltration", "impact"):
            techniques.add(tag_lower)

    # 6. Family-based inference
    family = (meta.get("family") or "").lower()
    if "packer" in family or family == "packers":
        techniques.add("defense-evasion")
    if "ransomware" in family:
        techniques.add("impact")
    if "stealer" in family or "infostealer" in family:
        techniques.add("credential-access")
        techniques.add("collection")
    if "rat" in family or "backdoor" in family:
        techniques.add("command-and-control")
    if "miner" in family or "cryptominer" in family:
        techniques.add("impact")

    return techniques

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

    def norm_match(m: Any) -> Dict[str, Any]:
        meta = dict(m.meta) if hasattr(m, "meta") else {}
        sev = _norm_severity(meta)
        tags = list(getattr(m, "tags", []) or [])
        techniques = _extract_techniques_from_match(m.rule, meta, tags)
        return {
            "rule": m.rule,
            "namespace": getattr(m, "namespace", "") or "",
            "meta": meta,
            "severity": sev,
            "tags": tags,
            "techniques": sorted(techniques),
        }

    # Global fast mode: при fast=True YARA останавливается после первого совпадения строки (критично для PoetRat_Python, Microsoft_Visual_Cpp) — избегаем RuntimeWarning: too many matches. Для Deep профиля вызывающий передаёт fast=False.
    try:
        matches = rules.match(str(path), externals=ext, timeout=timeout_sec, fast=fast)
    except Exception as e:
        return [{"rule": "yara_match_error", "namespace": "errors", "meta": {"error": str(e)[:400]}}]

    out: List[Dict[str, Any]] = [norm_match(m) for m in matches]

    # Скан внешних баз (rules/external/) — пофайловый кэш при ошибке компиляции всего
    external_list, _ = _load_external_rules()
    for rules_ext, ns_prefix in external_list:
        try:
            for m in rules_ext.match(str(path), externals=ext, timeout=max(2, timeout_sec // 2), fast=fast):
                rec = norm_match(m)
                rec["namespace"] = ns_prefix + "/" + rec.get("namespace", "") if rec.get("namespace") else ns_prefix
                out.append(rec)
        except Exception:
            continue

    sev_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    out.sort(key=lambda x: (sev_order.get(x.get("severity","medium"), 1), str(x.get("rule"))), reverse=True)
    # Ограничение числа хитов (max_hits) снижает риск "too many matches" и ускоряет обработку
    if len(out) > max_hits:
        out = out[:max_hits]
        out.append({"rule": "yara_truncated", "namespace": "meta", "meta": {"max_hits": max_hits}})
    return out


def run_yara_on_data(
    data: bytes,
    rules_dir: str | None = None,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_hits: int = DEFAULT_MAX_HITS,
    fast: bool = DEFAULT_FAST_MODE,
    use_builtin: bool = DEFAULT_USE_BUILTIN,
) -> List[Dict[str, Any]] | None:
    """
    v3.0: YARA по буферу (для островов энтропии в streaming_scanner).
    Не загружает файл в RAM целиком — вызывающий передаёт только нужный кусок.
    """
    try:
        import yara  # type: ignore
    except Exception:
        return None
    rules, errs = _load_or_compile_rules(Path(rules_dir) if rules_dir else None, use_builtin)
    if rules is None:
        return [{"rule": "yara_error", "namespace": "errors", "meta": {"errors": errs}}]
    ext = {
        "is_pe": 1 if data[:2] == b"MZ" else 0,
        "is_elf": 1 if data[:4] == b"\x7fELF" else 0,
        "file_size": len(data),
    }

    def norm_match(m: Any) -> Dict[str, Any]:
        meta = dict(m.meta) if hasattr(m, "meta") else {}
        sev = _norm_severity(meta)
        tags = list(getattr(m, "tags", []) or [])
        techniques = _extract_techniques_from_match(m.rule, meta, tags)
        return {
            "rule": m.rule,
            "namespace": getattr(m, "namespace", "") or "",
            "meta": meta,
            "severity": sev,
            "tags": tags,
            "techniques": sorted(techniques),
        }

    try:
        matches = rules.match(data=data, externals=ext, timeout=timeout_sec, fast=fast)
    except Exception as e:
        return [{"rule": "yara_match_error", "namespace": "errors", "meta": {"error": str(e)[:400]}}]
    out = [norm_match(m) for m in matches]
    if len(out) > max_hits:
        out = out[:max_hits]
        out.append({"rule": "yara_truncated", "namespace": "meta", "meta": {"max_hits": max_hits}})
    return out


def _normalize_mitre_id(s: str) -> str:
    """MITRE IDs (pattern T\\d+ or T\\d+\\.\\d+) в верхнем регистре для Evidence. Использует r'T\\d+(\\.\\d+)?' без SyntaxWarning."""
    s = (s or "").strip()
    if not s:
        return s
    m = _MITRE_ID_PATTERN.search(s)
    if m:
        return m.group(0).upper()
    if len(s) >= 2 and s[0].lower() == "t" and s[1:].replace(".", "").isdigit():
        return s.upper()
    return s


def extract_all_techniques(yara_hits: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """
    Агрегирует все техники и rule_hits из YARA результатов.
    Парсит meta.technique, meta.mitre, meta.attack из правил.
    Возвращает (techniques, rule_hits) для заполнения Evidence.capa.
    MITRE ID в едином формате (T1562, T1546.012, без дублей).
    rule_hits дедуплицированы (IsPE32 и др. не дублируются).
    """
    all_techniques: Set[str] = set()
    rule_hits_seen: Set[str] = set()
    rule_hits: List[str] = []

    for hit in yara_hits:
        if hit.get("namespace") == "errors":
            continue
        rule_name = hit.get("rule", "")
        if rule_name:
            key = f"YARA:{rule_name}"
            if key not in rule_hits_seen:
                rule_hits_seen.add(key)
                rule_hits.append(key)
        techniques = hit.get("techniques") or []
        if not techniques and hit.get("meta"):
            techniques = _extract_techniques_from_match(
                rule_name,
                hit.get("meta", {}),
                hit.get("tags") or [],
            )
        for t in techniques:
            if t:
                norm = _normalize_mitre_id(t) if isinstance(t, str) else str(t)
                if norm:
                    all_techniques.add(norm)

    return sorted(all_techniques), rule_hits[:50]
