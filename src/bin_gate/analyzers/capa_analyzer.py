from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
import os, json, shutil, subprocess

# ======== ФЛАГ ГЛУБОКОГО АНАЛИЗА CAPA ========
# По умолчанию False — используем быстрые методы (YARA + DIE).
# Включается флагом --deep-capa или ENABLE_DEEP_CAPA=1
ENABLE_DEEP_CAPA = bool(int(os.getenv("ENABLE_DEEP_CAPA", "0")))

# Жёсткий таймаут 45с для устранения зависаний; лимит размера выключен (0 = нет лимита)
DEFAULT_TIMEOUT_SEC = int(os.getenv("CAPA_TIMEOUT_SEC", "45"))
DEFAULT_MAX_MB      = int(os.getenv("CAPA_MAX_MB", "0"))
# Ограничение набора правил для ускорения (критичные тактики)
CAPA_SCOPE_TAGS = os.getenv("CAPA_SCOPE_TAGS", "anti-analysis,impact")

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


def _extract_attck_by_tactic(rule: dict) -> List[tuple]:
    """Из meta.att&ck извлекает пары (tactic, technique_id) для матрицы MITRE ATT&CK."""
    result: List[tuple] = []
    meta = rule.get("meta", {})
    atk = meta.get("att&ck") or meta.get("attack") or []
    if not isinstance(atk, list):
        return result
    for item in atk:
        if not isinstance(item, dict):
            continue
        tactic = (item.get("tactic") or "").strip().lower().replace(" ", "-")
        tid = (item.get("id") or item.get("technique") or "").strip()
        if tactic:
            result.append((tactic, tid or meta.get("name") or rule.get("name") or ""))
    # Keyword fallback: по имени правила
    name = (meta.get("name") or rule.get("name") or "").lower()
    for k, v in KEYWORDS_TO_TACTICS.items():
        if k in name and not any(r[0] == v for r in result):
            result.append((v, name[:80]))
    return result

def run_capa(
    path: Path,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    max_mb: int = DEFAULT_MAX_MB,
    rules_dir: str | None = None,
    *,
    enable_deep: Optional[bool] = None,
    prefilled_techniques: Optional[List[str]] = None,
    prefilled_rule_hits: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Возвращает:
      { "rule_hits":[...], "tactics":[...], "errors":[], "source": "capa"|"yara_die"|"skipped" }

    Если enable_deep=False (по умолчанию), возвращает предсобранные данные из YARA/DIE.
    Если enable_deep=True, выполняет реальный запуск capa.
    """
    # Определяем режим работы
    deep_mode = enable_deep if enable_deep is not None else ENABLE_DEEP_CAPA

    out: Dict[str, Any] = {
        "rule_hits": [],
        "tactics": [],
        "techniques": [],  # новое поле для совместимости
        "errors": [],
        "source": "skipped",
    }

    # Если глубокий анализ отключён — используем предсобранные данные
    if not deep_mode:
        if prefilled_techniques:
            out["tactics"] = sorted(set(prefilled_techniques))
            out["techniques"] = sorted(set(prefilled_techniques))
            # Матрица по тактикам для отчёта (YARA/DIE не дают id, используем имя тактики)
            by_t: Dict[str, List[str]] = {}
            for t in out["tactics"]:
                by_t.setdefault(t, []).append(t)
            out["attck_by_tactic"] = by_t
        else:
            out["attck_by_tactic"] = {}
        if prefilled_rule_hits:
            out["rule_hits"] = prefilled_rule_hits[:50]
        out["source"] = "yara_die"
        return out

    # --- Глубокий режим: запуск реального capa ---
    out["source"] = "capa"

    if _too_big(path, max_mb):
        out["errors"].append(f"capa_skipped_large_file(size_mb>{max_mb})")
        return out

    exe = _which_capa()
    if not exe:
        out["errors"].append("capa_not_found")
        # Fallback на YARA/DIE данные
        if prefilled_techniques:
            out["tactics"] = sorted(set(prefilled_techniques))
            out["techniques"] = sorted(set(prefilled_techniques))
        if prefilled_rule_hits:
            out["rule_hits"] = prefilled_rule_hits[:50]
        out["source"] = "yara_die_fallback"
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
    # Ограничение набора правил (anti-analysis, impact) — меньше времени на метаданные
    if CAPA_SCOPE_TAGS:
        for tag in CAPA_SCOPE_TAGS.split(","):
            t = tag.strip()
            if t:
                cmd += ["-t", t]

    cmd.append(str(path))
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        out["errors"].append(f"capa_timeout({timeout_sec}s)")
        out["status"] = "timeout"
        # При таймауте возвращаем YARA/DIE данные как fallback
        if prefilled_techniques:
            out["tactics"] = sorted(set(prefilled_techniques))
            out["techniques"] = sorted(set(prefilled_techniques))
        if prefilled_rule_hits:
            out["rule_hits"] = prefilled_rule_hits[:50]
        out["source"] = "yara_die_timeout_fallback"
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
    attck_by_tactic: Dict[str, List[str]] = {}
    for r in rules:
        meta = r.get("meta", {})
        name = meta.get("name") or r.get("name")
        if name:
            hits.append(str(name))
        for t in _extract_tactics_from_rule(r):
            tactics.add(t)
        for tactic, tech_id in _extract_attck_by_tactic(r):
            if tactic not in attck_by_tactic:
                attck_by_tactic[tactic] = []
            if tech_id and tech_id not in attck_by_tactic[tactic]:
                attck_by_tactic[tactic].append(tech_id)

    # Мержим с YARA/DIE данными
    if prefilled_techniques:
        for t in prefilled_techniques:
            tactics.add(t)
            tstr = str(t).lower().replace("_", "-")
            if tstr and tstr not in (attck_by_tactic.get(tstr) or []):
                attck_by_tactic.setdefault(tstr, []).append(str(t))
    if prefilled_rule_hits:
        hits.extend(prefilled_rule_hits)

    out["rule_hits"] = sorted(set(hits))[:50]
    out["tactics"] = sorted(tactics)
    out["techniques"] = sorted(tactics)
    out["attck_by_tactic"] = {k: list(v)[:30] for k, v in attck_by_tactic.items()}
    return out


def get_techniques_from_yara_die(
    yara_techniques: Optional[List[str]] = None,
    yara_rule_hits: Optional[List[str]] = None,
    die_findings: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Собирает данные техник из YARA и DIE для быстрого заполнения Evidence.capa
    без запуска capa.
    """
    techniques: Set[str] = set()
    rule_hits: List[str] = []

    if yara_techniques:
        for t in yara_techniques:
            techniques.add(t)

    if yara_rule_hits:
        rule_hits.extend(yara_rule_hits)

    if die_findings:
        for f in die_findings:
            rule_hits.append(f"DIE:{f}")
            # Мап DIE-детектов в техники
            f_lower = f.lower()
            if "packer" in f_lower or "protector" in f_lower:
                techniques.add("defense-evasion")
            if "crypto" in f_lower:
                techniques.add("defense-evasion")
            if "obfuscator" in f_lower:
                techniques.add("defense-evasion")
            if "inject" in f_lower:
                techniques.add("defense-evasion")
            if "compiler" in f_lower and "c++" in f_lower:
                pass  # Не добавляем техники для обычных компиляторов

    return {
        "tactics": sorted(techniques),
        "techniques": sorted(techniques),
        "rule_hits": rule_hits[:50],
        "source": "yara_die",
        "errors": [],
    }
