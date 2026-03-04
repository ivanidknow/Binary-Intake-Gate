# v3.1: Attack Storyline Engine — корреляция техник MITRE в цепочки атак (Kill Chain)
"""
Связывает разрозненные события в логические сценарии.
Комбо-пары тактик с фиксированными весами; детекция Staged Execution (LNK → скрипт → инъекция).
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional, Set, Tuple

# Пары техник (базовый ID без суффикса) → бонусный штраф за цепочку атак
# Initial Access (T1204) + Defense Evasion (T1562) = +30
# Credential Access (T1003) + Exfiltration (T1020) = +50 (критично)
# Discovery (T1082) + Lateral Movement (T1021) = +40
STORYLINE_COMBO_PAIRS: List[Tuple[Tuple[str, str], int]] = [
    (("T1204", "T1562"), 30),   # Initial Access + Defense Evasion
    (("T1003", "T1020"), 50),   # Credential Access + Exfiltration (критично)
    (("T1082", "T1021"), 40),   # Discovery + Lateral Movement
]


def _collect_technique_bases(ev: Dict[str, Any]) -> Set[str]:
    """Собирает базовые ID техник (T1204, T1562, ...) из evidence без суффикса .001."""
    bases: Set[str] = set()
    def add(tid: str) -> None:
        if not tid or not isinstance(tid, str):
            return
        t = tid.strip().upper()
        if t.startswith("T") and t[1:2].isdigit():
            base = t.split(".")[0]
            if len(base) >= 5:  # T + 4 digits
                bases.add(base)

    for hint in (ev.get("pe") or {}).get("technique_hints") or []:
        add(hint)
    for hint in ev.get("technique_hints") or []:
        add(hint)
    for tech in (ev.get("emulation") or {}).get("techniques") or []:
        add(tech)
    capa = ev.get("capa") or {}
    for tech in capa.get("techniques") or capa.get("rule_hits") or []:
        if isinstance(tech, str) and "T" in tech:
            for part in tech.replace(",", " ").split():
                add(part)
    attck = capa.get("attck_by_tactic") or {}
    if isinstance(attck, dict):
        for techs in attck.values():
            if isinstance(techs, (list, tuple)):
                for t in techs:
                    add(t)
    return bases


def compute_storyline_combo_score(ev: Dict[str, Any]) -> Tuple[int, List[str]]:
    """
    Проверка на пересечение стадий Kill Chain: если в одном файле/сессии найдены обе техники из пары,
    применяется соответствующий штраф. Возвращает (суммарный бонус, список описаний для reasons).
    """
    bases = _collect_technique_bases(ev)
    score = 0
    reasons: List[str] = []
    for (t1, t2), penalty in STORYLINE_COMBO_PAIRS:
        if t1 in bases and t2 in bases:
            score += penalty
            reasons.append(f"Цепочка атак: {t1}+{t2} (+{penalty})")
    return score, reasons


def detect_staged_execution(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Детекция Staged Execution: один артефакт (LNK) загружает другой (скрипт), который вызывает API инъекции.
    Возвращает граф атаки для отчёта или None.
    """
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, str]] = []
    path = (ev.get("meta") or {}).get("path") or ev.get("path") or ""
    if not path:
        return None
    script_analysis = ev.get("script_analysis") or {}
    office_deep = script_analysis.get("office_deep") or {}
    lnk = office_deep.get("lnk") or {}
    stagers = (script_analysis.get("office_deep") or {}).get("stagers") or office_deep.get("stagers") or []
    th = list((ev.get("pe") or {}).get("technique_hints") or []) + list(ev.get("technique_hints") or [])
    injection_tech = [t for t in th if isinstance(t, str) and ("T1055" in t or "injection" in str(t).lower())]
    has_loader = bool(lnk.get("command_line") or lnk.get("target_path") or stagers)
    has_injection = bool(injection_tech)
    if has_loader and has_injection:
        nodes.append({"id": "artifact", "label": path.split("/")[-1].split("\\")[-1], "type": "file"})
        nodes.append({"id": "script_stage", "label": "Script/LNK stage", "type": "stager"})
        nodes.append({"id": "injection", "label": "Injection API", "type": "technique"})
        edges.append({"from": "artifact", "to": "script_stage"})
        edges.append({"from": "script_stage", "to": "injection"})
        return {"nodes": nodes, "edges": edges, "staged": True}
    return None
