# src/bin_gate/analyzers/persistence_logic.py
# Анализ «живучести»: поиск в извлечённых строках путей автозагрузки (Registry Run, RunOnce, Winlogon, Services, Task Scheduler).
# Если бинарник содержит такие пути и не является системной утилитой — подозрительно (RISK_PERSISTENCE_DETECTED).

from __future__ import annotations
import re
from typing import Dict, Any, List

# Паттерны путей автозагрузки (нормализованные к нижнему регистру для сопоставления)
# Registry: HKCU/HKLM \...\Run, RunOnce, Winlogon; Services; Task Scheduler paths
_PERSISTENCE_PATTERNS = [
    (r"\\run\b", "Registry Run"),
    (r"\\runonce\b", "Registry RunOnce"),
    (r"\\winlogon\b", "Winlogon"),
    (r"\\services\\", "Services"),
    (r"\\currentversion\\run", "Registry Run"),
    (r"\\currentversion\\runonce", "Registry RunOnce"),
    (r"software\\microsoft\\windows\\currentversion\\run", "Registry Run"),
    (r"software\\microsoft\\windows\\currentversion\\runonce", "Registry RunOnce"),
    (r"software\\microsoft\\windows nt\\currentversion\\winlogon", "Winlogon"),
    (r"\\task scheduler\\", "Task Scheduler"),
    (r"\\tasks\\", "Tasks folder"),
    (r"schtasks", "schtasks"),
    (r"taskeng\.exe", "Task Scheduler"),
    (r"hkcu\\software\\microsoft\\windows\\currentversion\\run", "HKCU Run"),
    (r"hklm\\software\\microsoft\\windows\\currentversion\\run", "HKLM Run"),
    # Policies: UAC / Windows Defender — подозрительная модификация безопасности
    (r"\\policies\\", "Policies"),
    (r"policies\\microsoft\\windows defender", "Windows Defender Policies"),
    (r"disableantispyware", "Defender Disable"),
    (r"enablelua", "UAC Policy"),
    (r"consentpromptbehavioradmin", "UAC Policy"),
    (r"software\\classes\\ms-settings", "UAC Bypass (ms-settings)"),
    # Winlogon Helper DLL (T1547.004)
    (r"winlogon\\shell", "Winlogon Shell"),
    (r"winlogon\\userinit", "Winlogon Userinit"),
    (r"currentversion\\winlogon", "Winlogon"),
    (r"\\userinit\.exe", "Userinit"),
]

# Легитимные системные пути/имена (если только они — не поднимать suspect)
_LEGIT_SYSTEM_HINTS = frozenset({
    "system32", "syswow64", "windows\\system32", "program files",
    "microsoft\\windows", "svchost", "services.exe", "winlogon.exe",
    "taskhost", "taskeng", "schtasks.exe",
})


def analyze_persistence(strings: List[str]) -> Dict[str, Any]:
    """
    Проверяет список строк на признаки путей автозагрузки.
    Возвращает: { "suspect": bool, "paths_found": [{"match": str, "category": str}], "summary": str }
    """
    result: Dict[str, Any] = {
        "suspect": False,
        "paths_found": [],
        "summary": "",
    }
    if not strings:
        return result

    seen: set = set()
    for s in (s for s in strings if isinstance(s, str) and len(s.strip()) > 4):
        low = s.lower().replace("/", "\\")
        for pattern, category in _PERSISTENCE_PATTERNS:
            if re.search(pattern, low):
                key = (low[:200], category)
                if key not in seen:
                    seen.add(key)
                    result["paths_found"].append({"match": s[:300], "category": category})

    if not result["paths_found"]:
        return result

    # Подозрительно, если есть совпадения и при этом не только легитимные системные контексты
    only_legit = all(
        any(leg in (m.get("match") or "").lower() for leg in _LEGIT_SYSTEM_HINTS)
        for m in result["paths_found"]
    )
    result["suspect"] = not only_legit
    categories = list({m["category"] for m in result["paths_found"]})
    result["summary"] = "Обнаружены пути автозагрузки: " + ", ".join(categories) if result["suspect"] else "Пути автозагрузки (системный контекст)"
    return result


def _normalize_registry_key_for_match(s: str) -> str:
    """Нормализация ключа реестра для сопоставления: нижний регистр, слэши в обратные."""
    if not s or not isinstance(s, str):
        return ""
    return s.lower().replace("/", "\\").strip()


def merge_persistence_with_vt(
    persistence_result: Dict[str, Any],
    vt_normalized_behavior: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """
    Кросс-верификация: если локально найденный ключ автозагрузки присутствует в VT
    normalized_behavior как изменённый реестр — помечаем путь как verified_by_vt: True.
    persistence_result модифицируется на месте и возвращается.
    """
    if not persistence_result or not vt_normalized_behavior:
        return persistence_result
    reg_modified = vt_normalized_behavior.get("registry_modified") or []
    vt_reg_set = {_normalize_registry_key_for_match(r) for r in reg_modified if r}
    if not vt_reg_set:
        return persistence_result
    paths_found = persistence_result.get("paths_found") or []
    verified_count = 0
    for item in paths_found:
        if not isinstance(item, dict):
            continue
        match = item.get("match") or ""
        norm = _normalize_registry_key_for_match(match)
        if not norm:
            continue
        # Совпадение: ключ из строк бинарника есть в списке изменённых VT
        if norm in vt_reg_set:
            item["verified_by_vt"] = True
            item["verified_by_behavior"] = True
            verified_count += 1
        else:
            # Частичное совпадение: любой из vt_reg содержит norm или наоборот
            for vt_key in vt_reg_set:
                if norm in vt_key or vt_key in norm:
                    item["verified_by_vt"] = True
                    item["verified_by_behavior"] = True
                    verified_count += 1
                    break
    persistence_result["verified_by_vt_count"] = verified_count
    persistence_result["any_verified_by_vt"] = verified_count > 0
    return persistence_result


def merge_persistence_with_emulation(
    persistence_result: Dict[str, Any],
    emulation_data: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """
    Если локально найденный ключ реестра подтверждается событием из emulation (registry),
    помечаем путь как verified_by_behavior: True.
    """
    if not persistence_result or not emulation_data:
        return persistence_result
    reg_list = emulation_data.get("registry") or []
    # emulation.registry может быть list of dict с ключами key/path/value или list of str
    emu_reg_set: set = set()
    for r in reg_list:
        if isinstance(r, str) and r.strip():
            emu_reg_set.add(_normalize_registry_key_for_match(r))
        elif isinstance(r, dict):
            for k in ("key", "path", "value"):
                v = r.get(k)
                if isinstance(v, str) and v.strip():
                    emu_reg_set.add(_normalize_registry_key_for_match(v))
                    break
    if not emu_reg_set:
        return persistence_result
    paths_found = persistence_result.get("paths_found") or []
    for item in paths_found:
        if not isinstance(item, dict):
            continue
        match = item.get("match") or ""
        norm = _normalize_registry_key_for_match(match)
        if not norm:
            continue
        if norm in emu_reg_set or any(norm in e or e in norm for e in emu_reg_set):
            item["verified_by_behavior"] = True
    return persistence_result
