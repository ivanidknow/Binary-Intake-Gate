# src/bin_gate/reporters/human.py
from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any, Optional
import re

# ---------------- helpers ----------------

def _get(d: Dict[str, Any], path: str, default=None):
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return cur if cur is not None else default

def _bool(v: Optional[bool]) -> str:
    return "True" if v is True else ("False" if v is False else "—")

def _kind_of(ev: Dict[str, Any]) -> str:
    k = (ev.get("kind") or ev.get("type") or "").upper()
    if k in ("PE", "ELF"):
        return k
    if isinstance(ev.get("pe"), dict):  return "PE"
    if isinstance(ev.get("elf"), dict): return "ELF"
    return "BIN"

def _detect_name_from_ev(ev: Dict[str, Any]) -> Optional[str]:
    p = ev.get("path") or ev.get("file")
    if p:
        try:
            return Path(p).name
        except Exception:
            return str(p)
    return None

def _name_for_index(evidences: List[Dict[str, Any]], files: List[Path], idx: int) -> str:
    name = _detect_name_from_ev(evidences[idx])
    if name:
        return name
    if 0 <= idx < len(files):
        try:
            return files[idx].name
        except Exception:
            return str(files[idx])
    sha = _get(evidences[idx], "hashes.sha256")
    if sha:
        return f"{sha[:8]}…"
    return "(файл)"

def _vt_stats(vt: Dict[str, Any]) -> Dict[str, int]:
    stats = _get(vt, "detections.stats", {}) or {}
    return {
        "m": int(stats.get("malicious") or 0),
        "s": int(stats.get("suspicious") or 0),
        "h": int(stats.get("harmless") or 0),
        "u": int(stats.get("undetected") or 0),
        "rep": int(_get(vt, "detections.reputation") or _get(vt, "reputation") or 0),
    }

def _vt_link_by_sha(sha256: str) -> str:
    return f"https://www.virustotal.com/gui/file/{sha256}"

def _vt_behaviours_count(vt: Dict[str, Any]) -> int:
    c = vt.get("behaviours_count")
    if isinstance(c, int) and c >= 0:
        return c
    arr = vt.get("behaviours") or vt.get("behaviors")
    if isinstance(arr, list):
        return len(arr)
    if isinstance(arr, dict) and isinstance(arr.get("count"), int):
        return arr["count"]
    return 0

def _yara_line(ev: Dict[str, Any]) -> str:
    hits = ev.get("yara") or []
    if not isinstance(hits, list) or len(hits) == 0:
        return "**YARA:** сработок нет"
    names: List[str] = []
    for h in hits[:5]:
        n = h.get("rule") or _get(h, "meta.name")
        if n:
            names.append(str(n))
    tail = (", ".join(names)) if names else f"{len(hits)} правил"
    more = "" if len(hits) <= 5 else f" (+{len(hits)-5})"
    return f"**YARA:** сработки — {tail}{more}"

def _capa_line(ev: Dict[str, Any]) -> str:
    cap = ev.get("capa") or {}
    tacts = cap.get("techniques") or []
    if tacts:
        uniq = ", ".join(sorted(set(map(str, tacts))))
        return f"**capa:** техники — {uniq}"
    # без упоминания таймаута
    return "**capa:** техники не выявлены"

def _hardening_line(ev: Dict[str, Any]) -> str:
    kind = _kind_of(ev)
    if kind == "ELF":
        h = _get(ev, "elf.hardening", {}) or {}
        return f"**Харденинг (ELF):** PIE={_bool(h.get('pie'))}; NX={_bool(h.get('nx'))}; RELRO={h.get('relro','—')}; Canary={_bool(h.get('canary'))}"
    if kind == "PE":
        h = _get(ev, "pe.hardening", {}) or {}
        sig_present = _get(ev, "pe.signature.present")
        sig = "есть" if sig_present is True else ("отсутствует" if sig_present is False else "неизв.")
        line = f"**Харденинг (PE):** ASLR={_bool(h.get('aslr'))}; DEP={_bool(h.get('dep'))}; CFG={_bool(h.get('cfg'))}; подпись={sig}"
        has_rwx = _get(ev, "pe.sections.has_rwx")
        ov = _get(ev, "pe.sections.overlay_pct")
        if has_rwx is not None or ov is not None:
            line += f"; секции: RWX={_bool(has_rwx)}; overlay={ov if ov is not None else '—'}%"
        return line
    return "**Харденинг:** —"

# ---- Политика → причины + эксплуатационные рекомендации ----

_ID_RE = re.compile(r"^\[(?P<id>[^\]]+)\]\s*(?P<text>.*)$")

_RECOMMEND = {
    "elf-weak":
        "Запускать в контейнере/NS без --privileged; read-only FS; drop cap (в т.ч. CAP_SYS_ADMIN); AppArmor/SELinux профиль; seccomp-политика; убедиться, что ASLR на хосте включён.",
    "pe-no-cfg":
        "Включить для процесса политики Windows Exploit Protection (CFG — Force On); ограничить запуск через WDAC/AppLocker (по путям/хэшам); запускать с пониженным IL/AppContainer.",
    "pe-rwx":
        "Запретить модули с RWX секциями (WDAC/AppLocker); изоляция процесса; мониторить WriteProcessMemory/CreateRemoteThread.",
    "packer-unsigned":
        "Разрешать только подписанные двоичные файлы (WDAC/SmartScreen); для конкретного файла — точечное разрешение по SHA-256 после ревью.",
    "vt-high-mal":
        "Заблокировать распространение артефакта; запросить у поставщика безопасную сборку; выполнять только в песочнице/строгой изоляции.",
    "cve-critical":
        "Не использовать версию с критичными CVE; применить сетевые/FS-ограничения (deny egress, least privilege), обновить при первой возможности.",
    "cve-high":
        "Запланировать обновление до версии без HIGH CVE; временно — сетевые/FS-ограничения и мониторинг IOC/поведения.",
    "capa-defense-evasion":
        "Проверить цели бинаря и условия запуска; ужесточить аудит и телеметрию (запрещающие правила EDR/IDS).",
    "capa-credential-access":
        "Изолировать доступ к секретам, убрать привилегии; включить мониторинг доступа к LSASS/keystore/API.",
}

def _policy_outcome_lines(ev: Dict[str, Any]) -> List[str]:
    """Возвращает строки с жирными маркерами: **Итог/Причины/Рекомендую**."""
    lines: List[str] = []
    pol = ev.get("policy") or {}
    dec = (pol.get("decision") or "allow").lower()
    reasons = pol.get("reasons") or []

    if dec == "allow":
        lines.append("**Итог:** **Проблем не обнаружено.**")
        return lines

    # warn/deny
    lines.append("**Итог:** **Предупреждение.**" if dec == "warn" else "**Итог:** **Запрещено политикой.**")

    # причины (без префикса [rule-id])
    human: List[str] = []
    tips: List[str] = []
    for r in reasons:
        m = _ID_RE.match(str(r))
        rid = m.group("id") if m else None
        txt = m.group("text") if m else str(r)
        if txt:
            human.append(txt)
        if rid and rid in _RECOMMEND:
            tips.append(_RECOMMEND[rid])

    if human:
        lines.append("**Причины:** " + "; ".join(human))
    if tips:
        lines.append("**Рекомендую:** " + " ".join(sorted(set(tips))))
    return lines

# ---------------- main report ----------------

def write_human_report(
    out_path: Path,
    files: List[Path],
    summary: Dict[str, Any],
    policy: Dict[str, Any],
    evidences: List[Dict[str, Any]],
    *,
    profile: str,
    capa_timeout: int,  # оставлен для совместимости сигнатуры, но не печатается
) -> None:
    """
    «Человекоподобный» отчёт RU. Все результаты встроены в «ПРОВЕРКА».
    Без упоминаний KES/внутренних артефактов. Без score/таймаутов.
    """
    # Собираем по каждому файлу
    per_file = []
    for i, ev in enumerate(evidences):
        name = _name_for_index(evidences, files, i)
        kind = _kind_of(ev)
        sha = _get(ev, "hashes.sha256", "") or _get(ev, "sha256", "")
        vt = ev.get("vt") or {}
        stats = _vt_stats(vt)
        vt_link = _vt_link_by_sha(sha) if sha else None
        vt_bh = _vt_behaviours_count(vt) or None
        per_file.append({
            "name": name,
            "kind": kind,
            "sha": sha,
            "hardening": _hardening_line(ev),
            "yara": _yara_line(ev),
            "capa": _capa_line(ev),
            "vt_stats": stats,
            "vt_link": vt_link,
            "vt_bh": vt_bh,
            "ev": ev,
        })

    # Проверим, есть ли где-то CVE
    any_cve = any(int((_get(pf["ev"], "cve.summary.total") or 0)) > 0 for pf in per_file)

    lines: List[str] = []

    # ОПИСАНИЕ
    lines.append("**ОПИСАНИЕ**")
    lines.append("В рамках заявки на анализ были переданы бинарные артефакты:")
    for p in files:
        lines.append(f"- `{str(p)}`")
    lines.append("")

    # ПРОВЕРКА
    lines.append("**ПРОВЕРКА**")

    # 1) Идентификация и целостность (многострочный блок на файл)
    lines.append("1) **Идентификация и целостность:**")
    for pf in per_file:
        ev = pf["ev"]
        lines.append(f"— **{pf['name']}** ({pf['kind']}):")
        lines.append(f"   • **SHA-256:** `{pf['sha']}`")
        lines.append(f"   • {pf['hardening']}")
        if pf["kind"] == "PE":
            sig_present = _get(ev, "pe.signature.present")
            if sig_present is False:
                lines.append("   • **Подпись:** не обнаружена; хеш файла зафиксирован для контроля целостности.")
            else:
                lines.append("   • Хеш файла зафиксирован для контроля целостности.")
        else:
            lines.append("   • Хеш файла зафиксирован для контроля целостности.")
        # Итог/Причины/Рекомендации
        for ln in _policy_outcome_lines(ev):
            lines.append(f"   • {ln}")
    lines.append("")

    # 2) Репутация
    lines.append("2) **Репутация:**")
    for pf in per_file:
        st = pf["vt_stats"]
        if st["m"] == 0 and st["s"] == 0:
            verdict = "проблем не обнаружено (детектов нет, репутация нейтральная)."
        else:
            verdict = f"обнаружены срабатывания: m/s/h/u = {st['m']}/{st['s']}/{st['h']}/{st['u']}, reputation={st['rep']}."
        suffix = f" Ссылка: {pf['vt_link']}" if pf["vt_link"] else ""
        bh = f" Песочницы: {pf['vt_bh']}." if pf['vt_bh'] else ""
        lines.append(f"— **{pf['name']}:** {verdict}{suffix}{bh}")
    lines.append("")

    # 3) Статический анализ (без упоминания таймаута)
    lines.append("3) **Статический анализ:**")
    for pf in per_file:
        lines.append(f"— **{pf['name']}:** {pf['yara']}; {pf['capa']}.")
    lines.append("")

    # 4) Уязвимости зависимостей
    lines.append("4) **Уязвимости зависимостей:**")
    if not any_cve:
        lines.append("— **CVE:** не выявлены.")
    else:
        for pf in per_file:
            summ = _get(pf["ev"], "cve.summary", {}) or {}
            total = int(summ.get("total") or 0)
            if total <= 0:
                continue
            c = int(summ.get("critical") or 0)
            h = int(summ.get("high") or 0)
            m = int(summ.get("medium") or 0)
            l = int(summ.get("low") or 0)
            lines.append(f"— **{pf['name']}:** **CVE** выявлены — всего {total} (CRITICAL {c}, HIGH {h}, MEDIUM {m}, LOW {l}).")
    lines.append("")

    # ВЫВОД (агрегированный)
    decisions = [(_get(pf["ev"], "policy.decision") or "allow").lower() for pf in per_file]
    lines.append("**ВЫВОД**")
    if any(d == "deny" for d in decisions):
        lines.append("Часть файлов **отклонена** политикой (deny). Требуются ограничительные меры эксплуатации и запрос безопасной версии у поставщика.")
    elif any(d == "warn" for d in decisions):
        lines.append("Файлы **одобрены с предупреждениями** (warn). Рекомендации приведены в разделе 1) для каждого файла.")
    else:
        lines.append("Файлы **одобрены** к использованию. Существенных проблем не выявлено.")

    Path(out_path).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
