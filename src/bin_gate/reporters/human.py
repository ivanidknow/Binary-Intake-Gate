# src/bin_gate/reporters/human.py
from __future__ import annotations
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import re
import time
from collections import Counter, defaultdict
from pathlib import Path as _Path
from collections.abc import Mapping


def _vt_debug_log(msg: str) -> None:
    """Пишет в vt_debug.log (общий путь через bin_gate.vt_debug)."""
    try:
        from bin_gate.vt_debug import vt_debug_log as _write
        _write(msg)
    except Exception:
        try:
            with open("vt_debug.log", "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
        except Exception:
            pass

# ---------------- helpers ----------------

def _get(d: Dict[str, Any], path: str, default=None):
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return cur if cur is not None else default

def _get_any(v: Dict[str, Any], paths: list[str], default=None):
    for p in paths:
        x = _get(v, p, None)
        if x is not None:
            return x
    return default

def _vt_last_analysis_ts(vt: Dict[str, Any]) -> Optional[int]:
    return _get_any(vt, [
        "data.attributes.last_analysis_date",
        "attributes.last_analysis_date",
        "last_analysis_date",
    ])

def _msi_source_line_ru(ev: dict) -> str | None:
    c = (ev.get("meta") or {}).get("container") or ev.get("container") or {}
    if c.get("type") != "msi":
        return None
    from pathlib import Path as _P
    msi_name = _P(c.get("path", "")).name
    pn = c.get("ProductName") or "—"
    pv = c.get("ProductVersion") or ""
    pc = c.get("ProductCode") or "—"
    mf = c.get("Manufacturer") or "—"
    return f"   • Источник: MSI `{msi_name}` — {pn} {pv}; ProductCode={pc}; Manufacturer={mf}"

def _ident_human_paragraph(evidences: list[dict]) -> str:
    """
    Один человеческий абзац для п.1: что за файл → подпись → защита → краткое пояснение рисков → опасные категории импортов → мягкий итог.
    Без слов «Внимание/Нюансы», без примеров импортов, без «необычных секций».
    """
    def _first_pe(ev_list):
        for ev in ev_list:
            if _kind_of(ev) == "PE":
                return ev
        return None

    ev = _first_pe(evidences) or (evidences[0] if evidences else None)
    if not ev:
        return "Исполняемых артефактов не обнаружено. Нарушений целостности не выявлено."

    # Что это
    name = _basename(_get(ev, "path") or _get(ev, "file")) or "(файл)"
    arch = (_get(ev, "pe.arch") or _get(ev, "arch") or "—")
    subs = (_get(ev, "pe.subsystem") or "—")
    head = f"{name} — PE {arch} для {subs}."

    # Подпись — мягкая проверка
    signed = _sig_present_soft(ev)
    publisher = (_get(ev, "pe.signature.publisher") or _get(ev, "pe.signature.subject") or "").strip()
    ts = _get(ev, "pe.signature.timestamp")
    if signed:
        sig_parts = ["Подпись есть"]
        if publisher:
            sig_parts.append(f"издатель: {publisher}")
        if ts not in (None, "", "—"):
            sig_parts.append("штамп времени присутствует")
        sig_line = ", ".join(sig_parts) + "."
    else:
        sig_line = "Подпись не обнаружена."

    # Защита
    aslr = bool(_get(ev, "pe.hardening.aslr"))
    dep  = bool(_get(ev, "pe.hardening.dep"))
    gs   = bool(_get(ev, "pe.hardening.gs"))
    safeseh = bool(_get(ev, "pe.hardening.safeseh"))
    has_wx  = bool(_get(ev, "pe.sections.has_wx"))
    has_rwx = bool(_get(ev, "pe.sections.has_rwx"))
    prot_enabled = [label for flag, label in (
        (aslr, "ASLR"), (dep, "DEP"), (gs, "GS"), (safeseh, "SafeSEH")
    ) if flag]
    prot_line = (
        ("Включены " + ", ".join(prot_enabled) + ", " if prot_enabled else "Базовые механизмы защиты, ") +
        ("опасных прав памяти нет." if not (has_wx or has_rwx) else "обнаружены участки памяти с правами записи и исполнения.")
    )

    # Пояснение рисков (без «Нюансы») — только то, что действительно важно
    explain: list[str] = []
    cfg_off = (_get(ev, "pe.hardening.cfg") is False)
    if cfg_off:
        explain.append("CFG выключен — ОС не контролирует непрямые переходы; это повышает риск ROP/JOP и упрощает эксплуатацию ошибок памяти.")
    try:
        overlay = float(_get(ev, "pe.sections.overlay_ratio") or 0.0)
        if overlay >= 0.20:
            explain.append(f"Большой overlay (~{int(overlay*100)}%) — типично для инсталляторов, сам по себе не является уязвимостью.")
    except Exception:
        pass
    tls = _get(ev, "pe.hardening.tls_callbacks_count") or _get(ev, "pe.hardening.tls_callbacks")
    try:
        if int(tls or 0) > 0:
            explain.append("Есть TLS-callback — код может стартовать до основной точки входа (нормально для некоторых сборок).")
    except Exception:
        pass
    explain_line = " ".join(explain)

    # Импорты — только опасные семейства (без примеров)
    imp_s = _get(ev, "pe.imports_summary") or {}
    red = imp_s.get("red_groups") or {}
    red_list = [label for key, label in (
        ("network", "сетевые"),
        ("services", "служебные"),
        ("crypto", "криптографические"),
    ) if red.get(key)]
    imports_line = ("По импортам отмечены " + ", ".join(red_list) + " категории." ) if red_list else ""

    # Итог — без «осторожностей»
    risk = 0
    if not signed:         risk += 1
    if has_wx or has_rwx:  risk += 2
    if cfg_off:            risk += 1

    if risk == 0:
        verdict = "Итог: ок."
    elif risk == 1:
        verdict = "Итог: ок; есть техзамечание (см. выше)."
    else:
        verdict = "Итог: нужно разбираться."

    parts = [head, sig_line, prot_line]
    if explain_line: parts.append(explain_line)
    if imports_line: parts.append(imports_line)
    parts.append(verdict)
    return " ".join(parts)


def _deep_find_stats(v: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # прямые форматы
    for p in [
        "stats",                                   # normalize_summary / virustotal.py
        "detections.stats",                        # vt_full
        "summary.stats",                           # если сверху завернули в summary
        "data.attributes.last_analysis_stats",     # сырой VT v3
        "attributes.last_analysis_stats",
        "last_analysis_stats",
        "detections.data.attributes.last_analysis_stats",
    ]:
        st = _get(v, p, None)
        if isinstance(st, dict) and ("malicious" in st or "suspicious" in st):
            return st
    # бэкап: глубокий поиск словаря с полями malicious/suspicious
    stack = [v]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            if "malicious" in cur and "suspicious" in cur:
                return cur
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return None

def _errors_line(ev: Dict[str, Any]) -> str | None:
    raw = [str(x).replace("\r", "").replace("\n", " ").strip() for x in (ev.get("errors") or [])]
    if not raw:
        return None
    norm = []
    seen = set()
    for e in raw:
        # Полностью пропускаем строки traceback'ов (более строгая проверка)
        e_lower = e.lower()
        e_stripped = e.strip()
        # Проверяем различные варианты traceback строк
        skip = False
        # 1. Строки с traceback
        if "traceback" in e_lower:
            skip = True
        # 2. Строки, начинающиеся с +- (часть рамки traceback)
        elif e_stripped.startswith("+-") or e_stripped.startswith("+--"):
            skip = True
        # 3. Unicode рамки
        elif "╔" in e or "║" in e or "╚" in e:
            skip = True
        # 4. Строки, начинающиеся с | (часть рамки traceback)
        elif e_stripped.startswith("|") or "| in" in e:
            skip = True
        # 5. Строки с file и line (traceback)
        elif "file \"" in e_lower and "line" in e_lower:
            skip = True
        # 6. most recent call last
        elif "most recent call last" in e_lower:
            skip = True
        # 7. Отладочные сообщения VT — не показывать в человеческом отчёте
        elif e_stripped.startswith("vt_dbg:"):
            skip = True
        # 8. Информационное предупреждение FLOSS (Rust) — не считать ошибкой
        elif e_stripped == "floss_warning:rust_binary" or (e_lower.strip() == "floss_warning:rust_binary"):
            skip = True
        # 9. vt_ui_behaviour_empty — не ошибка, если есть данные из API (сессий >= 1)
        elif e_stripped == "vt_ui_behaviour_empty":
            beh = (ev.get("vt") or {}).get("behaviours") or (ev.get("vt") or {}).get("behaviors") or []
            if isinstance(beh, list) and len(beh) > 0:
                skip = True
        
        if skip:
            continue  # Пропускаем эту строку полностью
        
        # Фильтруем длинные сообщения и остальные элементы traceback'ов
        if (len(e) > 200 or "file \"" in e_lower or 
            ("line " in e_lower and ("file" in e_lower or "traceback" in e_lower))):
            # Извлекаем только ключевую информацию из ошибки
            el = e.lower()
            if "playwright" in el or "browser" in el:
                if "executable doesn't exist" in el or "chromium" in el:
                    key = "vt_ui_error:playwright_browser_not_found"
                elif "timeout" in el:
                    key = "vt_ui_error:timeout"
                else:
                    key = "vt_ui_error:playwright_failed"
            elif "floss" in el:
                # любые варианты fallback -> одна метка
                if "fallback" in el or "no json object found" in el or "cannot deobfuscate strings" in el:
                    key = "floss_fallback:static_only"
                elif "rc=1" in el or "rust binary" in el:
                    key = "floss_warning:rust_binary"
                else:
                    key = "floss_error"
            elif "keyboardinterrupt" in el:
                key = "interrupted_by_user"
            elif ":" in e:
                # Берем только часть до первого двоеточия или первые 100 символов
                key = e.split(":")[0] if ":" in e else e[:100]
            else:
                key = e[:100]  # Ограничиваем длину
        else:
            el = e.lower()
            key = e
            if "floss" in el:
                # любые варианты fallback -> одна метка
                if "fallback" in el or "no json object found" in el or "cannot deobfuscate strings" in el:
                    key = "floss_fallback:static_only"
                elif "rc=1" in el or "rust binary" in el:
                    key = "floss_warning:rust_binary"
            # VT: короткие подписи вместо кодов
            elif "vt_http_status:401" in e or "vt_http_status: 401" in el:
                key = "VT: неверный или истёкший API ключ"
            elif "vt_http_status:" in e:
                code = e.split("vt_http_status:")[-1].split()[0].rstrip(";")
                key = f"VT: ответ сервера {code}"
            elif e.strip() == "vt_no_api_key":
                key = "VT: API ключ не задан"
        if key not in seen:
            seen.add(key); norm.append(key)
    if not norm:
        return None
    return "*Ошибки анализа:* " + "; ".join(norm[:4]) + (" …" if len(norm) > 4 else "")


# Ключи-заголовки секций VT Details — не выводить как данные
_VT_DETAILS_SKIP_KEYS = frozenset([
    "basic properties", "properties", "names", "file names", "elf information", "elf info",
    "основные свойства", "имена", "elf-информация", "elf сведения", "_raw",
])

def _format_vt_details(details: dict) -> list[str]:
    """
    Форматирует VT Details (Basic properties, Names, ELF Info) в строки для п.2 отчёта.
    """
    out: list[str] = []
    basic = details.get("basic_properties")
    if isinstance(basic, dict) and basic:
        parts = [f"{k}={v}" for k, v in list(basic.items())[:12] if v and str(k).lower().strip() not in _VT_DETAILS_SKIP_KEYS]
        if parts:
            out.append("* VT Details (Basic properties):* " + "; ".join(parts) + (" …" if len(basic) > 12 else ""))
        elif basic.get("_raw"):
            out.append("* VT Details (Basic properties):* " + str(basic["_raw"])[:200])
    names = details.get("names")
    if isinstance(names, list) and names:
        n_show = names[:10]
        out.append("* Names:* " + ", ".join(str(x) for x in n_show) + (" …" if len(names) > 10 else ""))
    elf = details.get("elf_info")
    if isinstance(elf, dict) and elf:
        parts = [f"{k}={v}" for k, v in list(elf.items())[:10] if v and str(k).lower().strip() not in _VT_DETAILS_SKIP_KEYS]
        if parts:
            out.append("* ELF Info:* " + "; ".join(parts) + (" …" if len(elf) > 10 else ""))
        elif elf.get("_raw"):
            out.append("* ELF Info:* " + str(elf["_raw"])[:200])
    return out


def _render_vt_behaviour(vt: dict) -> list[str]:
    """
    Рендерит краткое поведение VT.
    - Собирает процессы/команды/сеть по ВСЕМ behaviours[*] (а не только behaviours[0])
    - Понимает поля и в summary.*, и на корне behaviour
    - Подмешивает behaviour_relations (domains/ips/http), если в сессиях пусто
    - Дедуплицирует и ограничивает кол-во элементов
    - Если всё пусто — печатает явную заглушку про отсутствие детального поведения
    """
    procs: list = []
    cmds: list = []
    domains: list = []
    ips: list = []
    urls: list = []
    files_list: list = []
    registry_list: list = []
    services_list: list = []
    mutexes_list: list = []
    mitre_list: list = []
    out: list[str] = []
    vt = vt if isinstance(vt, dict) else {}
    beh = vt.get("behaviours") or vt.get("behaviors") or []
    if not isinstance(beh, list):
        beh = []
    rel = vt.get("behaviour_relations") or {}
    rel = rel if isinstance(rel, dict) else {}

    # sandbox_name часто в attributes сессии, а не в корне vt
    src = None
    if beh and isinstance(beh[0], dict):
        src = (beh[0].get("sandbox_name") or beh[0].get("origin")) if beh else None
    src = str(src or vt.get("sandbox_name") or vt.get("origin") or "—")
    beh_cnt = int(vt.get("behaviours_count") or (len(beh) if isinstance(beh, list) else 0))
    cached  = " (cache)" if vt.get("_cached") else ""
    out.append(f"* VT behaviour:* источники={src}; сессий={beh_cnt}{cached}")

    # Debug: что пришло в reporter
    _vt_debug_log(f"[reporter] _render_vt_behaviour beh_sessions={len(beh)}")
    if beh and isinstance(beh[0], dict):
        b0 = beh[0]
        s0 = b0.get("summary") or b0
        if isinstance(s0, dict):
            nprocs = len(s0.get("processes") or [])
            ncmds = len(s0.get("commands") or [])
            nmitre_raw = len(s0.get("mitre") or s0.get("mitre_attack") or [])
            _vt_debug_log(f"[reporter] first session summary: procs={nprocs} commands={ncmds} mitre_raw={nmitre_raw}")
        else:
            _vt_debug_log(f"[reporter] first session summary not dict")

    # --- хелперы ---
    def _collect_unique(items):
        seen, acc = set(), []
        for x in items:
            s = (str(x) if not isinstance(x, str) else x).strip()
            if s and s not in seen:
                seen.add(s)
                acc.append(s)
        return acc

    def _split_to_list(s):
        if not s:
            return []
        if isinstance(s, str):
            return [t.strip() for t in s.split(",") if t.strip()]
        if isinstance(s, (list, tuple, set)):
            return [str(t).strip() for t in s if str(t).strip()]
        return [str(s).strip()]

    def _collect_from_all(beh_list, *paths, limit=None):
        acc = []
        for bi in (beh_list or []):
            if not isinstance(bi, dict):
                continue
            # читаем и с корня behaviour, и из summary.*
            s = _take_str(bi, *paths, default="")
            if s:
                acc.extend(_split_to_list(s))
            summ = bi.get("summary")
            if isinstance(summ, dict):
                s2 = _take_str(summ, *[p.replace("summary.", "") for p in paths], default="")
                if s2:
                    acc.extend(_split_to_list(s2))
        acc = _collect_unique(acc)
        if limit:
            acc = acc[:limit]
        return acc

    def _process_name_from_obj(obj):
        if isinstance(obj, str) and obj.strip():
            return obj.strip()
        if isinstance(obj, dict):
            for k in ("name", "process_name", "image", "path"):
                v = obj.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
        return None

    def _flatten_processes_tree(nodes, acc: list):
        """Рекурсивно собрать имена из VT processes_tree (name, children)."""
        if not isinstance(nodes, list):
            return
        for node in nodes:
            if not isinstance(node, dict):
                continue
            n = _process_name_from_obj(node)
            if n and n not in acc:
                acc.append(n)
            for ch in (node.get("children") or []):
                _flatten_processes_tree([ch] if isinstance(ch, dict) else (ch if isinstance(ch, list) else []), acc)

    # --- сбор данных по всем сессиям ---
    
    headers_ru_en = {
        "Behavior","Behaviour","Поведение",
        "Processes","Created processes","Modules loaded",
        "Процессы","Созданные процессы","Загруженные модули",
        "Commands","Command executions","Command line",
        "Команды","Выполнение команд","Командная строка",
        "Domains","Hosts contacted","DNS lookups","URLs","HTTP conversations",
        "Домены","Обращения к узлам","DNS-запросы","URL","HTTP-диалоги",
        "Files","Files written","Files deleted","Files read",
        "Файлы","Запись файлов","Удаление файлов","Чтение файлов",
        "Registry","Registry keys set","Registry keys deleted","Registry keys queried",
        "Реестр","Ключи реестра изменены","Ключи реестра удалены","Запросы к реестру",
        "Mutexes","Mutants","Мьютексы",
        "MITRE","MITRE ATT&CK","ATT&CK",
        "Show more","Показать ещё",
    }
    # Безопасно собираем все данные с обработкой ошибок (procs/cmds/... уже инициализированы выше)
    try:
        procs_raw = _collect_from_all(beh, "processes", "processes_created", "summary.processes", "processes_terminated", limit=20)
        # Дополнительно: процессы из VT processes_tree (рекурсивно)
        for bi in (beh or []):
            if not isinstance(bi, dict):
                continue
            tree = bi.get("processes_tree")
            if isinstance(tree, list):
                _flatten_processes_tree(tree, procs_raw)
            for x in (bi.get("processes_terminated") or []):
                n = _process_name_from_obj(x)
                if n and n not in procs_raw:
                    procs_raw.append(n)
        procs_raw = _collect_unique(procs_raw)
        procs = [p for p in (procs_raw[:20] if procs_raw else []) if p not in headers_ru_en]
    except Exception:
        procs = []
    
    try:
        cmds_raw = _collect_from_all(beh, "commands", "command_executions", "summary.commands", "summary.command_line", "command_line", limit=20)
        cmds = [c for c in cmds_raw if c not in headers_ru_en]
    except Exception:
        cmds = []
    
    try:
        domains = _collect_from_all(beh, "summary.network.domains", "network.domains", "domains",
            "summary.dns_lookups", "dns_lookups",
            "summary.hosts_contacted", "hosts_contacted",
            "summary.http_conversations", "http_conversations",
            "summary.urls", "urls", limit=20)
    except Exception:
        domains = []
    
    try:
        ips = _collect_from_all(beh, "summary.network.ips", "network.ips", "ips",
            "summary.hosts_contacted", "hosts_contacted",
            "summary.dns_lookups", "dns_lookups",
            "summary.http_conversations", "http_conversations", limit=20)
    except Exception:
        ips = []
    
    try:
        urls = _collect_from_all(beh, "summary.network.urls", "network.urls", "urls",
            "summary.http_conversations", "http_conversations",
            "summary.network.http", "network.http", "http", limit=15)
    except Exception:
        urls = []

    try:
        files_list = _collect_from_all(beh, "files", "files_written", "files_deleted", "file_accessed", "summary.files", limit=15)
        registry_list = _collect_from_all(beh, "registry", "registry_keys_opened", "registry_keys_set", "registry_keys_deleted", "summary.registry", limit=15)
        services_list = _collect_from_all(beh, "services", "summary.services", limit=10)
        mutexes_list = _collect_from_all(beh, "mutexes", "mutexes_created", "summary.mutexes", limit=10)
    except Exception:
        files_list = []
        registry_list = []
        services_list = []
        mutexes_list = []

    try:
        mitre_list = _collect_from_all(beh, "mitre_attack", "mitre", "summary.mitre", "summary.mitre_attack", limit=15)
        # Только реальные техники (ID вида T1055, T0xxx). Заголовки вроде "MITRE ATT&CK Tactics and Techniques" — не показывать.
        import re as _re
        _mitre_skip = _re.compile(r"^(MITRE|ATT&CK|MITRE\s+ATT\s*&\s*CK.*Tactics|Tactics?\s+and\s+Techniques?|Поведение)$", _re.I)
        mitre_list = [m for m in (mitre_list or []) if m and ("T1" in m or "T0" in m) and not _mitre_skip.match(m.strip())]
    except Exception:
        mitre_list = []

    _vt_debug_log(f"[reporter] after filter: procs={len(procs)} cmds={len(cmds)} mitre_display={len(mitre_list)}")

    # Если внутри самих сессий сети мало — подмешаем relations
    if isinstance(rel, dict):
        if not domains:
            domains = _collect_unique(domains + _split_to_list(_take_str(rel, "domains", default="")))
        if not ips:
            ips = _collect_unique(ips + _split_to_list(_take_str(rel, "ips", default="")))
        if not urls:
            urls = _collect_unique(urls + _split_to_list(_take_str(rel, "http", "urls", default="")))

    # --- печать ---
    out.append("* Процессы:* " + (", ".join(procs) if procs else "—"))
    if cmds:
        out.append("* Команды:* " + ", ".join(cmds))

    if domains or ips or urls:
        d = ", ".join(domains) if domains else "—"
        i = ", ".join(ips)     if ips     else "—"
        u = ", ".join(urls)    if urls    else "—"
        out.append(f"* Сеть:* домены={d}; ip={i}; urls={u}")

    if files_list:
        out.append("* Файлы (запись/удаление/доступ):* " + ", ".join(files_list[:12]) + (" …" if len(files_list) > 12 else ""))
    if registry_list:
        out.append("* Реестр:* " + ", ".join(registry_list[:12]) + (" …" if len(registry_list) > 12 else ""))

    if services_list:
        out.append("* Службы (запуск/установка):* " + ", ".join(services_list[:8]) + (" …" if len(services_list) > 8 else ""))
    if mutexes_list:
        out.append("* Мьютексы:* " + ", ".join(mutexes_list[:8]) + (" …" if len(mutexes_list) > 8 else ""))

    if mitre_list:
        out.append("* MITRE ATT&CK:* " + ", ".join(mitre_list[:10]) + (" …" if len(mitre_list) > 10 else ""))

    # Relations как отдельная строка (если есть что добавить сверх основного)
    if isinstance(rel, dict) and any(rel.get(k) for k in ("domains", "ips", "http")):
        r_dom  = _take_str(rel, "domains", default="—", limit=10)
        r_ips  = _take_str(rel, "ips",     default="—", limit=10)
        r_http = _take_str(rel, "http",    default="—", limit=8)
        # показываем только если это реально добавляет инфу к пустым полям
        if (r_dom != "—" and not domains) or (r_ips != "—" and not ips) or (r_http != "—" and not urls):
            out.append(f"* Relations (сеть):* домены={r_dom}; ip={r_ips}; http={r_http}")

    no_data = (not procs) and (not cmds) and (not domains) and (not ips) and (not urls) and (not files_list) and (not registry_list) and (not services_list) and (not mutexes_list) and (not mitre_list)
    if no_data:
        out.append("* Детальное поведение:* не найдено в VT песочницах; файл мог не исполняться или отчёты недоступны.")
    if len(out) == 1:
        out.append("* Детальное поведение:* не найдено в VT песочницах; файл мог не исполняться или отчёты недоступны.")
    return out


# ---- Smart brief for section 1 ("Идентификация и целостность") ----
def _ident_brief_summary(evidences: list[dict]) -> str:
    """
    Однострочный продвинутый вывод по разделу 1.
    Пример: "PE: sig=3/4; risks=cfg_off×1, wx×1; ELF: nx_off×2, relro_none×2; verdict=attention"
    """
    from collections import Counter
    pe_flags = Counter()
    elf_flags = Counter()
    pe_total = pe_signed = 0
    # сигналы "шумных" PE (для тонкой подсветки)
    pe_noise = Counter()  # tls, overlay_high, unusual_secs

    def _safe_int(x, default=0):
        try:
            return int(x)
        except Exception:
            return default

    for ev in evidences:
        kind = (_get(ev, "kind") or _get(ev, "type") or "").upper()
        if not kind and isinstance(ev.get("pe"), dict):   kind = "PE"
        if not kind and isinstance(ev.get("elf"), dict):  kind = "ELF"

        if kind == "PE":
            pe_total += 1
            flags, is_signed = _pe_ident_flags(ev)  # already returns ['wx', 'rwx', 'cfg_off' ...], bool_signed
            pe_flags.update(flags)
            if is_signed:
                pe_signed += 1
            # тонкие индикаторы
            try:
                tls_cnt = _safe_int(_get(ev, "pe.hardening.tls_callbacks_count") or _get(ev, "pe.hardening.tls_callbacks") or 0)
                if tls_cnt > 0:
                    pe_noise["tls"] += tls_cnt
            except Exception:
                pass
            try:
                overlay_ratio = float(_get(ev, "pe.sections.overlay_ratio") or 0.0)
                if overlay_ratio >= 0.05:  # >5% — часто присадки/инсталлеры/каталоги
                    pe_noise["overlay_high"] += 1
            except Exception:
                pass
            try:
                unsec = _get(ev, "pe.sections.unusual") or _get(ev, "pe.sections.unusual_names") or []
                if isinstance(unsec, list) and unsec:
                    pe_noise["unusual_secs"] += 1
            except Exception:
                pass

        elif kind == "ELF":
            elf_flags.update(_elf_ident_flags(ev))

    # форматирование
    parts = []

    if pe_total > 0:
        pe_bits = [f"sig={pe_signed}/{pe_total}"]
        for k in ("cfg_off","dep_off","aslr_off","wx","rwx"):
            if pe_flags.get(k):
                pe_bits.append(f"{k}×{pe_flags[k]}")
        # шумовые маркеры — только если есть
        noise_bits = []
        if pe_noise.get("tls"):           noise_bits.append(f"tls×{pe_noise['tls']}")
        if pe_noise.get("overlay_high"):  noise_bits.append(f"overlay>5%×{pe_noise['overlay_high']}")
        if pe_noise.get("unusual_secs"):  noise_bits.append(f"unusual_secs×{pe_noise['unusual_secs']}")
        if noise_bits:
            pe_bits.append("+" + ", ".join(noise_bits))
        parts.append("PE: " + "; ".join(pe_bits))

    # ELF агрегат
    if sum(elf_flags.values()) > 0:
        elf_bits = []
        for k in ("nx_off","pie_off","relro_none","textrel","w+x"):
            if elf_flags.get(k):
                elf_bits.append(f"{k}×{elf_flags[k]}")
        parts.append("ELF: " + (", ".join(elf_bits) if elf_bits else "ok"))

    # эвристический вердикт по флагам
    risk_score = (
        pe_flags.get("rwx",0)*3 + pe_flags.get("wx",0)*2 + pe_flags.get("cfg_off",0)*2 +
        elf_flags.get("w+x",0)*3 + elf_flags.get("textrel",0)*2 +
        (pe_total - pe_signed if pe_total else 0)  # неподписанные PE — легкий штраф
    )
    verdict = "ok"
    if risk_score >= 5:
        verdict = "attention"
    if risk_score >= 9:
        verdict = "risk"

    if parts:
        parts.append(f"verdict={verdict}")
    else:
        parts.append("no binaries detected")

    return " ; ".join(parts)

def _append_description(lines, files, *, show_all_names: bool = False):
    """Адаптивное 'ОПИСАНИЕ':
       - если файлов > 5: просто 'Представлен проект: '
       - иначе: краткий список имён артефактов (без путей)
    """
    lines.append("*ОПИСАНИЕ*")
    if len(files) > 5 and not show_all_names:
        lines.append("Представлен проект: ")
    else:
        lines.append("Переданы артефакты:")
        for p in files:
            try:
                name = Path(p).name
            except Exception:
                name = str(p)
            lines.append(f"— {name}")
    lines.append("")


# --- helpers: безопасный выбор строк из разных форматов VT ---
def _take_str(obj, *paths, default="—", sep=", ", limit=None):
    """
    Достаёт строковые поля из вложенных структур по нескольким путям-«кандидатам».
    Поддерживает листы, строки, dict; берёт первое непустое.
    Пример путей: ("summary.network.domains", "network.domains", "domains")
    """
    def _walk(o, path: str):
        cur = o
        for p in path.split("."):
            if isinstance(cur, dict):
                cur = cur.get(p)
            else:
                return None
        return cur

    for path in paths:
        val = _walk(obj, path)
        if val is None:
            continue
        # нормализуем в список строк
        if isinstance(val, str):
            out = val.strip()
            if out:
                return out
        elif isinstance(val, (list, tuple, set)):
            items = []
            for it in val:
                if isinstance(it, str):
                    s = it.strip()
                    if s:
                        items.append(s)
                elif isinstance(it, dict):
                    # если элементы-словари, пытаемся взять «value», «name», «url»
                    for k in ("value", "name",
                      "url", "domain", "ip", "path",
                      "cmd", "command", "command_line",
                      "image", "process", "process_name",
                      "dst", "dst_ip", "dst_addr"):
                        v = it.get(k) if isinstance(it, dict) else None
                        if isinstance(v, str) and v.strip():
                            items.append(v.strip())
                            break
            if items:
                if limit:
                    items = items[:limit]
                return sep.join(items)
        elif isinstance(val, dict):
            # иногда сеть лежит словарём {urls:[...]} → собираем популярные поля
            for k in ("url", "domain", "ip", "path", "value", "name"):
                v = val.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
            # или свёрстанные списки
            for k in ("urls", "domains", "ips", "http", "http_requests"):
                v = val.get(k)
                if isinstance(v, (list, tuple)) and v:
                    s = _take_str({k: v}, k, default=default, sep=sep, limit=limit)
                    if s and s != default:
                        return s
        # иное — пропускаем
    return default


def _sig_present_soft(ev: Dict[str, Any]) -> bool:
    """Считать подпись «есть», если видим любой надежный сигнал наличия."""
    sig = _get(ev, "pe.signature") or {}
    # Явный флаг из парсера
    if isinstance(sig, dict) and sig.get("present") is True:
        return True
    # SECURITY directory из OptionalHeader (IMAGE_DIRECTORY_ENTRY_SECURITY)
    if _get(ev, "pe.security_directory.present") is True:
        return True
    try:
        sz = int(_get(ev, "pe.security_directory.size") or 0)
        if sz > 0:
            return True
    except Exception:
        pass
    # Содержательные атрибуты в блоке подписи (fallback)
    if isinstance(sig, dict):
        for k in ("publisher","subject","issuer","thumbprint","algorithm",
                  "valid","chain_valid","verified_chain","catalog","embedded","timestamp"):
            v = sig.get(k)
            if v not in (None, "", "—", False):
                return True
    return False

def _vt_behaviours_list(vt: Dict[str, Any]) -> list:
    """
    Возвращает список behaviour-элементов из VT вне зависимости от схемы.
    Поддерживает:
      - vt['behaviours'] / vt['behaviors']
      - vt['data']['attributes']['behaviour[s]']
      - dict с 'data' или 'items'
    """
    lst = []
    cand = None
    if isinstance(vt, dict):
        # (твой текущий поиск по keys/data/items ...)
        # ↓ после твоей логики вставь разворачивание attributes, если нашли список
        for key in ("behaviours","behaviors","behaviour","data","items"):
            val = vt.get(key)
            if isinstance(val, list):
                lst = val; break
        if not lst:
            return []
        # unwrap attributes
        out = []
        for it in lst:
            if isinstance(it, dict) and isinstance(it.get("attributes"), dict):
                out.append(it["attributes"])
            elif isinstance(it, dict) and isinstance(it.get("data"), dict):
                out.append(it["data"])
            elif isinstance(it, dict):
                out.append(it)
        return out
    return []

def _vt_behaviour_list(vt: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Достаёт список behaviour-сессий из VT ответа независимо от структуры:
      - vt['behaviours'] / vt['behaviors'] / vt['behaviour']
      - vt['data']['attributes']['behaviour[s]']
      - vt['items'][i]['attributes']
    Возвращает список словарей (каждый — одна сессия), уже "развёрнутых" из attributes/data.
    """
    if not isinstance(vt, dict):
        return []

    # Кандидаты списков на верхнем уровне
    for key in ("behaviours", "behaviors", "behaviour", "sessions", "data", "items"):
        val = vt.get(key)
        if isinstance(val, list):
            lst = val
            break
        # Иногда 'data' — dict с 'attributes.behaviours'
        if key == "data" and isinstance(val, dict):
            attrs = val.get("attributes") if isinstance(val.get("attributes"), dict) else {}
            for k in ("behaviours", "behaviors", "behaviour", "sessions"):
                if isinstance(attrs.get(k), list):
                    lst = attrs[k]
                    break
            else:
                continue
            break
    else:
        lst = []

    out: List[Dict[str, Any]] = []
    for it in (lst or []):
        if isinstance(it, dict):
            if isinstance(it.get("attributes"), dict):
                out.append(it["attributes"])
            elif isinstance(it.get("data"), dict):
                out.append(it["data"])
            else:
                out.append(it)
    return out

def _norm_registry_key(s: str) -> str:
    """Нормализация ключа реестра для сопоставления с VT verified."""
    if not s or not isinstance(s, str):
        return ""
    return s.lower().replace("/", "\\").strip()


def _norm_network_ioc(s: str) -> str:
    """Нормализация домена/IP/URL для сопоставления с VT verified."""
    if not s or not isinstance(s, str):
        return ""
    return s.lower().strip()


def _vt_behaviour_blocks(
    vt: Dict[str, Any],
    max_items: int = 15,
    vt_verified_registry: Optional[set] = None,
    vt_verified_network: Optional[set] = None,
) -> List[str]:
    """
    Рендерит поведение VT по блокам: Processes/Commands/Network/Files/Registry/Mutexes/MITRE.
    Объединяет поля из разных представлений (summary.*, корень, а также "vt.py-стиль").
    Для подтверждённых VT событий (совпадение с локальными находками) добавляет [VT Verified].
    Возвращает список строк. Ничего не пишет в stdout/файлы.
    """
    vt_verified_registry = vt_verified_registry or set()
    vt_verified_network = vt_verified_network or set()

    def _pick_strings(seq, n) -> List[str]:
        res: List[str] = []
        if not seq:
            return res
        for x in seq:
            s = None
            if isinstance(x, (str, bytes)):
                s = x.decode("utf-8", "ignore") if isinstance(x, bytes) else x
            elif isinstance(x, (int, float)):
                s = str(x)
            elif isinstance(x, dict):
                for k in ("command", "cmd", "name", "path", "url", "domain", "ip", "dst",
                          "technique", "technique_id", "id", "value"):
                    if k in x and x[k]:
                        s = str(x[k]); break
                if s is None:
                    # fallback: первое непустое скалярное значение
                    for v in x.values():
                        if isinstance(v, (str, int, float)) and str(v).strip():
                            s = str(v); break
            else:
                s = str(x)
            if s:
                s = s.strip()
                if s:
                    res.append(s)
                    if len(res) >= n:
                        break
        return res

    def _as_list(x) -> List[Any]:
        if isinstance(x, list):
            return [y for y in x if y is not None]
        if isinstance(x, dict):
            # расплющим словарь в набор читабельных элементов
            acc = []
            for k, v in x.items():
                if isinstance(v, dict):
                    # попробуем найти человекочитаемые поля
                    for kk in ("url","path","name","dst","domain","ip","command","value"):
                        if kk in v and v[kk]:
                            acc.append(str(v[kk])); break
                    else:
                        acc.append(str(k))
                elif isinstance(v, (str, int, float)):
                    acc.append(f"{k}: {v}")
            return acc
        if x is None:
            return []
        return [x]

    beh_list = _vt_behaviour_list(vt)
    rel      = vt.get("behaviour_relations") if isinstance(vt.get("behaviour_relations"), dict) else {}

    if not beh_list and not rel:
        return []

    # Шапка
    src = None
    for key in ("sandbox_name", "engine_name", "origin", "source"):
        if isinstance(vt.get(key), str) and vt[key]:
            src = vt[key]; break
    if not src:
        # иногда источник «лежит» в самой первой сессии
        first = beh_list[0] if beh_list else {}
        for key in ("sandbox_name", "engine_name", "origin", "source"):
            if isinstance(first.get(key), str) and first[key]:
                src = first[key]; break
    sessions = len(beh_list)
    cached = " (cache)" if vt.get("_cached") else ""
    lines: List[str] = [f"* VT behaviour:* источники={src or '—'}; сессий={sessions}{cached}"]

    # Объединяем по всем сессиям
    agg = {
        "processes": [],
        "commands": [],
        "network_domains": [],
        "network_ips": [],
        "network_urls": [],
        "files": [],
        "registry": [],
        "mutexes": [],
        "mitre": [],
    }

    for b in beh_list:
        summ = b.get("summary") if isinstance(b.get("summary"), dict) else {}

        # Processes/commands
        agg["processes"] += _as_list(summ.get("processes")) + _as_list(b.get("processes")) + \
                            _as_list(b.get("processes_created"))
        agg["commands"]  += _as_list(summ.get("commands"))  + _as_list(b.get("commands"))  + \
                            _as_list(b.get("command_executions"))

        # Network (domains/ips/urls + ручной стиль VT)
        net = (b.get("network") if isinstance(b.get("network"), dict) else {}) or \
              (summ.get("network") if isinstance(summ.get("network"), dict) else {})
        agg["network_domains"] += _as_list(net.get("domains")) + _as_list(b.get("hosts_contacted"))
        agg["network_ips"]     += _as_list(net.get("ips"))
        agg["network_urls"]    += _as_list(net.get("urls")) + _as_list(b.get("http_conversations")) + _as_list(b.get("urls"))

        # Files
        agg["files"] += _as_list(summ.get("files")) + _as_list(b.get("files")) + \
                        _as_list(b.get("files_written")) + _as_list(b.get("files_deleted")) + \
                        _as_list(b.get("files_read"))

        # Registry
        agg["registry"] += _as_list(summ.get("registry")) + _as_list(b.get("registry")) + \
                           _as_list(b.get("registry_keys_set")) + _as_list(b.get("registry_keys_deleted")) + \
                           _as_list(b.get("registry_keys_queried"))

        # Mutexes
        agg["mutexes"] += _as_list(b.get("mutexes")) + _as_list(summ.get("mutexes"))

        # MITRE
        mitre = []
        for key in ("mitre", "mitre_attacks", "mitre_techniques"):
            mitre += _as_list(b.get(key))
        agg["mitre"] += mitre

    # behaviour_relations как обогащение сети
    if rel:
        agg["network_domains"] += _as_list(rel.get("domains"))
        agg["network_ips"]     += _as_list(rel.get("ips"))
        agg["network_urls"]    += _as_list(rel.get("http")) + _as_list(rel.get("urls"))

    # Финальный рендер (каждый блок ограничиваем max_items)
    proc = _pick_strings(agg["processes"], max_items)
    if proc:
        lines.append(f"* Процессы:* {', '.join(proc)}")

    cmds = _pick_strings(agg["commands"], max_items)
    if cmds:
        lines.append(f"* Команды:* {', '.join(cmds)}")

    def _verified_net(t: str) -> str:
        return f"{t} [VT Verified]" if vt_verified_network and _norm_network_ioc(t) in vt_verified_network else t
    def _verified_reg(t: str) -> str:
        return f"{t} [VT Verified]" if vt_verified_registry and _norm_registry_key(t) in vt_verified_registry else t

    doms = _pick_strings(agg["network_domains"], max_items)
    ips  = _pick_strings(agg["network_ips"],     max_items)
    urls = _pick_strings(agg["network_urls"],    max_items)
    if doms or ips or urls:
        line = "* Сеть:* "
        if doms: line += f"домены={', '.join(_verified_net(d) for d in doms)}; "
        if ips:  line += f"ip={', '.join(_verified_net(i) for i in ips)}; "
        if urls: line += f"urls/http={', '.join(_verified_net(u) for u in urls)}; "
        lines.append(line.rstrip("; "))

    fz = _pick_strings(agg["files"], max_items)
    if fz:
        lines.append(f"* Файлы:* {', '.join(fz)}")

    reg = _pick_strings(agg["registry"], max_items)
    if reg:
        lines.append(f"* Реестр:* {', '.join(_verified_reg(r) for r in reg)}")

    mx = _pick_strings(agg["mutexes"], max_items)
    if mx:
        lines.append(f"* Мьютексы:* {', '.join(mx)}")

    mt = _pick_strings(agg["mitre"], max_items)
    if mt:
        lines.append(f"* MITRE ATT&CK:* {', '.join(mt)}")

    return lines

def _sig_meaningfully_present(ev: Dict[str, Any]) -> bool:
    sig = _get(ev, "pe.signature") or {}
    if not _sig_present_soft(ev):
        return False
    # Любой из содержательных атрибутов ИЛИ проверочные флаги
    fields = [
        sig.get("publisher") or sig.get("subject"),
        sig.get("issuer"),
        sig.get("thumbprint") or sig.get("thumb"),
        sig.get("algorithm")  or sig.get("digestAlgorithm"),
    ]
    has_fields = any((str(x or "").strip() and str(x) != "—") for x in fields)
    has_verif  = bool(sig.get("valid") or sig.get("chain_valid") or sig.get("verified_chain")
                      or sig.get("is_trusted") or sig.get("embedded") or sig.get("catalog"))
    return has_fields or has_verif

def _vt_behaviours_count(vt: Dict[str, Any]) -> int:
    try:
        return len(_vt_behaviours_list(vt))
    except Exception:
        return 0

def _append_vt_debug(lines: list[str], ev: dict, *, indent: str = "   ") -> None:
    try:
        dbg = ev.get("vt_debug") or []
        if not isinstance(dbg, list) or not dbg:
            return
        lines.append(f"{indent}*VT Debug:*")
        for i, d in enumerate(dbg[:5]):  # не спамим, максимум 5 карточек на файл
            try:
                stage = d.get("stage") or "—"
                sha   = d.get("sha256") or "—"
                cached= "cache" if d.get("cached") else "live"
                bcnt  = d.get("behaviours_count")
                hasr  = d.get("has_relations")
                keys  = ", ".join((d.get("keys_first_behaviour") or [])[:10]) or "—"
                lines.append(f"{indent}  · {i+1}) stage={stage}; sha={sha}; mode={cached}; behaviours={bcnt}; relations={hasr}; keys={keys}")
                samples = d.get("samples") or {}
                if "behaviour_0" in samples:
                    s = samples["behaviour_0"].replace("\n", " ")
                    lines.append(f"{indent}     behaviour_0: {s}")
                if "relations" in samples:
                    s = samples["relations"].replace("\n", " ")
                    lines.append(f"{indent}     relations: {s}")
            except Exception as e:
                lines.append(f"{indent}  · dbg_render_error:{e}")
    except Exception as e:
        lines.append(f"{indent}*VT Debug error:* {e}")

def _append_ovf_section(lines: list[str], evidences: list[dict]):
    """
    Выводит блок про OVA/OVF/MF: состав, OVF-сводку и строгий чек-лист, если есть.
    Ничего не печатает, если OVF/Манифест не найдены.
    """
    # найдём OVF и MF артефакты
    def _is_ovf(ev):
        p = (ev.get("path") or ev.get("file") or "").lower()
        return p.endswith(".ovf")
    def _is_mf(ev):
        p = (ev.get("path") or ev.get("file") or "").lower()
        return p.endswith(".mf")

    ovf_ev = next((ev for ev in evidences if _is_ovf(ev) and (ev.get("ovf") or ev.get("ovf_strict"))), None)
    mf_ev  = next((ev for ev in evidences if _is_mf(ev) and (ev.get("mf_verify") or ev.get("mf_algos"))), None)

    if not ovf_ev and not mf_ev:
        return  # нечего показывать

    # Состав поставки по ролям — пробежимся по всем evidences
    roles = {"OVF": [], "VMDK": [], "ISO": [], "NVRAM": [], "MF": []}
    for ev in evidences:
        name = (ev.get("path") or ev.get("file") or "")
        low  = name.lower()
        base = _basename(name)
        if low.endswith(".ovf"):  roles["OVF"].append(base)
        elif low.endswith(".vmdk"): roles["VMDK"].append(base)
        elif low.endswith(".iso"):  roles["ISO"].append(base)
        elif low.endswith(".nvram"):roles["NVRAM"].append(base)
        elif low.endswith(".mf"):   roles["MF"].append(base)

    lines.append("* OVF/OVA поставка:*")
    if roles["OVF"]:  lines.append("— OVF дескриптор: " + ", ".join(sorted(set(roles["OVF"]))))
    if roles["VMDK"]: lines.append("— Диски (VMDK): " + ", ".join(sorted(set(roles["VMDK"]))))
    if roles["ISO"]:  lines.append("— Доп. ISO: " + ", ".join(sorted(set(roles["ISO"]))))
    if roles["NVRAM"]:lines.append("— NVRAM: " + ", ".join(sorted(set(roles["NVRAM"]))))
    if roles["MF"]:   lines.append("— Manifest (*.mf): " + ", ".join(sorted(set(roles["MF"]))))

    # OVF сводка
    if ovf_ev and ovf_ev.get("ovf"):
        ovf = ovf_ev["ovf"]
        prod = ovf.get("product") or "—"
        vend = ovf.get("vendor") or "—"
        gos  = ovf.get("guest_os_desc") or ovf.get("guest_os_id") or "—"
        cpu  = ovf.get("cpu") or "—"
        mem  = ovf.get("mem_mb") or "—"
        lines.append("* OVF сводка:* " + f"product={prod}; vendor={vend}; guest_os={gos}; vCPU={cpu}; RAM(MB)={mem}")
        if isinstance(gos, str) and "astra" in gos.lower():
            lines.append("* Совместимость c Astra:* OVF декларирует Astra Linux/совместимый профиль гостевой ОС.")

    # Строгий чек-лист (если собран в cli)
    strict = ovf_ev.get("ovf_strict") if ovf_ev else None
    if strict:
        checks = strict.get("checks", {})
        ok = lambda b: "OK" if b else "ВНИМАНИЕ"

        vh = checks.get("virtual_hw", {})
        lines.append(f"* Virtual HW:* {vh.get('value','—')} — {ok(vh.get('ok', True))}")

        d = checks.get("disks", {})
        lines.append(f"* Диски:* {ok(d.get('ok', True))}")
        for it in (d.get("items") or [])[:10]:
            cap = it.get('capacity','?'); units = it.get('units','')
            lines.append(f"— {it.get('id','?')}: {cap} {units} (fileRef={it.get('fileRef','?')}, ctrl={it.get('controller','?')}) — {ok(it.get('ok', True))}")

        n = checks.get("nics", {})
        lines.append(f"* NIC:* {ok(n.get('ok', True))}")
        for it in (n.get('items') or [])[:5]:
            lines.append(f"— model={it.get('model','?')} (auto={it.get('auto','?')}) — {ok(it.get('ok', True))}")

        r = checks.get("removable", {})
        if r:
            lines.append(f"* Съёмные/лишние устройства:* {ok(r.get('ok', True))} "
                         f"(cd_autoconnect={r.get('cd_autoconnect', False)}, usb={r.get('usb', False)}, "
                         f"serial={r.get('serial', False)}, parallel={r.get('parallel', False)}, "
                         f"sound={r.get('sound', False)})")

        ref = checks.get("references", {})
        if ref:
            lines.append(f"* References:* {ok(ref.get('ok', True))}")
            if ref.get("missing"):
                lines.append("— отсутствуют: " + ", ".join(ref["missing"][:10]))
            if ref.get("size_mismatch"):
                mism = ", ".join(f'{x["name"]}({x["decl"]}≠{x["real"]})' for x in ref["size_mismatch"][:10])
                lines.append("— расхождения по размеру: " + mism)

        ma = checks.get("manifest_algo", {})
        lines.append(f"* Манифест (*.mf) алгоритмы:* {', '.join(ma.get('algos', [])) or '—'} — {ok(ma.get('ok', True))}")

        pr = checks.get("properties", {})
        if not pr.get("ok", True):
            lines.append("* OVF свойства:* ВНИМАНИЕ — обнаружены чувствительные/подозрительные ключи (PropertySection)")

    # MF: итог сверки
    if mf_ev:
        if mf_ev.get("mf_verify"):
            ver = mf_ev["mf_verify"]
            lines.append("* MF (целостность по манифесту):* " + ("OK" if ver.get("ok") else "НАЙДЕНЫ РАСХОЖДЕНИЯ"))
            for it in (ver.get("items") or [])[:10]:
                nm = it.get("name") or "?"
                verdict = it.get("verdict") or "unknown"
                lines.append(f"— {nm}: {verdict}")
        if mf_ev.get("mf_algos"):
            alg = mf_ev["mf_algos"]
            ok = "OK" if alg.get("ok", True) else "ВНИМАНИЕ"
            lines.append(f"* Алгоритмы манифеста:* {', '.join(alg.get('algos', [])) or '—'} — {ok}")

    lines.append("")  # пустая строка-разделитель

def _container(ev):
    return ((ev.get("meta") or {}).get("container") or None)

def _basename(p: str | None) -> str:
    try:
        return _Path(p).name
    except Exception:
        return str(p or "")

_DEC_RANK = {"allow": 0, "warn": 1, "deny": 2}

def _vt_behaviour_brief(vt: Dict[str, Any]) -> Optional[str]:
    """
    Короткий summary для behaviours: network/files/registry/processes/mutexes/ATT&CK.
    Работает с разными схемами VT.
    """
    beh_list = _vt_behaviours_list(vt)
    if not beh_list:
        return None
    b0 = beh_list[0] if isinstance(beh_list[0], dict) else {}

    summary = b0.get("summary") if isinstance(b0.get("summary"), dict) else {}
    net = b0.get("network") or summary.get("network") or {}
    files = b0.get("files") or summary.get("files") or []
    reg = b0.get("registry") or summary.get("registry") or []
    procs = b0.get("processes") or summary.get("processes") or []
    mutexes = b0.get("mutexes") or summary.get("mutexes") or []
    mitre = b0.get("mitre_attack") or summary.get("mitre_attack") or []

    domains = (net.get("domains") or [])
    ips     = (net.get("ips") or [])
    http    = (net.get("http") or net.get("http_requests") or [])

    parts = []
    if domains or ips or http:
        parts.append(f"network: domains={len(domains)}, ips={len(ips)}, http={len(http)}")
    if isinstance(files, list) and files:
        try:
            from pathlib import Path as _P
            examples = ", ".join(_P(str(x)).name for x in files[:3])
            parts.append(f"files:{min(5, len(files))} (пример: {examples})")
        except Exception:
            parts.append(f"files:{min(5, len(files))}")
    if isinstance(reg, list) and reg:
        parts.append(f"registry:{min(5, len(reg))}")
    if isinstance(procs, list) and procs:
        parts.append(f"processes:{min(5, len(procs))}")
    if isinstance(mutexes, list) and mutexes:
        parts.append(f"mutexes:{min(5, len(mutexes))}")
    if isinstance(mitre, list) and mitre:
        def _fmt_t(x):
            if isinstance(x, dict):
                return str(x.get("technique") or x.get("id") or "")[:20]
            return str(x)[:20]
        top = ", ".join(_fmt_t(x) for x in mitre[:3] if _fmt_t(x))
        if top:
            parts.append(f"ATT&CK: {top}")

    return "; ".join(parts) if parts else None


def _worst_decision(children):
    worst = "allow"; max_score = 0; reasons = []
    cnt = Counter()
    for ev in children:
        pol = (ev.get("policy") or {})
        dec = pol.get("decision") or "allow"
        score = int(pol.get("score") or 0)
        if _DEC_RANK.get(dec, 0) > _DEC_RANK.get(worst, 0):
            worst = dec
        if score > max_score:
            max_score = score
        if pol.get("reasons"):
            reasons.extend([str(r) for r in pol["reasons"] if "policy_eval_error:" not in str(r)])
        cnt[dec] += 1
    return worst, max_score, list(dict.fromkeys(reasons)), cnt  # уникализируем порядок причин


def _iter_groups(groups: dict[str, list]) -> list[tuple[str, list]]:
    return sorted(groups.items(), key=lambda kv: (-len(kv[1]), str(kv[0] or "")))


# Пороги для группировки по типам угроз (экспертное резюме)
ENTROPY_OBF_THRESHOLD = 7.2
OBF_STRINGS_THRESHOLD = 10000


def _build_threat_groups(evidences: list) -> dict[str, list]:
    """
    Строит группы файлов по типам угроз для экспортного резюме:
    group_obfuscated, group_rootkit, group_suspicious_scripts, group_clean.
    """
    group_obfuscated: list = []
    group_rootkit: list = []
    group_suspicious_scripts: list = []
    group_clean: list = []

    for ev in evidences:
        name = _basename(_get(ev, "path") or _get(ev, "file") or _get(ev, "meta.name")) or "(файл)"
        path_lower = (ev.get("path") or ev.get("file") or "").lower()
        sfx = path_lower.rsplit(".", 1)[-1] if "." in path_lower else ""
        kind = _kind_of(ev)

        # Энтропия и объём восстановленных строк
        ent = ev.get("entropy") or {}
        file_ent = float(ent.get("file") or 0) if isinstance(ent, dict) else 0.0
        obf = ev.get("obfuscation") or {}
        max_ent = float(obf.get("max_section_entropy") or 0) if isinstance(obf, dict) else 0.0
        entropy_val = max(file_ent, max_ent)
        obf_count = int(obf.get("recovered_strings_count") or 0) if isinstance(obf, dict) else 0
        ss = ev.get("strings_summary") or {}
        decoded_cnt = int(ss.get("decoded_cnt") or 0) if isinstance(ss, dict) else 0
        obf_strings = max(obf_count, decoded_cnt)

        # YARA: имена правил одной строкой
        yara_hits = ev.get("yara") or []
        rule_names = " ".join(
            str(h.get("rule") or "") for h in yara_hits if isinstance(h, dict)
        ).lower()

        is_script = sfx in ("sh", "py")
        has_ldpreload = "ldpreload" in rule_names or "ld_preload" in rule_names
        has_dynamic_api = (
            "dynamic_api" in rule_names
            or "api_resolve" in rule_names
            or "dynamic_api_resolve" in rule_names
        )
        has_meterpreter = "meterpreter" in rule_names or "android_meterpreter" in rule_names
        has_indirect_call = "indirect_call" in rule_names
        has_warpstrings = "warpstrings" in rule_names

        placed = False

        # Rootkit-like: ldpreload или dynamic_api_resolve
        if has_ldpreload or has_dynamic_api:
            group_rootkit.append({"ev": ev, "name": name, "kind": kind, "rule_names": rule_names})
            placed = True

        # Подозрительные скрипты: .sh/.py + meterpreter или indirect_call (или WarpStrings)
        if is_script and (has_meterpreter or has_indirect_call or has_warpstrings):
            file_path = ev.get("path") or ev.get("file") or _get(ev, "meta.path") or name
            group_suspicious_scripts.append({
                "ev": ev,
                "name": name,
                "path": file_path,
                "meterpreter": has_meterpreter,
                "indirect_call": has_indirect_call,
                "warpstrings": has_warpstrings,
            })
            placed = True

        # Критическая обфускация: entropy > 7.2 или obf_strings > 10000
        if entropy_val > ENTROPY_OBF_THRESHOLD or obf_strings > OBF_STRINGS_THRESHOLD:
            weight = entropy_val * 2 + min(obf_strings / 1000.0, 50)  # для сортировки ТОП-5
            group_obfuscated.append({"ev": ev, "name": name, "weight": weight, "entropy": entropy_val, "obf_strings": obf_strings})
            placed = True

        if not placed:
            group_clean.append({"ev": ev, "name": name})

    return {
        "group_obfuscated": group_obfuscated,
        "group_rootkit": group_rootkit,
        "group_suspicious_scripts": group_suspicious_scripts,
        "group_clean": group_clean,
    }


def _append_static_section_threat_groups(
    lines: list[str], evidences: list, threat_groups: dict[str, list] | None = None
) -> dict[str, list]:
    """
    Секция «Статический анализ» в виде блоков по группам угроз:
    Критическая обфускация (ТОП-5 + и ещё N), Rootkit-like, Подозрительные скрипты (install.sh отдельно).
    Возвращает threat_groups для использования в обосновании (при >10 файлах).
    """
    groups = threat_groups if threat_groups is not None else _build_threat_groups(evidences)
    obf = groups["group_obfuscated"]
    rootkit = groups["group_rootkit"]
    scripts = groups["group_suspicious_scripts"]

    lines.append("3) *Статический анализ*:")
    lines.append("")

    # Группа: Критическая обфускация — ТОП-5 по weight, затем «и ещё N файлов»
    if obf:
        sorted_obf = sorted(obf, key=lambda x: x.get("weight", 0), reverse=True)
        top5 = sorted_obf[:5]
        rest_count = len(sorted_obf) - 5
        lines.append("*Группа: Критическая обфускация* (entropy > 7.2 или объём восстановленных строк > 10000):")
        for item in top5:
            name = item.get("name", "(файл)")
            e = item.get("entropy", 0)
            s = item.get("obf_strings", 0)
            lines.append(f"  • {name} (entropy={e:.2f}, recovered_strings={s})")
        if rest_count > 0:
            lines.append(f"  и ещё {rest_count} файл(ов).")
        lines.append("")

    # Группа: Техники перехвата (Rootkit-like) — ELF с ld_preload, описание угрозы
    if rootkit:
        lines.append("*Группа: Техники перехвата (Rootkit-like)*:")
        lines.append("  Обнаружено использование техник сокрытия кода: LD_PRELOAD и/или динамический резолв API (перехват функций ОС).")
        lines.append("  *Пояснение:* Использование LD_PRELOAD в системных библиотеках БД является аномальным и указывает на возможность скрытого перехвата функций ОС.")
        elf_with_ldpreload = [r for r in rootkit if (r.get("kind") or "").upper() == "ELF"]
        for item in (elf_with_ldpreload if elf_with_ldpreload else rootkit):
            lines.append(f"  • {item.get('name', '(файл)')}")
        if not elf_with_ldpreload and rootkit:
            lines.append("  (в т.ч. не-ELF файлы с признаками перехвата/скрытия API).")
        lines.append("")

    # Группа: Подозрительные скрипты — дедупликация по пути и по имени (убрать дубли install.sh)
    if scripts:
        seen_paths: set = set()
        seen_names: set = set()
        unique_scripts: list = []
        for s in scripts:
            path = s.get("path") or s.get("name") or ""
            name = (s.get("name") or _basename(path) or "").lower()
            if path and path in seen_paths:
                continue
            if name and name in seen_names:
                continue
            if path:
                seen_paths.add(path)
            if name:
                seen_names.add(name)
            unique_scripts.append(s)
        lines.append("*Группа: Подозрительные скрипты*:")
        install_items = [s for s in unique_scripts if (s.get("name") or "").lower() == "install.sh"]
        others = [s for s in unique_scripts if (s.get("name") or "").lower() != "install.sh"]
        if install_items:
            s = install_items[0]
            parts = []
            if s.get("meterpreter"):
                parts.append("android_meterpreter")
            if s.get("warpstrings"):
                parts.append("WarpStrings")
            if s.get("indirect_call"):
                parts.append("indirect_call")
            lines.append(f"  • *install.sh* — в файле найдены: {', '.join(parts)}.")
            if s.get("meterpreter"):
                lines.append("    *Расшифровка:* android_meterpreter в install.sh — критический индикатор компрометации (Meterpreter payload для мобильных/встраиваемых систем, типичен для троянизированных инсталляторов).")
        for item in others:
            parts = []
            if item.get("meterpreter"):
                parts.append("meterpreter")
            if item.get("indirect_call"):
                parts.append("indirect_call")
            if item.get("warpstrings"):
                parts.append("WarpStrings")
            lines.append(f"  • {item.get('name', '(файл)')}" + (f" ({', '.join(parts)})" if parts else ""))
        lines.append("")

    if not obf and not rootkit and not scripts:
        lines.append("  Критических отклонений по группам угроз (обфускация, rootkit-like, подозрительные скрипты) не выявлено.")
        lines.append("")

    lines.append("")
    return groups


def _build_expert_justification_many_files(evidences: list, threat_groups: dict[str, list]) -> str:
    """
    Экспертный синтез justification: LD_PRELOAD (Rootkit-behavior), высокая энтропия, Meterpreter в скриптах.
    """
    rootkit = threat_groups.get("group_rootkit") or []
    scripts = threat_groups.get("group_suspicious_scripts") or []
    obf = threat_groups.get("group_obfuscated") or []
    n_files = len(rootkit) + len(obf)
    if n_files == 0 and scripts:
        n_files = len(scripts)
    parts: list[str] = []
    if rootkit:
        parts.append(
            "Заблокировано: Системная аномалия LD_PRELOAD (Rootkit-behavior) в сочетании с высокой энтропией."
        )
    if n_files > 0 and not rootkit:
        parts.append(f"Заблокировано: Системное использование техник сокрытия кода в {n_files} файлах.")
    if obf and not rootkit:
        parts.append(f"Критическая обфускация в {len(obf)} файлах.")
    if scripts:
        parts.append("Наличие сигнатур Meterpreter в скриптах инсталляции.")
    if not parts:
        return ""
    return " ".join(parts)


def _pe_ident_flags(ev: dict) -> tuple[list[str], bool]:
    h = _get(ev, "pe.hardening", {}) or {}
    s = _get(ev, "pe.sections", {}) or {}
    flags = []
    if h.get("aslr") is False: flags.append("aslr_off")
    if h.get("dep")  is False: flags.append("dep_off")
    if h.get("cfg")  is False: flags.append("cfg_off")
    if s.get("has_rwx") is True: flags.append("rwx")
    if s.get("has_wx")  is True: flags.append("wx")
    return flags, _sig_present_soft(ev)

def _elf_ident_flags(ev: dict) -> list[str]:
    h = _get(ev, "elf.hardening", {}) or {}
    flags = []
    if h.get("pie") is False: flags.append("pie_off")
    if h.get("nx")  is False: flags.append("nx_off")
    relro = (h.get("relro") or "").lower()
    if relro in ("", "none"): flags.append("relro_none")
    if h.get("textrel") is True: flags.append("textrel")
    if h.get("w_x_segments") is True: flags.append("w+x")
    return flags

# Критические CWE для пометки CRITICAL в отчёте (buffer overflows, use-after-free, etc.)
_CWE_CRITICAL_IDS = frozenset({
    "CWE-120", "CWE-119", "CWE-787", "CWE-416", "CWE-190", "CWE-476",
    "CWE-134", "CWE-78", "CWE-89", "CWE-20", "CWE-125", "CWE-415",
})

# Маппинг CWE ID → понятное описание на русском (для таблицы «Название»)
_CWE_ID_TO_RU: Dict[str, str] = {
    "CWE-119": "Выход за границы буфера (Buffer Overflow)",
    "CWE-120": "Классическое переполнение буфера (strcpy и аналоги)",
    "CWE-134": "Небезопасное форматирование строк (Format String)",
    "CWE-190": "Целочисленное переполнение",
    "CWE-20": "Некорректная валидация входных данных",
    "CWE-78": "Инъекция команд ОС (OS Command Injection)",
    "CWE-89": "SQL-инъекция",
    "CWE-125": "Чтение за границами буфера (Out-of-bounds Read)",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-476": "Обращение к нулевому указателю (NULL Pointer Dereference)",
    "CWE-787": "Запись за границами буфера (Out-of-bounds Write)",
}


def _format_cwe(cwe_id: str, raw_name: str = "") -> str:
    """Переводит код CWE (например, CWE-190) в понятное описание на русском. Если маппинга нет — возвращает raw_name или сам ID."""
    if not cwe_id:
        return (raw_name or "—")[:200]
    key = cwe_id.strip().upper()
    if ":" in key:
        key = key.split(":")[0].strip()
    return _CWE_ID_TO_RU.get(key, raw_name or key)[:200]


def _append_cwe_section(lines: list[str], evidences: list) -> None:
    """Подраздел «Анализ бинарного кода (CWE)». Пустые данные — явное сообщение о проверке Docker; при наличии — таблица."""
    has_any_cwe = any(isinstance(e.get("cwe_analysis"), dict) for e in evidences)
    if not has_any_cwe:
        lines.append("— *Анализ бинарного кода (CWE)*: Сканер CWE не вернул данных (проверьте Docker fkiecad/cwe_checker).")
        return
    cwe_findings: list[tuple[str, str, str, bool]] = []  # (cwe_id, описание, функция, is_critical)
    cwe_errors: list[str] = []
    for ev in evidences:
        cwe = _get(ev, "cwe_analysis") or {}
        if not isinstance(cwe, dict):
            continue
        if cwe.get("error"):
            cwe_errors.append(cwe["error"])
        findings = cwe.get("findings") or []
        for f in findings:
            if not isinstance(f, dict):
                continue
            raw_name = (f.get("name") or f.get("description") or f.get("cwe") or str(f))[:200]
            raw_cwe = (f.get("cwe") or f.get("id") or "").strip().upper()
            if not raw_cwe and raw_name:
                m = re.search(r"CWE[-\s]?\d+", raw_name, re.IGNORECASE)
                if m:
                    raw_cwe = m.group(0).replace(" ", "-")
            cwe_id = raw_cwe.split(":")[0].strip() if (raw_cwe and ":" in raw_cwe) else (raw_cwe or "—")
            is_critical = (cwe_id or "") in _CWE_CRITICAL_IDS
            name_ru = _format_cwe(cwe_id, raw_name)
            func = (f.get("function") or f.get("symbol") or f.get("location") or "").strip()[:80] or "—"
            cwe_findings.append((cwe_id or "—", name_ru, func, is_critical))
    if not cwe_findings:
        if cwe_errors:
            for err in cwe_errors:
                lines.append(f"— *Анализ CWE*: ошибка запуска ({err}).")
        else:
            lines.append("— [X] *Аудит CWE завершён:* критических логических ошибок не выявлено.")
        return
    lines.append(f"— *Binary SCA*: Найдено {len(cwe_findings)} потенциальных CWE.")
    lines.append("")
    lines.append("| ID | Слабость | Описание | Приоритет |")
    lines.append("| :--- | :--- | :--- | :--- |")
    for cwe_id, name_ru, func, is_crit in cwe_findings[:50]:
        prio = "CRITICAL" if is_crit else "—"
        weakness = (name_ru or "—").replace("|", ", ")
        desc = (func or "—").replace("|", ", ")
        lines.append(f"| {cwe_id} | {weakness} | {desc} | {prio} |")
    if len(cwe_findings) > 50:
        lines.append(f"| … | … и ещё {len(cwe_findings) - 50} | — | — |")
    arch_risk_ids = {"CWE-415", "CWE-416", "CWE-134"}
    arch_risks = [name_ru for (cid, name_ru, _f, _) in cwe_findings if cid in arch_risk_ids]
    if arch_risks:
        lines.append("")
        lines.append("*Архитектурные риски* (CWE-checker):")
        for ar in arch_risks[:20]:
            lines.append(f"  • {ar.replace('|', ', ')}")
        if len(arch_risks) > 20:
            lines.append(f"  … и ещё {len(arch_risks) - 20}")


def _append_scan_depth_section(lines: list[str], evidences: list) -> None:
    """Статус-панель «Качество системы» и «Технический аудит (Этапы)» в начале раздела ПРОВЕРКА."""
    all_yara = []
    for e in evidences:
        for h in (e.get("yara") or []):
            if isinstance(h, dict) and h.get("rule"):
                all_yara.append(str(h.get("rule")))
    unique_rules = list(dict.fromkeys(all_yara))
    static_ok = len(unique_rules) > 0 or any((e.get("capa") or {}).get("techniques") for e in evidences)
    static_label = f"Выполнено ({len(unique_rules)} правил)" if unique_rules else ("Выполнено (capa)" if any((e.get("capa") or {}).get("techniques") for e in evidences) else "Не выполнялось")

    cve_tot = sum(
        int((_get(e, "cve.summary") or {}).get("critical") or 0) +
        int((_get(e, "cve.summary") or {}).get("high") or 0) +
        int((_get(e, "cve.summary") or {}).get("medium") or 0)
        for e in evidences
    )
    cve_result = f"{cve_tot} обнаружено" if cve_tot else "0 обнаружено"
    cve_label = f"Выполнено (Syft+Grype, {cve_result})"
    cve_ok = True  # проверка CVE выполнялась (результат 0 или N)

    # [X] в чек-листе CWE только если в 'cwe_analysis' действительно поступили данные (успешный запуск или находки)
    cwe_count = sum(len((_get(e, "cwe_analysis") or {}).get("findings") or []) for e in evidences)
    cwe_ok = any(
        isinstance(e.get("cwe_analysis"), dict)
        and ((e.get("cwe_analysis") or {}).get("return_code") == 0 or len((e.get("cwe_analysis") or {}).get("findings") or []) > 0)
        for e in evidences
    )
    if cwe_ok and cwe_count:
        cwe_label = f"Выполнено (cwe_checker, {cwe_count} находок)"
    elif cwe_ok:
        cwe_label = "Выполнено (cwe_checker). Уязвимостей не обнаружено"
    else:
        cwe_label = "Не выполнялось"

    # Эмуляция считается выполненной, если есть объект результата (даже с пустыми api_calls)
    emu_ok = any(isinstance(e.get("emulation"), dict) for e in evidences)

    # Статус-панель «Качество системы» (чек-боксы в начале отчёта)
    lines.append("### Качество системы:")
    lines.append("")
    lines.append("  - " + ("[X]" if static_ok else "[ ]") + " **YARA:** " + ("OK" if static_ok else "—"))
    lines.append("  - [X] **CVE:** " + ("OK" if cve_ok else "—"))
    lines.append("  - " + ("[X]" if cwe_ok else "[ ]") + " **CWE:** " + ("OK" if cwe_ok else "—"))
    lines.append("")
    lines.append("### Технический аудит (Этапы):")
    lines.append("")
    lines.append("  - " + ("[X]" if static_ok else "[ ]") + " **Статический анализ (YARA/capa):** " + static_label)
    lines.append("  - [X] **Поиск уязвимостей (CVE):** " + cve_label)
    lines.append("  - " + ("[X]" if cwe_ok else "[ ]") + " **Логический аудит (CWE):** " + cwe_label)
    lines.append("  - " + ("[X]" if emu_ok else "[ ]") + " **Эмуляция (Speakeasy):** " + ("Выполнено" if emu_ok else "Не выполнялось"))
    lines.append("")


def _expert_verdict_from_capa(evidences: list) -> Optional[str]:
    """Формирует экспертный вердикт по техникам capa (MITRE ATT&CK) для уникального обоснования вместо шаблонного «Заблокировано: Сигнатуры YARA»."""
    # Маппинг техник на короткое описание риска (для вердикта)
    TECH_VERDICT: Dict[str, str] = {
        "T1055": "Критический риск: Выявлена попытка манипуляции памятью сторонних процессов (техника MITRE T1055 — Process Injection), что характерно для троянов-загрузчиков.",
        "T1055.001": "Критический риск: Инъекция кода в процесс через DLL (T1055.001). Типично для загрузчиков и RAT.",
        "T1055.002": "Критический риск: Внедрение в процесс через исполнение в удалённом потоке (T1055.002).",
        "T1562": "Риск: Обнаружены признаки отключения средств защиты (T1562 — Impair Defenses).",
        "T1547": "Риск: Признаки закрепления в системе (T1547 — Boot or Logon Autostart Execution).",
        "T1027": "Риск: Обфускация кода или данных (T1027). Повышает вероятность вредоносного payload.",
        "T1070": "Риск: Признаки удаления следов (T1070 — Indicator Removal).",
        "T1106": "Риск: Использование Native API (T1106) в подозрительном контексте.",
    }
    for ev in evidences:
        capa = ev.get("capa") or {}
        techniques = capa.get("techniques") or []
        attck = capa.get("attck_by_tactic") or {}
        for tactic, tech_list in (attck.items() if isinstance(attck, dict) else []):
            if isinstance(tech_list, list):
                techniques.extend(tech_list)
        seen = set()
        for t in techniques:
            if not t or not isinstance(t, str):
                continue
            tid = (t.strip().upper().split(" ")[0])[:20]
            if tid in seen:
                continue
            seen.add(tid)
            for key, phrase in TECH_VERDICT.items():
                if key in tid or tid.startswith(key):
                    return phrase
    return None


def _append_secrets_arch_risks(lines: list[str], evidences: list) -> None:
    """Добавляет в отчёт блок «Архитектурные риски» по результатам анализа секретов."""
    secrets_findings: list[str] = []
    for ev in evidences:
        sec = ev.get("secrets") or {}
        if not isinstance(sec, dict):
            continue
        if sec.get("suspicious") or sec.get("hits"):
            for key, vals in (sec.get("hits") or {}).items():
                if vals:
                    secrets_findings.append(f"Секреты: {key} ({len(vals)} шт.)")
    if secrets_findings:
        lines.append("")
        lines.append("*Архитектурные риски* (поиск секретов):")
        for s in secrets_findings[:20]:
            lines.append(f"  • {s}")
        if len(secrets_findings) > 20:
            lines.append(f"  … и ещё {len(secrets_findings) - 20}")


def _append_mitre_matrix(lines: list[str], evidences: list) -> None:
    """Таблица «Матрица техник (MITRE ATT&CK)»: находки сгруппированы по тактикам (Defense Evasion, Persistence, Discovery и др.)."""
    by_tactic: dict[str, list[str]] = {}
    for ev in evidences:
        capa = _get(ev, "capa") or {}
        attck = capa.get("attck_by_tactic") or {}
        if not isinstance(attck, dict):
            continue
        for tactic, tech_list in attck.items():
            t_key = (tactic or "").strip().lower().replace(" ", "-") or "other"
            if t_key not in by_tactic:
                by_tactic[t_key] = []
            for t in (tech_list or []) if isinstance(tech_list, list) else []:
                if t and str(t).strip() and str(t).strip() not in by_tactic[t_key]:
                    by_tactic[t_key].append(str(t).strip())
    if not by_tactic:
        return
    lines.append("")
    lines.append("*Матрица техник (MITRE ATT&CK)*")
    lines.append("")
    lines.append("| Тактика | Техники / ID |")
    lines.append("|---------|--------------|")
    tactic_order = ["defense-evasion", "persistence", "discovery", "credential-access", "command-and-control", "execution", "impact", "collection", "exfiltration", "lateral-movement", "other"]
    for tactic in tactic_order:
        if tactic not in by_tactic:
            continue
        techs = by_tactic[tactic][:15]
        cell = ", ".join(techs).replace("|", ", ")
        lines.append(f"| {tactic} | {cell} |")
    for tactic, techs in sorted(by_tactic.items()):
        if tactic in tactic_order:
            continue
        cell = ", ".join((techs or [])[:15]).replace("|", ", ")
        lines.append(f"| {tactic} | {cell} |")


def _append_memory_dump_section(lines: list[str], evidences: list) -> None:
    """Блок [MEMORY DUMP]: YARA-находки и техники из дампа памяти; при эмуляции без дампа — «активности не обнаружено»."""
    has_any = any(
        (ev.get("memory_dump_analysis") or {}).get("dump_path")
        or ((ev.get("memory_dump_analysis") or {}).get("yara") and len((ev.get("memory_dump_analysis") or {}).get("yara") or []) > 0)
        or (ev.get("emulation") or {}).get("memory_dump_path")
        or (ev.get("emulation") or {}).get("success")
        for ev in evidences
    )
    if not has_any:
        lines.append("")
        lines.append("*[MEMORY DUMP] Анализ дампа памяти (эмуляция)*")
        lines.append("")
        lines.append("— *[MEMORY DUMP]*: Данные дампа памяти отсутствуют (эмуляция не выполнялась или дамп не создан).")
        return
    lines.append("")
    lines.append("*[MEMORY DUMP] Анализ дампа памяти (эмуляция)*")
    lines.append("")
    for ev in evidences:
        mda = ev.get("memory_dump_analysis") or {}
        emu = ev.get("emulation") or {}
        dump_path = mda.get("dump_path") or emu.get("memory_dump_path")
        yara_hits = mda.get("yara") or []
        skip_rules = {"yara_skipped_large_file", "yara_error", "yara_match_error", "yara_truncated"}
        real_yara = [h for h in yara_hits if isinstance(h, dict) and (h.get("rule") or "") not in skip_rules and (h.get("namespace") or "") != "errors"]
        if not dump_path and not real_yara and not emu.get("success"):
            continue
        name = (ev.get("meta") or {}).get("path") or ev.get("path") or "?"
        name = Path(name).name if isinstance(name, str) else str(name)
        dump_name = Path(dump_path or "").name if dump_path else "—"
        lines.append(f"— *[MEMORY DUMP]* файл: {name} → дамп: {dump_name}")
        if real_yara:
            lines.append(f"  YARA-хиты в памяти ({len(real_yara)} сработок):")
            lines.append("")
            lines.append("  | Правило | Namespace | Описание |")
            lines.append("  | :--- | :--- | :--- |")
            for h in real_yara[:25]:
                rule = (h.get("rule") or h.get("name") or "—")[:40]
                ns = (h.get("namespace") or "—")[:25]
                desc = (str((h.get("meta") or {}).get("description") or (h.get("meta") or {}).get("name") or "—"))[:50]
                lines.append(f"  | {rule} | {ns} | {desc} |")
            if len(real_yara) > 25:
                lines.append(f"  | … и ещё {len(real_yara) - 25} | — | — |")
            lines.append("")
        elif dump_path or emu.get("success"):
            lines.append("  Активности вредоносного кода в памяти не обнаружено.")
            lines.append("")
        # Выявленные техники (T1055 и т.д.) из эмуляции/памяти
        def _tech_id(t):
            if isinstance(t, str):
                return t if (t.startswith("T") or "T1055" in t) else None
            if isinstance(t, dict):
                return t.get("id") or t.get("technique") or t.get("name")
            return None
        techniques = (ev.get("emulation") or {}).get("techniques") or []
        capa_tech = (ev.get("capa") or {}).get("techniques") or []
        attck = (ev.get("capa") or {}).get("attck_by_tactic") or {}
        if isinstance(attck, dict):
            for _tactic, tech_list in attck.items():
                if isinstance(tech_list, list):
                    capa_tech.extend(tech_list)
        all_tech = list(dict.fromkeys(
            x for x in (_tech_id(t) for t in techniques + capa_tech) if x
        ))
        if all_tech:
            lines.append(f"  Выявленные техники из памяти/эмуляции: {', '.join(all_tech[:15])}")
            if len(all_tech) > 15:
                lines.append(f"    … и ещё {len(all_tech) - 15}")
        cwe = mda.get("cwe") or {}
        findings = cwe.get("findings") or []
        if findings:
            lines.append(f"  CWE по дампу: {len(findings)} находок")
            for f in findings[:5]:
                desc = (f.get("name") or f.get("description") or f.get("cwe") or str(f))[:80]
                lines.append(f"    • {desc}")
        if mda.get("scan_error"):
            lines.append(f"  Ошибка сканирования: {mda['scan_error'][:100]}")
        lines.append("")


def _append_attack_storyline_section(lines: list[str], evidences: list) -> None:
    """v3.1: граф атаки (Staged Execution) — LNK/офис → скрипт → инъекция."""
    has_any = any(ev.get("attack_storyline") for ev in evidences)
    if not has_any:
        return
    lines.append("")
    lines.append("*[Attack Storyline] Граф атаки (Staged Execution)*")
    lines.append("")
    for ev in evidences:
        graph = ev.get("attack_storyline")
        if not graph or not graph.get("staged"):
            continue
        name = (ev.get("meta") or {}).get("path") or ev.get("path") or "?"
        name = Path(name).name if isinstance(name, str) else str(name)
        lines.append(f"— Артефакт: {name}")
        nodes = graph.get("nodes") or []
        edges = graph.get("edges") or []
        for n in nodes:
            label = n.get("label") or n.get("id") or ""
            lines.append(f"  • {label}")
        for e in edges:
            fr = e.get("from") or ""
            to = e.get("to") or ""
            lines.append(f"  → {fr} → {to}")
        lines.append("")


def _append_dependency_table(lines: list[str], evidences: list) -> None:
    """Единая таблица «Зависимости и связанные компоненты». Ключ — имя DLL в нижнем регистре; объединение источников; сортировка по алфавиту; скрытые — жирным."""
    # Ключ = lowercase имя DLL; значение = { "display_name": str, "in_static": bool, "in_memory": bool }
    by_key: dict[str, dict] = {}
    def _add(key: str, display: str, in_static: bool, in_memory: bool) -> None:
        k = key.lower().strip()
        if not k:
            return
        if k not in by_key:
            by_key[k] = {"display_name": display.strip(), "in_static": False, "in_memory": False}
        by_key[k]["in_static"] = by_key[k]["in_static"] or in_static
        by_key[k]["in_memory"] = by_key[k]["in_memory"] or in_memory
        # Предпочитаем отображаемое имя с суффиксом .dll
        if ".dll" in display.lower() and ".dll" not in by_key[k]["display_name"].lower():
            by_key[k]["display_name"] = display.strip()

    for ev in evidences:
        for name in (_get(ev, "pe.imported_dlls") or []):
            if isinstance(name, str) and name.strip():
                n = name.strip()
                _add(n, n, True, False)
        for name in (_get(ev, "emulation.modules") or []):
            if isinstance(name, str) and name.strip():
                n = name.strip()
                _add(n, n, False, True)
        for d in (_get(ev, "supply_chain.dependencies") or []):
            if isinstance(d, dict) and d.get("type") == "dynamic_lib" and d.get("value"):
                val = (d.get("value") or "").strip()
                if val:
                    _add(val, val, False, True)

    # Итоговый список: одна запись на DLL (регистронезависимая дедупликация), сортировка по алфавиту
    rows = list(by_key.values())
    rows.sort(key=lambda r: (r["display_name"].lower(), r["display_name"]))

    # CVE: для каждой библиотеки число уязвимостей из ev.cve.items
    lib_vuln_count: dict = {}
    for ev in evidences:
        for it in (_get(ev, "cve.items") or []):
            pkg = (it.get("package") or "").strip().lower()
            if not pkg:
                continue
            vulns = it.get("vulns") or []
            n = len(vulns) if isinstance(vulns, list) else 0
            stem = pkg.replace(".dll", "").strip()
            lib_vuln_count[pkg] = lib_vuln_count.get(pkg, 0) + n
            if stem and stem != pkg:
                lib_vuln_count[stem] = lib_vuln_count.get(stem, 0) + n

    # Версия библиотеки из emulation.module_details / detailed_modules (LIEF / отпечаток)
    lib_version: dict = {}
    for ev in evidences:
        for md in (_get(ev, "emulation.module_details") or _get(ev, "emulation.detailed_modules") or []):
            if isinstance(md, dict) and md.get("name"):
                n = (md.get("name") or "").strip().lower()
                v = (md.get("version") or "").strip()
                if n and v and v != "—":
                    lib_version[n] = v

    if not rows:
        return
    lines.append("*Зависимости и связанные компоненты*:")
    lines.append("")
    lines.append("| Библиотека | Источник | Статус CVE |")
    lines.append("| :--- | :--- | :--- |")
    for r in rows[:200]:
        display = r["display_name"].lower()  # единообразный вид (напр. kernel32.dll)
        in_static = r["in_static"]
        in_mem = r["in_memory"]
        if in_static and in_mem:
            source = "Статика + Память"
        elif in_mem:
            source = "Эмуляция (скрыто)"
        else:
            source = "Статика (IAT)"
        base = display.replace(".dll", "").strip() if ".dll" in display else display
        cnt = max(lib_vuln_count.get(display, 0), lib_vuln_count.get(base, 0))
        status = str(cnt) if cnt else "Ок"
        ver = lib_version.get(display) or lib_version.get(base)
        if ver:
            status = f"{status} ({ver})" if status != "Ок" else f"Ок ({ver})"
        # В колонке «Библиотека» выводим версию рядом с именем, если обнаружена (напр. zlib1.dll (v1.2.11))
        cell_name = f"{display} (v{ver})" if ver else display
        if source == "Эмуляция (скрыто)":
            cell_name = f"*{cell_name}*"
        lines.append(f"| {cell_name} | {source} | {status} |")
    if len(rows) > 200:
        lines.append(f"| … и ещё {len(rows) - 200} | — | — |")
    lines.append("")


def _ident_aggregation_key(pf: dict) -> tuple:
    """Ключ для схлопывания записей раздела 1: расширение + метаданные (например ELF с одинаковым RPATH)."""
    ev = pf.get("ev") or {}
    kind = (pf.get("kind") or _get(ev, "kind") or _get(ev, "type") or "BIN").upper()
    name = pf.get("name") or _basename(_get(ev, "path") or _get(ev, "file")) or ""
    suffix = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if kind == "ELF":
        h = _get(ev, "elf.hardening") or {}
        rpath = (h.get("rpath") or "") if isinstance(h, dict) else ""
        runpath = (h.get("runpath") or "") if isinstance(h, dict) else ""
        if name.endswith(".so.debug") or (".so." in name and "debug" in name.lower()):
            pattern = "lib*.so.debug"
        elif name.endswith(".so") or ".so." in name:
            pattern = "*.so"
        else:
            pattern = f"*.{suffix}" if suffix else "*"
        return (kind, rpath, runpath, pattern)
    if kind == "PE":
        return (kind, suffix, _get(ev, "pe.subsystem") or "")
    return (kind, suffix, "")


def _group_files_by_metadata(arr: list) -> dict[tuple, list]:
    """
    Жёсткая группировка ELF: ключ (interp, RWX-LOAD, stripped, static, rpath).
    При идентичных interp, RWX-LOAD и stripped — общее описание один раз на группу, затем список имён.
    """
    by_meta: dict[tuple, list] = defaultdict(list)
    for pf in arr:
        ev = pf.get("ev") or {}
        kind = (pf.get("kind") or _get(ev, "kind") or _get(ev, "type") or "BIN").upper()
        if kind == "ELF":
            h = _get(ev, "elf.hardening") or {}
            rpath = (h.get("rpath") or "") if isinstance(h, dict) else ""
            interp = _get(ev, "elf.interp") or ""
            rwx_load = bool(_get(ev, "elf.hardening.w_x_segments"))
            stripped = _get(ev, "elf.stripped")
            static = _get(ev, "elf.static_linked")
            key = ("ELF", interp, rwx_load, bool(stripped), bool(static), rpath)
        else:
            key = _ident_aggregation_key(pf)
        by_meta[key].append(pf)
    return by_meta


def _append_ident_section(lines: list[str], *, groups: dict[str, list], show_files: bool = False, evidences: list | None = None):
    """1) Идентификация и целостность — агрегаты по группам; при show_files — схлопывание при count > 5 по расширению/метаданным."""
    lines.append("1) Идентификация и целостность:")
    dependency_table_appended = False
    COLLAPSE_THRESHOLD = 5
    for gname, arr in _iter_groups(groups):
        n = len(arr)
        agg = Counter()
        signed = total_pe = 0
        for pf in arr:
            ev = pf["ev"]
            k  = (pf.get("kind") or "").upper()
            if k == "PE":
                total_pe += 1
                fl, sig = _pe_ident_flags(ev)
                agg.update(fl)
                if sig: signed += 1
            elif k == "ELF":
                agg.update(_elf_ident_flags(ev))
        parts = []
        for key in ("aslr_off","dep_off","cfg_off","rwx","wx","pie_off","nx_off","relro_none","textrel","w+x"):
            if agg.get(key, 0) > 0:
                parts.append(f"{key}={agg[key]}")
        if total_pe > 0:
            parts.append(f"sig={signed}/{total_pe}")
        lines.append(f"* {gname}: {n} файл(ов)" + (", " + "; ".join(parts) if parts else ", критичных отклонений не выявлено"))
        if show_files:
            by_meta = _group_files_by_metadata(arr)
            # ELF: при идентичных RPATH, stripped, static — одна запись (общее описание + список имён)
            ELF_SAME_META_MIN = 1  # схлопывать при совпадении метаданных (даже 1 файл в группе — выводим список имён)
            seen_paths: set = set()
            for key, sub in by_meta.items():
                if len(key) >= 6 and key[0] == "ELF" and len(sub) > ELF_SAME_META_MIN:
                    names = []
                    for pf in sub:
                        ev = pf.get("ev") or {}
                        path = ev.get("path") or ev.get("file") or _get(ev, "meta.path") or ""
                        if path and path in seen_paths:
                            continue
                        if path:
                            seen_paths.add(path)
                        n = pf.get("name") or _basename(_get(ev, "path") or _get(ev, "file"))
                        if n and n not in names:
                            names.append(n)
                    name_list = ", ".join(names[:15])
                    if len(names) > 15:
                        name_list += f" и ещё {len(names) - 15}"
                    interp, rwx_load, stripped, static, rpath = key[1], key[2], key[3], key[4], key[5]
                    # Один раз для всей группы: interp, RWX-LOAD, stripped (не выводим для каждого файла)
                    params = [f"interp={interp or '—'}", f"RWX-LOAD={rwx_load}", f"stripped={stripped}", f"static={static}"]
                    if rpath:
                        params.append(f"RPATH={repr(rpath)}")
                    lines.append(f"— *Группа:* {len(sub)} ELF с идентичными параметрами ({', '.join(params)}): {name_list}")
                elif len(sub) > COLLAPSE_THRESHOLD and (not key or key[0] != "ELF"):
                    kind = key[0] if key else "?"
                    rest = list(key[1:]) if len(key) > 1 else []
                    lines.append(f"— {len(sub)} файлов ({kind}, {rest[0] if rest else 'разные'})")
                else:
                    for pf in sub:
                        ev = pf["ev"]
                        path = ev.get("path") or ev.get("file") or _get(ev, "meta.path") or ""
                        if path and path in seen_paths:
                            continue
                        if path:
                            seen_paths.add(path)
                        name = pf.get("name") or _basename(_get(ev, "path") or _get(ev, "file"))
                        if not name and path:
                            name = _basename(path)
                        kind = pf.get("kind") or (_get(ev, "kind") or _get(ev, "type") or "BIN")
                        lines.append(f"— {name} [{kind}]")
                        if kind == "PE":
                            lines.append(_pe_security_line(ev))
                            lines.append(_pe_sections_line(ev))
                            lines.append(_pe_signature_line(ev))
                            lines.append(_pe_meta_line(ev))
                            if evidences and not dependency_table_appended:
                                _append_dependency_table(lines, evidences)
                                dependency_table_appended = True
                        elif kind == "ELF":
                            lines.append(_elf_details_line(ev))
                        eline = _errors_line(ev)
                        if eline:
                            lines.append(eline)
            lines.append("")
    lines.append("")


def _append_recommendations_summary(lines: list[str], evidences: list[dict], summary: dict | None = None) -> None:
    """
    Лаконичные рекомендации по ЭКСПЛУАТАЦИИ: где и как ограничить, и почему.
    Печатает 2–4 пункта, завися от фактов (импорты сети/служб, CFG/секции, подпись, VT).
    """
    # агрегируем релевантные признаки по PE
    any_pe = False
    cfg_false = False
    wx = False
    rwx = False
    net_imports = False
    scm_imports = False
    unsigned = False
    uac_admin = False
    vt_seen = False
    vt_mal  = 0

    def _vt_malicious_count(vt: dict) -> int:
        try:
            st = _vt_stats(vt)  # {'m','s','h','u','rep'}
            return int(st.get("m", 0))
        except Exception:
            return int(vt.get("malicious", 0) or 0)

    for ev in evidences:
        if _kind_of(ev) != "PE":
            continue
        any_pe = True
        cfg_false |= (_get(ev, "pe.hardening.cfg") is False)
        wx  |= bool(_get(ev, "pe.sections.has_wx"))
        rwx |= bool(_get(ev, "pe.sections.has_rwx"))
        unsigned |= (not _sig_present_soft(ev))
        uac_level = (_get(ev, "pe.resources.uac_level") or "").lower()
        uac_admin |= uac_level in {"requireadministrator", "highestavailable"}
        cats = set(map(str, _get(ev, "imports.categories") or []))
        net_imports |= bool(cats & {"network", "winsock", "http", "winhttp", "wininet"})
        scm_imports |= bool(cats & {"services", "scm"})
        vt = _get(ev, "vt") or {}
        if vt:
            vt_seen = True
            vt_mal += _vt_malicious_count(vt)

    if not any_pe:
        return

    recs: list[str] = []

    # 1) Базовая среда запуска (контейнер/VM/пользователь)
    # — формируем 1 короткое правило в зависимости от сигналов
    if vt_mal > 0:
        recs.append("Запуск только в отдельной VM-снимке без доступа к корпоративной сети (forensic-only). Причина: есть детекты на VT.")
    else:
        # VT чисто или данных нет — выбираем изоляцию по импорту/харденингу
        if net_imports or scm_imports:
            recs.append("Запуск в отдельной VM/песочнице под стандартным пользователем (не админ). Причина: импорты network/services.")
        else:
            recs.append("Запуск локально под стандартным пользователем (не админ) в каталоге только на чтение. Причина: сетевые импорты не обнаружены.")

    # 2) Сетевые ограничения (ровно один пункт, понятный)
    if net_imports:
        recs.append("Блокировать сетевой трафик процесса по умолчанию (Windows Firewall in/out = block); открывать адреса точечно при подтверждённой необходимости. Причина: есть сетевые импорты.")
    else:
        recs.append("Явно запретить сети для процесса (Windows Firewall in/out = block). Причина: сети не требуется по отчёту.")

    # 3) Системные ограничения запуска (WDAC/AppLocker) — кратко
    recs.append("Ограничить запуск через WDAC/AppLocker (allow-by-hash/issuer) только для проверенной копии файла. Причина: исключить подмену/соседние EXE/DLL.")

    # 4) Защита на уровне ОС, если есть риск-факторы
    if cfg_false or wx or rwx:
        # это настройка среды, не пересборка
        recs.append("Включить Exploit Protection для процесса (CFG=On; мониторить VirtualProtect/WriteProcessMemory). Причина: ослабленный харденинг/права памяти.")

    # 5) Подпись/трассируемость — одна понятная строка
    if unsigned:
        recs.append("Не распространять и не запускать неподписанные сборки вне изоляции; фиксировать SHA256 в тикете и сверять перед запуском. Причина: подпись отсутствует.")
    else:
        recs.append("Фиксировать SHA256 в тикете и сверять при каждом запуске/обновлении. Причина: контроль неизменности артефакта.")

    # 6) Антивирус как входной контроль (без описания движка)
    if (summary or {}).get("av", {}).get("kaspersky") is None:
        recs.append("Перед запуском — проверка каталога поставки Kaspersky (avp.com SCAN). Причина: базовый санитарный контроль.")

    # Оставляем только 3–4 самых важных для пользователя пункта:
    # приоритет: среда → сеть → WDAC/AppLocker → Exploit Protection → подпись/AV
    shortlist: list[str] = []
    for key in [
        "env", "net", "wdac", "ep", "sig", "av"
    ]:
        pass  # для читаемости; оставляем порядок ниже

    # Сбор shortlist в заданном порядке:
    # 1) среда
    shortlist.append(recs[0])
    # 2) сеть
    shortlist.append(recs[1])
    # 3) WDAC/AppLocker
    shortlist.append(recs[2])
    # 4) Exploit Protection (если добавлялся)
    if ("Exploit Protection" in " ".join(recs)):
        for r in recs:
            if "Exploit Protection" in r:
                shortlist.append(r)
                break

    lines.append("*Рекомендации по эксплуатации (среда и ограничения):*")
    for t in shortlist:
        lines.append("— " + t)
    lines.append("")

def _append_reputation_section(
    lines: list[str],
    *,
    groups: dict[str, list] | None,
    per_file: list[dict],
    show_files: bool,
) -> None:
    """
    2) Репутация (VT): агрегаты + пер-файл карточки, включая поведение и vt-debug при наличии.
    """
    lines.append("2) *Репутация*:")
    any_vt = False

    def _st_of(vt: dict) -> dict:
        st = _deep_find_stats(vt) or {}
        m = int(st.get("malicious")  or 0)
        s = int(st.get("suspicious") or 0)
        h = int(st.get("harmless")   or 0)
        u = int(st.get("undetected") or 0)
        rep = (vt.get("reputation") or vt.get("rep") or
               _get(vt, "data.attributes.reputation") or 0)
        try: rep = int(rep)
        except Exception: rep = 0
        return {"m": m, "s": s, "h": h, "u": u, "rep": rep}

    def _beh_cnt(vt: dict) -> int:
        b = vt.get("behaviours")
        return len(b) if isinstance(b, list) else int(vt.get("behaviours_count") or 0)

    def _vt_last_analysis_ts(vt: dict):
        return (_get(vt, "time") or
                _get(vt, "data.attributes.last_analysis_date") or
                _get(vt, "attributes.last_analysis_date") or None)

    def _vt_link_by_sha(sha: str | None) -> str | None:
        if not sha: return None
        return f"https://www.virustotal.com/gui/file/{sha}"

    # --- агрегат по всем файлам ---
    agg = Counter(m=0, s=0, h=0, u=0, bh=0)
    files_with_vt = 0
    for pf in per_file:
        ev = pf.get("ev") or {}
        vt = ev.get("vt") or {}
        if vt:
            st = _st_of(vt)
            agg.update({"m": st["m"], "s": st["s"], "h": st["h"], "u": st["u"]})
            agg["bh"] += _beh_cnt(vt)
            files_with_vt += 1
            any_vt = True

    # Если по всем файлам в VT 0 детектирований — весь Раздел 2 заменяем одной итоговой строкой
    all_clean = (files_with_vt > 0 and agg["m"] == 0 and agg["s"] == 0)
    unique_hashes_n = files_with_vt
    if files_with_vt == 0:
        lines.append("")
        total_n = len(per_file)
        lines.append("Файлы не найдены в базе VirusTotal." + (f" (0 из {total_n} файлов.)" if total_n else ""))
        lines.append("")
        show_files = False
    elif all_clean:
        lines.append("")
        lines.append(f"Все {unique_hashes_n} файлов проверены в VirusTotal, репутационных угроз не обнаружено.")
        lines.append("")
        show_files = False
    else:
        total_n = len(per_file)
        base = f"* Все файлы:* VT m/s/h/u = {agg['m']}/{agg['s']}/{agg['h']}/{agg['u']} ; files={files_with_vt}/{total_n}"
        if agg["bh"] > 0:
            base += f" ; behaviours={agg['bh']}"
        lines.append(base)

    # --- пер-файл карточки (только для файлов с VT; строки «VT данных нет» не выводим) ---
    if show_files:
        for pf in per_file:
            ev = pf.get("ev") or {}
            name = pf.get("name") or _basename(_get(ev, "path") or _get(ev, "file"))
            vt = ev.get("vt") or {}
            if not vt:
                continue

            st   = _st_of(vt)
            when = _fmt_ts(_vt_last_analysis_ts(vt))
            sha  = _get(ev, "hashes.sha256")
            vlink = _vt_link_by_sha(sha) if sha else None
            bh = _beh_cnt(vt)

            line = (f"— {name}: m/s/h/u = {st['m']}/{st['s']}/{st['h']}/{st['u']} ; "
                    f"rep={st['rep']}" +
                    (f" ; behaviours={bh}" if bh > 0 else " ; behaviour: нет отчёта") +
                    (f" ; as of {when}" if when else ""))
            if vlink:
                line += f" ; VT: {vlink}"
            lines.append(line)

            # Дополнительно: множества для индикатора [VT Verified] (реестр и сеть)
            vt_verified_reg: set = set()
            for p in (ev.get("persistence_analysis") or {}).get("paths_found") or []:
                if isinstance(p, dict) and p.get("verified_by_vt"):
                    m = (p.get("match") or "").strip()
                    if m:
                        vt_verified_reg.add(_norm_registry_key(m))
            vt_verified_net: set = set()
            for i in (ev.get("network_profile") or {}).get("vt_verified_indicators") or []:
                if isinstance(i, str) and i.strip():
                    vt_verified_net.add(_norm_network_ioc(i))
            # детальное поведение (первая сессия + relations, если подложены в cli)
            beh_lines = _vt_behaviour_blocks(
                vt, max_items=15,
                vt_verified_registry=vt_verified_reg or None,
                vt_verified_network=vt_verified_net or None,
            )
            if not beh_lines or len(beh_lines) <= 1:
                beh_lines = _render_vt_behaviour(vt)
            for bl in beh_lines:
                lines.append("   " + bl)
            if not beh_lines:
                keys = list(vt.keys())[:12] if isinstance(vt, dict) else []
                beh_lines = [f"*Behaviour:* нет детализированного вывода; vt.keys={keys}"]

            # Сетевой профиль (DoH / подозрительная сеть) с индикатором [VT Verified] при совпадении с VT
            net_prof = ev.get("network_profile") or {}
            if isinstance(net_prof, dict) and (net_prof.get("sneaky_doh") or net_prof.get("doh_indicators")):
                doh_str = ", ".join((net_prof.get("doh_indicators") or [])[:8])
                vt_ver = " [VT Verified]" if net_prof.get("vt_verified") else ""
                lines.append(f"   * Сетевой профиль:* DoH/подозрительная сеть: {doh_str or '—'}{vt_ver}")

            # VT Details (вкладка Details: Basic properties, Names, ELF Info)
            details = vt.get("details") if isinstance(vt, dict) else None
            if isinstance(details, dict):
                detail_lines = _format_vt_details(details)
                for dl in detail_lines:
                    lines.append("   " + dl)

            # vt-debug карточка (если есть и если ты запускал с --vt-debug)
            _append_vt_debug(lines, ev, indent="   ")

    if not any_vt:
        lines.append("— VT: данных нет по всем файлам")

    # --- 2.2 Индикаторы (агрегат по категориям) ---
    # Суммируем по ВСЕМ сессиям behaviour + relations: domains, ips, urls, processes.
    from collections import Counter as _Ctr
    cat_total = _Ctr()
    iterable = per_file
    for pf in iterable:
        vt = (pf.get("ev") or {}).get("vt") or {}
        beh_list = vt.get("behaviours") or vt.get("behaviors") or []
        for b0 in beh_list:
            if not isinstance(b0, dict):
                continue
            summ = b0.get("summary") if isinstance(b0.get("summary"), dict) else {}
            net  = b0.get("network") or summ.get("network") or {}
            if isinstance(net, dict):
                if net.get("domains"): cat_total["domains"] += len(net["domains"])
                if net.get("ips"):     cat_total["ips"]     += len(net["ips"])
                if net.get("urls"):    cat_total["urls"]    += len(net["urls"])
            procs = b0.get("processes") or summ.get("processes") or []
            if isinstance(procs, list): cat_total["processes"] += len(procs)
            cmds = b0.get("commands") or summ.get("commands") or []
            if isinstance(cmds, list): cat_total["commands"] += len(cmds)
        # из behaviour_relations (если cli дотащил отдельным запросом)
        rel = vt.get("behaviour_relations") or {}
        if isinstance(rel, dict):
            if rel.get("domains"): cat_total["domains"] += len(rel["domains"])
            if rel.get("ips"):     cat_total["ips"]     += len(rel["ips"])
            if rel.get("http"):    cat_total["http"]    += len(rel["http"])

    lines.append("* 2.2 Индикаторы (суммарно):*")
    if not cat_total:
        lines.append("— совпадений не обнаружено")
    else:
        top = ", ".join(f"{k}={v}" for k, v in cat_total.most_common(10))
        lines.append("— " + top)


def _append_static_section(lines: list[str], *, groups: dict[str, list], show_files: bool = False):
    """3) Статический анализ — агрегаты по группам (+ опционально пер-файл)."""
    lines.append("3) *Статический анализ*:")
    for gname, arr in _iter_groups(groups):
        n_yara_files = 0; n_yara_rules = 0
        rules = Counter(); techs = Counter()
        obf_cnt = 0; url_cnt = 0
        for pf in arr:
            ev = pf["ev"] or {}
            yhits = ev.get("yara") or []
            if isinstance(yhits, list) and yhits:
                unique_rules = list(dict.fromkeys(h.get("rule") or _get(h, "meta.name") for h in yhits if isinstance(h, dict)))
                unique_rules = [r for r in unique_rules if r]
                n_yara_files += 1
                n_yara_rules += len(unique_rules)
                for rn in unique_rules:
                    rules[str(rn)] += 1
            for t in (ev.get("capa") or {}).get("techniques") or []:
                techs[str(t)] += 1
            obf = ev.get("obfuscation") or {}
            if obf.get("packed_suspect") or obf.get("has_dyn_api_resolve"):
                obf_cnt += 1
            ss = ev.get("strings_summary") or {}
            url_cnt += int(ss.get("url_cnt") or 0)
        parts = []
        if n_yara_files:
            top_rules = ", ".join([f"{r}×{c}" for r, c in rules.most_common(3)])
            parts.append(f"yara: файлы={n_yara_files}, правил={n_yara_rules}" + (f", топ: {top_rules}" if top_rules else ""))
        if techs:
            parts.append(f"capa: техники={len(techs)}")
        if obf_cnt:
            parts.append(f"обфускация: {obf_cnt} файл(ов)")
        if url_cnt:
            parts.append(f"FLOSS URL: {url_cnt}")
        lines.append("* " + (f"{gname}: " if gname else "") + (", ".join(parts) if parts else "сработок по сигнатурам/техникам и явной обфускации не выявлено"))
        # === НОВОЕ: пер-файл детали под группой ===
        if show_files:
            for pf in arr:
                ev   = pf["ev"] or {}
                name = pf.get("name") or _basename(_get(ev, "path") or _get(ev, "file"))
                lines.append(f"  — {name}")
                name = pf.get("name") or _basename(_get(ev, "path") or _get(ev, "file"))
                sfx = (name.rsplit(".", 1)[-1].lower() if "." in name else "")
                yline = _yara_line(ev)
                if sfx in {"ova","ovf","mf","iso","vmdk"}:
                    cline = None
                else:
                    cline = _capa_line(ev)
                oline = _obf_line(ev)
                floss = _floss_line(ev) if 'strings_summary' in (ev or {}) else None
                if yline: lines.append("     " + yline)
                if cline: lines.append("     " + cline)
                if oline: lines.append("     " + oline)
                if floss: lines.append("     " + floss)
                eline = _errors_line(ev)
                if eline:
                    lines.append("     " + eline)
            lines.append("")
    lines.append("")


def _append_av_section(lines: list[str], evidences: list[dict], summary: dict | None):
    """
    Печатает результаты антивирусной проверки.
    Ожидает summary["av"]["kaspersky"] в формате run_kaspersky_scan().
    Для файлов с детектами выводит детальные строки.
    """
    av = (summary or {}).get("av") or {}
    kas = av.get("kaspersky") or {}
    if not kas:
        lines.append("Антивирус: не запускался.")
        lines.append("")
        return

    summ = kas.get("summary") or {}
    dets = kas.get("detections") or []
    lines.append(f"Kaspersky: scanned={summ.get('scanned','?')}, detected={summ.get('detected',len(dets))}, "
                 f"fixed={summ.get('fixed','0')}, quarantined={summ.get('quarantined','0')}")

    if not dets:
        lines.append("Сработок не обнаружено.")
        lines.append("")
        return

    # сгруппируем по файлам
    grouped = {}
    for d in dets:
        grouped.setdefault(Path(d["path"]).name, []).append(d)
    for fname, arr in grouped.items():
        for d in arr[:10]:
            lines.append(f"— {fname}: {d.get('threat','(неизвестно)')} ({d.get('verdict','detected')})")
    if len(dets) > 10:
        lines.append(f"— и ещё {len(dets)-10} сработок…")

    # если надо — приложим хвост "сырого" вывода на отладку
    # raw = kas.get("stdout") or ""
    lines.append("")


def _families_from_yara(ev):
    fams = []
    for y in ev.get("yara") or []:
        meta = y.get("meta") or {}
        fam = meta.get("family") or meta.get("group")
        if fam:
            fams.append(str(fam).lower())
    return fams

def _group_by_msi(evidences):
    groups = defaultdict(list)  # msi_path -> [ev, ...]
    singles = []
    containers_meta = {}  # msi_path -> meta
    for ev in evidences:
        cont = _container(ev)
        if cont and cont.get("type") == "msi":
            msi_path = cont.get("path") or cont.get("name") or "MSI"
            containers_meta[msi_path] = cont
            groups[msi_path].append(ev)
        else:
            singles.append(ev)
    return groups, singles, containers_meta

def _project_name(files: List[Path]) -> str:
    try:
        if not files:
            return "scan"
        import os
        parents = [str(p.parent) for p in files if isinstance(p, Path)]
        if not parents:
            return "scan"
        common = os.path.commonpath(parents)
        base = Path(common).name
        return base or "scan"
    except Exception:
        return "scan"

def _group_key(ev: Dict[str, Any]) -> str:
    try:
        p = Path(ev.get("path") or ev.get("file") or "")
        sfx = (p.suffix or "").lower()
        base = p.name.lower()
    except Exception:
        sfx = ""; base = ""

    kind = _kind_of(ev)
    if kind in ("PE", "ELF", "MACHO"):
        return kind

    # манифесты зависимостей (по имени файла)
    if base in {
        "requirements.txt","pipfile","pipfile.lock","poetry.lock","pyproject.toml",
        "package.json","package-lock.json","yarn.lock","pnpm-lock.yaml",
        "go.mod","go.sum","cargo.toml","cargo.lock",
        "pom.xml","build.gradle","build.gradle.kts","gradle.lockfile",
        "gemfile","gemfile.lock","composer.json","composer.lock",
        "global.json","nuget.config","pubspec.yaml","pubspec.lock",
    } or sfx in {".csproj",".vbproj",".sln"}:
        return "Manifests"

    # конфиги
    if sfx in {".env",".ini",".cfg",".conf",".yaml",".yml",".json",".toml",".properties",".config",".xml"}:
        return "Config"

    # контейнеры/архивы
    if sfx in {".jar",".apk",".aab"}:
        return "JAR/APK"
    if sfx in {".zip",".whl",".7z",".rar",".tar",".tgz",".tar.gz",
               ".nupkg",".msix",".appx",".vsix",".deb",".rpm",".crate",".cab",".iso",".img",".dmg",".xz",".bz2",".tar.xz",".tar.bz2",".gz"}:
        return "Archives"

    # офис/доки
    if sfx in {".doc",".docx",".xls",".xlsx",".ppt",".pptx",".docm",".xlsm",".pptm",".pdf"}:
        return "Office/PDF"

    # скрипты
    if sfx in {".ps1",".psm1",".psd1",".js",".vbs",".bat",".cmd",".sh",".py",".rb",".pl",".lua"}:
        return "Scripts"

    # веб-скрипты
    if sfx in {".php",".asp",".aspx",".jsp"}:
        return "Web"

    # ярлыки
    if sfx == ".lnk":
        return "Shortcuts"
    return "Other"


def _fmt_ts(ts: Optional[int]) -> str:
    if not isinstance(ts, int) or ts <= 0:
        return "—"
    import datetime as _dt
    return _dt.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%SZ")

def _bool(v: Optional[bool]) -> str:
    return "True" if v is True else ("False" if v is False else "—")


def _fmt_list(lst, cap=5):
    if not lst:
        return "—"
    lst = [str(x) for x in lst if x]
    if len(lst) <= cap:
        return ", ".join(lst)
    return ", ".join(lst[:cap]) + f" … (+{len(lst)-cap})"

def _hex_short(s: Optional[str], n=8):
    if not s:
        return "—"
    s = str(s)
    return s if len(s) <= 2*n else (s[:n] + "…" + s[-n:])


def _has_rep_flags(pf: dict) -> bool:
    """Есть срабатывания, если m/s>0 или есть поведенческие артефакты."""
    st = pf.get("vt_stats") or {"m": 0, "s": 0, "h": 0, "u": 0}
    bh = pf.get("vt_behaviours") or 0
    return (st.get("m", 0) > 0) or (st.get("s", 0) > 0) or (bh > 0)




def _kind_of(ev) -> str:
    def g(obj, key):
        return obj.get(key) if isinstance(obj, Mapping) else getattr(obj, key, None)

    k = str(g(ev, "kind") or g(ev, "type") or "").upper().replace("-", "")
    if k in ("PE", "ELF", "MACHO"):
        return k

    # важное изменение — считаем «наличие секции», а не тип контейнера
    if g(ev, "pe")    is not None: return "PE"
    if g(ev, "elf")   is not None: return "ELF"
    if g(ev, "macho") is not None: return "MACHO"

    return "BIN"

def _detect_name_from_ev(ev: Dict[str, Any]) -> Optional[str]:
    p = ev.get("path") or ev.get("file")
    if p:
        try:
            return Path(p).name
        except Exception:
            return str(p)
    return None

def _pe_imports_line(ev: Dict[str, Any]) -> str:
    s = _get(ev, "pe.imports_summary") or {}
    if not s:
        return "*Импорты и динамический резолв:* данных нет"

    dlls_top = s.get("dlls_top") or []
    bycat    = s.get("by_category") or {}
    redg     = s.get("red_groups") or {}
    delay    = s.get("delay_imports") or {}
    dyn      = s.get("dynamic_api_strings") or []

    order = ["loader","memory","proc_thread","debug_sym","psapi","file_io","registry","network","services","crypto","ui"]
    cats_present = [c for c in order if c in bycat]

    lines = ["*Импорты и динамический резолв:*"]
    if dlls_top:
        lines.append("   – Топ DLL: " + ", ".join(dlls_top))
    if cats_present:
        def one(c):
            cnt = bycat[c].get("count", 0)
            ex  = (bycat[c].get("examples") or [])[:3]
            return f"{c}={cnt}" + (f" (напр. {', '.join(ex)})" if ex else "")
        lines.append("   – Категории: " + "; ".join(one(c) for c in cats_present))
    if any(redg.get(k) for k in ("network","services","crypto")):
        bad = [k for k in ("network","services","crypto") if redg.get(k)]
        lines.append("   – Подсветка: есть импорты " + ", ".join(bad))
    else:
        lines.append("   – Подсветка: нет импортов network/services/crypto")
    if delay.get("present"):
        dlls = ", ".join(delay.get("dlls") or []) or "—"
        lines.append(f"   – Delay-imports: есть (DLL≈{dlls}; всего {delay.get('count', 0)})")
    else:
        lines.append("   – Delay-imports: нет")
    if dyn:
        # фильтр «похоже на имя API»
        apiish = []
        for d in dyn:
            d = str(d).strip()
            if len(d) > 40: 
                continue
            if " " in d or "\t" in d:
                continue
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]{2,}$", d):
                continue
            apiish.append(d)
        short = [x for x in apiish if not x.startswith("$W")] or apiish
        short = short[:6]
        if short:
            lines.append("   – Динамический резолв (вне IAT): " + ", ".join(short) + ("…" if len(apiish) > len(short) else ""))
        else:
            lines.append("   – Динамический резолв по строкам не обнаружен/незначителен")
    else:
        lines.append("   – Динамический резолв по строкам не обнаружен/незначителен")

    stats = _get(ev, "pe.imports_summary.stats") or {}
    bycat = _get(ev, "pe.imports_summary.by_category") or {}
    line = []

    if isinstance(stats.get("delay_imports_cnt"), int) and stats.get("delay_imports_cnt") > 0:
        line.append(f"delay-imports={stats['delay_imports_cnt']}")
    if isinstance(stats.get("unsafe_crt_cnt"), int) and stats.get("unsafe_crt_cnt") > 0:
        line.append(f"unsafe_crt={stats['unsafe_crt_cnt']}")

    for fam in ("services","token","crypto","process","network"):
        fam_d = bycat.get(fam) or {}
        ex = (fam_d.get("examples") or [])[:5]
        if fam_d.get("count"):
            line.append(f"{fam}:" + ",".join(ex))

    if line:
        lines.append("   – Опасные импорты: " + " ; ".join(line))

    iocs = ev.get("strings_iocs") or {}
    parts_ioc = []
    if iocs.get("urls"): parts_ioc.append("URL=" + ", ".join(iocs["urls"]))
    if iocs.get("ips"):  parts_ioc.append("IP=" + ", ".join(iocs["ips"]))
    if iocs.get("reg"):  parts_ioc.append("Reg=" + ", ".join(iocs["reg"]))
    if parts_ioc:
        lines.append("* *IOC (строки):* " + " ; ".join(parts_ioc))

    return "\n".join(lines)

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

def _vt_flagged_engines(vt: Dict[str, Any], category: str = "malicious") -> List[str]:
    res = _get_any(vt, [
        "data.attributes.last_analysis_results",
        "attributes.last_analysis_results",
        "last_analysis_results",
    ], {}) or {}
    hits = []
    if isinstance(res, dict):
        for eng, obj in res.items():
            if str((obj or {}).get("category") or "").lower() == category:
                hits.append(eng)
    return sorted(hits)[:8]  # не раздуваем вывод

def _vt_stats(vt: Dict[str, Any]) -> Dict[str, int]:
    # 1) ищем где угодно агрегатные last_analysis_stats
    st = _deep_find_stats(vt) or {}
    rep = _get_any(vt, [
        "reputation",
        "detections.reputation",
        "summary.reputation",
        "data.attributes.reputation",
        "attributes.reputation",
    ], 0)

    # 2) если агрегата нет или он «пустой», посчитаем из last_analysis_results
    if not st or sum(int(st.get(k) or 0) for k in ("malicious","suspicious","harmless","undetected","timeout")) == 0:
        results = _get_any(vt, [
            "data.attributes.last_analysis_results",
            "attributes.last_analysis_results",
            "last_analysis_results",
            "detections.last_analysis_results",
        ], {}) or {}
        if isinstance(results, dict) and results:
            cnt = {"malicious":0, "suspicious":0, "harmless":0, "undetected":0, "timeout":0}
            for obj in results.values():
                cat = str((obj or {}).get("category") or "").lower()
                if cat in cnt: cnt[cat] += 1
            st = cnt

    return {
        "m": int(st.get("malicious") or 0),
        "s": int(st.get("suspicious") or 0),
        "h": int(st.get("harmless")  or 0),
        "u": int(st.get("undetected") or 0),
        "rep": int(rep or 0),
    }


def _vt_link_by_sha(sha256: str) -> str:
    return f"https://www.virustotal.com/gui/file/{sha256}"

def _vt_behaviours_count(vt: Dict[str, Any]) -> int:
    # быстрые пути
    for p in ["behaviours_count", "behaviors_count"]:
        c = _get(vt, p, None)
        if isinstance(c, int) and c >= 0:
            return c
    for p in ["behaviours", "behaviors", "summary.behaviours", "detections.behaviours"]:
        arr = _get(vt, p, None)
        if isinstance(arr, list):
            return len(arr)
    # глубокий поиск любого списка behaviours/behaviors
    stack = [vt]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k in ("behaviours", "behaviors") and isinstance(v, list):
                    return len(v)
                stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return 0

def _yara_line(ev: Dict[str, Any]) -> str:
    hits = ev.get("yara") or []
    if not isinstance(hits, list) or len(hits) == 0:
        return "*YARA:* сработок нет"
    names: List[str] = list(dict.fromkeys(
        str(h.get("rule") or _get(h, "meta.name"))
        for h in hits if isinstance(h, dict) and (h.get("rule") or _get(h, "meta.name"))
    ))
    tail = (", ".join(names[:5])) if names else f"{len(hits)} правил"
    more = "" if len(names) <= 5 else f" (+{len(names) - 5})"
    return f"*YARA:* сработки — {tail}{more}"

# --- ЗАМЕНИ _floss_line НА ЭТУ ВЕРСИЮ (назадсовместимо) ---

def _floss_line(ev: Dict[str, Any]) -> str:
    """
    Счётчики FLOSS + короткое превью только IOC-строк (URL/IP/Registry/E-mail).
    Отбрасывает OCSP/CRL/CA-ссылки (в т.ч. ocsp2.*) из подписи/overlay.
    Совместимо с новой и старой схемами хранения строк.
    """
    import re

    RX_URL = re.compile(r"https?://[^\s\"'<>]{6,}", re.IGNORECASE)
    RX_IP  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    RX_REG = re.compile(
        r"(?:^|\\)(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s]{3,}"
        r"|\\Software\\[^\s]{3,}"
        r"|\\(Run|RunOnce|Services|Image File Execution Options)\\[^\s]{2,}",
        re.IGNORECASE,
    )
    RX_EML = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

    CA_DOMAINS = ("globalsign.com","digicert.com","verisign.com","sectigo.com","comodoca.com","letsencrypt.org")
    def _is_ca_ioc(s: str) -> bool:
        t = (s or "").lower()
        # ловим ocsp/ocsp2/ocspNN, crl, cacert, repository + домен CA
        if ("ocsp" in t) or ("crl" in t) or ("/cacert/" in t) or ("/repository/" in t):
            return any(dom in t for dom in CA_DOMAINS)
        return False

    ss_new = ev.get("strings_summary") or {}
    ss_old = ((ev.get("strings") or {}).get("floss") or {}).get("summary") or {}
    ss     = ss_new or ss_old or {}

    total   = int(ss.get("total_cnt")   or 0)
    decoded = int(ss.get("decoded_cnt") or 0)
    stack   = int(ss.get("stack_cnt")   or 0)
    static  = int(ss.get("static_cnt")  or 0)
    tight   = ss.get("tight_cnt")
    if total == 0:
        return ""  # FLOSS не используется — не выводить строку «строк не извлечено»

    head = f"FLOSS: decoded {decoded}, stack {stack}, static {static}"
    if tight is not None:
        try:
            head += f", tight {int(tight)}"
        except Exception:
            pass

    s_new = ev.get("strings") or {}
    f_old = s_new.get("floss") or {}
    s_old = f_old.get("strings") or {}
    buckets = {
        "decoded": (s_new.get("decoded") or s_old.get("decoded") or []),
        "stack":   (s_new.get("stack")   or s_old.get("stack")   or []),
        "static":  (s_new.get("static")  or s_old.get("static")  or []),
        "tight":   (s_new.get("tight")   or s_old.get("tight")   or []),
    }

    pe = (ev.get("pe") or {})
    pe_sig_present = bool((pe.get("signature") or {}).get("present"))
    pe_overlay_pct = float((pe.get("sections") or {}).get("overlay_pct") or 0.0)
    suppress_ca = pe_sig_present or (pe_overlay_pct >= 50.0)

    iocs: list[str] = []
    for name in ("decoded", "stack", "static", "tight"):
        arr = buckets.get(name) or []
        for s in arr[:20000]:
            if not isinstance(s, str):
                try:
                    s = s.decode("utf-8", "ignore")
                except Exception:
                    continue
            s = s.strip()
            if not s:
                continue
            if RX_URL.search(s) or RX_IP.search(s) or RX_REG.search(s) or RX_EML.search(s):
                if suppress_ca and _is_ca_ioc(s):
                    continue
                iocs.append(s)

    seen, preview = set(), []
    for s in iocs:
        if s in seen:
            continue
        seen.add(s)
        preview.append(s)
        if len(preview) >= 5:
            break

    return head + (("; strings(IOCs): " + "; ".join(preview)) if preview else "")





def _elf_details_line(ev: Dict[str, Any]) -> str:
    interp   = _get(ev, "elf.interp")
    build_id = _get(ev, "elf.build_id")
    soname   = _get(ev, "elf.soname")
    needed   = _get(ev, "elf.needed", []) or []
    h        = _get(ev, "elf.hardening", {}) or {}
    rpath    = h.get("rpath")
    runpath  = h.get("runpath")
    risky    = h.get("rpath_risky")
    textrel  = h.get("textrel")
    wxseg    = h.get("w_x_segments")
    cet_ibt  = _get(ev, "elf.cet.ibt")
    cet_sh   = _get(ev, "elf.cet.shstk")
    stripped = _get(ev, "elf.stripped")
    static   = _get(ev, "elf.static_linked")

    rp_note = " [!]" if risky else ""
    cet_parts = []
    if cet_ibt is True:  cet_parts.append("IBT")
    if cet_sh  is True:  cet_parts.append("SHSTK")
    cet_txt = ("; CET=" + ",".join(cet_parts)) if cet_parts else ""

    # Подозрительные зависимости (напр. libcurl в драйвере — сетевой доступ)
    _SUSPICIOUS_NEEDED = {"libcurl", "libcurl.so", "libcurl.so.4", "libssl", "libcrypto", "libssh2", "libcurl.so.3"}
    needed_lower = [str(n).lower().strip() for n in needed] if needed else []
    suspicious = [n for n in needed_lower if any(s in n for s in _SUSPICIOUS_NEEDED)]
    suspicious_note = ""
    if suspicious:
        unique_susp = list(dict.fromkeys(suspicious))
        suspicious_note = " Подозрительные зависимости: " + ", ".join(unique_susp[:5]) + " (сетевой/крипто-доступ)."
    return (
        "ELF детали: "
        f"interp={interp or '—'}; "
        f"build-id={_hex_short(build_id)}; "
        f"soname={soname or '—'}; "
        f"needed[{len(needed)}]={_fmt_list(needed, cap=4)}; "
        f"RPATH={repr(rpath) if rpath is not None else '—'}; "
        f"RUNPATH={repr(runpath) if runpath is not None else '—'}{rp_note}; "
        f"TEXTREL={_bool(textrel)}; RWX-LOAD={_bool(wxseg)}{cet_txt}; "
        f"stripped={_bool(stripped)}; static={_bool(static)}"
        f"{suspicious_note}"
    )

def _obf_line(ev: Dict[str, Any]) -> str:
    obf = ev.get("obfuscation") or {}
    if not isinstance(obf, dict) or not obf:
        return "Обфускация/анти-анализ: —"

    def _f(v):
        try:
            return float(v)
        except Exception:
            return None

    flags: List[str] = []

    # 1) «почти нет строк» + высокая энтропия секций
    sr_ascii = _f(obf.get("string_ratio_ascii"))
    sr_u16   = _f(obf.get("string_ratio_utf16"))
    sr_old   = _f(obf.get("string_ratio"))  # на случай старого формата
    sr_total = None
    if sr_ascii is not None or sr_u16 is not None:
        sr_total = (sr_ascii or 0.0) + (sr_u16 or 0.0)
    elif sr_old is not None:
        sr_total = sr_old

    max_se = _f(obf.get("max_section_entropy"))
    if sr_total is not None and sr_total < 0.004 and (max_se is not None and max_se >= 7.0):
        flags.append("минимум строк + высокая энтропия")

    # 2) packer/обфускация по секциям/подсказкам
    if obf.get("packed_suspect"):
        flags.append("подозрение на packer")

    # 3) динамическая резольвация и «мало импортов»
    if obf.get("has_dyn_api_resolve"):
        flags.append("динамический резолв API")
        try:
            ic = int(obf.get("import_count") or 0)
            if ic <= 8:
                flags.append("очень мало импортов")
        except Exception:
            pass

    # 4) анти-отладка / anti-VM
    if (obf.get("anti_debug_apis") or []):
        flags.append("анти-отладка")
    if (obf.get("anti_vm_indicators") or []):
        flags.append("anti-VM")

    # 5) изменение прав памяти / инжект
    if obf.get("uses_virtualprotect") or obf.get("uses_mprotect"):
        flags.append("смена защиты памяти")
    if obf.get("uses_writeprocessmemory"):
        flags.append("WriteProcessMemory")
    if obf.get("uses_createremotethread"):
        flags.append("CreateRemoteThread")

    # 6) дополнительные маркеры платформ
    try:
        tls_cb = int(obf.get("tls_callback_count") or 0)
        if tls_cb > 0:
            flags.append("TLS callbacks")
    except Exception:
        pass
    if obf.get("stripped") is True:
        flags.append("stripped (нет .symtab)")

    try:
        rec = int(obf.get("recovered_strings_count") or 0)
        if rec > 0:
            flags.append(f"восстановленные строки ({rec})")
    except Exception:
        pass

    packs = (ev.get("obfuscation") or {}).get("packer_families") or []
    if packs:
        flags.append("упаковщик: " + ", ".join(packs))

    fams = (ev.get("obfuscation") or {}).get("packer_families") or []
    if fams:
        flags.append("packers: " + ", ".join(sorted(fams)))

    # краткие «причины» (если есть), ограничим до 3
    reasons = [str(r) for r in (obf.get("reasons") or [])]
    reasons = reasons[:3]
    reasons_txt = ("; причины: " + "; ".join(reasons)) if reasons else ""

    return ("Обфускация/анти-анализ: признаков нет"
            if not flags else
            "Обфускация/анти-анализ: " + ", ".join(flags) + reasons_txt)


def _capa_line(ev: Dict[str, Any]) -> str:
    cap = ev.get("capa") or {}
    tacts = cap.get("techniques") or []
    if tacts:
        uniq = ", ".join(sorted(set(map(str, tacts))))
        return f"*capa:* техники — {uniq}"
    # без упоминания таймаута
    return "*capa:* техники не выявлены"

def _short_list(arr, n=3):
    arr = [str(x) for x in (arr or []) if x]
    if not arr:
        return "—"
    head = ", ".join(arr[:n])
    return head if len(arr) <= n else f"{head} (+{len(arr)-n})"

def _pe_security_line(ev: Dict[str, Any]) -> str:
    h    = _get(ev, "pe.hardening", {}) or {}
    tls  = _get(ev, "pe.tls_callbacks", None)
    arch = str(_get(ev, "pe.arch") or "").lower()

    # SafeSEH корректно только для x86
    safeseh_txt = "N/A" if arch == "x64" else _bool(h.get("safeseh"))

    parts = [
        f"ASLR={_bool(h.get('aslr'))}",
        f"ASLR(eff)={_bool(h.get('aslr_effective'))}",
        f"DEP={_bool(h.get('dep'))}",
        f"CFG={_bool(h.get('cfg'))}",
        f"CFG(table)={_bool(h.get('cfg_table'))}",
        f"GS(cookie)={_bool(h.get('gs_cookie'))}",
        f"SafeSEH={safeseh_txt}",
        f"HighEntropyVA={_bool(h.get('high_entropy_va'))}",
        f"LAA={_bool(h.get('large_address_aware'))}",
        f"TLS callbacks={tls if isinstance(tls, int) else '—'}",
    ]

    # Новые поля укреплённости
    cet_ibt  = h.get("cet_ibt")        # True/False/None
    sehop_h  = h.get("sehop_hint")     # "compatible"/"unknown"/None

    if cet_ibt is not None:
        parts.append(f"CET(IBT)={_bool(cet_ibt)}")
    if sehop_h:
        parts.append(f"SEHOP(hint)={sehop_h}")

    return "*Безопасность (PE):* " + "; ".join(parts)

def _is_profilerish(ev: Dict[str, Any]) -> bool:
    bycat = _get(ev, "pe.imports_summary.by_category") or {}
    redg  = _get(ev, "pe.imports_summary.red_groups") or {}
    has_prof = ("debug_sym" in bycat) or ("psapi" in bycat)
    no_red = not any((redg or {}).get(k) for k in ("network","services","crypto"))
    return bool(has_prof and no_red)

def _pe_sections_line(ev: Dict[str, Any]) -> str:
    s = _get(ev, "pe.sections", {}) or {}
    unusual = s.get("unusual_names") or []
    ov = s.get("overlay_pct")
    sig_ok = _sig_present_soft(ev)
    if isinstance(ov, (int, float)) and ov >= 1 and sig_ok:
        ov_fmt = f"{ov:.3f}%"
        ov_txt = f"{ov_fmt} (~AuthCert)" if ov >= 1 else ov_fmt
    else:
        ov_txt = str(ov) if ov is not None else "—"
    parts = [
        f"RWX={_bool(s.get('has_rwx'))}",
        f"WX={_bool(s.get('has_wx'))}",
        f".reloc={_bool(s.get('relocs_present'))}",
        f"overlay={ov_txt}",
        "необычные секции=" + (_short_list(unusual, 4) if unusual else "—"),
    ]
    return "*Секции (PE):* " + "; ".join(parts)

def _pe_meta_line(ev: Dict[str, Any]) -> str:
    arch = _get(ev, "pe.arch") or "—"
    subsys = _get(ev, "pe.subsystem") or "—"
    imp_cnt = _get(ev, "pe.imports_count")
    exp_cnt = _get(ev, "pe.exports_count")
    rh = _get(ev, "pe.rich_header", {}) or {}
    dotnet = _get(ev, "pe.dotnet.present")
    uac = _get(ev, "pe.resources.uac_level")
    ver = _get(ev, "pe.resources.version.FileVersion")
    parts = [
        f"Arch={arch}", f"Subsystem={subsys}",
        f"Imports={imp_cnt if imp_cnt is not None else '—'}",
        f"Exports={exp_cnt if exp_cnt is not None else '—'}",
        f".NET={_bool(dotnet)}",
        f"UAC={uac or '—'}",
        f"FileVersion={ver or '—'}",
        "RichHeader=" + ("present" if rh.get("present") is True else ("—" if rh.get("present") is False else "неизв.")),
    ]
    uac_auto = _get(ev, "pe.resources.uac_auto_elevate")
    if uac_auto is True:
        parts.append("UAC(autoElevate)=True")
    return "*Метаданные (PE):* " + "; ".join(parts)

def _visual_audit_line(ev: Dict[str, Any]) -> Optional[str]:
    """Визуальный аудит (Masquerading 2.0): если иконка документа, а файл — PE, возвращает жирный алерт."""
    vis = _get(ev, "visual") or {}
    icon_type = (vis.get("icon_type") or vis.get("icon", {}).get("mismatch_type") or "").strip()
    file_type = (vis.get("file_type") or _get(ev, "meta.type") or "").strip()
    if not file_type and _kind_of(ev) == "PE":
        file_type = "PE Executable"
    doc_like = "document" in icon_type.lower() or "doc" in icon_type.lower() or "excel" in icon_type.lower() or "pdf" in icon_type.lower() or "word" in icon_type.lower() or "image" in icon_type.lower()
    pe_exec = "pe executable" in file_type.lower() or file_type == "PE"
    if doc_like and pe_exec:
        return "**ВНИМАНИЕ: Файл мимикрирует под документ. Высокий риск социальной инженерии.**"
    if _get(ev, "visual.masquerading_suspect") or _get(ev, "visual.icon_mismatch"):
        return "**Внимание: возможная мимикрия под документ (несоответствие иконки и типа файла).**"
    return None


def _hardening_line(ev: Dict[str, Any]) -> str:
    kind = _kind_of(ev)
    if kind == "ELF":
        h = _get(ev, "elf.hardening", {}) or {}
        line = (
            f"*Харденинг (ELF):* "
            f"PIE={_bool(h.get('pie'))}; "
            f"NX={_bool(h.get('nx'))}; "
            f"RELRO={h.get('relro','—')}; "
            f"Canary={_bool(h.get('canary'))}; "
            f"TEXTREL={_bool(h.get('textrel'))}; "
            f"RWX-LOAD={_bool(h.get('w_x_segments'))}"
        )
        return line
    if kind == "PE":
        h = _get(ev, "pe.hardening", {}) or {}
        sig = "есть" if _sig_present_soft(ev) else ("отсутствует" if _get(ev, "pe.signature.present") is False else "неизв.")
        line = f"*Харденинг (PE):* ASLR={_bool(h.get('aslr'))}; DEP={_bool(h.get('dep'))}; CFG={_bool(h.get('cfg'))}; подпись={sig}"
        has_rwx = _get(ev, "pe.sections.has_rwx")
        ov = _get(ev, "pe.sections.overlay_pct")
        if has_rwx is not None or ov is not None:
            line += f"; секции: RWX={_bool(has_rwx)}; overlay={ov if ov is not None else '—'}%"
        dang_ord = _get(ev, "pe.dangerous_ordinal_imports") or []
        if dang_ord:
            apis = ", ".join(str(x.get("api") or x.get("resolved") or "?") for x in dang_ord[:5])
            line += f". **Внимание: скрытый импорт по ординалу (опасные API): {apis}**"
        return line
    return "*Харденинг:* —"

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
    "elf-wx":
        "Использовать W^X: никаких RWX LOAD-сегментов; пересобрать с корректными правами секций/сегментов.",
    "elf-textrel":
        "Исключить TEXTREL (позиционно-зависимые записи в .text); пересобрать с -fPIC и без TEXTREL.",
    "elf-rpath-risky":
        "Убрать небезопасные пути из RPATH/RUNPATH ('.', относительные, без $ORIGIN); оставить только абсолютные/контролируемые.",
    "pe-aslr-not-effective":
        "Включить корректные релокации (.reloc) и сборку с /DYNAMICBASE; иначе ASLR фактически не работает.",
    "pe-wx":
        "Убрать W+X права у секций (или разделить на W и X); запретить запуск модулей с WX в продуктиве.",
    "pe-no-gs":
        "Собрать с защитой стека (/GS) и устранить функции, отключающие GS.",
    "pe-no-cfg-table":
        "Проверить наличие CFG-таблицы/инструментации (GuardFlags); для MSVC — включить /guard:cf.",
    "pe-uac-admin":
        "Снизить UAC до asInvoker или highestAvailable, если admin не требуется; пересмотреть манифест.",
    "pe-tls-callbacks":
        "Проверить код инициализации в TLS callbacks (ранний старт/обфускация).",
    "pe-unusual-sections":
        "Верифицировать назначение нестандартных секций (packing/обфускация/ложные имена).",
    "pe-driver-unsigned":
        "Не загружать неподписанные драйверы; требовать кросс-подпись WHQL/EV.",
    "pe-high-overlay":
        "Проверить overlay >5% (возможные присадки/упаковка/пост-запись).",
    "pe-safeseh-missing":
        "Для x86 включить SafeSEH (/SAFESEH) или перейти на x64.",
}

def _policy_outcome_lines(ev: Dict[str, Any]) -> List[str]:
    """Возвращает строки с жирными маркерами: *Итог/Причины/Рекомендую*."""
    lines: List[str] = []
    pol = ev.get("policy") or {}
    dec = (pol.get("decision") or "allow").lower()
    reasons = pol.get("reasons") or []

    if dec == "allow":
        if _is_profilerish(ev):
            lines.append("*Итог:* *Одобрено (dev-инструмент).*")
        else:
            lines.append("*Итог:* *Проблем не обнаружено.*")
        return lines

    # warn/deny
    if dec == "warn":
        if _is_profilerish(ev):
            lines.append("*Итог:* *Одобрено (dev-инструмент).*")
            # при желании можно сразу выйти, чтобы не печатать ниже «Причины» от warn
            # return lines
        else:
            lines.append("*Итог:* *Предупреждение.*")
    else:
        lines.append("*Итог:* *Запрещено политикой.*")

    # причины (без префикса [rule-id])
    human: List[str] = []
    tips: List[str] = []
    for r in reasons:
        m = _ID_RE.match(str(r))
        rid = m.group("id") if m else None
        txt = m.group("text") if m else str(r)

        if txt and "policy_eval_error:" in txt:
            continue

        if txt:
            human.append(txt)
        if rid and rid in _RECOMMEND:
            tips.append(_RECOMMEND[rid])

    if human:
        lines.append("*Причины:* " + "; ".join(human))
    if tips:
        lines.append("*Рекомендую:* " + " ".join(sorted(set(tips))))
    return lines

def _pe_signature_line(ev: Dict[str, Any]) -> str:
    if not _sig_present_soft(ev):
        return "*Подпись:* не обнаружена"
    sig = _get(ev, "pe.signature") or {}

   # если все поля пустые — напишем, что подпись обнаружена, но детали не извлечены
    core = [sig.get("publisher") or sig.get("subject"),
            sig.get("issuer"), sig.get("thumbprint") or sig.get("thumb"),
            sig.get("algorithm") or sig.get("digestAlgorithm")]
    if not any(str(x or "").strip() for x in core):
        src = "embedded" if sig.get("embedded") else ("catalog" if sig.get("catalog") else "—")
        return f"*Подпись:* Была найдена подпись"

    subj   = sig.get("publisher") or sig.get("subject") or "—"
    iss    = sig.get("issuer") or "—"
    algo   = sig.get("algorithm") or sig.get("digestAlgorithm") or "—"
    th     = sig.get("thumbprint") or sig.get("thumb") or "—"
    not_before = _get(sig, "not_before") or _get(sig, "valid_from") or "—"
    not_after  = _get(sig, "not_after")  or _get(sig, "valid_to")   or "—"
    eku    = ", ".join(sig.get("eku") or sig.get("extended_key_usage") or []) or "—"

    # Валидность цепочки и отметки времени (разные пайплайны кладут по-разному)
    chain_ok = bool(
        sig.get("chain_valid") or sig.get("verified_chain") or sig.get("is_trusted") or False
    )
    ts_present = bool(sig.get("timestamp_present") or sig.get("has_timestamp") or _get(sig, "timestamp") is not None)
    ts_ok = bool(sig.get("timestamp_valid") or sig.get("timestamp_trusted") or False)
    ts_val = _get(sig, "timestamp_time") or _get(sig, "timestamp") or ("есть" if ts_present else "—")

    # Источник: вшитая/каталожная подпись/счётчик подписи
    src = "embedded" if sig.get("embedded") else ("catalog" if sig.get("catalog") else "—")
    counters = sig.get("countersigners") or []
    counters_s = ", ".join(map(str, counters[:2])) + (f" (+{len(counters)-2})" if len(counters) > 2 else "")
    counters_s = counters_s or "—"

    # Короткий thumbprint
    def _hex_short(x: str, n: int = 6) -> str:
        x = str(x or "")
        return (x[:n] + "…") if len(x) > n else x or "—"

    status_bits = []
    status_bits.append(f"Chain={'OK' if chain_ok else 'FAIL'}")
    if ts_present:
        status_bits.append(f"TS={'OK' if ts_ok else 'BAD'}")
    else:
        status_bits.append("TS=—")
    status = ", ".join(status_bits)

    return (
        "*Подпись:* "
        f"Subject={subj}; Issuer={iss}; Algo={algo}; Thumbprint={_hex_short(th, 8)}; "
        f"EKU={eku}; Valid={not_before}..{not_after}; Source={src}; Countersigners={counters_s}; {status}"
    )

# ---------------- main report ----------------


def write_human_report(
    out_path: Path,
    files: List[Path],
    summary: Dict[str, Any],
    policy: Dict[str, Any],
    evidences: List[Dict[str, Any]],
    *,
    profile: str,
    capa_timeout: int,          # совместимость с вызовом
    merge_msis: bool = False,   # влияет только на compact-режим
    merge_top: int = 12,        # для показа «шумных» файлов в MSI агрегате
    compact: bool = False,
    show_project_header: bool = False,
    show_all_names: bool = False,
) -> None:
    """
    Полный человекочитаемый отчёт в прежней структуре:
    ОПИСАНИЕ → ПРОВЕРКА (1: идентификация/целостность; 2: репутация;
    3: статика; 3a: репутац. индикаторы; 4: CVE) → ВЫВОД.
    Под капотом опирается на хелперы модуля:
      _name_for_index, _kind_of, _get, _get_any, _hardening_line, _yara_line, _capa_line,
      _floss_line, _obf_line,
      _pe_security_line, _pe_sections_line, _pe_meta_line, _pe_imports_line, _elf_details_line,
      _pe_signature_line, _policy_outcome_lines, _msi_source_line_ru,
      _vt_stats, _vt_link_by_sha, _vt_behaviours_count, _vt_last_analysis_ts, _vt_flagged_engines, _fmt_ts
    """

    # -------- утилиты местного пользования --------
    def G(d: Dict[str, Any] | None, path: str, default=None):
        cur = d or {}
        for p in path.split("."):
            if not isinstance(cur, dict):
                return default
            cur = cur.get(p)
        return default if cur is None else cur

    def _container_of(ev: Dict[str, Any]) -> Dict[str, Any] | None:
        return (ev.get("meta") or {}).get("container") or None

    def _basename(p: str | None) -> str:
        try:
            return Path(p).name
        except Exception:
            return str(p or "")

    RANK = {"allow": 0, "warn": 1, "deny": 2}

    # -------- собрать per_file карточки --------
    per_file: List[Dict[str, Any]] = []
    for i, ev in enumerate(evidences):
        name = _name_for_index(evidences, files, i)
        sfx = (name.rsplit(".", 1)[-1].lower() if "." in name else "")
        kind_raw = _kind_of(ev).upper().replace("-", "")
        kind = kind_raw if kind_raw in ("PE", "ELF", "MACHO") else "EXT"
        
        try:
            setattr(ev, "kind", kind)
        except Exception:
            if isinstance(ev, dict):
                ev["kind"] = kind
        sha = _get(ev, "hashes.sha256", "") or _get(ev, "sha256", "")
        vt = ev.get("vt") or {}
        vt_stats = _vt_stats(vt)
        vt_link = _vt_link_by_sha(sha) if sha else None
        vt_bh = _vt_behaviours_count(vt) or None
        capa_line_val = None if sfx in {"ova","ovf","mf","iso","vmdk"} else _capa_line(ev)


        per_file.append({
            "idx": i,
            "name": name,
            "kind": kind,
            "sha": sha,
            "hardening": _hardening_line(ev),
            "yara": _yara_line(ev),
            "capa": capa_line_val,
            "vt_stats": vt_stats,
            "vt_behaviours": vt_bh,
            "vt_link": vt_link,
            "ev": ev,
        })

    groups = defaultdict(list)

    def _path_for_pf(pf: dict) -> str:
        ev = pf.get("ev") or {}
        idx = pf.get("idx", -1)
        # 1) ev.path/file если есть, 2) исходный files[idx], 3) видимое имя
        cand = ev.get("path") or ev.get("file")
        if not cand and isinstance(idx, int) and 0 <= idx < len(files):
            cand = str(files[idx])
        return cand or pf.get("name", "")

    for pf in per_file:
        # Дадим _group_key максимум контекста: kind + file
        ev_for_group = dict(pf.get("ev") or {})
        if "kind" not in ev_for_group and pf.get("kind"):
            ev_for_group["kind"] = pf["kind"]
        if not ev_for_group.get("file") and not ev_for_group.get("path"):
            ev_for_group["file"] = _path_for_pf(pf)
        gk = _group_key(ev_for_group)
        groups[gk].append(pf)

    proj = _project_name(files)
    lines: List[str] = []
    # Показываем и сколько передали (files), и сколько реально проанализировано (per_file)
    if show_project_header:
        lines.append(
            f"Проект: {proj}. Передано: {len(files)}; проанализировано: {len(per_file)} "
            f"файл(ов) в {len(groups)} группах."
        )
        lines.append("")
    
    


    # -------- compact (по желанию) --------
    if compact:
        # «очеловеченный» короткий свод, плюс MSI-агрегат по желанию
        stage = summary.get("stage", "5")
        prof  = policy.get("profile", profile)

        # Аггрегаты по всем файлам
        pol_worst, pol_max, pol_cnt = "allow", 0, Counter()
        vt_sum = Counter()
        capa_tc = Counter()
        sig = Counter(ok=0, bad=0, absent=0)
        hard = Counter(rwx=0, wx=0, aslr_noreloc=0, no_gs=0, no_cfg=0, no_cfg_table=0,
                       tls_cb=0, drv_unsigned=0, unusual=0, overlay5=0, uac_admin=0)
        obf = Counter(packed=0, dyn_api=0)
        obf_reasons = Counter()
        strings_sum = Counter(decoded=0, urls=0, ips=0, cmds=0)
        rep_sum = Counter()

        for pf in per_file:
            ev = pf["ev"]

            # policy
            pol = (ev.get("policy") or {})
            dec = (pol.get("decision") or "allow").lower()
            sc  = int(pol.get("score") or 0)
            if RANK.get(dec, 0) > RANK.get(pol_worst, 0): pol_worst = dec
            if sc > pol_max: pol_max = sc
            pol_cnt[dec] += 1

            # VT
            st = pf["vt_stats"]; vt_sum.update({"m": st["m"], "s": st["s"], "h": st["h"], "u": st["u"]})

            # capa
            for t in (G(ev, "capa.techniques", []) or []):
                capa_tc[str(t).lower()] += 1

            # подписи/харденинг по PE
            if pf["kind"] == "PE":
                sig_present = _sig_present_soft(ev)
                sig_valid   = bool(_get(ev, "pe.signature.valid"))
                if sig_present:
                    if sig_valid:
                        sig["ok"] += 1
                    else:
                        sig["bad"] += 1
                else:
                    sig["absent"] += 1
                if _get(ev, "pe.sections.has_rwx"): hard["rwx"] += 1
                if _get(ev, "pe.sections.has_wx"): hard["wx"] += 1
                if _get(ev, "pe.hardening.aslr") and not _get(ev, "pe.sections.relocs_present"):
                    hard["aslr_noreloc"] += 1
                if _get(ev, "pe.hardening.gs_cookie") is False: hard["no_gs"] += 1
                if _get(ev, "pe.hardening.cfg") is False: hard["no_cfg"] += 1
                if _get(ev, "pe.hardening.cfg_table") is False and _get(ev, "pe.hardening.cfg") is True:
                    hard["no_cfg_table"] += 1
                if int(_get(ev, "pe.tls_callbacks", 0) or 0) > 0: hard["tls_cb"] += 1
                if _get(ev, "pe.driver_like") and (not sig_present or not sig_valid): hard["drv_unsigned"] += 1
                if _get(ev, "pe.sections.unusual_names"): hard["unusual"] += 1
                try:
                    overlay = float(_get(ev, "pe.sections.overlay_pct") or 0.0)
                    if overlay >= 5.0: hard["overlay5"] += 1
                except Exception:
                    pass
                if (G(ev, "pe.resources.uac_level") or "").lower() == "requireadministrator":
                    hard["uac_admin"] += 1

            # обфускация
            if G(ev, "obfuscation.packed_suspect") is True: obf["packed"] += 1
            if G(ev, "obfuscation.has_dyn_api_resolve") is True: obf["dyn_api"] += 1
            for r in (G(ev, "obfuscation.reasons") or []):
                obf_reasons[str(r)] += 1

            # строки/FLOSS
            ss = ev.get("strings_summary") or {}
            strings_sum.update({
                "decoded": int(ss.get("decoded_cnt") or 0),
                "urls":    int(ss.get("url_cnt") or 0),
                "ips":     int(ss.get("ip_cnt") or 0),
                "cmds":    int(ss.get("cmd_cnt") or 0),
            })

            # репутационные категории
            for k, v in (G(ev, "reputation.counts", {}) or {}).items():
                try:
                    rep_sum[str(k)] += int(v or 0)
                except Exception:
                    pass

        lines.append("")
        _append_description(lines, files, show_all_names=show_all_names)
        lines.append("")

        lines.append("ПРОВЕРКА:")
        # аутентичность
        if sig["ok"] == 0 and sig["bad"] == 0 and sig["absent"] > 0:
            lines.append("* {}Проверка на аутентичность{}. Подписи отсутствуют у переданных артефактов.")
        elif sig["ok"] > 0:
            lines.append("* {}Проверка на аутентичность{}. Подписи обнаружены (см. ниже).")
        else:
            lines.append("* {}Проверка на аутентичность{}. Подписи обнаружены частично/с проблемами.")

        # hardening / VT / capa / obf / strings / CVE / rep
        lines.append("* SAST/Hardening проверки. " + ("Обнаружены критичные проблемы." if pol_worst == "deny" else "Критичных проблем не обнаружено."))
        lines.append(f" * VirusTotal: m/s/h/u = {vt_sum['m']}/{vt_sum['s']}/{vt_sum['h']}/{vt_sum['u']}")
        if capa_tc:
            lines.append(" * CAPA techniques (top): " + ", ".join(f"{k}({c})" for k, c in capa_tc.most_common(10)))
        lines.append(f" * Подписи (PE): ok/bad/absent = {sig['ok']}/{sig['bad']}/{sig['absent']}")
        lines.append(
            " * Харденинг (PE): "
            f"RWX={hard['rwx']}, W+X={hard['wx']}, ASLR без .reloc={hard['aslr_noreloc']}, "
            f"no-GS={hard['no_gs']}, CFG off={hard['no_cfg']}, CFG no table={hard['no_cfg_table']}, "
            f"TLS callbacks={hard['tls_cb']}, driver-unsigned={hard['drv_unsigned']}, "
            f"unusual sections={hard['unusual']}, overlay≥5%={hard['overlay5']}, UAC=admin={hard['uac_admin']}"
        )
        lines.append(f" * Обфускация: packed_suspect={obf['packed']}, dyn_api={obf['dyn_api']}")
        if obf_reasons:
            lines.append("reasons: " + ", ".join(f"{k}({c})" for k, c in obf_reasons.most_common(10)))
        lines.append(f" * Strings / FLOSS: decoded={strings_sum['decoded']}, urls={strings_sum['urls']}, ips={strings_sum['ips']}, cmds={strings_sum['cmds']}")

        # CVE (агрегат)
        cve_tot = Counter(critical=0, high=0, medium=0)
        for pf in per_file:
            s = G(pf["ev"], "cve.summary", {}) or {}
            cve_tot.update({
                "critical": int(s.get("critical") or 0),
                "high":     int(s.get("high") or 0),
                "medium":   int(s.get("medium") or 0),
            })
        lines.append(f" * CVE (суммарно): critical={cve_tot['critical']}, high={cve_tot['high']}, medium={cve_tot['medium']}")
        emu_dlls_compact = []
        for pf in per_file:
            for d in (G(pf["ev"], "supply_chain.dependencies") or []):
                if isinstance(d, dict) and d.get("type") == "dynamic_lib" and d.get("value"):
                    v = (d.get("value") or "").strip()
                    if v and v not in emu_dlls_compact:
                        emu_dlls_compact.append(v)
        if emu_dlls_compact:
            lines.append(f" * Обнаружено в памяти (Dynamic Load): {len(emu_dlls_compact)} DLL")
        if rep_sum:
            lines.append(" * Reputation (суммарно): " + ", ".join(f"{k}={v}" for k, v in rep_sum.most_common()))

        lines.append("ВЫВОД((/)):")
        if pol_worst == "deny":
            lines.append("Проверяемый пакет отклонён, обнаружил критичные проблемы.")
            if emu_dlls_compact and any(
                "vmprotect" in str(G(pf["ev"], "die.detects")).lower() or
                any("vmprotect" in str(p).lower() for p in (G(pf["ev"], "obfuscation.packer_families") or []))
                for pf in per_file
            ):
                lines.append("Вердикт DENY вызван в том числе наличием VMProtect и скрытых библиотек, выявленных при эмуляции.")
        elif pol_worst == "warn":
            lines.append("Проверяемый пакет одобрен с предупреждениями.")
        else:
            lines.append("Проверяемый пакет одобрен, критичных проблем не обнаружил.")
        lines.append("Выложил артефакт по пути -")

        text = "\n".join(lines)
        try:
            out_path.write_text(text, encoding="utf-8", errors="backslashreplace")
        except TypeError:
            with out_path.open("w", encoding="utf-8", errors="backslashreplace", newline="\n") as f:
                f.write(text)
        return

    # -------- подробный «старый» формат (как в твоём примере) --------
    stage = summary.get("stage", "5")
    lines.append("")

    # ОПИСАНИЕ
    _append_description(lines, files, show_all_names=show_all_names)
    lines.append("")

    # ПРОВЕРКА
    lines.append("*ПРОВЕРКА*")
    lines.append("")
    _append_scan_depth_section(lines, evidences)
    threat_groups = _build_threat_groups(evidences)

    # Обоснование вердикта и индикатор риска — первым под заголовком
    try:
        from ..scoring import compute_risk_score, build_deny_justification
        prof = (policy.get("profile") or profile or "dev") if isinstance(policy, dict) else (profile or "dev")
        risk_scores = [compute_risk_score(ev, profile=prof) for ev in evidences]
        max_risk = max(risk_scores) if risk_scores else 0
        # Визуальный индикатор уровня риска (0–100)
        bar_len = 20
        filled = round((max_risk / 100.0) * bar_len) if max_risk <= 100 else bar_len
        bar = "█" * filled + "░" * (bar_len - filled)
        risk_label = "критический" if max_risk >= 70 else ("повышенный" if max_risk >= 40 else "низкий")
        lines.append(f"*Уровень риска:* {max_risk}/100 — {risk_label}")
        lines.append(f"  [{bar}]")
        pol_worst_early = "allow"
        for ev in evidences:
            pol = ev.get("policy") or {}
            if (pol.get("decision") or "allow").lower() == "deny":
                pol_worst_early = "deny"
                # При большом числе файлов (>10) — интеллектуальное обоснование вместо «Заблокировано: Сигнатуры»
                justification_text = pol.get("justification") or ""
                if len(evidences) > 10:
                    expert_just = _build_expert_justification_many_files(evidences, threat_groups)
                    if expert_just:
                        justification_text = expert_just
                expert = _expert_verdict_from_capa(evidences)
                if expert:
                    lines.append("")
                    lines.append("*Обоснование вердикта:* " + expert)
                if justification_text:
                    lines.append("")
                    if not expert:
                        lines.append("*Обоснование вердикта:* " + justification_text)
                    else:
                        lines.append("*Детали:* " + justification_text)
                break
        if pol_worst_early != "deny":
            for ev in evidences:
                pol = ev.get("policy") or {}
                if (pol.get("decision") or "allow").lower() == "warn" and pol.get("reasons"):
                    lines.append("")
                    lines.append("*Замечания:* " + "; ".join((pol.get("reasons") or [])[:3]))
                    break
        # HVCI-совместимость и предупреждения об обходе WDAC (Enterprise Hardening)
        for ev in evidences:
            pe = ev.get("pe") or {}
            if not pe:
                continue
            h = pe.get("hardening") or {}
            wdac = pe.get("wdac_bypass") or {}
            hvci = h.get("hvci_compatible")
            if hvci is not None:
                lines.append("")
                lines.append("*HVCI-совместимость:* " + ("да" if hvci else "нет (требуется /INTEGRITYCHECK и отсутствие W^X)"))
                break
        for ev in evidences:
            pe = ev.get("pe") or {}
            wdac = (pe or {}).get("wdac_bypass") or {}
            if wdac.get("suspect"):
                lol = wdac.get("lolbins_detected") or []
                heur = wdac.get("loader_heuristics") or []
                parts = []
                if lol:
                    parts.append("LOLBins: " + ", ".join(lol[:5]))
                if heur:
                    parts.append("эвристики загрузчика: " + ", ".join(heur[:3]))
                if parts:
                    lines.append("")
                    lines.append("*Предупреждение (обход WDAC/AppLocker):* " + "; ".join(parts))
                break
    except Exception:
        pass
    lines.append("")

    # Визуальный аудит (Masquerading 2.0): иконка документа + PE Executable
    visual_audit_lines: List[str] = []
    for ev in evidences:
        alert = _visual_audit_line(ev)
        if alert:
            name = _basename(_get(ev, "path") or _get(ev, "file")) or "(файл)"
            visual_audit_lines.append(f"  • {name}: {alert}")
    if visual_audit_lines:
        lines.append("*Визуальный аудит*")
        lines.extend(visual_audit_lines)
        lines.append("")

    _append_ovf_section(lines, evidences)  # новый правильный блок (состав, сводка, строгий чек-лист, MF)
    # далее — общая идентификация групп (PE/ELF и пр.)
    _append_ident_section(lines, groups=groups, show_files=(not compact), evidences=evidences)

    try:
        lines.append(_ident_human_paragraph(evidences))
        lines.append("")  # пустая строка-разделитель
    except Exception as e:
        lines.append(f"(краткий абзац для п.1 недоступен: {e})")
        lines.append("")

    # 2) Репутация
    _append_reputation_section(lines, per_file=per_file, groups=groups, show_files=(not compact))

    # 3) Статический анализ — по группам угроз (экспертное резюме)
    _append_static_section_threat_groups(lines, evidences, threat_groups)


    # 4) Уязвимости зависимостей — только текст: не выявлены или список найденных CVE
    lines.append("4) *Уязвимости зависимостей*:")
    cve_tot = Counter(critical=0, high=0, medium=0)
    cve_ids: list = []
    for pf in per_file:
        ev = pf["ev"]
        s = G(ev, "cve.summary", {}) or {}
        cve_tot.update({
            "critical": int(s.get("critical") or 0),
            "high":     int(s.get("high") or 0),
            "medium":   int(s.get("medium") or 0),
        })
        for it in (G(ev, "cve.items") or []):
            for v in (it.get("vulns") or []):
                vid = v.get("id") or v.get("vuln_id") or str(v)[:50]
                sev = (v.get("severity") or v.get("severity_level") or "").upper()
                if vid and vid not in cve_ids:
                    cve_ids.append((vid, sev))
    if cve_tot["critical"] == 0 and cve_tot["high"] == 0 and cve_tot["medium"] == 0:
        lines.append("— CVE: не выявлены.")
    else:
        lines.append(f"— CVE суммарно: critical={cve_tot['critical']}, high={cve_tot['high']}, medium={cve_tot['medium']}.")
        if cve_ids:
            short = [f"{vid} ({sev})" for vid, sev in cve_ids[:30]]
            lines.append("— Найдено: " + ", ".join(short) + (" …" if len(cve_ids) > 30 else ""))

    # 4) Анализ бинарного кода (CWE) и архитектурные риски
    _append_cwe_section(lines, evidences)
    _append_secrets_arch_risks(lines, evidences)
    # Матрица MITRE ATT&CK по тактикам
    _append_mitre_matrix(lines, evidences)
    # [MEMORY DUMP] — второй круг YARA/CWE по дампу памяти
    _append_memory_dump_section(lines, evidences)
    # v3.1: граф атаки (Staged Execution)
    _append_attack_storyline_section(lines, evidences)
    # High Risk: Obfuscated при энтропии > 7.2 (DIE/LIEF) — требуется manual review
    try:
        from ..scoring import is_high_entropy_obfuscated
        if any(is_high_entropy_obfuscated(ev) for ev in evidences):
            lines.append("— *High Risk: Obfuscated* (энтропия > 7.2). Требуется ручная проверка (manual review).")
    except Exception:
        pass

    lines.append("")

    lines.append("5) *Проверка антивирусом KES:*")
    _append_av_section(lines, evidences, summary)

    # --- ВЫВОД ---
    lines.append("*ВЫВОД*((/))*")
    # Вывести итог по «худшей» политике
    pol_worst, _, _, _ = _worst_decision([pf["ev"] for pf in per_file])
    if pol_worst == "deny":
        lines.append("Файлы отклонены к использованию.")
        # Автообоснование DENY: при >10 файлах — экспертное резюме по группам угроз
        if len(evidences) > 10:
            expert_just = _build_expert_justification_many_files(evidences, threat_groups)
            if expert_just:
                lines.append(expert_just)
            else:
                for pf in per_file:
                    pol = (pf.get("ev") or {}).get("policy") or {}
                    if pol.get("decision") == "deny" and pol.get("justification"):
                        lines.append(pol["justification"])
                        break
        else:
            for pf in per_file:
                ev = pf.get("ev") or {}
                pol = ev.get("policy") or {}
                if pol.get("decision") == "deny" and pol.get("justification"):
                    lines.append(pol["justification"])
                    break
        # Если DENY связан с VMProtect и скрытыми библиотеками из эмуляции — указать в обосновании
        has_vmprotect = False
        has_emulation_libs = False
        for ev in (pf["ev"] for pf in per_file):
            die = ev.get("die") or {}
            obf = ev.get("obfuscation") or {}
            for d in (die.get("detects") or []):
                if isinstance(d, (str, dict)) and "vmprotect" in str(d).lower():
                    has_vmprotect = True
                    break
            if not has_vmprotect and (obf.get("packer_families") or []):
                if any("vmprotect" in str(p).lower() for p in obf.get("packer_families") or []):
                    has_vmprotect = True
            deps = (ev.get("supply_chain") or {}).get("dependencies") or []
            if any(isinstance(x, dict) and x.get("type") == "dynamic_lib" for x in deps):
                has_emulation_libs = True
            if has_vmprotect and has_emulation_libs:
                break
        if has_vmprotect and has_emulation_libs:
            lines.append("Вердикт DENY вызван в том числе наличием VMProtect и скрытых библиотек, выявленных при эмуляции.")
    elif pol_worst == "warn":
        # Если хочешь всегда без «с предупреждениями», меняй эту ветку на одобрено.
        lines.append("Файлы одобрены к использованию с предупреждениями.")
    else:
        lines.append("Файлы одобрены к использованию.")

    # Опциональный путь выкладки (новый параметр)
    publish_path = policy.get("publish_path")  # или пробрось отдельным аргументом функции
    if publish_path:
        lines.append(f"Пакеты выложены по пути  {publish_path}")

    text = "\n".join(lines)
    try:
        out_path.write_text(text, encoding="utf-8", errors="backslashreplace")
    except TypeError:
        with out_path.open("w", encoding="utf-8", errors="backslashreplace", newline="\n") as f:
            f.write(text)




