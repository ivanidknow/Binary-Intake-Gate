from __future__ import annotations
import sys, argparse, pathlib, os
from typing import List, Tuple, Optional
from .msi_support import collect_targets_with_msi, annotate_evidence, cleanup_tmp_dirs
from .reporters.markdown import write_markdown_report
from .policy.loader import load_policy
from .policy.engine import evaluate_policy
from .evidence import new_evidence
from .analyzers.reputation_scan import run_reputation_scan
import subprocess, shlex, re


from .analyzers.ovf_ova import analyze_ovf, analyze_ovf_strict, parse_mf, verify_mf_against_hashes, fold_manifest_algorithms
from pathlib import Path
from .analyzers.hashes import compute_hashes
from .analyzers.entropy import file_entropy, sections_entropy_pe, sections_entropy_elf
from .analyzers.pe_hardening import analyze_pe_hardening
from .analyzers.elf_checksec import analyze_elf_checksec
from .analyzers.capa_analyzer import run_capa, get_techniques_from_yara_die, DEFAULT_TIMEOUT_SEC, DEFAULT_MAX_MB, ENABLE_DEEP_CAPA
from .analyzers.yara_scan import (
    run_yara,
    extract_all_techniques as extract_yara_techniques,
    DEFAULT_TIMEOUT_SEC as YARA_DEF_TIMEOUT,
    DEFAULT_MAX_MB as YARA_DEF_MAX_MB,
    DEFAULT_MAX_HITS as YARA_DEF_MAX_HITS,
    DEFAULT_FAST_MODE as YARA_DEF_FAST,
    DEFAULT_USE_BUILTIN as YARA_DEF_BUILTIN,
)
from .integrations.virustotal_client import (
    vt_fetch_behaviours_raw,
    HARDCODED_VT_API_KEY,
    vt_debug_log,
    fetch_network_relations as vt_fetch_network_relations,
)
from .integrations.vt_playwright import vt_fetch_behaviour_ui, vt_fetch_behaviour_by_link, vt_fetch_details_ui, sha256_from_vt_link
from .analyzers.source_scripts import analyze as analyze_source_script
from .analyzers.manifests import analyze as analyze_manifest
from .analyzers.macho_checksec import analyze as analyze_macho_checksec
from .reporters.sarif import write_sarif_report
from .reporters.github_checks import write_step_summary, emit_workflow_commands
from .reporters.human import write_human_report
from .cve.collector import collect_cve_for_file, pre_scan_vulnerabilities, get_batch_results_for_file, is_batch_scan_ready, BatchVulnerabilityMap
from .analyzers.obfuscation import analyze_obfuscation
from .analyzers.packers_detect import detect_packers_from_yara
from .analyzers.die_scanner import (
    run_die, check_die_prereqs, extract_techniques_from_die, get_die_findings_for_capa,
    pre_scan_die, get_batch_die_info, is_die_batch_ready, DieBatchMap
)
from .analyzers.python_pkg import analyze_python_pkg, can_handle_python_pkg
from .analyzers.archive_dispatcher import ArchiveExpander, is_potential_archive
from .analyzers.office_pdf_lnk import analyze as analyze_office_pdf_lnk
from .analyzers.signing_trust import analyze as analyze_signing_trust
from .analyzers.dotnet_intel import analyze as analyze_dotnet_intel
from .analyzers.jar_apk_analyzer import analyze as analyze_jar_apk
from .analyzers.secrets_scan import analyze as analyze_secrets
from .analyzers.webshell_scan import analyze as analyze_webshell
from .analyzers.powershell_analyzer import analyze as analyze_powershell
from .integrations.virustotal_client import vt_wait_behaviours_raw
import json

# Stage 3: кэш + VT (в т.ч. upload через API/UI)
from .cache.sqlite_cache import Cache
from .integrations.virustotal import (
    vt_lookup_sha256,
    vt_upload_file_api,
    vt_poll_analysis,
    vt_extract_sha_from_analysis,
)
from .integrations.vt_full import vt_fetch_full_metrics
from .integrations.vt_playwright import vt_upload_file_ui

import sys, os
# Сохраняем оригинальные потоки для интерактивных команд (--help, cve-check, etc.)
_orig_stdout = sys.stdout
_orig_stderr = sys.stderr

try:
    _log_path = os.path.join(os.getcwd(), "cli_debug.log")
    _log_file = open(_log_path, "a", encoding="utf-8")
    sys.stderr = _log_file
    sys.stdout = _log_file
    print("[DBG] redirected stdout/stderr to cli_debug.log")
except Exception:
    pass  # do not crash if cwd is read-only or path invalid


def _cli_dbg(msg: str) -> None:
    """Пишет в cli_debug.log (тот же поток, что и print)."""
    try:
        print(f"[cli_dbg] {msg}", flush=True)
    except Exception:
        pass


SOURCE_SCRIPT_EXTS = {".sh", ".bash", ".ksh", ".zsh", ".py", ".rb", ".pl", ".lua"}
CONFIG_EXTS = {".env", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".json", ".toml", ".properties", ".config", ".xml"}

BINARY_EXTS = {
    ".exe", ".dll", ".sys", ".ocx", ".drv", *SOURCE_SCRIPT_EXTS, *CONFIG_EXTS,
    ".elf", ".so", ".ko",
    ".dylib", ".bundle",
    ".bin", ".dat", ".out", ".msi",
    ".zip", ".jar", ".apk", ".aab", ".whl", ".7z", ".rar", ".tar", ".tgz", ".tar.gz",
    # пакеты/дистрибутивы
    ".nupkg", ".msix", ".appx", ".vsix", ".deb", ".rpm", ".crate", ".xpi", ".crx",
    # документы/ярлыки
    ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".pdf", ".lnk",
    # скрипты/веб
    ".js", ".vbs", ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".php", ".asp", ".aspx", ".jsp",
    ".ova", ".ovf", ".vmdk", ".mf",
}

# Подмножество BINARY_EXTS, которое считаем «исполняемыми» для VT:
# нативные бинарники и инсталляторы (PE/ELF/Mach-O, драйверы, .msi и пр.).
VT_EXECUTABLE_EXTS = {
    ".exe", ".dll", ".sys", ".ocx", ".drv",
    ".elf", ".so", ".ko",
    ".dylib", ".bundle",
    ".bin", ".out", ".msi",
}


MANIFEST_BASENAMES = {
    # Python
    "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "pyproject.toml",
    # Node.js
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    # Go
    "go.mod", "go.sum",
    # Rust
    "Cargo.toml", "Cargo.lock",
    # Java / JVM
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    # Ruby
    "Gemfile", "Gemfile.lock",
    # PHP
    "composer.json", "composer.lock",
    # .NET
    # (csproj/vbproj по расширению, sln — по имени)
    "global.json", "nuget.config",
    # Dart/Flutter
    "pubspec.yaml", "pubspec.lock",
}

try:
    BINARY_EXTS
except NameError:
    BINARY_EXTS = set()


def _is_vt_candidate(kind: str, sfx: str) -> bool:
    """
    True  -> для этого файла имеет смысл дергать VT (lookup/behaviours).
    Сейчас ограничиваемся нативными исполняемыми/драйверами/инсталляторами.
    """
    sfx = (sfx or "").lower()
    if kind in ("PE", "ELF", "MACHO"):
        return True
    if kind == "EXT" and sfx in VT_EXECUTABLE_EXTS:
        return True
    return False

def _behaviours_effectively_empty(vt: dict) -> bool:
    """
    True  -> поведение по сути пусто во всех сессиях
    False -> есть что показать хотя бы в одной сессии
    """
    try:
        beh = (vt or {}).get("behaviours") or (vt or {}).get("behaviors") or []
        if not isinstance(beh, list) or not beh:
            return True

        def _listish(x) -> bool:
            return isinstance(x, (list, tuple)) and len(x) > 0

        def _net_has(d: dict) -> bool:
            if not isinstance(d, dict):
                return False
            return any(_listish(d.get(k)) for k in ("domains","ips","urls","http","url"))

        def _sess_has_data(b: dict) -> bool:
            if not isinstance(b, dict):
                return False
            s = b.get("summary") if isinstance(b.get("summary"), dict) else {}

            if _net_has(b.get("network") or {}) or _net_has(s.get("network") or {}) or _net_has(s):
                return True

            keys = [
                "processes","commands","modules_loaded",
                "created_files","files","registry","mutexes",
                "mitre","mitre_attack",
            ]
            for k in keys:
                if _listish(b.get(k)) or _listish(s.get(k)):
                    return True
            return False

        return not any(_sess_has_data(b0) for b0 in beh if isinstance(b0, dict))
    except Exception:
        return True
    
def _behaviour_looks_stub(b: dict) -> bool:
    """
    True -> это поведенческая заглушка (почти пустой объект из VT-UI),
            например только summary/sandbox_name/origin без полезных списков.
    Сессия с sandbox_name считается реальной (не stub), даже если списки пусты.
    """
    if not isinstance(b, dict):
        return True
    # Реальная сессия VT (API или UI) — не сбрасывать, чтобы в отчёте было "сессий=1"
    if b.get("sandbox_name") or b.get("origin"):
        pass  # проверим дальше, есть ли данные
    k = set(b.keys())
    # голые ключи из UI
    if k.issubset({"summary", "sandbox_name", "origin"}):
        pass  # возможно, в summary ещё что-то будет
    # summary без содержательных списков — тоже заглушка
    s = b.get("summary") if isinstance(b.get("summary"), dict) else {}
    listish_keys = (
        "processes", "commands", "network", "modules_loaded", "mitre", "mitre_attack",
        "dns_lookups", "hosts_contacted", "http_conversations",
        "files_written", "files_deleted", "file_accessed",
        "registry_keys_opened", "registry_keys_set", "windows_run_keys_set",
        "mutexes_created", "dlls_loaded", "imported_dlls",
    )
    # есть ли в b или в summary хоть какие-то ненулевые списки
    for kk in listish_keys:
        v = b.get(kk)
        if isinstance(v, (list, tuple)) and v:
            return False
        if isinstance(s.get(kk), (list, tuple)) and s.get(kk):
            return False

    # network как dict с непустыми списками?
    for net_container in (b.get("network"), s.get("network"), s):
        if isinstance(net_container, dict):
            for nk in ("domains", "ips", "urls", "http", "url"):
                nv = net_container.get(nk)
                if isinstance(nv, (list, tuple)) and nv:
                    return False

    # Есть sandbox_name/origin — считаем сессию реальной (показываем "сессий=1", детали могут быть пусты)
    if b.get("sandbox_name") or b.get("origin"):
        return False
    return True  # ничего полезного не нашли -> заглушка


def _normalize_vt_behaviours(raw) -> list[dict]:
    """
    Приводим VT /behaviours -> attributes к канонической схеме рендера.
    На входе raw: list[dict], где каждый dict = attributes из VT.
    На выходе list[dict], где каждый dict = { summary, processes, commands, network{domains,ips,urls}, files, registry, mutexes, modules_loaded, ... }
    """
    if not isinstance(raw, list):
        return []

    out = []

    def _as_list(x):
        if not x: return []
        if isinstance(x, (list, tuple)): return list(x)
        return [x]

    def _process_name(obj) -> str | None:
        """Из объекта процесса (dict или str) извлечь имя."""
        if isinstance(obj, str) and obj.strip():
            return obj.strip()
        if isinstance(obj, dict):
            for k in ("name", "process_name", "image", "path", "value"):
                v = obj.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
        return None

    def _flatten_processes_tree(nodes, acc: list) -> None:
        """Рекурсивно собрать имена из processes_tree (VT API: name, children)."""
        if not isinstance(nodes, list):
            return
        for node in nodes:
            if not isinstance(node, dict):
                continue
            n = _process_name(node)
            if n and n not in acc:
                acc.append(n)
            for ch in _as_list(node.get("children")):
                _flatten_processes_tree([ch] if isinstance(ch, dict) else ch, acc)

    def _is_ip(s: str) -> bool:
        if not isinstance(s, str): return False
        parts = s.split(".")
        if len(parts) != 4: return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except Exception:
            return False

    for att in raw:
        if not isinstance(att, dict):
            continue

        summary = att.get("summary") or {}
        # процессы: summary.processes, processes_created (dict→name), processes_tree (рекурсия), processes_terminated
        processes = []
        for x in _as_list(summary.get("processes")):
            n = _process_name(x)
            if n:
                processes.append(n)
        for x in _as_list(att.get("processes_created")):
            n = _process_name(x)
            if n:
                processes.append(n)
        _flatten_processes_tree(att.get("processes_tree") or [], processes)
        for x in _as_list(att.get("processes_terminated")):
            n = _process_name(x)
            if n:
                processes.append(n)
        processes = list(dict.fromkeys(p for p in processes if p))  # уникальные, без пустых

        # команды: summary.commands, command_executions (dict→command_line/command/arguments)
        commands = []
        for x in _as_list(summary.get("commands")) + _as_list(att.get("command_executions")):
            if isinstance(x, str) and x.strip():
                commands.append(x.strip())
            elif isinstance(x, dict):
                c = x.get("command_line") or x.get("command") or x.get("cmd") or x.get("value")
                if isinstance(c, str) and c.strip():
                    commands.append(c.strip())
                else:
                    # VT иногда отдаёт arguments: ["sh", "-c", "cmd"]
                    args_list = x.get("arguments")
                    if isinstance(args_list, list) and args_list:
                        commands.append(" ".join(str(a) for a in args_list))
        commands = list(dict.fromkeys(c for c in commands if c))

        # сеть
        dns_lookups       = _as_list(att.get("dns_lookups"))
        hosts_contacted   = _as_list(att.get("hosts_contacted"))   # домены/или IP
        http_conversations= _as_list(att.get("http_conversations"))# URL list

        domains = []
        ips     = []
        urls    = []

        # dns_lookups может быть list[str] или list[dict]
        for x in dns_lookups:
            if isinstance(x, str):
                # часто это домены
                if _is_ip(x): ips.append(x)
                else: domains.append(x)
            elif isinstance(x, dict):
                d = x.get("domain") or x.get("host")
                if isinstance(d, str):
                    if _is_ip(d): ips.append(d)
                    else: domains.append(d)

        for x in hosts_contacted:
            if isinstance(x, str):
                if _is_ip(x): ips.append(x)
                else: domains.append(x)
            elif isinstance(x, dict):
                h = x.get("host") or x.get("domain") or x.get("ip")
                if isinstance(h, str):
                    if _is_ip(h): ips.append(h)
                    else: domains.append(h)

        for x in http_conversations:
            if isinstance(x, str):
                urls.append(x)
            elif isinstance(x, dict):
                u = x.get("url") or x.get("uri") or x.get("http")
                if isinstance(u, str):
                    urls.append(u)

        # файлы: нормализуем dict→path string (как в vt.py)
        def _file_path(obj) -> str | None:
            if isinstance(obj, str) and obj.strip():
                return obj.strip()
            if isinstance(obj, dict):
                for k in ("path", "file_path", "path_name", "name", "value"):
                    v = obj.get(k)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
            return None

        files = []
        for key in ("files_written", "files_deleted", "file_accessed", "files_opened"):
            for x in _as_list(att.get(key)):
                p = _file_path(x)
                if p and p not in files:
                    files.append(p)

        registry = []
        for key in ("registry_keys_opened", "registry_keys_set", "registry_keys_deleted", "windows_run_keys_set"):
            for x in _as_list(att.get(key)):
                if isinstance(x, str):
                    r = x
                elif isinstance(x, dict):
                    r = x.get("path") or x.get("key") or x.get("value") or ""
                else:
                    r = str(x) if x else ""
                if isinstance(r, str) and r.strip() and r not in registry:
                    registry.append(r.strip())

        mutexes = _as_list(att.get("mutexes_created"))
        modules_loaded = _as_list(att.get("modules_loaded") or att.get("dlls_loaded") or att.get("imported_dlls"))
        # services (как в vt.py)
        services = []
        for key in ("services_started", "services_installed"):
            for x in _as_list(att.get(key)):
                s = x if isinstance(x, str) else (x.get("name") or x.get("display_name") or x.get("value") or "") if isinstance(x, dict) else ""
                if isinstance(s, str) and s.strip() and s not in services:
                    services.append(s.strip())

        # MITRE — summary или верхний уровень attributes (VT API: mitre_attack_techniques)
        mitre = _as_list(summary.get("mitre") or summary.get("mitre_attack"))
        mitre += _as_list(att.get("mitre_attack_techniques"))
        # элементы могут быть dict с id/name — приводим к строкам
        mitre_str = []
        for m in mitre:
            if isinstance(m, str) and m.strip():
                mitre_str.append(m.strip())
            elif isinstance(m, dict):
                mid = m.get("id") or m.get("technique_id") or m.get("name") or m.get("value")
                if isinstance(mid, str) and mid.strip():
                    mitre_str.append(mid.strip())
        mitre = list(dict.fromkeys(mitre_str))

        # Собираем канонизированный блок (поля как в vt.py + summary/network)
        beh = {
            "summary": summary,
            "processes": processes,
            "commands": commands,
            "network": {"domains": domains, "ips": ips, "urls": urls},
            "files": files,
            "registry": registry,
            "mutexes": mutexes,
            "modules_loaded": modules_loaded,
        }
        if mitre:
            beh["mitre_attack"] = mitre
        if services:
            beh["services"] = services

        # сохраняем sandbox_name для отчёта (источники)
        if att.get("sandbox_name"):
            beh["sandbox_name"] = att["sandbox_name"]

        # выкинем пустые поля, чтобы не шуметь
        beh = {k: v for k, v in beh.items() if (isinstance(v, dict) and any(v.values())) or (isinstance(v, list) and v) or (k == "summary" and isinstance(v, dict)) or (k == "sandbox_name" and v)}
        out.append(beh)

    return out



def run_kaspersky_scan(scan_root: str, avp_path: str, timeout_s: int = 900) -> dict:
    """
    Запускает:  avp.com SCAN <scan_root>
    Возвращает dict: {"ok": bool, "stdout": str, "stderr": str,
                      "detections": [{"path": str, "threat": str, "verdict": str}], 
                      "summary": {"scanned": int, "detected": int, "fixed": int, "quarantined": int}}
    Парсинг сделан толерантным к форматам avp.com.
    """
    cmd = f"\"{avp_path}\" SCAN {shlex.quote(scan_root)}"
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout_s)
    except Exception as e:
        return {"ok": False, "error": f"exec:{e}", "detections": [], "summary": {}}

    out = proc.stdout or ""
    err = proc.stderr or ""
    detections = []
    # Грубые регэкспы на типовые строки
    # Например: "Detected: <threat> ; Object: <path>" | "Infected object: <path> <threat>"
    for line in out.splitlines():
        m = re.search(r"(Detected|Infected)\s*[:\-]\s*(?P<threat>.+?)\s*(;|$)", line, re.IGNORECASE)
        p = re.search(r"(Object|File)\s*[:\-]\s*(?P<path>[^\r\n]+)$", line, re.IGNORECASE)
        if m and p:
            detections.append({"path": p.group("path").strip(),
                               "threat": m.group("threat").strip(),
                               "verdict": "detected"})
        else:
            # Другой формат: "... <path> : detected <threat>"
            z = re.search(r"(?P<path>[A-Za-z]:[\\/].+?)\s*:\s*(detected|infected)\s+(?P<threat>.+)$",
                          line, re.IGNORECASE)
            if z:
                detections.append({"path": z.group("path").strip(),
                                   "threat": z.group("threat").strip(),
                                   "verdict": "detected"})

    # Сводка: пытаемся вытащить числа
    summary = {}
    m = re.search(r"Scanned\s*[:\-]\s*(\d+)", out, re.IGNORECASE)
    if m: summary["scanned"] = int(m.group(1))
    m = re.search(r"(Detected|Infected)\s*[:\-]\s*(\d+)", out, re.IGNORECASE)
    if m: summary["detected"] = int(m.group(2))
    for key, pat in [("fixed", r"(Disinfected|Fixed)\s*[:\-]\s*(\d+)"),
                     ("quarantined", r"(Quarantined)\s*[:\-]\s*(\d+)")]:
        m = re.search(pat, out, re.IGNORECASE)
        if m: summary[key] = int(m.group(2))

    return {"ok": proc.returncode == 0 or bool(detections),
            "stdout": out, "stderr": err, "detections": detections, "summary": summary}


def _vt_dbg(ev,
            *,
            stage: str,
            sha256: str | None = None,
            vt_data: dict | None = None,
            note: str | None = None,
            args=None) -> None:
    """
    Безопасный отладочный дамп для VT-этапов.
    - Не использует dict.setdefault на Evidence.
    - Ставит метку стадии, sha256, короткий обзор ключей VT и behaviours.
    - На любые ошибки пишет в ev.errors и молча продолжает.
    """
    try:
        dbg: dict = {
            "stage": str(stage),
            "sha256": (sha256 or ""),
        }

        # Параметры запуска (минимально полезные)
        try:
            if args is not None:
                dbg["ui_headed"] = bool(getattr(args, "vt_ui_headed", False))
                dbg["mode"]      = str(getattr(args, "vt_upload_mode", ""))
                dbg["min_int"]   = getattr(args, "vt_min_interval", None)
                dbg["timeout"]   = getattr(args, "vt_timeout", None)
        except Exception:
            pass

        # Обзор VT-структуры
        if isinstance(vt_data, dict):
            try:
                vt_keys = sorted(list(vt_data.keys()))[:20]
                dbg["vt_keys"] = vt_keys
            except Exception:
                dbg["vt_keys"] = "<?>"

            # behaviours: краткая сводка
            try:
                beh = vt_data.get("behaviours") or vt_data.get("behaviors") or []
                dbg["beh_cnt"] = len(beh) if isinstance(beh, list) else 0
                if isinstance(beh, list) and beh:
                    b0 = beh[0] if isinstance(beh[0], dict) else {}
                    dbg["beh0_keys"] = sorted(list(b0.keys()))[:20] if isinstance(b0, dict) else []
                    # иногда полезно увидеть summary/network-ключи
                    s0 = b0.get("summary") if isinstance(b0, dict) else None
                    if isinstance(s0, dict):
                        dbg["beh0_sum_keys"] = sorted(list(s0.keys()))[:20]
                        n0 = s0.get("network") if isinstance(s0.get("network"), dict) else {}
                        if isinstance(n0, dict) and n0:
                            dbg["beh0_net_keys"] = sorted(list(n0.keys()))[:20]
            except Exception:
                pass

            # relations (если подмешивали отдельно)
            try:
                rel = vt_data.get("behaviour_relations")
                if isinstance(rel, dict):
                    dbg["relations_keys"] = sorted(list(rel.keys()))[:10]
            except Exception:
                pass

            # пометки кэша/приклейки
            try:
                if vt_data.get("_cached"):
                    dbg["cached"] = True
                if vt_data.get("_beh_attached"):
                    dbg["beh_attached"] = True
            except Exception:
                pass

        if note:
            dbg["note"] = str(note)

        # ----- безопасная запись в Evidence -----
        try:
            # vt_debug (инициализация, если нет)
            if not hasattr(ev, "vt_debug") or not isinstance(getattr(ev, "vt_debug", None), list):
                setattr(ev, "vt_debug", [])
            ev.vt_debug.append(dbg)

            # чтобы не разрасталось до бесконечности
            if len(ev.vt_debug) > 200:
                ev.vt_debug = ev.vt_debug[-200:]
        except Exception as e:
            # если даже это не удалось — попробуем записать в errors
            try:
                if hasattr(ev, "errors") and isinstance(ev.errors, list):
                    ev.errors.append(f"vt_debug_append_error:{e}")
            except Exception:
                pass

    except Exception as e_outer:
        # финальный страховочный catch — не ломаем пайплайн отчёта
        try:
            if hasattr(ev, "errors") and isinstance(ev.errors, list):
                ev.errors.append(f"vt_debug_error:{e_outer}")
        except Exception:
            pass

def sniff_magic(p: pathlib.Path) -> Tuple[bool, str]:
    try:
        if can_handle_python_pkg(p):
            return True, "EXT"
    except Exception:
        pass
    try:
        with p.open("rb") as f:
            head = f.read(4)
        if len(head) >= 2 and head[0:2] == b"MZ":
            return True, "PE"
        if len(head) >= 4 and head[0:4] == b"\x7fELF":
            return True, "ELF"
        if len(head) >= 4 and head in (
            b"\xFE\xED\xFA\xCE", b"\xCE\xFA\xED\xFE",  # Mach-O 32
            b"\xFE\xED\xFA\xCF", b"\xCF\xFA\xED\xFE",  # Mach-O 64
            b"\xCA\xFE\xBA\xBE", b"\xBE\xBA\xFE\xCA",  # FAT (universal)
            b"\xCA\xFE\xBA\xBF", b"\xBF\xBA\xFE\xCA",  # FAT64 (universal 64)
        ):
            return True, "MACHO"
    except Exception:
        return False, "NONE"

    name = p.name.lower()
    if name in {n.lower() for n in MANIFEST_BASENAMES}:
        return True, "MANIFEST"
    if p.suffix.lower() in {".csproj", ".vbproj", ".sln"}:
        return True, "MANIFEST"

    if p.suffix.lower() in BINARY_EXTS:
        return True, "EXT"
    return False, "NONE"

def discover_files(root: pathlib.Path) -> list[pathlib.Path]:
    files: List[pathlib.Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        is_bin, _kind = sniff_magic(p)
        if is_bin:
            files.append(p)
    return files

def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    parser = argparse.ArgumentParser(
        prog="bin-gate",
        description="Binary Intake Gate — Stage 5 (Policy Engine + profiles; VT cache/upload; capa+YARA; CVE/OSV)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_scan = sub.add_parser("scan", help="Scan path and produce report + evidence.json")

    # Команда: по одной ссылке VT — парсинг поведения через веб (образец vt.py)
    p_vt = sub.add_parser("vt-behaviour", help="По ссылке VT получить поведение через веб (процессы, команды, файлы, реестр, сеть)")
    p_vt.add_argument("link", help="Ссылка на файл в VT (gui или api), напр. https://www.virustotal.com/gui/file/<sha256>/...")
    p_vt.add_argument("--browser", default="chromium", help="Playwright: chromium/firefox/webkit")
    p_vt.add_argument("--headed", action="store_true", help="Запустить браузер с окном")
    p_vt.add_argument("--timeout", type=int, default=90, help="Таймаут загрузки страницы (сек)")
    p_vt.add_argument("--json", action="store_true", help="Вывести результат в JSON")

    # CVE container management commands
    p_cve_update = sub.add_parser("cve-update", help="Update Grype vulnerability database (docker pull + db update)")
    p_cve_update.add_argument("--timeout", type=int, default=600, help="Update timeout (s)")

    p_cve_check = sub.add_parser("cve-check", help="Check CVE scanning prerequisites (Docker, Syft, Grype images)")
    p_cve_check.add_argument("--pull", action="store_true", help="Pull missing images")

    p_scan.add_argument("path", help="Path to scan (dir or file)")
    p_scan.add_argument("--policy", default=None, help="Path to policy.yaml (optional)")
    p_scan.add_argument("--out", default="report.md", help="Output Markdown report path")

    # capa knobs
    p_scan.add_argument("--no-capa", action="store_true", help="Disable capa analyzer")
    p_scan.add_argument("--capa-timeout", type=int, default=DEFAULT_TIMEOUT_SEC, help="Timeout seconds for capa (default env CAPA_TIMEOUT_SEC or 60)")
    p_scan.add_argument("--capa-max-mb", type=int, default=DEFAULT_MAX_MB, help="Skip capa if file bigger than N MB (default 0=no limit; env CAPA_MAX_MB)")
    p_scan.add_argument("--capa-rules", default=os.getenv("CAPA_RULES_DIR"), help="Path to capa rules directory (clone of capa-rules). Env: CAPA_RULES_DIR")
    p_scan.add_argument("--deep-capa", action="store_true", default=False,
                    help="Enable deep capa analysis (slow). By default uses fast YARA+DIE technique extraction. Env: ENABLE_DEEP_CAPA=1")
    p_scan.add_argument("--human-per-file", action="store_true",
                    help="В human-отчёт добавить карточки по каждому файлу (может быть очень большим)")
    
    p_scan.add_argument(
    "--human-list-all",
    action="store_true",
    help="В секции ОПИСАНИЕ всегда выводить список всех имён файлов, даже если их > 5"
)

    # yara knobs
    p_scan.add_argument("--no-yara", action="store_true", help="Disable YARA analyzer")
    p_scan.add_argument("--yara-rules", default=os.getenv("YARA_RULES_DIR"), help="Path to directory with YARA rules (*.yar*)")
    p_scan.add_argument("--yara-timeout", type=int, default=YARA_DEF_TIMEOUT, help="YARA timeout seconds (default 7 or env YARA_TIMEOUT_SEC)")
    p_scan.add_argument("--yara-max-mb", type=int, default=YARA_DEF_MAX_MB, help="Skip YARA if file bigger than N MB (default 0=no limit; env YARA_MAX_MB)")
    p_scan.add_argument("--yara-max-hits", type=int, default=YARA_DEF_MAX_HITS, help="Cap YARA hits per file (default 80)")
    p_scan.add_argument("--yara-fast", action="store_true", default=YARA_DEF_FAST, help="YARA fast mode (stop at first match per rule)")
    p_scan.add_argument("--yara-no-builtin", action="store_true", help="Do not use builtin rules if rules dir is empty")
    p_scan.add_argument("--full-report", dest="full_report", action="store_true",
                    help="Принудительно подробный human-отчёт (отключает --compact-report)")

    # offline / cache
    p_scan.add_argument("--no-network", action="store_true", help="Disable network calls (VT UI/API); cache still used for reads")
    p_scan.add_argument("--cache-db", default=None, help="Path to cache sqlite (default: user cache dir)")

    # Python-пакеты
    p_scan.add_argument("--py-bandit", action="store_true", default=False,
                        help="Run Bandit SAST on Python packages (wheel/sdist)")
    p_scan.add_argument("--no-py-ast", action="store_true", default=False,
                        help="Disable AST scan for Python packages")
    p_scan.add_argument("--no-py-record", action="store_true", default=False,
                        help="Disable RECORD verification for wheels")
    p_scan.add_argument("--bandit-config", default="policy/bandit.yaml",
                        help="Path to Bandit config (YAML). If absent, Bandit runs with defaults")
    
    p_scan.add_argument(
        "--no-archives", action="store_true",
        help="Отключить распаковку архивов (zip/jar/apk/whl/docx/tar/7z/rar)"
    )
    p_scan.add_argument(
        "--arch-depth", type=int, default=int(os.getenv("ARCH_DEPTH", "2")),
        help="Глубина вложенной распаковки (по умолчанию 2)"
    )
    p_scan.add_argument(
        "--arch-max-children", type=int, default=int(os.getenv("ARCH_MAX_CHILDREN", "5000")),
        help="Макс. количество файлов после распаковки"
    )
    p_scan.add_argument(
        "--arch-max-mb", type=int, default=int(os.getenv("ARCH_MAX_MB", "512")),
        help="Лимит распакованных данных (МБ) на прогон"
    )
    p_scan.add_argument(
        "--arch-timeout", type=int, default=int(os.getenv("ARCH_TIMEOUT", "90")),
        help="Таймаут на один архив (сек)"
    )
    p_scan.add_argument("--vt-debug", action="store_true",
                    help="в отчёт добавлять отладочные карточки по VT (что нашли/не нашли, размеры, ключи)")

    # MSI merge + compact
    p_scan.add_argument("--msi-merge-report", dest="msi_merge", action="store_true",
                        help="Схлопывать содержимое MSI в один агрегированный блок отчёта")
    p_scan.add_argument("--msi-merge-top", type=int, default=12,
                        help="Сколько внутренних файлов MSI показать в примерах (по умолчанию 12)")
    p_scan.add_argument("--compact-report", dest="compact", action="store_true",
                        help="Короткий отчёт: без списков артефактов/примеров, только агрегированный итог")
    p_scan.add_argument("--no-parallel", dest="parallel", action="store_false", default=True,
                        help="Отключить параллельный анализ (ProcessPoolExecutor + async VT)")
    p_scan.add_argument("--workers", type=int, default=4,
                        help="Количество параллельных воркеров (default: 4, env: BIN_GATE_WORKERS)")
    p_scan.add_argument("--deep-scan", dest="deep_scan", action="store_true", default=False,
                        help="Для файлов >50 МБ запускать полный пайплайн (capa, DIE); иначе только hashes, entropy, YARA")

    # VT
    p_scan.add_argument("--no-vt", action="store_true", help="Disable VirusTotal lookups")
    p_scan.add_argument("--vt-api-key", default=os.getenv("VT_API_KEY"), help="VT API key (env VT_API_KEY)")
    p_scan.add_argument("--vt-timeout", type=int, default=20, help="VT HTTP timeout (s)")
    p_scan.add_argument("--vt-min-interval", type=float, default=6.0, help="Min seconds between VT requests")
    p_scan.add_argument("--vt-ttl-hours", type=int, default=24*7, help="Cache TTL for VT (hours)")
    p_scan.add_argument("--vt-upload", action="store_true", help="If VT hash not found, try uploading the file")
    p_scan.add_argument("--vt-upload-mode", choices=["auto","api","ui"], default="auto", help="Upload strategy: api/ui/auto")
    p_scan.add_argument("--vt-ui-browser", default="chromium", help="Playwright browser (chromium/firefox/webkit)")
    p_scan.add_argument("--vt-ui-headed", action="store_true", help="Playwright headed mode (solve captcha if shown)")
    p_scan.add_argument("--vt-ui-timeout", type=int, default=180, help="Playwright upload timeout (s)")
    p_scan.add_argument("--vt-ui-force", dest="vt_ui_force", action="store_true", default=False,
                        help="Allow UI upload fallback on API 401/429; without this only API is used (no browser)")

    # profile + human + reporters
    p_scan.add_argument("--profile", choices=["dev","staging","prod"], default=os.getenv("BIN_GATE_PROFILE","dev"),
                        help="Policy profile (dev/staging/prod). Env: BIN_GATE_PROFILE")
    p_scan.add_argument("--human-out", default=None, help="Path to human-friendly report (Markdown, RU)")
    p_scan.add_argument("--sarif-out", default=None, help="Write SARIF v2.1.0 report to this path (e.g., sarif.json)")
    p_scan.add_argument("--gh-summary", action="store_true", help="Append a summary to $GITHUB_STEP_SUMMARY (GitHub Actions)")
    p_scan.add_argument("--gh-annotations", action="store_true", help="Emit ::warning/::error annotations for GitHub Actions")
    p_scan.add_argument("--fail-on", choices=["none","warn","deny"], default=os.getenv("BIN_GATE_FAIL_ON","none"),
                        help="Exit non-zero if at least one file reaches this level")
    p_scan.add_argument(
        "--arch-verbose", action="store_true",
        help="Подробные логи распаковки архивов"
    )
    p_scan.add_argument(
        "--arch-tmp", type=pathlib.Path, default=None,
        help="Корень временной распаковки (задай короткий путь на Windows, напр. C:\\\\a)"
    )

    # DIE (Detect It Easy) - packer/compiler detection via Docker
    p_scan.add_argument("--no-die", action="store_true", help="Disable DIE packer/compiler detection")
    p_scan.add_argument("--die-timeout", type=int, default=60, help="DIE container timeout (s)")
    p_scan.add_argument("--die-min-len", type=int, default=4, help="Minimum string length for extraction")
    p_scan.add_argument("--die-max-mb", type=int, default=50, help="Skip DIE if file bigger than N MB (0 = no limit)")
    p_scan.add_argument("--die-no-batch", action="store_true", help="Disable DIE batch mode (run per-file instead)")

    # CVE (via Docker containers: Syft + Grype)
    p_scan.add_argument("--no-cve", action="store_true", help="Disable CVE scanning (Syft/Grype containers)")
    p_scan.add_argument("--cve-no-batch", action="store_true", default=False,
                        help="Disable batch CVE mode (run Syft+Grype per file instead of once for whole directory)")
    p_scan.add_argument("--cve-ecosystem", choices=["Debian","Ubuntu","Alpine","RedHat"], default=os.getenv("CVE_ECOSYSTEM"),
                        help="[legacy, ignored] Ecosystem hint (Syft auto-detects)")
    p_scan.add_argument("--cve-inventory", default=os.getenv("CVE_INVENTORY"),
                        help="[legacy, ignored] Path to JSON inventory (Syft generates SBOM)")
    p_scan.add_argument("--cve-libmap", default=os.getenv("CVE_LIBMAP"),
                        help="[legacy, ignored] Path to lib->package mapping")
    p_scan.add_argument("--cve-timeout", type=int, default=120, help="Docker container timeout (s)")
    p_scan.add_argument("--cve-max-per-pkg", type=int, default=20, help="[legacy] Limit advisories per package")
    p_scan.add_argument("--cve-resolve", default=os.getenv("CVE_RESOLVE","auto"),
                        choices=["auto","dpkg","rpm","apk","pacman","none"],
                        help="[legacy, ignored] Syft handles resolution automatically")
    p_scan.add_argument("--dll-scan-depth", type=int, default=int(os.getenv("DLL_SCAN_DEPTH","2")), help="PE deep DLL scan max depth")
    p_scan.add_argument("--dll-scan-max", type=int, default=int(os.getenv("DLL_SCAN_MAX","200")), help="PE deep DLL scan max files")

    # reputation
    p_scan.add_argument("--no-reputation", action="store_true", help="Disable reputation keyword scan")
    p_scan.add_argument("--reputation-rules", default=os.getenv("REPUTATION_RULES"), help="Path to YAML with reputation terms/regex")
    p_scan.add_argument("--reputation-max-bytes", type=int, default=int(os.getenv("REPUTATION_MAX_BYTES","20971520")),
                        help="Max file size (bytes) for strings scan")
    p_scan.add_argument("--reputation-min-str", type=int, default=int(os.getenv("REPUTATION_MIN_STR","4")),
                        help="Min string length for extraction")

    p_scan.add_argument("--no-obf", action="store_true", help="Disable obfuscation heuristics")
    p_scan.add_argument("--obf-max-mb", type=int, default=50, help="Skip obfuscation analysis for files bigger than N MB (0 = no limit)")


    parser.add_argument("--avp-scan", action="store_true",
                    help="Запустить AV-проверку Kaspersky (avp.com SCAN)")
    parser.add_argument("--avp-path", default=r"/mnt/c/Program Files (x86)/Kaspersky Lab/KES.12.8.0/avp.com",
                        help="Путь к avp.com (Windows/WSL путь).")
    parser.add_argument("--avp-timeout", type=int, default=900,
                        help="Таймаут AV-сканирования (сек).")

    args = parser.parse_args(argv)

    # Использовать ключ из проекта, если не задан через --vt-api-key или VT_API_KEY
    # (только для команд, где этот аргумент определён)
    if hasattr(args, "vt_api_key") and not args.vt_api_key:
        args.vt_api_key = os.getenv("VT_API_KEY") or HARDCODED_VT_API_KEY

    # Команда vt-behaviour: на вход только ссылка, парсинг через веб
    if getattr(args, "cmd", None) == "vt-behaviour":
        link = getattr(args, "link", "").strip()
        if not link:
            print("[bin-gate] укажите ссылку на файл VT", file=sys.stderr)
            return 2
        sha, beh_list, errs = vt_fetch_behaviour_by_link(
            link,
            browser=getattr(args, "browser", "chromium"),
            headless=not bool(getattr(args, "headed", False)),
            timeout_sec=int(getattr(args, "timeout", 90)),
        )
        if errs:
            for e in errs:
                print(f"[bin-gate] {e}", file=sys.stderr)
        if not sha:
            return 3
        if getattr(args, "json", False):
            import json
            out = {"sha256": sha, "behaviours": beh_list, "errors": errs}
            print(json.dumps(out, ensure_ascii=False, indent=2))
        else:
            print(f"SHA256: {sha}")
            print(f"Сессий: {len(beh_list)}")
            for i, b in enumerate(beh_list or []):
                s = (b.get("summary") or b) if isinstance(b, dict) else {}
                if isinstance(s, dict):
                    for key in ("processes", "commands", "files", "registry", "mutexes", "mitre"):
                        val = s.get(key)
                        if isinstance(val, list) and val:
                            print(f"  {key}: {val[:25]}{' …' if len(val) > 25 else ''}")
                        elif isinstance(val, dict) and val:
                            for k, v in list(val.items())[:5]:
                                if isinstance(v, list) and v:
                                    print(f"  {key}.{k}: {v[:15]}{' …' if len(v) > 15 else ''}")
                    net = s.get("network") if isinstance(s.get("network"), dict) else {}
                    if net and any(net.get(k) for k in ("domains", "ips", "urls")):
                        for k in ("domains", "ips", "urls"):
                            v = net.get(k)
                            if isinstance(v, list) and v:
                                print(f"  network.{k}: {v[:15]}{' …' if len(v) > 15 else ''}")
                if isinstance(b, dict) and b.get("sandbox_name"):
                    print(f"  sandbox: {b.get('sandbox_name')}")
        return 0 if beh_list else 1

    # CVE container commands (use original stdout for interactive output)
    if getattr(args, "cmd", None) == "cve-update":
        from .cve.collector import update_grype_db, check_container_prereqs
        print("[bin-gate] Checking Docker availability...", file=_orig_stdout, flush=True)
        prereqs = check_container_prereqs()
        if not prereqs["docker_available"]:
            print("[bin-gate] ERROR: Docker daemon is not available", file=_orig_stdout, flush=True)
            return 1
        print("[bin-gate] Updating Grype vulnerability database...", file=_orig_stdout, flush=True)
        timeout = int(getattr(args, "timeout", 600))
        ok, msg = update_grype_db(timeout_sec=timeout)
        if ok:
            print(f"[bin-gate] SUCCESS: {msg}", file=_orig_stdout, flush=True)
            return 0
        else:
            print(f"[bin-gate] FAILED: {msg}", file=_orig_stdout, flush=True)
            return 1

    if getattr(args, "cmd", None) == "cve-check":
        from .cve.collector import check_container_prereqs, _pull_image, SYFT_IMAGE, GRYPE_IMAGE
        print("[bin-gate] Checking CVE scanning prerequisites...", file=_orig_stdout, flush=True)
        prereqs = check_container_prereqs()
        print(f"  Docker daemon: {'OK' if prereqs['docker_available'] else 'NOT AVAILABLE'}", file=_orig_stdout, flush=True)
        print(f"  Syft image ({prereqs['syft_image']['image']}): {'OK' if prereqs['syft_image']['exists'] else 'NOT FOUND'}", file=_orig_stdout, flush=True)
        print(f"  Grype image ({prereqs['grype_image']['image']}): {'OK' if prereqs['grype_image']['exists'] else 'NOT FOUND'}", file=_orig_stdout, flush=True)
        if prereqs["ready"]:
            print("[bin-gate] All prerequisites OK — ready to scan", file=_orig_stdout, flush=True)
            return 0
        if not prereqs["docker_available"]:
            print("[bin-gate] ERROR: Docker daemon is not running or not installed", file=_orig_stdout, flush=True)
            return 1
        if getattr(args, "pull", False):
            print("[bin-gate] Pulling missing images...", file=_orig_stdout, flush=True)
            if not prereqs["syft_image"]["exists"]:
                print(f"  Pulling {SYFT_IMAGE}...", file=_orig_stdout, flush=True)
                ok, err = _pull_image(SYFT_IMAGE)
                print(f"    {'OK' if ok else 'FAILED: ' + err}", file=_orig_stdout, flush=True)
            if not prereqs["grype_image"]["exists"]:
                print(f"  Pulling {GRYPE_IMAGE}...", file=_orig_stdout, flush=True)
                ok, err = _pull_image(GRYPE_IMAGE)
                print(f"    {'OK' if ok else 'FAILED: ' + err}", file=_orig_stdout, flush=True)
            # Re-check
            prereqs = check_container_prereqs()
            if prereqs["ready"]:
                print("[bin-gate] All prerequisites OK after pull", file=_orig_stdout, flush=True)
                return 0
        print("[bin-gate] Missing images. Run 'bin-gate cve-check --pull' or 'docker pull <image>'", file=_orig_stdout, flush=True)
        return 1

    if args.cmd != "scan":
        return 1

    # --- DOCKER VALIDATION (HARD FAIL if unavailable) ---
    from .docker_utils import validate_docker_at_startup, DockerNotAvailableError
    try:
        docker_status = validate_docker_at_startup()
        _cli_dbg(f"[docker] Docker validated: version={docker_status.version}")
    except DockerNotAvailableError as e:
        print(f"[bin-gate] CRITICAL: Docker is required but unavailable: {e}", file=sys.stderr)
        print("[bin-gate] Install Docker and ensure daemon is running.", file=sys.stderr)
        return 10  # Hard fail exit code

    root = pathlib.Path(args.path).resolve()
    if not root.exists():
        print(f"[bin-gate] path not found: {root}", file=sys.stderr)
        return 2

    files, msi_containers, origin_of, _tmp_dirs = collect_targets_with_msi(root, sniff_magic, logger=None)

    archive_stats = None
    if not args.no_archives:
        tmp_root = None
        if args.arch_tmp:
            args.arch_tmp.mkdir(parents=True, exist_ok=True)
            tmp_root = args.arch_tmp

        exp = ArchiveExpander(
            max_depth=int(args.arch_depth),
            max_children=int(args.arch_max_children),
            max_expanded_size=int(args.arch_max_mb) * 1024 * 1024,
            per_archive_timeout=int(args.arch_timeout),
            keep_temp=True,
            verbose=bool(args.arch_verbose),
            **({"temp_root": tmp_root} if tmp_root else {})
        )

        for fp in list(files):
            try:
                if is_potential_archive(fp):
                    exp.expand(fp)
            except Exception:
                # при --arch-verbose подробности увидишь внутри ArchiveExpander
                pass

        for t in exp.tasks:
            files.append(t.path)
            origin_of[str(t.path)] = [str(x) for x in t.origin_chain]

        archive_stats = exp.stats

    cache = Cache(pathlib.Path(args.cache_db)) if args.cache_db else Cache()
    vt_ttl = max(0, int(args.vt_ttl_hours)) * 3600

    # Чтобы в логах было видно, что запущен новый билд и куда пишется vt_debug.log
    try:
        from bin_gate.vt_debug import get_vt_debug_log_path, vt_debug_log as _vlog
        _vlog(f"[vt_debug] bin-gate scan started (MITRE filter build) log={get_vt_debug_log_path()}")
    except Exception:
        pass

    # --- BATCH CVE SCAN (Syft + Grype один раз для всей директории) ---
    _cve_batch_map: Optional[BatchVulnerabilityMap] = None
    _cve_batch_error: str = ""
    _cve_use_batch: bool = not getattr(args, "cve_no_batch", False)
    
    if not args.no_cve and _cve_use_batch:
        _cli_dbg("[cve] Starting batch CVE scan with Syft+Grype...")
        try:
            import time as _cve_time
            _cve_start = _cve_time.perf_counter()
            cve_batch_ok, cve_batch_err, _cve_batch_map = pre_scan_vulnerabilities(root)
            _cve_elapsed = _cve_time.perf_counter() - _cve_start
            if cve_batch_ok:
                _summary = _cve_batch_map._scan_result.summary if _cve_batch_map._scan_result else {}
                _cli_dbg(f"[cve] Batch CVE scan complete in {_cve_elapsed:.1f}s: total={_summary.get('total',0)} crit={_summary.get('critical',0)} high={_summary.get('high',0)}")
            else:
                _cve_batch_error = cve_batch_err
                _cli_dbg(f"[cve] Batch CVE scan failed after {_cve_elapsed:.1f}s: {cve_batch_err}")
        except Exception as e:
            _cve_batch_error = f"batch_init_error:{e}"
            _cli_dbg(f"[cve] Batch CVE exception: {e}")
    elif not args.no_cve and not _cve_use_batch:
        _cli_dbg("[cve] Batch mode disabled (--cve-no-batch), will use per-file scanning")

    # --- BATCH DIE SCAN (один контейнер для всей директории) ---
    _die_batch_map: Optional[DieBatchMap] = None
    _die_batch_error: str = ""
    _die_use_batch: bool = not getattr(args, "no_die", False) and not getattr(args, "die_no_batch", False)
    
    if _die_use_batch:
        _cli_dbg("[die] Starting batch DIE scan...")
        try:
            import time as _die_time
            _die_start = _die_time.perf_counter()
            die_batch_ok, die_batch_err, _die_batch_map = pre_scan_die(root)
            _die_elapsed = _die_time.perf_counter() - _die_start
            if die_batch_ok:
                _files_count = _die_batch_map.files_count if _die_batch_map else 0
                _cli_dbg(f"[die] Batch DIE scan complete in {_die_elapsed:.1f}s: {_files_count} files indexed")
            else:
                _die_batch_error = die_batch_err
                _cli_dbg(f"[die] Batch DIE scan failed after {_die_elapsed:.1f}s: {die_batch_err}")
        except Exception as e:
            _die_batch_error = f"batch_init_error:{e}"
            _cli_dbg(f"[die] Batch DIE exception: {e}")
    elif not getattr(args, "no_die", False):
        _cli_dbg("[die] Batch mode disabled, will use per-file scanning")

    policy = load_policy(args.policy) if args.policy else {
        "version": 2,
        "profiles": {"dev": {"thresholds": {"deny": 80, "warn": 40}}},
        "rules": []
    }
    policy["profile"] = args.profile

    evidences = []
    _hash_index: dict[str, dict[str, str]] = {}

    # ProcessPoolExecutor often fails in PyInstaller/frozen exe (spawn re-exec); use sequential
    use_parallel = getattr(args, "parallel", True) and not getattr(sys, "frozen", False)
    if use_parallel:
        # Optimized path: cache → ProcessPoolExecutor → async VT → CVE
        file_tuples: List[Tuple[pathlib.Path, str]] = []
        for fp in files:
            is_bin, kind = sniff_magic(fp)
            if not is_bin:
                continue
            if can_handle_python_pkg(fp):
                kind = "EXT"
            file_tuples.append((fp, kind))
        from .orchestrate import run_parallel_scan
        evidences = run_parallel_scan(
            file_tuples,
            origin_of,
            args,
            cache,
            vt_ttl,
            evidence_ttl_sec=vt_ttl,
        )
        for ev in evidences:
            ev.setdefault("meta", {})["profile"] = args.profile
            try:
                polres = evaluate_policy(ev, policy or {}, profile=args.profile)
            except Exception as e:
                polres = {"decision": "allow", "score": 0, "reasons": [f"policy_engine_error:{e}"], "matched": []}
            ev["policy"] = polres
        for ev in evidences:
            name = (ev.get("meta") or {}).get("name", "")
            h = ev.get("hashes") or {}
            _hash_index[name] = {k: v for k, v in h.items() if k in ("sha1", "sha256", "sha512") and v}

    for fp in files:
        if use_parallel:
            continue
        is_bin, kind = sniff_magic(fp)
        if not is_bin:
            continue

        py_pkg = can_handle_python_pkg(fp)
        if py_pkg:
            kind = "EXT"

        ev = new_evidence(fp, kind)
        try:
            setattr(ev, "kind", kind)
        except Exception:
            pass
        if isinstance(ev, dict):
            ev["kind"] = kind
        annotate_evidence(ev, origin_of)
        sfx = fp.suffix.lower()
        yara_externals = {}

        # --- базовые метрики всегда ---
        try:
            ev.hashes = compute_hashes(fp)
            if ev.hashes:
                _hash_index[fp.name] = {
                    k: v for k, v in (ev.hashes or {}).items()
                    if k in ("sha1", "sha256", "sha512")
                }
        except Exception as e:
            ev.errors.append(f"hashes_error:{e}")

        try:
            ev.entropy = {"file": file_entropy(fp)}
        except Exception as e:
            ev.errors.append(f"entropy_error:{e}")
            ev.entropy = {"file": None}

        # --- python-пакет ---
        if py_pkg:
            try:
                py_doc = analyze_python_pkg(
                    pathlib.Path(fp),
                    tmp_root=pathlib.Path(getattr(args, "tmp_root", pathlib.Path.cwd() / ".tmp_bin_gate")),
                    enable_ast=not getattr(args, "no_py_ast", False),
                    enable_bandit=getattr(args, "py_bandit", False),
                    bandit_config=pathlib.Path(getattr(args, "bandit_config", "policy/bandit.yaml")),
                    verify_record=not getattr(args, "no_py_record", False),
                )
                if py_doc:
                    if "meta" in py_doc:
                        ev.meta = py_doc["meta"]
                    ev.python_pkg = py_doc.get("python_pkg", {})
            except Exception as e:
                ev.errors.append(f"pythonpkg_error:{e}")

        # --- PE/ELF/интеграции — ТОЛЬКО если это не python-пакет ---
        if not py_pkg:
            if kind == "PE":
                try:
                    peinfo = analyze_pe_hardening(fp)
                    ev.pe = {k: v for k, v in peinfo.items() if k != "errors"}
                    if peinfo.get("errors"):
                        ev.errors.extend(peinfo["errors"])
                    ev.entropy["sections"] = sections_entropy_pe(fp)
                except Exception as e:
                    ev.errors.append(f"pe_error:{e}")
            elif kind == "MACHO":
                try:
                    macho_info = analyze_macho_checksec(fp)
                    if macho_info:
                        ev.macho = macho_info
                except Exception as e:
                    ev.errors.append(f"macho_error:{e}")
            # --- PowerShell (специализированный анализ) ---
            try:
                if sfx in (".ps1", ".psm1", ".psd1"):
                    ps_doc = analyze_powershell(fp)
                    if ps_doc:
                        ev.powershell = ps_doc
                        # прокинем счётчики во внешние переменные для YARA
                        if isinstance(ps_doc.get("externals"), dict):
                            yara_externals.update({f"ps_{k}": v for k, v in ps_doc["externals"].items()})
            except Exception as e:
                ev.errors.append(f"powershell_error:{e}")
            # --- Исходники/скрипты (sh/py/rb/pl/lua + bat/cmd) ---
            try:
                if sfx in SOURCE_SCRIPT_EXTS or sfx in {".bat", ".cmd"}:
                    src_doc = analyze_source_script(fp)
                    if src_doc:
                        ev.source = src_doc
                        ext = src_doc.get("externals") or {}
                        if isinstance(ext, dict):
                            # префикс src_ чтобы не конфликтовало с ps_*/die_*
                            yara_externals.update({f"src_{k}": v for k, v in ext.items()})
            except Exception as e:
                ev.errors.append(f"source_error:{e}")
            # --- Манифесты зависимостей ---
            try:
                base = fp.name.lower()
                if (base in {n.lower() for n in MANIFEST_BASENAMES}) or (sfx in {".csproj", ".vbproj", ".sln"}):
                    man = analyze_manifest(fp)
                    if man:
                        ev.manifest = man
                        # CVE из batch-скана (Syft+Grype) или per-file при --cve-no-batch
                        if not args.no_cve:
                            try:
                                if _cve_use_batch and _cve_batch_map and _cve_batch_map.is_ready:
                                    cve_doc = _cve_batch_map.get_results_for_file(fp)
                                elif _cve_use_batch and _cve_batch_error:
                                    cve_doc = {"summary": {}, "items": [], "notes": [f"cve_batch_failed:{_cve_batch_error}"]}
                                elif _cve_use_batch:
                                    cve_doc = get_batch_results_for_file(fp)
                                else:
                                    # Per-file mode (--cve-no-batch)
                                    cve_doc = collect_cve_for_file(fp)
                                if cve_doc:
                                    ev.cve = cve_doc
                            except Exception as e:
                                ev.errors.append(f"cve_manifest_error:{e}")
            except Exception as e:
                ev.errors.append(f"manifest_error:{e}")
            # --- Документы/скрипты/LNK ---
            try:
                sfx = fp.suffix.lower()
                if sfx in (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                            ".docm", ".xlsm", ".pptm", ".pdf",
                            ".ps1", ".psm1", ".psd1", ".js", ".vbs", ".lnk",
                            ".bat", ".cmd", ".sh", ".py", ".rb", ".pl", ".lua"):
                    ev.docscripts = analyze_office_pdf_lnk(fp)
            except Exception as e:
                ev.errors.append(f"docscripts_error:{e}")

            # --- Спец-анализ OVF/MF ---
            sfx = Path(fp).suffix.lower()
            try:
                if sfx == ".ovf":
                    ovf_doc = analyze_ovf(Path(fp))
                    ev.ovf = ovf_doc
                    # strict variant
                    ovf_strict = analyze_ovf_strict(Path(fp))
                    if ovf_strict:
                        ev.ovf_strict = ovf_strict
                elif sfx == ".mf":
                    mf_map = parse_mf(Path(fp))
                    if mf_map:
                        ev.mf_manifest = {"entries": mf_map}
                        ev.mf_algos = fold_manifest_algorithms(mf_map)
            except Exception as e:
                ev.errors.append(f"ovf_mf_error:{e}")

            av_summary = None
            if args.avp_scan and args.avp_path:
                # Сканируем корень, который передан на вход (или рабочий каталог с распаковкой — выбери, что у тебя принято)
                scan_root = str(Path(args.path).resolve()) if hasattr(args, "path") else "."
                avres = run_kaspersky_scan(scan_root, args.avp_path, args.avp_timeout)
                av_summary = {"kaspersky": avres}
                # Привязываем детекты к evidence по basename / абсолютному пути
                dets = avres.get("detections", [])
                by_name = {}
                for d in dets:
                    by_name.setdefault(Path(d["path"]).name.lower(), []).append(d)
                for ev in evidences:
                    p = (ev.get("path") or ev.get("file") or "")
                    base = Path(p).name.lower()
                    if base in by_name:
                        ev["av"] = {"engine": "kaspersky", "detections": by_name[base]}

            # --- ZIP/JAR/APK/WHL/ZIP-подобные ---
            try:
                if sfx in (".jar", ".apk", ".aab", ".whl", ".zip"):
                    ev.archive_meta = analyze_jar_apk(fp)
            except Exception as e:
                ev.errors.append(f"archive_meta_error:{e}")

            # --- Веб-шеллы ---
            try:
                if sfx in (".php", ".asp", ".aspx", ".jsp"):
                    ev.webshell = analyze_webshell(fp)
            except Exception as e:
                ev.errors.append(f"webshell_error:{e}")

            # --- Секреты (универсально; внутри лимит размера) ---
            try:
                ev.secrets = analyze_secrets(fp)
            except Exception as e:
                ev.errors.append(f"secrets_error:{e}")

            # если ты где-то сериализуешь origin chain в ev:
            if str(fp) in origin_of and not getattr(ev, "origin_chain", None):
                ev.origin_chain = origin_of[str(fp)]
            elif kind == "ELF":
                try:
                    elfinfo = analyze_elf_checksec(fp)
                    ev.elf = {k: v for k, v in elfinfo.items() if k != "errors"}
                    if elfinfo.get("errors"):
                        ev.errors.extend(elfinfo["errors"])
                    ev.entropy["sections"] = sections_entropy_elf(fp)
                except Exception as e:
                    ev.errors.append(f"elf_error:{e}")
            elif kind == "MACHO":
                try:
                    ev.macho = analyze_macho_checksec(fp)
                except Exception as e:
                    ev.errors.append(f"macho_error:{e}")
            ev.entropy.setdefault("sections", {})

            # --- Техники будут собраны позже из YARA + DIE ---
            # capa теперь вызывается после YARA и DIE для интеграции данных
            _prefilled_techniques: list = []
            _prefilled_rule_hits: list = []

            # --- DIE (Detect It Easy) for packer/compiler detection ---
            # Используем batch результаты если доступны, иначе per-file
            die_doc = None
            if (not getattr(args, "no_die", False)) and kind in ("PE", "ELF", "MACHO"):
                try:
                    # Batch mode: получаем из pre-computed результатов
                    if _die_use_batch and _die_batch_map and _die_batch_map.is_ready:
                        die_result = _die_batch_map.get_die_info(fp)
                        die_errs = []
                        if die_result.get("batch_lookup") == "not_found":
                            die_errs.append("die_batch_file_not_found")
                    elif _die_use_batch and _die_batch_error:
                        die_result = {"error": _die_batch_error, "batch_mode": True}
                        die_errs = [f"die_batch_failed:{_die_batch_error}"]
                    else:
                        # Per-file mode: запускаем DIE для каждого файла
                        die_result, die_errs = run_die(
                            fp,
                            timeout_sec=int(getattr(args, "die_timeout", 60)),
                            min_len=int(getattr(args, "die_min_len", 4)),
                            max_mb=int(getattr(args, "die_max_mb", 50)),
                        )
                    
                    if die_errs:
                        ev.errors.extend([f"die_{e}" for e in die_errs if "fallback" not in str(e).lower() and "not_found" not in str(e).lower()])

                    # Store DIE results
                    die_doc = die_result
                    ev.die = die_result

                    # Update strings (DIE extracts basic strings)
                    if not hasattr(ev, "strings") or not isinstance(getattr(ev, "strings", None), dict):
                        ev.strings = {}
                    if not hasattr(ev, "strings_summary") or not isinstance(getattr(ev, "strings_summary", None), dict):
                        ev.strings_summary = {}

                    die_strings = die_result.get("strings") or []
                    if die_strings:
                        ev.strings.setdefault("static", [])
                        ev.strings["static"].extend(die_strings[:500])

                    die_summary = die_result.get("strings_summary") or {}
                    ev.strings_summary.update({
                        "total_cnt":  int(die_summary.get("total_cnt") or len(die_strings)),
                        "static_cnt": int(die_summary.get("total_cnt") or len(die_strings)),
                        "url_cnt":    int(die_summary.get("url_cnt") or 0),
                        "ip_cnt":     int(die_summary.get("ip_cnt") or 0),
                        "cmd_cnt":    int(die_summary.get("cmd_cnt") or 0),
                    })

                    # Update packer_families from DIE detections
                    die_packers = die_result.get("packer_families") or []
                    if die_packers:
                        if not hasattr(ev, "yara_families") or ev.yara_families is None:
                            ev.yara_families = []
                        # Add "packers" family if any packer detected
                        if "packers" not in ev.yara_families:
                            ev.yara_families.append("packers")
                        # Add specific packer families
                        for pf in die_packers:
                            if pf and pf not in ev.yara_families:
                                ev.yara_families.append(pf)

                    # Update obfuscation from DIE
                    if not hasattr(ev, "obfuscation") or not isinstance(getattr(ev, "obfuscation", None), dict):
                        ev.obfuscation = {}
                    die_entropy = die_result.get("entropy") or {}
                    if die_entropy.get("file"):
                        ev.obfuscation["max_section_entropy"] = die_entropy.get("file")
                    if die_packers:
                        ev.obfuscation["packed_suspect"] = True
                        ev.obfuscation["packer_families"] = die_packers
                    die_score = die_result.get("score") or 0
                    if die_score > 0:
                        ev.obfuscation["score"] = max(ev.obfuscation.get("score", 0), die_score)
                    die_reasons = die_result.get("reasons") or []
                    if die_reasons:
                        ev.obfuscation.setdefault("reasons", [])
                        ev.obfuscation["reasons"].extend(die_reasons)

                    # YARA externals for DIE data
                    total = ev.strings_summary.get("total_cnt", 0)
                    yara_externals.update({
                        "die_total_cnt":     total,
                        "die_url_cnt":       ev.strings_summary.get("url_cnt", 0),
                        "die_ip_cnt":        ev.strings_summary.get("ip_cnt", 0),
                        "die_cmd_cnt":       ev.strings_summary.get("cmd_cnt", 0),
                        "die_has_strings":   1 if total > 0 else 0,
                        "die_packer_count":  len(die_packers),
                        "die_score":         die_score,
                    })

                except Exception as e:
                    ev.errors.append(f"die_error:{e}")
            # --- end DIE ---



            # --- IOC from strings (URLs/IPs/Registry) ---
            try:
                urls, ips, regs = [], [], []
                for bucket in ("decoded", "static"):
                    for s in (ev.strings or {}).get(bucket, []) or []:
                        if not isinstance(s, str):
                            s = str(s)
                        urls += re.findall(r"https?://[^\s\"'<>]+", s, re.IGNORECASE)
                        ips  += re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", s)
                        if re.search(r"(?:HKLM|HKCU)\\|\\Software\\|\\Run\\|\\Services\\|Image File Execution Options", s, re.IGNORECASE):
                            regs.append(s)

                def _top_k(seq, k=5):
                    out, seen = [], set()
                    for x in seq:
                        x = x.strip()
                        if x and x not in seen:
                            seen.add(x); out.append(x)
                        if len(out) >= k:
                            break
                    return out

                iocs = {}
                if urls: iocs["urls"] = _top_k(urls, 5)
                if ips:  iocs["ips"]  = _top_k(ips, 5)
                if regs: iocs["reg"]  = _top_k(regs, 5)
                if iocs:
                    ev.strings_iocs = iocs
            except Exception as e:
                ev.errors.append(f"strings_iocs_error:{e}")

            if not args.no_yara:
                try:
                    yara_hits = run_yara(
                        fp,
                        rules_dir=args.yara_rules,
                        timeout_sec=args.yara_timeout,
                        max_mb=args.yara_max_mb,
                        max_hits=args.yara_max_hits,
                        fast=bool(args.yara_fast),
                        use_builtin=not args.yara_no_builtin,
                        externals=yara_externals,
                    )
                    if yara_hits is not None:
                        ev.yara = yara_hits
                except Exception as e:
                    ev.errors.append(f"yara_error:{e}")

            try:
                packers = detect_packers_from_yara(ev.yara or [])
                if packers:
                    ev.obfuscation = ev.obfuscation or {}
                    ev.obfuscation.setdefault("reasons", []).append("packer_signature")
                    ev.obfuscation["packed_suspect"] = True
                    prev_pf = set(ev.obfuscation.get("packer_families") or [])
                    ev.obfuscation["packer_families"] = sorted(prev_pf.union(set(packers)))
                    ev.obfuscation["score"] = min(100, int(ev.obfuscation.get("score", 0)) + 30)
            except Exception as e:
                ev.errors.append(f"packers_detect_error:{e}")

            PACKER_FAMS = {
                "upx","vmprotect","themida","mpress","aspack","asprotect",
                "pecompact","fsg","enigma","molebox","telock","obsidium",
                "confuser","dotfuscator","petite","nspack","armadillo","upack","generic"
            }
            if ev.yara:
                fams = []
                for hit in ev.yara:
                    fam = str((hit.get("meta") or {}).get("family","")).lower()
                    if fam in PACKER_FAMS:
                        fams.append(fam)
                if fams:
                    ev.obfuscation = (ev.obfuscation or {})
                    prev_pf = set(ev.obfuscation.get("packer_families") or [])
                    ev.obfuscation["packer_families"] = sorted(prev_pf.union(set(fams)))

            if not args.no_obf and kind in ("PE","ELF"):
                try:
                    sz = fp.stat().st_size
                    if args.obf_max_mb <= 0 or (sz <= args.obf_max_mb * 1024 * 1024):
                        prev_obf = ev.obfuscation or {}
                        obf = analyze_obfuscation(
                            fp, kind,
                            pe_info=(ev.pe if kind == "PE" else None),
                            elf_info=(ev.elf if kind == "ELF" else None),
                            die_info=(getattr(ev, "die", None)),
                        )
                        if prev_obf:
                            obf["reasons"] = sorted(set((obf.get("reasons") or []) + (prev_obf.get("reasons") or [])))
                            obf["score"] = max(int(obf.get("score") or 0), int(prev_obf.get("score") or 0))
                            for k in ("packed_suspect","has_dyn_api_resolve",
                                      "uses_virtualprotect","uses_mprotect",
                                      "uses_writeprocessmemory","uses_createremotethread"):
                                obf[k] = bool(prev_obf.get(k) or obf.get(k) or False)
                            pf_prev = set(prev_obf.get("packer_families") or [])
                            pf_new  = set(obf.get("packer_families") or [])
                            if pf_prev or pf_new:
                                obf["packer_families"] = sorted(pf_prev.union(pf_new))
                        ev.obfuscation = obf
                except Exception as e:
                    ev.errors.append(f"obf_error:{e}")

            # --- Сбор техник ATT&CK из YARA и DIE (замена тяжёлого capa) ---
            if not args.no_capa and kind in ("PE", "ELF"):
                try:
                    # 1. Извлекаем техники из YARA
                    yara_techniques, yara_rule_hits = [], []
                    if ev.yara:
                        yara_techniques, yara_rule_hits = extract_yara_techniques(ev.yara)
                        _prefilled_techniques.extend(yara_techniques)
                        _prefilled_rule_hits.extend(yara_rule_hits)

                    # 2. Извлекаем техники из DIE
                    die_techniques, die_rule_hits = [], []
                    if getattr(ev, "die", None):
                        die_techniques, die_rule_hits = extract_techniques_from_die(ev.die)
                        _prefilled_techniques.extend(die_techniques)
                        _prefilled_rule_hits.extend(die_rule_hits)

                    # 3. Вызываем capa (быстрый режим по умолчанию, глубокий при --deep-capa)
                    enable_deep = getattr(args, "deep_capa", False) or ENABLE_DEEP_CAPA
                    capa_res = run_capa(
                        fp,
                        timeout_sec=args.capa_timeout,
                        max_mb=args.capa_max_mb,
                        rules_dir=args.capa_rules,
                        enable_deep=enable_deep,
                        prefilled_techniques=list(set(_prefilled_techniques)),
                        prefilled_rule_hits=_prefilled_rule_hits,
                    )

                    # 4. Записываем результаты в Evidence
                    ev.capa = {
                        "techniques": capa_res.get("techniques", []),
                        "rule_hits": capa_res.get("rule_hits", []),
                        "source": capa_res.get("source", "unknown"),
                    }

                    # Обновляем capa_tactics для политик
                    ev.capa_tactics = capa_res.get("techniques", [])

                    if capa_res.get("errors"):
                        ev.errors.extend(capa_res["errors"])

                except Exception as e:
                    ev.errors.append(f"capa_error:{e}")

            if not args.no_reputation and args.reputation_rules:
                try:
                    rep = run_reputation_scan(
                        fp,
                        rules_path=pathlib.Path(args.reputation_rules),
                        max_bytes=int(args.reputation_max_bytes),
                        min_str_len=int(args.reputation_min_str),
                    )
                    if rep:
                        ev.reputation = rep
                except Exception as e:
                    ev.errors.append(f"reputation_error:{e}")

            # --- CVE из batch-скана (Syft+Grype) или per-file при --cve-no-batch ---
            if (not args.no_cve):
                try:
                    # Используем batch результаты вместо индивидуальных запусков Docker
                    if _cve_use_batch and _cve_batch_map and _cve_batch_map.is_ready:
                        cve_doc = _cve_batch_map.get_results_for_file(Path(fp))
                    elif _cve_use_batch and _cve_batch_error:
                        cve_doc = {"summary": {}, "items": [], "notes": [f"cve_batch_failed:{_cve_batch_error}"]}
                    elif _cve_use_batch:
                        cve_doc = get_batch_results_for_file(Path(fp))
                    else:
                        # Per-file mode (--cve-no-batch)
                        cve_doc = collect_cve_for_file(Path(fp))
                    
                    if cve_doc:
                        ev.cve = {
                            "summary": cve_doc.get("summary", {}),
                            "items":   cve_doc.get("items",   []),
                            "batch_mode": cve_doc.get("batch_mode", _cve_use_batch),
                        }
                        for note in cve_doc.get("notes", []) or []:
                            if "no_vulns_for_file" not in note:  # Не засоряем лог штатными сообщениями
                                ev.errors.append(f"cve_note:{note}")
                except Exception as e:
                    ev.errors.append(f"cve_error:{e}")

        # --- VT (общий для всех, включая python-пакеты) ---
        sha256 = (ev.hashes or {}).get("sha256")
        # VT только для исполняемых файлов (PE/ELF/Mach-O + несколько EXT-типов).
        if sha256 and not args.no_vt and _is_vt_candidate(kind, sfx):
            _fname = os.path.basename(fp) if fp else ""
            vt_debug_log(f"[vt_debug] sha256={sha256} path={_fname}")
            _cli_dbg(f"VT branch start sha256={sha256[:16]}... path={_fname} (one vt_wait_behaviours_raw CALL per hash per run; repeated GETs = old exe with polling loop)")

            cached = cache.get("vt_full", sha256, None if vt_ttl == 0 else vt_ttl)
            if cached is not None:
                cached["_cached"] = True
                ev.vt = cached
                ev.errors.append("vt_dbg:enter_cache_hit")  # попадёт в human_report.md
                _beh = ev.vt.get("behaviours") or ev.vt.get("behaviors") or []
                _cnt = len(_beh) if isinstance(_beh, list) else 0
                _k0 = list((_beh[0] or {}).keys())[:15] if _beh and isinstance(_beh[0], dict) else []
                vt_debug_log(f"[vt_debug] cache_hit sha256={sha256} behaviours_count={_cnt} keys0={_k0}")

                # НОРМАЛИЗУЕМ кэш, если данные в формате VT API (attributes: processes_tree, processes_created, sandbox_name)
                # или без summary — чтобы процессы/команды/сеть парсились в отчёте
                _cached_raw = ev.vt.get("behaviours") or ev.vt.get("behaviors") or []
                _first = (_cached_raw[0] or {}) if isinstance(_cached_raw, list) and _cached_raw and isinstance(_cached_raw[0], dict) else {}
                _is_raw_api = _first.get("processes_tree") is not None or _first.get("processes_created") is not None or (_first.get("sandbox_name") is not None and isinstance(_first.get("processes"), list) is False)
                _no_summary = "summary" not in _first
                if isinstance(_cached_raw, list) and _cached_raw and isinstance(_cached_raw[0], dict) and (_no_summary or _is_raw_api):
                    _norm = _normalize_vt_behaviours(_cached_raw)
                    if _norm:
                        ev.vt["behaviours"] = _norm
                        ev.vt["behaviours_count"] = len(_norm)
                        ev.vt["_beh_attached"] = True
                        ev.errors.append(f"vt_dbg:cache_norm ok sessions={len(_norm)}")
                # --- RAW behaviours (единственный источник) ---
                try:
                    _beh_list = (ev.vt.get("behaviours") or ev.vt.get("behaviors") or [])
                    _stub = False
                    if isinstance(_beh_list, list) and _beh_list:
                        _stub_cnt = 0
                        for _b in _beh_list:
                            if isinstance(_b, dict) and _behaviour_looks_stub(_b):
                                _stub_cnt += 1
                        if _stub_cnt == len(_beh_list):
                            _stub = True
                            ev.errors.append(f"vt_dbg:cache_behaviour_stub sessions={len(_beh_list)}")

                    if _stub:
                        ev.vt["behaviours"] = []
                        ev.vt["behaviours_count"] = 0
                        ev.vt.pop("_beh_attached", None)

                    # ❷ Маяк решения перед условием
                    _empty = _behaviours_effectively_empty(ev.vt)
                    ev.errors.append(f"vt_dbg:cache_probe empty={_empty}")
                    vt_debug_log(f"[vt_debug] sha256={sha256} cache_probe empty={_empty}")
                    # ====== Поведение парсим через веб (как vt.py по образцу), API — запасной вариант ======
                    if _empty:
                        ev.errors.append("vt_dbg:cache_empty->will_fetch")
                        vt_debug_log(f"[vt_debug] sha256={sha256} cache_empty -> ui_fetch then api")
                        # --- Сначала веб (вкладка Behaviour): всё поднаготную из GUI ---
                        ui_beh, ui_errs = vt_fetch_behaviour_ui(
                            sha256,
                            browser=getattr(args, "vt_ui_browser", "chromium"),
                            headless=not bool(getattr(args, "vt_ui_headed", False)),
                            timeout_sec=max(90, int(getattr(args, "vt_ui_timeout", 180) or 180)),
                        )
                        if ui_errs:
                            ev.errors.extend(ui_errs)
                        ui_cand = _normalize_vt_behaviours(ui_beh) if ui_beh else []
                        vt_debug_log(f"[vt_debug] sha256={sha256} ui_fetch result sessions={len(ui_cand)} errs={ui_errs[:3]}")
                        if ui_cand and not _behaviours_effectively_empty({"behaviours": ui_cand}):
                            ev.vt["behaviours"] = ui_cand
                            ev.vt["behaviours_count"] = len(ui_cand)
                            ev.vt["_beh_attached"] = True
                            ev.vt["_cached"] = False
                            _vt_dbg(ev, stage="cache_hit_after_ui", sha256=sha256, vt_data=ev.vt, note="ui scrape OK", args=args)
                        # --- Дополняем API-сессиями (мерж UI + API), если есть ключ ---
                        if args.vt_api_key:
                            vt_debug_log(f"[vt_debug] sha256={sha256} api_fetch (merge with ui)")
                            _cli_dbg(f"vt_wait_behaviours_raw CALL sha256={sha256[:16]}... call_site=cache_empty_merge_ui")
                            raw_beh, raw_errs = vt_wait_behaviours_raw(
                                sha256,
                                api_key=args.vt_api_key,
                                timeout_total_sec=max(60, int(getattr(args, "vt_ui_timeout", 90) or 90)),
                                poll_interval_sec=max(6, int(getattr(args, "vt_min_interval", 6) or 6)),
                            )
                            _cli_dbg(f"vt_wait_behaviours_raw RETURN sha256={sha256[:16]}... sessions={len(raw_beh or [])} errs={raw_errs[:5] if raw_errs else []}")
                            if raw_errs:
                                ev.errors.extend(raw_errs)
                            api_cand = _normalize_vt_behaviours(raw_beh) if raw_beh else []
                            vt_debug_log(f"[vt_debug] sha256={sha256} api_sessions={len(api_cand)}")
                            # Мерж: UI-сессии + API-сессии. Если UI пустой — берём все API-сессии (разные запуски одной песочницы = разный контент).
                            existing = list(ev.vt.get("behaviours") or ev.vt.get("behaviors") or [])
                            if not existing and api_cand:
                                existing = list(api_cand)
                            else:
                                seen_sandbox = {str((b or {}).get("sandbox_name") or (b or {}).get("origin") or i): True for i, b in enumerate(existing)}
                                for b in (api_cand or []):
                                    sb = str((b or {}).get("sandbox_name") or (b or {}).get("origin") or "")
                                    if sb not in seen_sandbox and (b or {}).get("sandbox_name"):
                                        seen_sandbox[sb] = True
                                        existing.append(b)
                            if existing:
                                ev.vt["behaviours"] = existing
                                ev.vt["behaviours_count"] = len(existing)
                                ev.vt["_beh_attached"] = True
                                ev.vt["_cached"] = False
                                vt_debug_log(f"[vt_debug] sha256={sha256} merged sessions={len(existing)}")
                                # Relations (как в vt.py: contacted_domains/ips/urls) для отчёта
                                try:
                                    rels, rerrs = vt_fetch_network_relations(
                                        sha256, key=args.vt_api_key,
                                        timeout=getattr(args, "vt_timeout", 20),
                                        min_interval=float(getattr(args, "vt_min_interval", 6) or 6),
                                    )
                                    if rerrs:
                                        ev.errors.extend(rerrs)
                                    if isinstance(rels, dict) and any(rels.get(k) for k in ("domains", "ips", "http")):
                                        ev.vt["behaviour_relations"] = rels
                                except Exception as relex:
                                    ev.errors.append(f"vt_rel_error:{relex}")
                                # Вкладка Details: Basic properties, Names, ELF Info
                                if not ev.vt.get("details"):
                                    try:
                                        details_data, details_errs = vt_fetch_details_ui(
                                            sha256,
                                            browser=getattr(args, "vt_ui_browser", "chromium"),
                                            headless=not bool(getattr(args, "vt_ui_headed", False)),
                                            timeout_sec=min(45, int(getattr(args, "vt_ui_timeout", 90) or 90)),
                                        )
                                        if details_errs:
                                            ev.errors.extend(details_errs)
                                        if isinstance(details_data, dict) and any(details_data.get(k) for k in ("basic_properties", "names", "elf_info")):
                                            ev.vt["details"] = details_data
                                    except Exception as dex:
                                        ev.errors.append(f"vt_details_error:{dex}")
                                # сохраняем в кэш, чтобы следующий запуск видел 2 сессии + details без повторного API
                                try:
                                    cache.put("vt_full", ev.vt.get("sha256") or sha256, ev.vt)
                                except Exception:
                                    pass
                        elif _behaviours_effectively_empty(ev.vt):
                            _cli_dbg(f"vt_wait_behaviours_raw CALL sha256={sha256[:16]}... call_site=cache_empty_else_raw")
                            raw_beh, raw_errs = vt_wait_behaviours_raw(
                                sha256,
                                api_key=args.vt_api_key,
                                timeout_total_sec=max(90, int(getattr(args, "vt_ui_timeout", 90) or 90)),
                                poll_interval_sec=max(6, int(getattr(args, "vt_min_interval", 6) or 6)),
                            )
                            _cli_dbg(f"vt_wait_behaviours_raw RETURN sha256={sha256[:16]}... sessions={len(raw_beh or [])} errs={raw_errs[:5] if raw_errs else []}")
                            if raw_errs:
                                ev.errors.extend(raw_errs)
                            cand = _normalize_vt_behaviours(raw_beh)
                            if cand and not _behaviours_effectively_empty({"behaviours": cand}):
                                ev.vt["behaviours"] = cand
                                ev.vt["behaviours_count"] = len(cand)
                                ev.vt["_beh_attached"] = True
                                ev.vt["_cached"] = False
                                _vt_dbg(ev, stage="cache_hit_after_raw", sha256=sha256, vt_data=ev.vt, note="raw plural OK", args=args)
                    else:
                        beh = (ev.vt.get("behaviours") or ev.vt.get("behaviors") or [])
                        cnt = len(beh) if isinstance(beh, list) else 0
                        keys0 = list(beh[0].keys())[:12] if (isinstance(beh, list) and beh and isinstance(beh[0], dict)) else []
                        ev.errors.append(f"vt_dbg:cache_skip_fetch empty=False; sessions={cnt}; keys0={keys0}")
                        # Сводка по первой сессии для дебага (почему в отчёте пусто)
                        b0 = beh[0] if beh and isinstance(beh[0], dict) else {}
                        s0 = b0.get("summary") or b0
                        nprocs = ncmds = nfiles = nreg = nnet = 0
                        if isinstance(s0, dict):
                            nprocs = len(s0.get("processes") or [])
                            ncmds = len(s0.get("commands") or [])
                            nfiles = len(s0.get("files") or [])
                            nreg = len(s0.get("registry") or [])
                            net = s0.get("network") or {}
                            nnet = sum(len(net.get(k) or []) for k in ("domains", "ips", "urls"))
                            vt_debug_log(f"[vt_debug] sha256={sha256} cache_skip (not empty) sessions={cnt} content: processes={nprocs} commands={ncmds} files={nfiles} registry={nreg} network={nnet}")
                        # Дополняем Details (Basic properties, Names, ELF) если в кэше их ещё нет
                        if not ev.vt.get("details"):
                            try:
                                details_data, details_errs = vt_fetch_details_ui(
                                    sha256,
                                    browser=getattr(args, "vt_ui_browser", "chromium"),
                                    headless=not bool(getattr(args, "vt_ui_headed", False)),
                                    timeout_sec=min(45, int(getattr(args, "vt_ui_timeout", 90) or 90)),
                                )
                                if details_errs:
                                    ev.errors.extend(details_errs)
                                if isinstance(details_data, dict) and any(details_data.get(k) for k in ("basic_properties", "names", "elf_info")):
                                    ev.vt["details"] = details_data
                                    try:
                                        cache.put("vt_full", ev.vt.get("sha256") or sha256, ev.vt)
                                    except Exception:
                                        pass
                            except Exception as dex:
                                ev.errors.append(f"vt_details_error:{dex}")
                        # Если в кэше сессия есть, но контент пустой — дополняем из API (как vt.py)
                        if cnt and (nprocs + ncmds + nfiles + nreg + nnet) == 0 and args.vt_api_key:
                            vt_debug_log(f"[vt_debug] sha256={sha256} cache content empty -> api refetch (like vt.py)")
                            _cli_dbg(f"vt_wait_behaviours_raw CALL sha256={sha256[:16]}... call_site=cache_content_empty_refetch")
                            raw_beh, raw_errs = vt_wait_behaviours_raw(
                                sha256,
                                api_key=args.vt_api_key,
                                timeout_total_sec=max(60, int(getattr(args, "vt_ui_timeout", 90) or 90)),
                                poll_interval_sec=max(6, int(getattr(args, "vt_min_interval", 6) or 6)),
                            )
                            _cli_dbg(f"vt_wait_behaviours_raw RETURN sha256={sha256[:16]}... sessions={len(raw_beh or [])} errs={raw_errs[:5] if raw_errs else []}")
                            if raw_errs:
                                ev.errors.extend(raw_errs)
                            cand = _normalize_vt_behaviours(raw_beh)
                            if cand and not _behaviours_effectively_empty({"behaviours": cand}):
                                ev.vt["behaviours"] = cand
                                ev.vt["behaviours_count"] = len(cand)
                                ev.vt["_beh_attached"] = True
                                vt_debug_log(f"[vt_debug] sha256={sha256} api refetch ok sessions={len(cand)}")
                except Exception as e:
                    ev.errors.append(f"vt_beh_raw_cache_error:{e}")
                    _vt_dbg(ev, stage="cache_hit_after_raw_error", sha256=sha256, vt_data=ev.vt, note=str(e), args=args)


            elif not args.no_network:
                vt_data = None
                if args.vt_api_key:
                    summary, errs = vt_lookup_sha256(
                        sha256,
                        api_key=args.vt_api_key,
                        timeout_sec=args.vt_timeout,
                        min_interval_sec=args.vt_min_interval
                    )
                    if errs:
                        ev.errors.extend(errs)
                else:
                    summary = None
                    ev.errors.append("vt_no_api_key")

                if summary and summary.get("found"):
                    data, errs2 = vt_fetch_full_metrics(
                        sha256,
                        api_key=args.vt_api_key,
                        timeout_sec=args.vt_timeout,
                        min_interval_sec=args.vt_min_interval
                    )
                    if errs2:
                        ev.errors.extend(errs2)
                    vt_data = data
                    # --- Поведение: сначала веб (GUI), потом API ---
                    try:
                        base_sha = (vt_data or {}).get("sha256") or sha256
                        if _behaviours_effectively_empty(vt_data or {}):
                            vt_debug_log(f"[vt_debug] no_cache sha256={base_sha} behaviour empty -> ui_fetch then api")
                            ui_beh, ui_errs = vt_fetch_behaviour_ui(
                                base_sha,
                                browser=getattr(args, "vt_ui_browser", "chromium"),
                                headless=not bool(getattr(args, "vt_ui_headed", False)),
                                timeout_sec=max(90, int(getattr(args, "vt_ui_timeout", 180) or 180)),
                            )
                            if ui_errs:
                                ev.errors.extend(ui_errs)
                            ui_cand = _normalize_vt_behaviours(ui_beh) if ui_beh else []
                            if ui_cand and not _behaviours_effectively_empty({"behaviours": ui_cand}):
                                vt_data["behaviours"] = ui_cand
                                vt_data["behaviours_count"] = len(ui_cand)
                                vt_data["_beh_attached"] = True
                                cache.put("vt_full", vt_data.get("sha256", base_sha), vt_data)
                            else:
                                _cli_dbg(f"vt_wait_behaviours_raw CALL sha256={base_sha[:16]}... call_site=no_cache_behaviour_empty")
                                raw_beh, raw_errs = vt_wait_behaviours_raw(
                                    base_sha,
                                    api_key=args.vt_api_key,
                                    timeout_total_sec=max(90, int(getattr(args, "vt_ui_timeout", 90) or 90)),
                                    poll_interval_sec=max(6, int(getattr(args, "vt_min_interval", 6) or 6)),
                                )
                                _cli_dbg(f"vt_wait_behaviours_raw RETURN sha256={base_sha[:16]}... sessions={len(raw_beh or [])} errs={raw_errs[:5] if raw_errs else []}")
                                if raw_errs:
                                    ev.errors.extend(raw_errs)
                                cand = _normalize_vt_behaviours(raw_beh)
                                probe = {"behaviours": cand}
                                if cand and not _behaviours_effectively_empty(probe):
                                    vt_data["behaviours"] = cand
                                    vt_data["behaviours_count"] = len(cand)
                                    vt_data["_beh_attached"] = True
                                    cache.put("vt_full", vt_data.get("sha256", base_sha), vt_data)
                                else:
                                    vt_data.pop("behaviours", None)
                                    vt_data["behaviours_count"] = 0
                    except Exception as e:
                        ev.errors.append(f"vt_beh_raw_nocache_error:{e}")
                else:
                    if args.vt_upload and not args.no_network:
                        uploaded_sha = None
                        # UI только при явном --vt-ui-force (при 429/401 не переключаемся на браузер)
                        allow_ui = getattr(args, "vt_ui_force", False)
                        order = (["api", "ui"] if args.vt_upload_mode == "auto" else [args.vt_upload_mode]) if allow_ui else ["api"]
                        for mode in order:
                            if mode == "api" and args.vt_api_key:
                                analysis_id, uerrs = vt_upload_file_api(
                                    fp, api_key=args.vt_api_key, timeout_sec=max(60, args.vt_timeout),
                                    allow_ui_fallback=allow_ui,
                                )
                                if uerrs:
                                    ev.errors.extend(uerrs)
                                if analysis_id:
                                    # Поддержка headless UI-фолбэка из vt_upload_file_api: "ui:<sha256>" / "exists:<sha256>"
                                    if isinstance(analysis_id, str) and analysis_id.startswith("ui:"):
                                        uploaded_sha = analysis_id.split(":", 1)[1]
                                    elif isinstance(analysis_id, str) and analysis_id.startswith("exists:"):
                                        uploaded_sha = analysis_id.split(":", 1)[1]
                                    else:
                                        adoc, perrs = vt_poll_analysis(analysis_id, api_key=args.vt_api_key, timeout_total_sec=300)
                                        if perrs:
                                            ev.errors.extend(perrs)
                                        if adoc:
                                            uploaded_sha = vt_extract_sha_from_analysis(adoc)
                            elif mode == "ui":
                                usha, uerrs = vt_upload_file_ui(
                                    fp,
                                    browser=args.vt_ui_browser,
                                    headless=(not args.vt_ui_headed),
                                    timeout_sec=args.vt_ui_timeout
                                )
                                if uerrs:
                                    ev.errors.extend(uerrs)
                                uploaded_sha = usha

                            if uploaded_sha:
                                data, errs3 = vt_fetch_full_metrics(
                                    uploaded_sha,
                                    api_key=args.vt_api_key,
                                    timeout_sec=args.vt_timeout,
                                    min_interval_sec=args.vt_min_interval
                                )
                                if errs3:
                                    ev.errors.extend(errs3)
                                vt_data = data

                                # --- Поведение: сначала веб (GUI), потом API ---
                                try:
                                    base_sha = (vt_data or {}).get("sha256") or sha256
                                    if _behaviours_effectively_empty(vt_data or {}):
                                        ui_beh, ui_errs = vt_fetch_behaviour_ui(
                                            base_sha,
                                            browser=getattr(args, "vt_ui_browser", "chromium"),
                                            headless=not bool(getattr(args, "vt_ui_headed", False)),
                                            timeout_sec=max(90, int(getattr(args, "vt_ui_timeout", 180) or 180)),
                                        )
                                        if ui_errs:
                                            ev.errors.extend(ui_errs)
                                        ui_cand = _normalize_vt_behaviours(ui_beh) if ui_beh else []
                                        if ui_cand and not _behaviours_effectively_empty({"behaviours": ui_cand}):
                                            vt_data["behaviours"] = ui_cand
                                            vt_data["behaviours_count"] = len(ui_cand)
                                            vt_data["_beh_attached"] = True
                                            cache.put("vt_full", vt_data.get("sha256", base_sha), vt_data)
                                        else:
                                            _cli_dbg(f"vt_wait_behaviours_raw CALL sha256={base_sha[:16]}... call_site=upload_path_behaviour_empty")
                                            raw_beh, raw_errs = vt_wait_behaviours_raw(
                                                base_sha,
                                                api_key=args.vt_api_key,
                                                timeout_total_sec=max(90, int(getattr(args, "vt_ui_timeout", 90) or 90)),
                                                poll_interval_sec=max(6, int(getattr(args, "vt_min_interval", 6) or 6)),
                                            )
                                            _cli_dbg(f"vt_wait_behaviours_raw RETURN sha256={base_sha[:16]}... sessions={len(raw_beh or [])} errs={raw_errs[:5] if raw_errs else []}")
                                            if raw_errs:
                                                ev.errors.extend(raw_errs)
                                            cand = _normalize_vt_behaviours(raw_beh)
                                            probe = {"behaviours": cand}
                                            if cand and not _behaviours_effectively_empty(probe):
                                                vt_data["behaviours"] = cand
                                                vt_data["behaviours_count"] = len(cand)
                                                vt_data["_beh_attached"] = True
                                                cache.put("vt_full", vt_data.get("sha256", base_sha), vt_data)
                                            else:
                                                vt_data.pop("behaviours", None)
                                                vt_data["behaviours_count"] = 0
                                except Exception as e:
                                    ev.errors.append(f"vt_beh_raw_nocache_error:{e}")
                                break

                if vt_data:
                    try:
                        b_sha = vt_data.get("sha256") or sha256

                        try:
                            rels, rerrs = vt_fetch_network_relations(
                                b_sha,
                                key=args.vt_api_key,
                                timeout=getattr(args, "vt_timeout", 20),
                                min_interval=float(getattr(args, "vt_min_interval", 6) or 6),
                            )
                            if rerrs:
                                ev.errors.extend(rerrs)
                            if isinstance(rels, dict) and any(rels.get(k) for k in ("domains", "ips", "http")):
                                vt_data["behaviour_relations"] = rels
                        except Exception as relex:
                            ev.errors.append(f"vt_rel_error:{relex}")
            
                    except Exception as e:
                        ev.errors.append(f"vt_behaviours_error:{e}")

                    # --- finalize VT in no-cache path ---
                    try:
                        b_sha = (vt_data or {}).get("sha256") or sha256
                        _vt_dbg(ev, stage="no_cache_after_raw", sha256=b_sha, vt_data=vt_data, note="raw plural + relations", args=args)
                    except Exception:
                        pass

                    vt_data["_cached"] = False
                    ev.vt = vt_data
                    cache.put("vt_full", vt_data.get("sha256", sha256), vt_data)


        # --- POLICY (для всех типов, включая python-пакеты) ---
        ev_dict = ev.to_dict()
        ev_dict.setdefault("meta", {})["profile"] = args.profile
        try:
            polres = evaluate_policy(ev_dict, policy or {}, profile=args.profile)
        except Exception as e:
            polres = {"decision": "allow", "score": 0, "reasons": [f"policy_engine_error:{e}"], "matched": []}
        ev_dict["policy"] = polres
        evidences.append(ev_dict)

    summary = {"stage": "5", "profile": policy.get("profile", args.profile), "scanned": len(files)}

    # после цикла по файлам (evidences собраны)
    # 1) сверка MF (верификация значений)
    for ev in evidences:
        p = ev.get("path","")
        if p.lower().endswith(".mf") and (ev.get("mf_manifest") or {}).get("entries"):
            mf_map = ev["mf_manifest"]["entries"]
            ev["mf_verify"] = verify_mf_against_hashes(mf_map, _hash_index)
            ev.setdefault("mf_algos", fold_manifest_algorithms(mf_map))

    # 2) References vs реальные файлы: найдем любой ovf_strict и сверим его declared files
    ovf_ev = next((x for x in evidences if x.get("ovf_strict")), None)
    if ovf_ev:
        ovf_info = ovf_ev["ovf_strict"]
        declared = { Path(f.get("href") or "").name: int(f.get("size") or 0) for f in (ovf_info["ovf"].get("files") or []) if f.get("href") }
        real_files = {}
        for e in evidences:
            name = Path(e.get("path","")).name
            sz = None
            # try take size from hashes metadata or from fs
            if e.get("hashes") and isinstance(e["hashes"], dict):
                # if your compute_hashes includes size under 'size' key
                if e["hashes"].get("size"):
                    sz = int(e["hashes"]["size"])
            if sz is None:
                try:
                    sz = Path(e.get("path","")).stat().st_size
                except Exception:
                    sz = 0
            real_files[name] = sz
        missing = [n for n in declared.keys() if n not in real_files]
        size_mismatch = []
        for n, s in declared.items():
            if n in real_files and s and real_files[n] and s != real_files[n]:
                size_mismatch.append({"name": n, "decl": s, "real": real_files[n]})
        ok = (not missing) and (not size_mismatch)
        ovf_info["checks"]["references"] = {"missing": missing, "orphan": [], "size_mismatch": size_mismatch, "ok": ok}
        # подтянем манифест-алгоритмы если есть *.mf
        mf_any = next((x for x in evidences if str(x.get("path","")).lower().endswith(".mf") and x.get("mf_algos")), None)
        if mf_any:
            ovf_info["checks"]["manifest_algo"] = mf_any["mf_algos"]

    write_markdown_report(
        pathlib.Path(args.out), files, summary, policy,
        evidences=evidences, merge_msis=getattr(args, "msi_merge", False),
        merge_top=getattr(args, "msi_merge_top", 12), compact=getattr(args, "compact", False),
    )

    if args.human_out:
        try:
            for ev in evidences:
                vt = ev.get("vt") if isinstance(ev, dict) else None
                if vt and isinstance(vt, dict):
                    b = vt.get("behaviours") or vt.get("behaviors") or []
                    nprocs = ncmds = 0
                    for sess in (b or []):
                        if isinstance(sess, dict):
                            nprocs += len(sess.get("processes") or [])
                            ncmds += len(sess.get("commands") or [])
                    vt_debug_log(f"[vt_debug] to_report path={ev.get('path','')} sha256={vt.get('sha256','')} sessions={len(b)} procs={nprocs} commands={ncmds}")
            write_human_report(
                pathlib.Path(args.human_out),
                files, summary, policy,
                evidences=evidences,
                profile=policy.get("profile", getattr(args, "profile", "dev")),
                capa_timeout=int(getattr(args, "capa_timeout", 120)),
                merge_msis=getattr(args, "msi_merge", False),
                merge_top=getattr(args, "msi_merge_top", 12),
                compact=(False if args.full_report else args.compact),
                show_all_names=(getattr(args, "human_list_all", False) or getattr(args, "full_report", False)),
            )
        except Exception as e:
            print(f"[bin-gate] human report error: {e}", file=sys.stderr)
            # Записать минимальный отчёт, чтобы файл не оставался пустым/старым
            try:
                pathlib.Path(args.human_out).write_text(
                    f"*Ошибка формирования отчёта:* {e}\n\n"
                    f"Файлов обработано: {len(evidences)}. Перезапустите скан или проверьте логи.",
                    encoding="utf-8",
                )
            except Exception:
                pass

    if args.sarif_out:
        write_sarif_report(pathlib.Path(args.sarif_out), evidences)
    if args.gh_summary:
        write_step_summary(evidences, summary, profile=summary["profile"])
    if args.gh_annotations:
        emit_workflow_commands(evidences)

    exit_code = 0
    if args.fail_on != "none":
        for ev in evidences:
            dec = (ev.get("policy") or {}).get("decision")
            if args.fail_on == "deny" and dec == "deny":
                exit_code = 1; break
            if args.fail_on == "warn" and dec in ("warn", "deny"):
                exit_code = 1; break

    cleanup_tmp_dirs(_tmp_dirs)
    print(f"[bin-gate] Stage 5 complete: {len(files)} file(s), report -> {args.out}"
          f"{' ; sarif -> ' + args.sarif_out if args.sarif_out else ''}")
    return exit_code
