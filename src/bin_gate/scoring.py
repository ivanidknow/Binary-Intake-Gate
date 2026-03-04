# scoring.py — Risk-based scoring (0–100) and DENY justification
# Методология: Hardening missing +10, CWE +30, DGA +50, No Signature +20.
# Для каждого DENY генерируется автоматическое обоснование.

from __future__ import annotations
from typing import Dict, Any, List, Optional

# Веса рисков (сумма не должна превышать 100 при полном наборе)
RISK_HARDENING_MISSING = 10   # Отсутствие ASLR/DEP/CFG и т.д.
RISK_CWE_DETECTED = 30       # Найдены CWE (Double Free, UAF, Format String)
RISK_DGA_DETECTED = 50       # Обнаружены DGA-домены
RISK_NO_SIGNATURE = 20       # Нет цифровой подписи (PE) — DEV
RISK_NO_SIGNATURE_PROD = 50  # Нет подписи в PROD → авто-блок
RISK_HIGH_ENTROPY = 25       # Энтропия > 7.2 → обфускация
RISK_URLHAUS_HIT = 40        # URL/домен в URLHaus
RISK_VMPROTECT = 100         # VMProtect (уже обрабатывается политикой)
RISK_MASQUERADING = 20      # Иконка документа (Excel/PDF/Word/Image), файл — PE
RISK_DEFENSE_EVASION_3 = 15  # Более 3 техник в категории Defense Evasion (capa)
RISK_ANTI_VM = 15            # Детекция Anti-VM / Anti-Analysis (CPUID, RDTSC, гипервизор)
RISK_EVASION_TECHNIQUE = 30   # Техники уклонения: отладочные API (IsDebuggerPresent и др.) в PE
RISK_PERSISTENCE_DETECTED = 15   # Строки автозагрузки (Run, RunOnce, Winlogon, Services, Task Scheduler)
RISK_ORDINAL_IMPORT = 10        # Импорт по ординалу (скрытый API, в т.ч. опасный)
RISK_SNEAKY_NETWORK = 20        # DoH/кастомные протоколы без бизнес-логики браузера
RISK_SECRETS_DETECTED = 15      # Найденные секреты/учётные данные в файле (AWS, токены и т.д.)
RISK_MALWARE_IN_MEMORY = 80      # Вредоносная сигнатура в дампе памяти (Deep Memory Scan) — критический фактор блокировки
RISK_YARA_MALWARE = 70           # Находка из внешней базы / категория malware (Yara-Rules, Neo23x0)
RISK_REVOKED_CERTIFICATE = 100   # Отозванный сертификат подписи (критический штраф)
RISK_CRYPTO_USAGE = 25           # Подозрительное использование шифрования (BCrypt + поиск файлов / Stratum miner)
RISK_SENSITIVE_DATA_ACCESS = 30  # Доступ к чувствительным данным (SetWindowsHookEx + пути профилей браузеров)
RISK_DISCOVERY_ACTIVITY = 15     # Массовый поиск файлов/процессов (T1083, T1057)
RISK_SCREEN_CAPTURE = 30        # Захват экрана в недоверенном ПО (BitBlt/GetDC — T1113)
RISK_NATIVE_API_USAGE = 20      # Использование ntdll в подозрительном контексте (T1106)
RISK_UAC_BYPASS_ATTEMPT = 50    # Критический: попытка обхода UAC (T1548.002)
RISK_DEFENDER_DISABLE_ATTEMPT = 60   # Критический: отключение Windows Defender через реестр (T1112)
RISK_ANTI_SANDBOX_STALL = 25    # Подозрительные циклы задержки по времени (T1124, обход песочниц)
RISK_SENSITIVE_STORAGE_ACCESS = 40   # Доступ к базам паролей/почте/куки (T1005, T1114, T1539)
RISK_DATA_STAGING = 20          # Создание скрытых хранилищ в Temp/AppData (T1074.001)
RISK_CLOUD_EXFILTRATION_STRINGS = 50  # Токены Telegram/Discord/Mega в недоверенном коде (T1567.002) — DENY
RISK_DNS_TUNNELING = 50         # Стелс-передача через DNS (T1071.004) — критический, DENY
RISK_DEFENSE_DISABLED = 70      # Отключение Firewall или AV (T1562.001, T1562.004) — DENY
RISK_LOG_CLEAR_ATTEMPT = 40     # Очистка журналов событий (T1070.001)
RISK_IFEO_INJECTION = 60        # Манипуляции с Image File Execution Options (T1546.012) — DENY
RISK_INTERNAL_NETWORK_SCAN = 40   # Перечисление серверов/портов в локальной сети (T1018, T1046)
RISK_DOMAIN_ENUMERATION = 35      # Запросы к Active Directory (T1087.002)
RISK_LATERAL_TRANSFER_ATTEMPT = 50  # Копирование на сетевые шары (T1570) — DENY/WARN
RISK_SUPPLY_CHAIN_TAMPERING = 80    # Модификация системных библиотек (T1195.002) — критично
RISK_UNCOMMON_PORT = 25             # Подозрительные сетевые порты (T1048.003)
RISK_HOSTS_MODIFICATION = 40        # Попытка правки файла hosts (T1562.006)
RISK_WMI_SUBSCRIPTION = 45           # WMI Event Subscription (T1546.003) — продвинутое закрепление
# Дифференцированный скоринг для редких/скрытных подтехник (Deep Coverage)
RISK_APC_INJECTION = 55              # T1055.004 — инъекция через APC (выше базовой инъекции)
RISK_TLS_EWMI_INJECTION = 50         # T1055.005, T1055.011 — TLS/EWMI
RISK_APPCERT_APPINIT = 45            # T1546.009, T1546.010 — загрузка DLL через реестр
RISK_SAFE_MODE_BOOT = 55             # T1562.009 — Safe Mode Boot
RISK_DISABLE_EVENT_LOGGING = 50      # T1562.002 — отключение журналирования (EtwEventWrite)
RISK_STEGANOGRAPHY = 35              # T1027.003 — стеганография в ресурсах (legacy)
# v2.0 Elite: повышенные веса для стего и padding
RISK_STEGANOGRAPHY_DETECTED = 50     # T1027.003 — детекция стеганографии (LSB высокая энтропия) — критично
RISK_EXOTIC_RUNTIME_SWIFT_RUBY = 25  # Swift/Ruby/Lua embedded — экзотический рантайм
RISK_PADDING_DETECTED = 30           # T1027.001 — бинарный padding (гигантский файл, ленивый анализ)
RISK_TAURI_WEBVIEW_SMUGGLING = 25    # T1027.006 — упакованные assets с обфусцированным JS (Tauri/WebView)
RISK_CUSTOM_CRYPTOR_T1027_013 = 35   # T1027.013 — цепочка GetVolumeInformation -> XOR -> VirtualAlloc
RISK_DCOM_LATERAL = 45               # T1021.003 — DCOM для латерального перемещения
RISK_EXOTIC_LANGUAGE = 15            # Экзотические для Enterprise языки (Nim, AutoIt, Zig) — часто дропперы (v1.2)
RISK_UNCOMMON_RUNTIME = 20           # Нестандартный рантайм для Enterprise (Nim, Zig, AutoIt) — APT/MITRE alignment
RISK_COMMERCIAL_PROTECTOR = 40       # Коммерческий протектор (Themida, Enigma)
RISK_OBFUSCATED_DOTNET = 30          # Обфускация .NET (ConfuserEx и др.)
RISK_PDB_DEV_PATH = 20               # PDB/пути окружения разработчика (\Users\admin\Desktop, ...) — +20
RISK_MALFORMED_HEADER_UPACK = 45     # Upack/деформация заголовков PE (нулевые размеры секций) — легитимный софт редко
BONUS_DOTNET_TRANSPARENT = 10        # .NET без обфускации — -10 к риску (высокая прозрачность)
# v3.0 Deep & Recursive Inspection
RISK_DEEP_OBFUSCATION_LAYERS = 60    # 3+ уровня вложенности распаковки/обфускации
RISK_SUSPICIOUS_MEDIA_METADATA = 40  # Подозрительные метаданные медиа (JPEG/PNG/IAT T1027.003)
RISK_SCRIPT_EVAL_DETECTED = 35       # Динамическое выполнение кода в скриптах (eval/exec/os.system)
# Attack Chain Analysis: комбо-риск — техники из разных стадий MITRE в одном файле (Credential Access + Exfiltration и т.д.)
RISK_ATTACK_CHAIN_COMBO = 40
# v3.2 Deep OSINT & External Reputation
RISK_EXTERNAL_C2_MATCH = 60       # IP/домен в C2-активности (AbuseIPDB/фиды) — блокировка
RISK_SUSPICIOUS_ASN = 25          # Нетипичный хостинг (VPS/анонимный) по Whois/ASN
RISK_UNCERTAIN_PUBLISHER = 10     # Издатель не в белом списке (только при наличии др. статического риска или Deep)
# RISK_SUPPLY_CHAIN_TAMPERING = 80 уже задан выше (T1195.002)

# Порог энтропии для "High Risk: Obfuscated"
ENTROPY_MANUAL_REVIEW_THRESHOLD = 7.2

# Маппинг подстрок scoring_reasons → MITRE ID для highlights["mitre_techniques"]
# Если в reasons появилась строка, содержащая ключ, добавляются соответствующие ID
REASON_TO_MITRE_MAP: Dict[str, List[str]] = {
    "Попытка отключения защиты": ["T1562", "T1562.001", "T1562.004"],
    "Манипуляции с Image File Execution Options": ["T1546.012"],
    "Манипуляции с IFEO": ["T1546.012"],
    "Перечисление серверов": ["T1018", "T1046"],
    "во внутренней сети": ["T1018", "T1046"],
    "Запросы к Active Directory": ["T1087.002"],
    "Копирование на сетевые ресурсы": ["T1570"],
    "Очистка журналов событий": ["T1070.001"],
    "Попытка отключения Windows Defender": ["T1112"],
    "Попытка обхода UAC": ["T1548.002"],
    "Подозрительная передача данных через DNS": ["T1071.004"],
    "Модификация системных библиотек": ["T1195.002"],
    "Попытка модификации файла hosts": ["T1562.006"],
    "WMI Event Subscription": ["T1546.003"],
    "Стеганография": ["T1027.003"],
    "Стеганография в ресурсах": ["T1027.003"],
    "Бинарный padding": ["T1027.001"],
    "Гигантский файл": ["T1027.001"],
    "Tauri/WebView smuggling": ["T1027.006"],
    "Custom cryptor": ["T1027.013"],
    "GetVolumeInformation": ["T1027.013"],
    "Upack": ["T1027"],
    "malformed header": ["T1027"],
    "Подозрительные метаданные медиа": ["T1027.003"],
    "Многослойная обфускация": ["T1027"],
    "Динамическое выполнение кода в скриптах": ["T1059"],
    "Цепочка атак (несколько стадий MITRE)": ["T1059"],
    "несколько стадий MITRE в одном файле": ["T1059"],
}

# Маппинг техник MITRE (T*) на тактики для Attack Chain / Combo-risk
# Используется для детекции «комбо»: техники из разных стадий в одном файле.
TECHNIQUE_TO_TACTIC: Dict[str, str] = {
    "T1059": "execution",
    "T1204": "execution",
    "T1547": "persistence",
    "T1546": "privilege-escalation",
    "T1562": "defense-evasion",
    "T1112": "defense-evasion",
    "T1070": "defense-evasion",
    "T1027": "defense-evasion",
    "T1110": "credential-access",
    "T1003": "credential-access",
    "T1555": "credential-access",
    "T1558": "credential-access",
    "T1083": "discovery",
    "T1057": "discovery",
    "T1018": "discovery",
    "T1046": "discovery",
    "T1087": "discovery",
    "T1021": "lateral-movement",
    "T1570": "lateral-movement",
    "T1005": "collection",
    "T1114": "collection",
    "T1539": "collection",
    "T1113": "collection",
    "T1071": "command-and-control",
    "T1102": "command-and-control",
    "T1048": "command-and-control",
    "T1567": "exfiltration",
    "T1041": "exfiltration",
    "T1020": "exfiltration",
    "T1082": "discovery",
    "T1056": "collection",
    "T1195": "initial-access",
    "T1548": "privilege-escalation",
    "T1197": "persistence",
    "T1055": "defense-evasion",
    "T1196": "defense-evasion",
}


def _get_ev_tactics(ev: Dict[str, Any]) -> set:
    """Собирает множество тактик MITRE по evidence (capa, emulation, technique_hints) для Combo-risk."""
    tactics: set = set()
    capa = ev.get("capa") or {}
    attck = capa.get("attck_by_tactic") or {}
    if isinstance(attck, dict):
        for tname, techs in attck.items():
            if tname and isinstance(techs, (list, tuple)) and len(techs) > 0:
                tactics.add(str(tname).strip().lower().replace("_", "-"))
    tactics_list = capa.get("tactics") or capa.get("techniques") or []
    for t in tactics_list:
        if t and isinstance(t, str):
            tactics.add(t.strip().lower().replace("_", "-"))
    emu = ev.get("emulation") or {}
    def _tid_to_tactic(tid: str) -> Optional[str]:
        base = tid.strip().upper().split(".")[0]
        return TECHNIQUE_TO_TACTIC.get(base)

    for tech in (emu.get("techniques") or []) if isinstance(emu, dict) else []:
        if isinstance(tech, str):
            t = _tid_to_tactic(tech)
            if t:
                tactics.add(t)
    for hint in (ev.get("pe") or {}).get("technique_hints") or []:
        if isinstance(hint, str) and hint.upper().startswith("T"):
            t = _tid_to_tactic(hint)
            if t:
                tactics.add(t)
    for hint in ev.get("technique_hints") or []:
        if isinstance(hint, str) and hint.upper().startswith("T"):
            t = _tid_to_tactic(hint)
            if t:
                tactics.add(t)
    return tactics


def get_mitre_from_reasons(reasons: List[str]) -> List[str]:
    """
    Извлекает MITRE ID из списка scoring_reasons по REASON_TO_MITRE_MAP.
    Возвращает список уникальных ID в едином формате (T1562 и т.д.).
    """
    mitre: List[str] = []
    reasons_str = " ".join(str(r) for r in reasons).lower()
    for key, ids in REASON_TO_MITRE_MAP.items():
        if key.lower() in reasons_str:
            mitre.extend(ids)
    return list(dict.fromkeys(m.upper() if m and m[0].upper() == "T" else m for m in mitre))


def _has_other_static_risk(ev: Dict[str, Any]) -> bool:
    """
    Есть ли хотя бы один другой статический риск (высокая энтропия, подозрительные секции, CWE, ordinal, persistence и т.д.).
    Используется для условного начисления RISK_UNCERTAIN_PUBLISHER (только при наличии другого риска или профиле Deep).
    """
    # High entropy
    obf = ev.get("obfuscation") or {}
    if isinstance(obf, dict) and obf.get("max_section_entropy") is not None:
        if float(obf.get("max_section_entropy", 0)) > ENTROPY_MANUAL_REVIEW_THRESHOLD:
            return True
    ent = ev.get("entropy") or {}
    if isinstance(ent, dict) and ent.get("file") is not None:
        if float(ent.get("file", 0)) > ENTROPY_MANUAL_REVIEW_THRESHOLD:
            return True
    # CWE
    cwe = ev.get("cwe_analysis") or {}
    if isinstance(cwe, dict) and (cwe.get("findings") or []):
        return True
    # Overlay suspicious
    pe = ev.get("pe") or {}
    ov = (pe.get("overlay") or {}) if isinstance(pe, dict) else {}
    if isinstance(ov, dict) and ov.get("suspicious") is True:
        return True
    # Ordinal imports
    if isinstance(pe, dict) and (pe.get("dangerous_ordinal_imports") or pe.get("has_ordinal_imports") or pe.get("ordinal_imports")):
        return True
    # Persistence
    pers = ev.get("persistence_analysis") or {}
    if isinstance(pers, dict) and pers.get("suspect") is True:
        return True
    # Capa defense evasion / anti-VM
    capa = ev.get("capa") or {}
    attck = capa.get("attck_by_tactic") or {}
    def_ev = list(attck.get("defense-evasion") or []) if isinstance(attck.get("defense-evasion"), list) else []
    if len(def_ev) > 3:
        return True
    rule_hits = capa.get("rule_hits") or []
    hit_str = " ".join(str(h) for h in rule_hits).lower()
    if any(k in hit_str for k in ("anti-vm", "vm-detection", "hypervisor", "anti-analysis", "sandbox")):
        return True
    # Anti-analysis in PE
    if isinstance(pe, dict):
        anti = pe.get("anti_analysis") or {}
        if isinstance(anti, dict) and anti.get("detected") is True:
            return True
    return False


def compute_risk_score(ev: Dict[str, Any], profile: str = "dev") -> int:
    """
    Вычисляет числовой риск 0–100 по методологии:
    Hardening missing +10, CWE +30, DGA +50, No Signature +20 (DEV) / +50 (PROD), и т.д.
    profile: "dev" | "prod" — в PROD отсутствие подписи/метки времени даёт +50 и фактически блокирует.
    """
    score = 0
    is_prod = (str(profile or "dev").lower() == "prod")
    is_deep = (str(profile or "dev").lower() == "deep")

    # Hardening missing
    pe = ev.get("pe") or {}
    h = (pe.get("hardening") or {}) if isinstance(pe, dict) else {}
    if isinstance(h, dict):
        if (h.get("aslr") is False or h.get("aslr_off") is True or
                h.get("dep") is False or h.get("nx") is False or
                h.get("cfg") is False or h.get("guard_cf") is False):
            score += RISK_HARDENING_MISSING
    elf = ev.get("elf") or {}
    eh = (elf.get("hardening") or {}) if isinstance(elf, dict) else {}
    if isinstance(eh, dict) and (eh.get("relro") == "none" or eh.get("nx") is False):
        score += RISK_HARDENING_MISSING

    # CWE detected
    cwe = ev.get("cwe_analysis") or {}
    if isinstance(cwe, dict):
        findings = cwe.get("findings") or []
        if findings:
            score += RISK_CWE_DETECTED

    # DGA detected
    ti = ev.get("threat_intel") or {}
    if isinstance(ti, dict):
        dga_count = (ti.get("dga") or {}).get("count", 0) if isinstance(ti.get("dga"), dict) else 0
        if dga_count and dga_count > 0:
            score += RISK_DGA_DETECTED

    # Отозванный сертификат — критический: риск 100, вердикт deny
    if isinstance(pe, dict):
        sig_obj = pe.get("signature")
        if isinstance(sig_obj, dict) and sig_obj.get("revoked") is True:
            return RISK_REVOKED_CERTIFICATE  # 100, ранний выход
        # v3.2: Stolen Cert Detection (база известных украденных отпечатков)
        if isinstance(sig_obj, dict) and sig_obj.get("stolen_cert_detected") is True:
            score += RISK_REVOKED_CERTIFICATE  # как отзыв
        # v3.2: Publisher Reputation — только если есть другой статический риск или профиль Deep (чтобы Low Risk проходил)
        if isinstance(sig_obj, dict) and sig_obj.get("uncertain_publisher") is True:
            if is_deep or _has_other_static_risk(ev):
                score += RISK_UNCERTAIN_PUBLISHER
    # No signature (PE) — в PROD жёстче
    if isinstance(pe, dict):
        sig_obj = pe.get("signature")
        if isinstance(sig_obj, dict):
            sig_present = sig_obj.get("present")
        else:
            sig_present = pe.get("signed") if sig_obj is None else sig_obj
        is_pe = pe.get("meta", {}).get("type") == "PE" or ev.get("meta", {}).get("type") == "PE"
        if (sig_present is False or sig_present is None) and is_pe:
            score += RISK_NO_SIGNATURE_PROD if is_prod else RISK_NO_SIGNATURE

    # Persistence: строки автозагрузки (Run, RunOnce, Winlogon, Services, Task Scheduler)
    # Находки, подтверждённые VT (verified_by_vt), получают множитель x1.5
    persistence = ev.get("persistence_analysis") or {}
    if isinstance(persistence, dict) and persistence.get("suspect"):
        risk = RISK_PERSISTENCE_DETECTED
        if persistence.get("any_verified_by_vt"):
            risk = int(round(risk * 1.5))
        score += risk

    # Ordinal import (скрытый импорт, в т.ч. опасный API)
    if isinstance(pe, dict):
        dang_ord = pe.get("dangerous_ordinal_imports") or []
        has_ord = pe.get("has_ordinal_imports") or bool(pe.get("ordinal_imports"))
        if dang_ord or has_ord:
            score += RISK_ORDINAL_IMPORT

    # Sneaky network (DoH без контекста браузера). VT-verified — множитель x1.5
    net = ev.get("network_profile") or {}
    if isinstance(net, dict) and net.get("sneaky_doh"):
        risk = RISK_SNEAKY_NETWORK
        if net.get("vt_verified"):
            risk = int(round(risk * 1.5))
        score += risk

    # Secrets detected (AWS keys, tokens, etc.)
    secrets = ev.get("secrets") or {}
    if isinstance(secrets, dict) and (secrets.get("suspicious") or secrets.get("hits")):
        score += RISK_SECRETS_DETECTED

    # High entropy (obfuscation)
    obf = ev.get("obfuscation") or {}
    if isinstance(obf, dict):
        max_ent = obf.get("max_section_entropy")
        if max_ent is not None and float(max_ent) > ENTROPY_MANUAL_REVIEW_THRESHOLD:
            score += RISK_HIGH_ENTROPY
    ent = ev.get("entropy") or {}
    if isinstance(ent, dict):
        file_ent = ent.get("file")
        if file_ent is not None and float(file_ent) > ENTROPY_MANUAL_REVIEW_THRESHOLD:
            score += RISK_HIGH_ENTROPY

    # URLHaus hit
    if isinstance(ti, dict):
        urlhaus = (ti.get("ti_matches") or {}).get("urlhaus") or []
        if urlhaus:
            score += RISK_URLHAUS_HIT

    # v3.2 OSINT: C2-активность по внешним фидам (AbuseIPDB и т.д.)
    osint = ev.get("osint") or {}
    if isinstance(osint, dict):
        if osint.get("c2_detected"):
            score += RISK_EXTERNAL_C2_MATCH
        if osint.get("suspicious_asn"):
            score += RISK_SUSPICIOUS_ASN

    # Visual masquerading: иконка документа (Excel, PDF, Word, Image), а file_type — PE
    vis = ev.get("visual") or {}
    icon = (vis.get("icon") or {}) if isinstance(vis.get("icon"), dict) else {}
    if vis.get("icon_mismatch") or vis.get("masquerading_suspect"):
        score += RISK_MASQUERADING
    elif icon.get("mismatch_type") and "executable" in str(icon.get("mismatch_type", "")).lower():
        score += RISK_MASQUERADING

    # Defense Evasion: более 3 техник в категории → +15
    capa = ev.get("capa") or {}
    tactics_list = capa.get("tactics") or capa.get("techniques") or []
    attck = capa.get("attck_by_tactic") or {}
    def_evasion = list(attck.get("defense-evasion") or []) if isinstance(attck.get("defense-evasion"), list) else []
    def_evasion += [t for t in tactics_list if t and "defense-evasion" in str(t).lower().replace("_", "-")]
    if len(set(def_evasion)) > 3:
        score += RISK_DEFENSE_EVASION_3

    # Anti-VM / Anti-Analysis: +15 (capa rule hits)
    rule_hits = capa.get("rule_hits") or []
    hit_str = " ".join(str(h) for h in rule_hits).lower()
    if any(k in hit_str for k in ("anti-vm", "vm-detection", "virtual machine", "cpuid", "rdtsc", "hypervisor", "anti-analysis", "sandbox")):
        score += RISK_ANTI_VM

    # Evasion: отладочные API в PE (IsDebuggerPresent и др.) — +30
    if isinstance(pe, dict):
        anti = pe.get("anti_analysis") or {}
        if isinstance(anti, dict) and anti.get("detected"):
            score += RISK_EVASION_TECHNIQUE

    # Behavior hints: подозрительное шифрование (ransomware/miner) и доступ к данным браузеров (keylogger/spyware)
    if isinstance(pe, dict):
        hints = pe.get("behavior_hints") or {}
        if isinstance(hints, dict):
            if hints.get("crypto_usage"):
                score += RISK_CRYPTO_USAGE
            if hints.get("sensitive_data_access"):
                score += RISK_SENSITIVE_DATA_ACCESS
            if hints.get("discovery_activity"):
                score += RISK_DISCOVERY_ACTIVITY
            if hints.get("screen_capture"):
                score += RISK_SCREEN_CAPTURE
            if hints.get("native_api_usage"):
                score += RISK_NATIVE_API_USAGE
            if hints.get("uac_bypass_attempt"):
                score += RISK_UAC_BYPASS_ATTEMPT
            if hints.get("defender_disable_attempt"):
                score += RISK_DEFENDER_DISABLE_ATTEMPT
            if hints.get("anti_sandbox_stall"):
                score += RISK_ANTI_SANDBOX_STALL
            if hints.get("sensitive_storage_access"):
                score += RISK_SENSITIVE_STORAGE_ACCESS
            if hints.get("data_staging"):
                score += RISK_DATA_STAGING
            if hints.get("cloud_exfiltration_strings"):
                score += RISK_CLOUD_EXFILTRATION_STRINGS
            if hints.get("defense_disabled"):
                score += RISK_DEFENSE_DISABLED
            if hints.get("log_clear_attempt"):
                score += RISK_LOG_CLEAR_ATTEMPT
            if hints.get("ifeo_injection"):
                score += RISK_IFEO_INJECTION
            if hints.get("internal_network_scan"):
                score += RISK_INTERNAL_NETWORK_SCAN
            if hints.get("domain_enumeration"):
                score += RISK_DOMAIN_ENUMERATION
            if hints.get("lateral_transfer_attempt"):
                score += RISK_LATERAL_TRANSFER_ATTEMPT
            if hints.get("supply_chain_tampering"):
                score += RISK_SUPPLY_CHAIN_TAMPERING
            if hints.get("uncommon_port"):
                score += RISK_UNCOMMON_PORT
            if hints.get("hosts_modification"):
                score += RISK_HOSTS_MODIFICATION
            if hints.get("wmi_subscription"):
                score += RISK_WMI_SUBSCRIPTION
    # Supply chain / uncommon port / hosts / WMI from technique_hints if not in behavior_hints
    if isinstance(pe, dict):
        th = pe.get("technique_hints") or []
        if "T1195.002" in th and not (isinstance(pe.get("behavior_hints"), dict) and pe.get("behavior_hints", {}).get("supply_chain_tampering")):
            score += RISK_SUPPLY_CHAIN_TAMPERING
        if "T1048.003" in th and not (isinstance(pe.get("behavior_hints"), dict) and pe.get("behavior_hints", {}).get("uncommon_port")):
            score += RISK_UNCOMMON_PORT
        if "T1562.006" in th and not (isinstance(pe.get("behavior_hints"), dict) and pe.get("behavior_hints", {}).get("hosts_modification")):
            score += RISK_HOSTS_MODIFICATION
        if "T1546.003" in th and not (isinstance(pe.get("behavior_hints"), dict) and pe.get("behavior_hints", {}).get("wmi_subscription")):
            score += RISK_WMI_SUBSCRIPTION
    # Internal network scan / domain enum from network_profile if not from hints
    net = ev.get("network_profile") or {}
    if isinstance(net, dict) and net.get("internal_ip_scan_suspect") and not (isinstance(pe, dict) and (pe.get("behavior_hints") or {}).get("internal_network_scan")):
        score += RISK_INTERNAL_NETWORK_SCAN
    # Deep Coverage: подтехники с повышенным весом (technique_hints)
    if isinstance(pe, dict):
        th = pe.get("technique_hints") or []
        if "T1055.004" in th:
            score += RISK_APC_INJECTION
        if "T1055.005" in th or "T1055.011" in th:
            score += RISK_TLS_EWMI_INJECTION
        if "T1546.009" in th or "T1546.010" in th:
            score += RISK_APPCERT_APPINIT
        if "T1547.005" in th or "T1547.014" in th:
            score += RISK_PERSISTENCE_DETECTED  # SSP / Active Setup
        if "T1562.009" in th:
            score += RISK_SAFE_MODE_BOOT
        if "T1562.002" in th:
            score += RISK_DISABLE_EVENT_LOGGING
        if "T1027.003" in th:
            # Если стего уже учтена по evidence.steganography.detected (+50), не дублируем
            if not (isinstance(ev.get("steganography"), dict) and ev.get("steganography", {}).get("detected")):
                score += RISK_STEGANOGRAPHY
        if "T1021.003" in th:
            score += RISK_DCOM_LATERAL
    # DNS tunneling (T1071.004) from technique_hints or network_profile — один раз
    if isinstance(pe, dict) and "T1071.004" in (pe.get("technique_hints") or []):
        score += RISK_DNS_TUNNELING
    elif isinstance(ev.get("network_profile"), dict) and ev["network_profile"].get("dns_tunneling_suspect"):
        score += RISK_DNS_TUNNELING
    # Emulation techniques: discovery/screen-capture/native-api if not already from behavior_hints
    emu = ev.get("emulation") or {}
    emu_tech = list(emu.get("techniques") or []) if isinstance(emu, dict) else []
    if not (isinstance(pe, dict) and (pe.get("behavior_hints") or {}).get("discovery_activity")):
        if any(t and ("T1083" in str(t) or "T1057" in str(t) or "file-directory-discovery" in str(t).lower() or "process-discovery" in str(t).lower()) for t in emu_tech):
            score += RISK_DISCOVERY_ACTIVITY
    if not (isinstance(pe, dict) and (pe.get("behavior_hints") or {}).get("screen_capture")):
        if any(t and ("T1113" in str(t) or "screen-capture" in str(t).lower()) for t in emu_tech):
            score += RISK_SCREEN_CAPTURE
    if not (isinstance(pe, dict) and (pe.get("behavior_hints") or {}).get("native_api_usage")):
        if any(t and ("T1106" in str(t) or "native-api" in str(t).lower()) for t in emu_tech):
            score += RISK_NATIVE_API_USAGE
    # UAC Bypass / Defender disable / Anti-sandbox stall from emulation if not from hints
    if not (isinstance(pe, dict) and (pe.get("behavior_hints") or {}).get("uac_bypass_attempt")):
        if any(t and "T1548.002" in str(t) for t in emu_tech):
            score += RISK_UAC_BYPASS_ATTEMPT
    if not (isinstance(pe, dict) and (pe.get("behavior_hints") or {}).get("defender_disable_attempt")):
        if any(t and "T1112" in str(t) for t in emu_tech):
            score += RISK_DEFENDER_DISABLE_ATTEMPT
    if not (isinstance(pe, dict) and (pe.get("behavior_hints") or {}).get("anti_sandbox_stall")):
        if any(t and "T1124" in str(t) for t in emu_tech):
            score += RISK_ANTI_SANDBOX_STALL
    if not (isinstance(pe, dict) and (pe.get("behavior_hints") or {}).get("defense_disabled")):
        if any(t and ("T1562.001" in str(t) or "T1562.004" in str(t)) for t in emu_tech):
            score += RISK_DEFENSE_DISABLED
    if not (isinstance(pe, dict) and (pe.get("behavior_hints") or {}).get("log_clear_attempt")):
        if any(t and "T1070.001" in str(t) for t in emu_tech):
            score += RISK_LOG_CLEAR_ATTEMPT
    if not (isinstance(pe, dict) and (pe.get("behavior_hints") or {}).get("ifeo_injection")):
        if any(t and "T1546.012" in str(t) for t in emu_tech):
            score += RISK_IFEO_INJECTION
    if not (isinstance(pe, dict) and (pe.get("behavior_hints") or {}).get("internal_network_scan")):
        if any(t and ("T1018" in str(t) or "T1046" in str(t)) for t in emu_tech):
            score += RISK_INTERNAL_NETWORK_SCAN
    if not (isinstance(pe, dict) and (pe.get("behavior_hints") or {}).get("domain_enumeration")):
        if any(t and "T1087.002" in str(t) for t in emu_tech):
            score += RISK_DOMAIN_ENUMERATION
    if not (isinstance(pe, dict) and (pe.get("behavior_hints") or {}).get("lateral_transfer_attempt")):
        if any(t and "T1570" in str(t) for t in emu_tech):
            score += RISK_LATERAL_TRANSFER_ATTEMPT

    # YARA: находки из внешних баз (malware / Yara-Rules / Neo23x0) — +70
    yara_hits = ev.get("yara") or []
    if isinstance(yara_hits, list):
        for h in yara_hits:
            if not isinstance(h, dict):
                continue
            ns = (h.get("namespace") or "").lower()
            if ns in ("errors", "meta"):
                continue
            rule_name = (h.get("rule") or "").strip()
            if rule_name.startswith("yara_"):
                continue
            meta = h.get("meta") or {}
            cat = str(meta.get("category") or meta.get("family") or "").lower()
            if "malware" in cat or "malware" in ns or "yara-rules" in ns or "neo23x0" in ns or "external" in ns:
                score += RISK_YARA_MALWARE
                break

    # Deep Memory Scan: вредоносная сигнатура в дампе памяти — критический фактор
    mda = ev.get("memory_dump_analysis") or {}
    yara_mem = mda.get("yara") if isinstance(mda, dict) else None
    if yara_mem and isinstance(yara_mem, list) and len(yara_mem) > 0:
        # Игнорируем только служебные хиты (errors, meta)
        skip_rules = {"yara_skipped_large_file", "yara_error", "yara_match_error", "yara_truncated"}
        real_hits = [h for h in yara_mem if isinstance(h, dict) and (h.get("namespace") or "") != "errors" and (h.get("rule") or "") not in skip_rules]
        if real_hits:
            score += RISK_MALWARE_IN_MEMORY

    # Экзотические языки (Nim, AutoIt, Zig) — +15 в контексте Enterprise (v1.2)
    try:
        from .analyzers.language_analyzer import is_exotic_language
        lang = (ev.get("meta") or {}).get("language")
        if is_exotic_language(lang):
            score += RISK_EXOTIC_LANGUAGE
    except Exception:
        pass

    # Нестандартный рантайм (Nim, Zig, AutoIt) — +20, APT/MITRE alignment
    try:
        lang = (ev.get("meta") or {}).get("language") or ""
        n = lang.strip().lower()
        if n in ("nim", "zig", "autoit", "autohotkey"):
            score += RISK_UNCOMMON_RUNTIME
    except Exception:
        pass

    # v2.0 Elite: стеганография (LSB высокая энтропия в иконках/BMP) — +50
    stego = ev.get("steganography") or {}
    if isinstance(stego, dict) and stego.get("detected"):
        score += RISK_STEGANOGRAPHY_DETECTED

    # v3.0: подозрительные метаданные медиа (JPEG/PNG/IAT) — +40
    if ev.get("suspicious_media_metadata"):
        score += RISK_SUSPICIOUS_MEDIA_METADATA

    # v3.0: 3+ уровня распаковки/обфускации — +60
    unpack_depth = ev.get("unpack_depth") or 0
    recursive_layers = ev.get("recursive_unpack_layers") or []
    if unpack_depth >= 3 or len(recursive_layers) >= 3:
        score += RISK_DEEP_OBFUSCATION_LAYERS

    # v3.0: динамическое выполнение кода в скриптах (eval/exec) — +35
    if ev.get("script_eval_detected"):
        score += RISK_SCRIPT_EVAL_DETECTED

    # v3.1 Attack Storyline: комбо-пары (T1204+T1562=+30, T1003+T1020=+50, T1082+T1021=+40)
    storyline_bonus = 0
    try:
        from .behavioral_graph import compute_storyline_combo_score
        storyline_bonus, _ = compute_storyline_combo_score(ev)
        score += storyline_bonus
    except Exception:
        pass
    # Attack Chain Analysis: общий комбо-риск — техники из разных стадий MITRE — +40 (если ещё не набрали по парам)
    ev_tactics = _get_ev_tactics(ev)
    if len(ev_tactics) >= 2 and storyline_bonus == 0:
        score += RISK_ATTACK_CHAIN_COMBO

    # v2.0 Elite: экзотический рантайм Swift/Ruby/Lua (embedded) — +25
    try:
        lang = (ev.get("meta") or {}).get("language") or ""
        n = lang.strip().lower()
        if n in ("swift", "ruby", "lua"):
            score += RISK_EXOTIC_RUNTIME_SWIFT_RUBY
    except Exception:
        pass

    # v2.0 Elite: бинарный padding (гигантский файл, ленивый анализ) — +30
    padding = ev.get("binary_padding") or ev.get("padding_detected")
    if isinstance(padding, dict) and padding.get("detected"):
        score += RISK_PADDING_DETECTED
    elif padding is True:
        score += RISK_PADDING_DETECTED

    # v2.0 T1027.006 Tauri/WebView smuggling (архив с assets/*.js высокой энтропии) — один раз
    tw = ev.get("tauri_webview_smuggling") or {}
    th_top = ev.get("technique_hints") or []
    if (isinstance(tw, dict) and tw.get("detected")) or "T1027.006" in th_top:
        score += RISK_TAURI_WEBVIEW_SMUGGLING

    # v2.0 T1027.013 Custom Cryptors (GetVolumeInformation -> XOR -> VirtualAlloc)
    if isinstance(pe, dict) and "T1027.013" in (pe.get("technique_hints") or []):
        score += RISK_CUSTOM_CRYPTOR_T1027_013

    # Legacy Upack / malformed PE header (нулевые размеры секций) — +45
    try:
        pe_obj = ev.get("pe") or {}
        if isinstance(pe_obj, dict):
            malformed = pe_obj.get("malformed_pe") or pe_obj.get("malformed_header_upack_suspect")
            obf_upack = ev.get("obfuscation") or {}
            packers_list = (obf_upack.get("packer_families") or []) if isinstance(obf_upack, dict) else []
            has_upack = any(p and "upack" in str(p).lower() for p in packers_list)
            if malformed and has_upack:
                score += RISK_MALFORMED_HEADER_UPACK
            elif malformed and packers_list:
                for p in packers_list:
                    if p and str(p).strip().lower() in ("fsg", "petite", "aspack"):
                        score += RISK_MALFORMED_HEADER_UPACK
                        break
    except Exception:
        pass

    # Коммерческий протектор (Themida, Enigma) — +40
    try:
        obf = ev.get("obfuscation") or {}
        if isinstance(obf, dict):
            for p in obf.get("packer_families") or []:
                pl = str(p).strip().lower()
                if pl in ("themida", "enigma"):
                    score += RISK_COMMERCIAL_PROTECTOR
                    break
        die = ev.get("die") or {}
        if isinstance(die, dict):
            for d in die.get("detects") or []:
                name = (d.get("name") or d.get("sName") or "") if isinstance(d, dict) else str(d)
                if "themida" in name.lower() or "enigma" in name.lower():
                    score += RISK_COMMERCIAL_PROTECTOR
                    break
    except Exception:
        pass

    # Обфускация .NET (ConfuserEx) — +30 (один раз)
    try:
        lang = (ev.get("meta") or {}).get("language") or ""
        if "dotnet" in lang.lower() or ".net" in lang.lower() or "c#" in lang.lower():
            dotnet_obf = False
            dotnet = ev.get("dotnet") or {}
            if isinstance(dotnet, dict) and (dotnet.get("anti_tamper") or {}).get("packer_detected"):
                dotnet_obf = True
            obf = ev.get("obfuscation") or {}
            if isinstance(obf, dict) and obf.get("score", 0) >= 40:
                dotnet_obf = True
            for h in ev.get("yara") or []:
                r = (h.get("rule") or "").lower()
                if "confuserex" in r or "confuser" in r:
                    dotnet_obf = True
                    break
            if dotnet_obf:
                score += RISK_OBFUSCATED_DOTNET
    except Exception:
        pass

    # .NET без обфускации — -10 (высокая прозрачность кода)
    try:
        lang = (ev.get("meta") or {}).get("language") or ""
        if "dotnet" in lang.lower() or "c#" in lang.lower() or ".net" in lang.lower():
            obf = ev.get("obfuscation") or {}
            obf_score = int(obf.get("score", 0)) if isinstance(obf, dict) else 0
            if obf_score < 30 and not (obf.get("packer_families") or []):
                score = max(0, score - BONUS_DOTNET_TRANSPARENT)
    except Exception:
        pass

    # PDB/пути окружения разработчика (\Users\admin\Desktop, \Users\*\Desktop) — +20 (v1.2)
    try:
        import re as _re
        _dev_path_pattern = _re.compile(r"\\\\[^\\]+\\users\\[^\\]+\\desktop|/users/[^/]+/desktop|\\\\[^\\]+\\users\\admin\\", _re.IGNORECASE)
        pdb_dev_added = False
        for key in ("strings", "pe"):
            if pdb_dev_added:
                break
            data = ev.get(key)
            if not data or not isinstance(data, dict):
                continue
            if key == "pe":
                debug_path = (data.get("debug") or {}) if isinstance(data.get("debug"), dict) else {}
                path_str = debug_path.get("pdb_path") or debug_path.get("path") or ""
                if path_str and _dev_path_pattern.search(path_str):
                    score += RISK_PDB_DEV_PATH
                    pdb_dev_added = True
            else:
                strings = data.get("static") or data.get("all") or []
                if isinstance(strings, list):
                    for s in strings[:500]:
                        if isinstance(s, str) and _dev_path_pattern.search(s):
                            score += RISK_PDB_DEV_PATH
                            pdb_dev_added = True
                            break
    except Exception:
        pass

    # Мультипликатор связок: Masquerading + Suspicious API Chain (Process Hollowing) → x1.2
    vis = ev.get("visual") or {}
    icon = (vis.get("icon") or {}) if isinstance(vis.get("icon"), dict) else {}
    masquerading = (
        vis.get("icon_mismatch") or vis.get("masquerading_suspect")
        or (icon.get("mismatch_type") and "executable" in str(icon.get("mismatch_type", "")).lower())
    )
    wdac = (pe.get("wdac_bypass") or {}) if isinstance(pe, dict) else {}
    loader_heuristics = wdac.get("loader_heuristics") or []
    has_injection_chain = (
        "loader_memory_remote_thread" in loader_heuristics
        or "loader_process_hollowing_chain" in loader_heuristics
    )
    emu = ev.get("emulation") or {}
    emu_techniques = list(emu.get("techniques") or []) if isinstance(emu, dict) else []
    has_emu_hollowing = any(
        t and ("process-hollowing" in str(t).lower() or "T1055" in str(t))
        for t in emu_techniques
    )
    if masquerading and (has_injection_chain or has_emu_hollowing):
        score = int(round(score * 1.2))

    return min(100, score)


def get_risk_reason_strings(ev: Dict[str, Any], profile: str = "dev") -> List[str]:
    """
    Возвращает человекочитаемые причины риска для списка reasons в политике.
    Восстанавливает цепочку: анализатор -> причины -> вердикт.
    """
    reasons: List[str] = []
    meta = ev.get("meta") or {}
    file_name = meta.get("name") or meta.get("path") or "файл"

    # КРИТИЧЕСКАЯ УГРОЗА: находки в дампе памяти — ставим первой в списке причин
    mda = ev.get("memory_dump_analysis") or {}
    yara_mem = mda.get("yara") if isinstance(mda, dict) else None
    if yara_mem and isinstance(yara_mem, list) and len(yara_mem) > 0:
        skip_rules = {"yara_skipped_large_file", "yara_error", "yara_match_error", "yara_truncated"}
        real_hits = [h for h in yara_mem if isinstance(h, dict) and (h.get("namespace") or "") != "errors" and (h.get("rule") or "") not in skip_rules]
        if real_hits:
            reasons.append("КРИТИЧЕСКАЯ УГРОЗА: Вредоносная сигнатура обнаружена в дампе памяти (Deep Memory Scan)")
            reasons.append("Заблокировано на основе анализа содержимого памяти")

    # Маскировка: критическое несоответствие типа и расширения (маскировка под документ)
    vis = ev.get("visual") or {}
    icon = (vis.get("icon") or {}) if isinstance(vis.get("icon"), dict) else {}
    if vis.get("icon_mismatch") or vis.get("masquerading_suspect"):
        reasons.append("Критическое несоответствие типа файла и расширения (маскировка под документ)")
        target = str(icon.get("mismatch_type") or icon.get("detected_type") or "документ").strip()
        if not target:
            target = "документ"
        reasons.append(f"Обнаружена маскировка: файл {file_name} имитирует тип {target}")
    elif icon.get("mismatch_type") and "executable" in str(icon.get("mismatch_type", "")).lower():
        reasons.append("Критическое несоответствие типа файла и расширения (маскировка под документ)")
        reasons.append(f"Обнаружена маскировка: файл {file_name} имитирует тип документа (исполняемый)")

    # Секреты: список типов
    secrets = ev.get("secrets") or {}
    if isinstance(secrets, dict) and (secrets.get("suspicious") or secrets.get("hits")):
        hits = secrets.get("hits")
        if isinstance(hits, dict) and hits:
            types_str = ", ".join(sorted(hits.keys())[:10])
            reasons.append(f"Обнаружены секреты: {types_str}")
        else:
            reasons.append("Обнаружены секреты: подозрительные паттерны")

    # YARA: сигнатура из внешней базы (malware)
    yara_hits = ev.get("yara") or []
    if isinstance(yara_hits, list):
        for h in yara_hits:
            if not isinstance(h, dict):
                continue
            ns = (h.get("namespace") or "").lower()
            if ns in ("errors", "meta"):
                continue
            rule_name = (h.get("rule") or "").strip()
            if rule_name.startswith("yara_"):
                continue
            meta = h.get("meta") or {}
            cat = str(meta.get("category") or meta.get("family") or "").lower()
            if "malware" in cat or "malware" in ns or "yara-rules" in ns or "neo23x0" in ns or "external" in ns:
                reasons.append("Обнаружена сигнатура вредоносного ПО (внешняя база YARA)")
                break

    # Экзотические языки (Nim, AutoIt) — часто используются для дропперов
    try:
        from .analyzers.language_analyzer import is_exotic_language
        if is_exotic_language((ev.get("meta") or {}).get("language")):
            reasons.append("Использование экзотического для Enterprise языка (Nim/AutoIt), типичного для дропперов")
    except Exception:
        pass

    # Нестандартный рантайм (Nim, Zig, AutoIt) — APT/MITRE alignment
    try:
        lang = (ev.get("meta") or {}).get("language") or ""
        n = lang.strip().lower()
        if n in ("nim", "zig", "autoit", "autohotkey"):
            reasons.append("Нестандартный для Enterprise рантайм (Nim/Zig/AutoIt), характерный для APT-группировок")
    except Exception:
        pass

    # Коммерческий протектор (Themida, Enigma)
    try:
        obf = ev.get("obfuscation") or {}
        die = ev.get("die") or {}
        for p in (obf.get("packer_families") or []) if isinstance(obf, dict) else []:
            if str(p).strip().lower() in ("themida", "enigma"):
                reasons.append("Обнаружен коммерческий протектор (Themida/Enigma)")
                break
        else:
            for d in (die.get("detects") or []) if isinstance(die, dict) else []:
                name = (d.get("name") or d.get("sName") or "") if isinstance(d, dict) else str(d)
                if "themida" in name.lower() or "enigma" in name.lower():
                    reasons.append("Обнаружен коммерческий протектор (Themida/Enigma)")
                    break
    except Exception:
        pass

    # Обфускация .NET (ConfuserEx)
    try:
        lang = (ev.get("meta") or {}).get("language") or ""
        if "dotnet" in lang.lower() or ".net" in lang.lower() or "c#" in lang.lower():
            dotnet_obf = False
            dotnet = ev.get("dotnet") or {}
            if isinstance(dotnet, dict) and (dotnet.get("anti_tamper") or {}).get("packer_detected"):
                dotnet_obf = True
            obf = ev.get("obfuscation") or {}
            if isinstance(obf, dict) and obf.get("score", 0) >= 40:
                dotnet_obf = True
            for h in ev.get("yara") or []:
                r = (h.get("rule") or "").lower()
                if "confuserex" in r or "confuser" in r:
                    dotnet_obf = True
                    break
            if dotnet_obf:
                reasons.append("Обнаружена обфускация .NET (ConfuserEx или аналог)")
    except Exception:
        pass

    # Остальные компоненты (для прозрачности)
    pe = ev.get("pe") or {}
    h = (pe.get("hardening") or {}) if isinstance(pe, dict) else {}
    if isinstance(h, dict) and (h.get("aslr") is False or h.get("dep") is False or h.get("cfg") is False):
        reasons.append("Отсутствие hardening (ASLR/DEP/CFG)")
    if isinstance(pe, dict):
        sig = pe.get("signature")
        if isinstance(sig, dict) and sig.get("revoked") is True:
            reasons.append("Обнаружен отозванный сертификат подписи (CRL/OCSP)")
        present = sig.get("present") if isinstance(sig, dict) else pe.get("signed")
        if present is False or present is None:
            reasons.append("Нет цифровой подписи")
    if (ev.get("persistence_analysis") or {}).get("suspect"):
        reasons.append("Обнаружены признаки автозагрузки (Run/RunOnce/Winlogon)")
    # Цепочка внедрения (Process Hollowing) по loader_heuristics или emulation
    pe = ev.get("pe") or {}
    wdac = (pe.get("wdac_bypass") or {}).get("loader_heuristics") or []
    emu_tech = list((ev.get("emulation") or {}).get("techniques") or [])
    if ("loader_memory_remote_thread" in wdac or "loader_process_hollowing_chain" in wdac) or any(
        t and ("process-hollowing" in str(t).lower() or "T1055" in str(t)) for t in emu_tech
    ):
        reasons.append("Detected Process Hollowing injection chain")
    if (ev.get("pe") or {}).get("anti_analysis", {}).get("detected"):
        reasons.append("Обнаружены техники уклонения (Anti-Analysis)")
    hints = (ev.get("pe") or {}).get("behavior_hints") or {}
    if isinstance(hints, dict) and hints.get("crypto_usage"):
        reasons.append("Подозрительное использование шифрования (BCrypt/Stratum)")
    if isinstance(hints, dict) and hints.get("sensitive_data_access"):
        reasons.append("Доступ к чувствительным данным (пути профилей браузеров)")
    emu_tech = list((ev.get("emulation") or {}).get("techniques") or [])
    if (isinstance(hints, dict) and hints.get("discovery_activity")) or any(t and ("T1083" in str(t) or "T1057" in str(t)) for t in emu_tech):
        reasons.append("Массовый поиск файлов/процессов (Discovery)")
    if (isinstance(hints, dict) and hints.get("screen_capture")) or any(t and "T1113" in str(t) for t in emu_tech):
        reasons.append("Захват экрана (BitBlt/GetDC) в недоверенном ПО")
    if (isinstance(hints, dict) and hints.get("native_api_usage")) or any(t and "T1106" in str(t) for t in emu_tech):
        reasons.append("Использование Native API (ntdll) в подозрительном контексте")
    if (isinstance(hints, dict) and hints.get("uac_bypass_attempt")) or any(t and "T1548.002" in str(t) for t in emu_tech):
        reasons.append("Попытка обхода UAC (T1548.002)")
    if (isinstance(hints, dict) and hints.get("defender_disable_attempt")) or any(t and "T1112" in str(t) for t in emu_tech):
        reasons.append("Попытка отключения Windows Defender через реестр (T1112)")
    if (isinstance(hints, dict) and hints.get("anti_sandbox_stall")) or any(t and "T1124" in str(t) for t in emu_tech):
        reasons.append("Подозрительная задержка по времени (обход песочниц, T1124)")
    if (isinstance(hints, dict) and hints.get("sensitive_storage_access")):
        reasons.append("Доступ к чувствительным хранилищам (пароли, почта, куки)")
    if (isinstance(hints, dict) and hints.get("data_staging")):
        reasons.append("Создание скрытых хранилищ данных (стейджинг)")
    if (isinstance(hints, dict) and hints.get("cloud_exfiltration_strings")):
        reasons.append("Строки экфильтрации в облако (Telegram/Discord/Mega)")
    th_hints = (ev.get("pe") or {}).get("technique_hints") or []
    dns_suspect = (ev.get("network_profile") or {}).get("dns_tunneling_suspect")
    if "T1071.004" in th_hints or dns_suspect:
        reasons.append("Подозрительная передача данных через DNS (туннелирование)")
    if (isinstance(hints, dict) and hints.get("defense_disabled")) or any(t and ("T1562.001" in str(t) or "T1562.004" in str(t)) for t in emu_tech):
        reasons.append("Попытка отключения защиты (Firewall/антивирус)")
    if (isinstance(hints, dict) and hints.get("log_clear_attempt")) or any(t and "T1070.001" in str(t) for t in emu_tech):
        reasons.append("Очистка журналов событий (удаление следов)")
    if (isinstance(hints, dict) and hints.get("ifeo_injection")) or any(t and "T1546.012" in str(t) for t in emu_tech):
        reasons.append("Манипуляции с Image File Execution Options (IFEO)")
    if (isinstance(hints, dict) and hints.get("internal_network_scan")) or any(t and ("T1018" in str(t) or "T1046" in str(t)) for t in emu_tech) or (ev.get("network_profile") or {}).get("internal_ip_scan_suspect"):
        reasons.append("Перечисление серверов/портов во внутренней сети (Lateral Movement)")
    if (isinstance(hints, dict) and hints.get("domain_enumeration")) or any(t and "T1087.002" in str(t) for t in emu_tech):
        reasons.append("Запросы к Active Directory (перечисление учётных записей)")
    if (isinstance(hints, dict) and hints.get("lateral_transfer_attempt")) or any(t and "T1570" in str(t) for t in emu_tech):
        reasons.append("Копирование на сетевые ресурсы (Lateral Tool Transfer)")
    if (isinstance(hints, dict) and hints.get("supply_chain_tampering")) or "T1195.002" in th_hints:
        reasons.append("Модификация системных библиотек (Supply Chain, T1195.002)")
    if (isinstance(hints, dict) and hints.get("uncommon_port")) or "T1048.003" in th_hints:
        reasons.append("Соединения на нестандартные порты (T1048.003)")
    if (isinstance(hints, dict) and hints.get("hosts_modification")) or "T1562.006" in th_hints:
        reasons.append("Попытка модификации файла hosts (блокировка обновлений AV)")
    if (isinstance(hints, dict) and hints.get("wmi_subscription")) or "T1546.003" in th_hints:
        reasons.append("WMI Event Subscription (закрепление через __EventFilter/CommandLineEventConsumer)")
    # Deep Coverage: причины по подтехникам
    if "T1055.004" in th_hints:
        reasons.append("Инъекция через APC (QueueUserAPC / NtQueueApcThread)")
    if "T1055.005" in th_hints or "T1055.011" in th_hints:
        reasons.append("Продвинутая инъекция (TLS или Extra Window Memory)")
    if "T1546.009" in th_hints or "T1546.010" in th_hints:
        reasons.append("Закрепление через AppCert/AppInit DLLs (реестр)")
    if "T1547.005" in th_hints or "T1547.014" in th_hints:
        reasons.append("Закрепление через SSP или Active Setup")
    if "T1562.009" in th_hints:
        reasons.append("Попытка загрузки в Safe Mode (обход защиты)")
    if "T1562.002" in th_hints:
        reasons.append("Отключение журналирования событий (EtwEventWrite)")
    if "T1027.003" in th_hints:
        reasons.append("Стеганография (скрытие данных в ресурсах)")
    # v3.0: подозрительные метаданные медиа (JPEG/PNG/IAT)
    if ev.get("suspicious_media_metadata"):
        reasons.append("Подозрительные метаданные медиа (JPEG/PNG/IAT, T1027.003)")
    # v3.0: многослойная распаковка/обфускация (3+ уровня)
    unpack_depth = ev.get("unpack_depth") or 0
    recursive_layers = ev.get("recursive_unpack_layers") or []
    if unpack_depth >= 3 or len(recursive_layers) >= 3:
        reasons.append("Многослойная обфускация/распаковка (3+ уровня)")
    # v3.0: динамическое выполнение кода в скриптах
    if ev.get("script_eval_detected"):
        reasons.append("Динамическое выполнение кода в скриптах (eval/exec/os.system)")
    # v3.1 Attack Storyline: комбо-пары (конкретные связки техник)
    try:
        from .behavioral_graph import compute_storyline_combo_score
        _, storyline_reasons = compute_storyline_combo_score(ev)
        reasons.extend(storyline_reasons)
    except Exception:
        pass
    # Attack Chain: комбо — техники из разных стадий MITRE (общий случай)
    if len(_get_ev_tactics(ev)) >= 2 and not any("Цепочка атак:" in r for r in reasons):
        reasons.append("Цепочка атак (несколько стадий MITRE в одном файле)")
    if "T1021.003" in th_hints:
        reasons.append("Удалённый запуск через DCOM (латеральное перемещение)")
    if (ev.get("network_profile") or {}).get("sneaky_doh"):
        reasons.append("DoH/подозрительная сетевая активность без контекста браузера")
    cwe = ev.get("cwe_analysis") or {}
    if (cwe.get("findings") or []):
        reasons.append("Обнаружены CWE (архитектурные уязвимости)")
    ti = ev.get("threat_intel") or {}
    dga_count = (ti.get("dga") or {}).get("count", 0) if isinstance(ti.get("dga"), dict) else 0
    if dga_count and dga_count > 0:
        reasons.append("Обнаружены DGA-домены")
    # v3.2 OSINT & Publisher
    osint = ev.get("osint") or {}
    if isinstance(osint, dict) and osint.get("c2_detected"):
        reasons.append("IP/домен в C2-активности (внешние фиды Threat Intelligence)")
    if isinstance(osint, dict) and osint.get("suspicious_asn"):
        reasons.append("Нетипичный хостинг (VPS/офшор по Whois/ASN)")
    if isinstance(pe, dict):
        sig_obj = pe.get("signature")
        if isinstance(sig_obj, dict) and sig_obj.get("uncertain_publisher") is True:
            prof = (profile or "dev")
            if str(prof).lower() == "deep" or _has_other_static_risk(ev):
                reasons.append("Издатель не в белом списке (Publisher Reputation)")

    return reasons


def get_risk_mitre_techniques(ev: Dict[str, Any], profile: str = "dev") -> List[str]:
    """
    Возвращает список MITRE ATT&CK ID по тем же условиям, что и get_risk_reason_strings.
    Используется для заполнения ev["highlights"]["mitre_techniques"] при обнаружении
    специфических причин (например, «Попытка отключения защиты» -> T1562).
    """
    mitre: List[str] = []
    pe = ev.get("pe") or {}
    hints = (pe.get("behavior_hints") or {}) if isinstance(pe, dict) else {}
    th_hints = list((ev.get("pe") or {}).get("technique_hints") or [])
    doc_hints = list(ev.get("technique_hints") or [])
    th_hints = list(set(th_hints + doc_hints))
    emu_tech = list((ev.get("emulation") or {}).get("techniques") or [])

    if isinstance(pe, dict):
        sig = pe.get("signature")
        if isinstance(sig, dict) and sig.get("revoked") is True:
            pass  # revoked не имеет отдельного T-id в матрице
    if (isinstance(hints, dict) and hints.get("defense_disabled")) or any(
        t and ("T1562.001" in str(t) or "T1562.004" in str(t)) for t in emu_tech
    ):
        mitre.extend(["T1562", "T1562.001", "T1562.004"])
    if (isinstance(hints, dict) and hints.get("defender_disable_attempt")) or any(t and "T1112" in str(t) for t in emu_tech):
        mitre.append("T1112")
    if (isinstance(hints, dict) and hints.get("uac_bypass_attempt")) or any(t and "T1548.002" in str(t) for t in emu_tech):
        mitre.append("T1548.002")
    if (isinstance(hints, dict) and hints.get("log_clear_attempt")) or any(t and "T1070.001" in str(t) for t in emu_tech):
        mitre.append("T1070.001")
    if (isinstance(hints, dict) and hints.get("ifeo_injection")) or any(t and "T1546.012" in str(t) for t in emu_tech):
        mitre.append("T1546.012")
    if (isinstance(hints, dict) and hints.get("internal_network_scan")) or any(
        t and ("T1018" in str(t) or "T1046" in str(t)) for t in emu_tech
    ) or (ev.get("network_profile") or {}).get("internal_ip_scan_suspect"):
        mitre.extend(["T1018", "T1046"])
    if (isinstance(hints, dict) and hints.get("domain_enumeration")) or any(t and "T1087.002" in str(t) for t in emu_tech):
        mitre.append("T1087.002")
    if (isinstance(hints, dict) and hints.get("lateral_transfer_attempt")) or any(t and "T1570" in str(t) for t in emu_tech):
        mitre.append("T1570")
    dns_suspect = (ev.get("network_profile") or {}).get("dns_tunneling_suspect")
    if "T1071.004" in th_hints or dns_suspect:
        mitre.append("T1071.004")
    if "T1195.002" in th_hints:
        mitre.append("T1195.002")
    if "T1048.003" in th_hints:
        mitre.append("T1048.003")
    if "T1562.006" in th_hints:
        mitre.append("T1562.006")
    if "T1546.003" in th_hints:
        mitre.append("T1546.003")
    # T1204.001 (Malicious Link), T1102 (Web Service) — из pe или docscripts/lnk
    if "T1204.001" in th_hints:
        mitre.append("T1204.001")
    if "T1102" in th_hints:
        mitre.append("T1102")
    # T1059.001 (PowerShell), T1059.003 (CMD), T1204.002 (Malicious File) — string patterns
    for tid in ("T1059.001", "T1059.003", "T1204.002"):
        if tid in th_hints:
            mitre.append(tid)
    # v0.1.9: Credentials & Impact из technique_hints (pe_hardening string patterns)
    for tid in ("T1003.001", "T1552.001", "T1003.002", "T1489", "T1490", "T1486", "T1531", "T1499", "T1020", "T1098"):
        if tid in th_hints:
            mitre.append(tid)
    # v1.0: все остальные подтехники из th_hints (T1055.003 Thread Hijacking, T1070.006 Timestomp и т.д.)
    for t in th_hints:
        if t and isinstance(t, str) and t.startswith("T") and t[1:].replace(".", "").isdigit():
            mitre.append(t)

    return list(dict.fromkeys(mitre))  # preserve order, no duplicates


def build_risk_summary(ev: Dict[str, Any], profile: str = "dev") -> str:
    """
    Сводка по модулям для justification при любом риске > 0 (не только deny).
    Формат: «Вредоносное ПО в памяти: Да/Нет, Секреты: Да, Маскировка: Нет, Уязвимости: Нет».
    Находки в памяти выводятся первыми.
    """
    parts = []
    mda = ev.get("memory_dump_analysis") or {}
    yara_mem = mda.get("yara") if isinstance(mda, dict) else None
    skip_rules = {"yara_skipped_large_file", "yara_error", "yara_match_error", "yara_truncated"}
    has_malware_in_memory = (
        yara_mem and isinstance(yara_mem, list) and len(yara_mem) > 0
        and any(
            isinstance(h, dict) and (h.get("namespace") or "") != "errors" and (h.get("rule") or "") not in skip_rules
            for h in yara_mem
        )
    )
    parts.append("Вредоносное ПО в памяти: " + ("Да" if has_malware_in_memory else "Нет"))

    secrets = ev.get("secrets") or {}
    hits = secrets.get("hits") if isinstance(secrets, dict) else None
    has_secrets = isinstance(secrets, dict) and (
        secrets.get("suspicious")
        or (hits and (isinstance(hits, dict) and len(hits) > 0 or isinstance(hits, list) and len(hits) > 0))
    )
    parts.append("Секреты: " + ("Да" if has_secrets else "Нет"))

    vis = ev.get("visual") or {}
    icon = (vis.get("icon") or {}) if isinstance(vis.get("icon"), dict) else {}
    masq = vis.get("icon_mismatch") or vis.get("masquerading_suspect") or (
        icon.get("mismatch_type") and "executable" in str(icon.get("mismatch_type", "")).lower()
    )
    parts.append("Маскировка: " + ("Да" if masq else "Нет"))

    cwe = ev.get("cwe_analysis") or {}
    vulns = bool(cwe.get("findings"))
    parts.append("Уязвимости: " + ("Да" if vulns else "Нет"))

    return ", ".join(parts) + "."


def check_differential_risk(current_score: int, historical_score: Optional[int]) -> bool:
    """
    True если риск вырос более чем на 30 пунктов (абсолютно) ИЛИ более чем на 30% относительно предыдущей версии.
    Используется для флага CRITICAL_RISK_JUMP и требования Manual Review.
    """
    if historical_score is None or historical_score <= 0:
        return False
    abs_diff = current_score - historical_score
    return abs_diff > 30 or (abs_diff / max(historical_score, 1)) > 0.30


def is_high_entropy_obfuscated(ev: Dict[str, Any]) -> bool:
    """True если DIE или энтропия файла/секций > 7.2 → требовать manual review."""
    obf = ev.get("obfuscation") or {}
    if isinstance(obf, dict):
        max_ent = obf.get("max_section_entropy")
        if max_ent is not None and float(max_ent) > ENTROPY_MANUAL_REVIEW_THRESHOLD:
            return True
    ent = ev.get("entropy") or {}
    if isinstance(ent, dict):
        file_ent = ent.get("file")
        if file_ent is not None and float(file_ent) > ENTROPY_MANUAL_REVIEW_THRESHOLD:
            return True
    die = ev.get("die") or {}
    if isinstance(die, dict):
        die_ent = (die.get("entropy") or {}) if isinstance(die.get("entropy"), dict) else {}
        if die_ent.get("file") is not None and float(die_ent.get("file", 0)) > ENTROPY_MANUAL_REVIEW_THRESHOLD:
            return True
    return False


def build_justification_from_reasons(reasons: List[str], prefix: str = "") -> str:
    """
    Динамически собирает текст обоснования из списка причин (scoring_reasons).
    Используется для deny и для risk > 0 (warn/allow с объяснением).
    """
    if not reasons:
        return prefix.strip() if prefix else ""
    return (prefix + "; ".join(str(r) for r in reasons[:12])).strip()


def build_deny_justification(ev: Dict[str, Any], policy_result: Dict[str, Any]) -> str:
    """
    Генерирует обоснование для DENY. Уникальные формулировки по аномалиям (rootkit-like, обфускация),
    затем scoring_reasons из policy_result.
    """
    expert_phrases: List[str] = []
    yara_hits = ev.get("yara") or []
    if isinstance(yara_hits, list):
        rule_names = " ".join(str(h.get("rule") or "") for h in yara_hits if isinstance(h, dict)).lower()
        if "ldpreload" in rule_names and ("dynamic_api" in rule_names or "api_resolve" in rule_names or "dynamic_api_resolve" in rule_names):
            expert_phrases.append(
                "Выявлены признаки поведения типа Rootkit: использование LD_PRELOAD для перехвата системных функций "
                "и скрытие таблицы импортов через динамический резолв."
            )
    obf = ev.get("obfuscation") or {}
    packed = isinstance(obf, dict) and obf.get("packed_suspect") is True
    if is_high_entropy_obfuscated(ev) and packed:
        expert_phrases.append(
            "Критический уровень обфускации (Entropy > 7.2) указывает на намеренное сокрытие логики работы "
            "от средств статического анализа."
        )
    elif is_high_entropy_obfuscated(ev):
        expert_phrases.append(
            "Критическая степень обфускации затрудняет статический анализ, "
            "что характерно для упакованных вредоносных модулей."
        )
    reasons = policy_result.get("reasons") or []
    if reasons or expert_phrases:
        critical_memory = [r for r in reasons if "КРИТИЧЕСКАЯ УГРОЗА" in str(r) or "дампе памяти" in str(r)]
        rest = [r for r in reasons if r not in critical_memory]
        ordered = expert_phrases + critical_memory + rest[:15]
        return "Заблокировано: " + "; ".join(str(r) for r in ordered) + "."

    parts: List[str] = []
    pe = ev.get("pe") or {}
    sig = (pe.get("signature") or {}) if isinstance(pe, dict) else {}
    if isinstance(sig, dict) and sig.get("revoked") is True:
        parts.append("отозванный сертификат подписи (CRL/OCSP)")
    h = (pe.get("hardening") or {}) if isinstance(pe, dict) else {}
    if isinstance(h, dict) and (h.get("aslr") is False or h.get("aslr_off") is True):
        parts.append("отсутствие ASLR")
    if isinstance(h, dict) and (h.get("dep") is False or h.get("nx") is False):
        parts.append("отсутствие DEP/NX")
    if isinstance(h, dict) and (h.get("cfg") is False or h.get("guard_cf") is False):
        parts.append("отсутствие CFG")

    if is_high_entropy_obfuscated(ev):
        parts.append("высокая энтропия (обфускация)")

    ti = ev.get("threat_intel") or {}
    dga_count = (ti.get("dga") or {}).get("count", 0) if isinstance(ti.get("dga"), dict) else 0
    if dga_count and dga_count > 0:
        parts.append("обращение к DGA-доменам")

    cwe = ev.get("cwe_analysis") or {}
    if (cwe.get("findings") or []):
        parts.append("обнаружены CWE (архитектурные риски)")

    secrets = ev.get("secrets") or {}
    if isinstance(secrets, dict) and (secrets.get("suspicious") or secrets.get("hits")):
        parts.append("обнаружены секреты/учётные данные в файле")

    urlhaus = (ti.get("ti_matches") or {}).get("urlhaus") or []
    if urlhaus:
        parts.append("совпадение с URLHaus")

    # v3.2 OSINT: C2 по внешним фидам, подозрительный ASN, неизвестный издатель
    osint = ev.get("osint") or {}
    if isinstance(osint, dict):
        if osint.get("c2_detected"):
            parts.append("C2-индикатор (AbuseIPDB/фиды)")
        if osint.get("suspicious_asn"):
            parts.append("подозрительный ASN/хостинг")
    pe_sig = (ev.get("pe") or {}).get("signature") or {}
    if isinstance(pe_sig, dict) and pe_sig.get("uncertain_publisher") is True:
        if str(profile or "dev").lower() == "deep" or _has_other_static_risk(ev):
            parts.append("неизвестный издатель подписи")

    vis = ev.get("visual") or {}
    if vis.get("icon_mismatch") or vis.get("masquerading_suspect"):
        parts.append("критическое несоответствие: файл маскируется под документ, являясь исполняемым")
    elif isinstance(vis.get("icon"), dict) and (vis.get("icon") or {}).get("mismatch_type"):
        mt = str((vis.get("icon") or {}).get("mismatch_type", "")).lower()
        if "executable" in mt and ("icon" in mt or "document" in mt):
            parts.append("критическое несоответствие: файл маскируется под документ, являясь исполняемым")

    if not parts:
        return "Заблокировано по результатам анализа."

    return "Заблокировано: " + ", ".join(parts) + "."
