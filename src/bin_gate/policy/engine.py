from __future__ import annotations
from typing import Dict, Any, List, Optional
import re
import ast

# ----------------------------
# Мини-движок правил (CEL-subset, безопасная оценка)
# Поддержка:
#  - логика: && || !  → and / or / not
#  - сравнения: == != > >= < <=
#  - in / not in (для списков/кортежей)
#  - литералы: true/false/null → True/False/None
#  - обращения к данным: pe.signature.present → _get("pe.signature.present")
#  - доступные верхнеуровневые переменные: pe, elf, vt, kes, hashes, meta, yara_families, capa_tactics, cve
# ----------------------------

# v0.0.8: Added emulation, threat_intel, visual, script for advanced malware detection
_ALLOWED_VARS = {
    "pe", "elf", "vt", "kes", "hashes", "meta", "yara_families", "capa_tactics", "cve",
    "reputation", "obfuscation", "obf",
    # v0.0.8 Advanced Malware Detection
    "emulation", "threat_intel", "ti", "visual", "script", "supply_chain",
}


def _get_path(ctx: Dict[str, Any], dotted: str) -> Any:
    """Безопасно забираем путь вида 'a.b.c' из словаря контекста."""
    cur: Any = ctx
    for part in dotted.split("."):
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(part, None)
        else:
            # дальше углубляться нельзя
            return None
    return cur

_GET_NAME = "_get"

# Разрешаем минимальный набор AST-узлов
_SAFE_NODES = (
    ast.Expression, ast.BoolOp, ast.UnaryOp, ast.BinOp, ast.Compare,
    ast.Name, ast.Call, ast.Load, ast.Constant, ast.List, ast.Tuple,
    ast.And, ast.Or, ast.Not, ast.Eq, ast.NotEq, ast.Gt, ast.GtE, ast.Lt, ast.LtE,
    ast.In, ast.NotIn
)

# Находим обращение к поддерживаемым переменным + цепочки .attr и заменяем на _get("...").
# Пример:  pe.signature.present  →  _get("pe.signature.present")
# v0.0.8: Added emulation, threat_intel, ti, visual, script, supply_chain
_VAR_PATTERN = re.compile(
    r"""
    (?<!["'])
    \b
    (?P<var>pe|elf|vt|kes|hashes|meta|yara_families|capa_tactics|
             cve|reputation|obfuscation|obf|
             emulation|threat_intel|ti|visual|script|supply_chain)
    (?:\.[A-Za-z_][A-Za-z0-9_]*)*
    \b
    """,
    re.VERBOSE
)

def _to_py(expr: str) -> str:
    """Конвертирует правило в безопасное подмножество Python-выражений."""
    s = expr

    # Логические операторы
    s = s.replace("&&", " and ")
    s = s.replace("||", " or ")
    # "!" → "not " (НО не для "!=")
    s = re.sub(r"(?<![=!])!(?!=)", " not ", s)

    # Литералы
    s = re.sub(r"\btrue\b", "True", s, flags=re.IGNORECASE)
    s = re.sub(r"\bfalse\b", "False", s, flags=re.IGNORECASE)
    s = re.sub(r"\bnull\b", "None", s, flags=re.IGNORECASE)

    # Доступ к данным → _get("a.b.c")
    def repl(m: re.Match) -> str:
        token = m.group(0)
        return f'{_GET_NAME}("{token}")'

    s = _VAR_PATTERN.sub(repl, s)
    return s

class _SafeEval(ast.NodeVisitor):
    def visit(self, node):  # type: ignore
        if not isinstance(node, _SAFE_NODES):
            raise ValueError(f"policy_unsafe_node:{type(node).__name__}")
        return super().visit(node)

def _eval_expr(expr: str, ctx: Dict[str, Any]) -> bool:
    py = _to_py(expr)
    tree = ast.parse(py, mode="eval")
    _SafeEval().visit(tree)
    code = compile(tree, "<policy>", "eval")
    return bool(eval(code, {_GET_NAME: lambda p: _get_path(ctx, p)}, {}))

# ----------------------------
# Публичный API
# ----------------------------

def _derive_ctx(ev: Dict[str, Any]) -> Dict[str, Any]:
    """Готовим контекст для правил из evidence-объекта."""
    ctx: Dict[str, Any] = {}

    # Базовые разделы (словари либо None)
    for k in ("pe", "elf", "vt", "kes", "hashes", "meta", "cve", "reputation", "die"):
        v = ev.get(k)
        ctx[k] = v if isinstance(v, dict) else None

    # YARA families → список строк
    families: List[str] = []
    for hit in ev.get("yara") or []:
        meta = hit.get("meta") or {}
        fam = meta.get("family") or meta.get("group")
        if fam:
            families.append(str(fam).lower())
    ctx["yara_families"] = families

    # capa tactics → список строк
    tacts: List[str] = []
    cap = ev.get("capa") or {}
    if isinstance(cap.get("techniques"), list):
        tacts = [str(x).lower() for x in cap["techniques"]]
    ctx["capa_tactics"] = tacts

    # obfuscation (defaults if missing)
    ctx["obf"] = ev.get("obfuscation") if isinstance(ev.get("obfuscation"), dict) else None
    obf = ev.get("obfuscation")
    if isinstance(obf, dict):
        ctx["obfuscation"] = {
            "reasons": list((obf.get("reasons") or [])),
            "score": int(obf.get("score") or 0),
            "has_dyn_api_resolve": bool(obf.get("has_dyn_api_resolve") or False),
            "packer_families": [str(x).lower() for x in (obf.get("packer_families") or [])],
        }
    else:
        ctx["obfuscation"] = {"reasons": [], "score": 0, "has_dyn_api_resolve": False, "packer_families": []}

    # --- v0.0.8 Advanced Malware Detection ---
    
    # Emulation results (подтехники и techniques — безопасный пустой список при отсутствии)
    emu = ev.get("emulation")
    if isinstance(emu, dict):
        _emu_tech = emu.get("techniques")
        techniques_list = list(_emu_tech) if isinstance(_emu_tech, list) else []
        ctx["emulation"] = {
            "enabled": bool(emu.get("enabled")),
            "success": bool(emu.get("success")),
            "api_calls": list(emu.get("api_calls") or []),
            "api_count": len(emu.get("api_calls") or []),
            "api_summary": emu.get("api_summary") if isinstance(emu.get("api_summary"), dict) else {},
            "mutexes": list(emu.get("mutexes") or []),
            "mutex_count": len(emu.get("mutexes") or []),
            "techniques": techniques_list,
            "files_created": len(emu.get("files", {}).get("created", [])),
            "files_written": len(emu.get("files", {}).get("written", [])),
            "registry_ops": len(emu.get("registry", [])),
            "network_ops": len(emu.get("network", [])),
            "shellcode_detected": bool(emu.get("shellcode", {}).get("detected")),
        }
    else:
        ctx["emulation"] = {
            "enabled": False, "success": False, "api_calls": [], "api_count": 0,
            "api_summary": {}, "mutexes": [], "mutex_count": 0, "techniques": [],
            "files_created": 0, "files_written": 0, "registry_ops": 0, "network_ops": 0,
            "shellcode_detected": False,
        }
    
    # Threat Intelligence results
    ti = ev.get("threat_intel")
    if isinstance(ti, dict):
        ctx["threat_intel"] = {
            "enabled": bool(ti.get("enabled")),
            "risk_level": ti.get("risk_level", "low"),
            "dga_count": ti.get("dga", {}).get("count", 0),
            "dga_score": ti.get("dga", {}).get("score", 0.0),
            "urlhaus_count": len(ti.get("ti_matches", {}).get("urlhaus", [])),
            "abusech_count": len(ti.get("ti_matches", {}).get("abusech", [])),
            "domains_count": len(ti.get("iocs", {}).get("domains", [])),
            "ips_count": len(ti.get("iocs", {}).get("ips", [])),
            "urls_count": len(ti.get("iocs", {}).get("urls", [])),
            "findings": ti.get("findings", []),
        }
        ctx["ti"] = ctx["threat_intel"]  # Alias
    else:
        ctx["threat_intel"] = {
            "enabled": False, "risk_level": "low", "dga_count": 0, "dga_score": 0.0,
            "urlhaus_count": 0, "abusech_count": 0, "domains_count": 0, "ips_count": 0,
            "urls_count": 0, "findings": [],
        }
        ctx["ti"] = ctx["threat_intel"]
    
    # Visual analysis (PE icon, resource entropy). Устойчиво к None для LNK/скриптов (нет PE-метаданных).
    vis = ev.get("visual")
    if isinstance(vis, dict):
        icon = vis.get("icon") if isinstance(vis.get("icon"), dict) else {}
        res_ent = vis.get("resource_entropy") if isinstance(vis.get("resource_entropy"), dict) else {}
        ctx["visual"] = {
            "icon_present": bool(icon.get("present") if icon is not None else False),
            "icon_mismatch": bool(icon.get("mismatch_detected") if icon else False),
            "icon_mismatch_type": icon.get("mismatch_type") if icon else None,
            "resource_suspicious": bool(res_ent.get("suspicious") if res_ent else False),
            "max_resource_entropy": float(res_ent.get("max_resource_entropy", 0.0) or 0.0) if res_ent else 0.0,
        }
    else:
        ctx["visual"] = {
            "icon_present": False, "icon_mismatch": False, "icon_mismatch_type": None,
            "resource_suspicious": False, "max_resource_entropy": 0.0,
        }
    # Script/Office analysis
    scr = ev.get("script_analysis")
    if isinstance(scr, dict):
        vba = scr.get("vba") or {}
        lnk = scr.get("lnk") or {}
        pdf = scr.get("pdf") or {}
        obf = scr.get("obfuscation") or {}
        ctx["script"] = {
            "type": scr.get("type"),
            "risk_score": scr.get("risk_score", 0),
            "stagers": scr.get("stagers", []),
            "stager_count": len(scr.get("stagers", [])),
            "decoded_payloads": len(scr.get("decoded_payloads", [])),
            # VBA specific
            "vba_has_macros": bool(vba.get("has_macros")),
            "vba_auto_exec": bool(vba.get("auto_exec")),
            "vba_suspicious": bool(vba.get("suspicious")),
            "vba_obfuscation_score": vba.get("obfuscation_score", 0),
            # LNK specific
            "lnk_valid": bool(lnk.get("valid")),
            "lnk_payloads": len(lnk.get("payloads", [])),
            "lnk_suspicious_patterns": len(lnk.get("suspicious_patterns", [])),
            # PDF specific
            "pdf_has_javascript": bool(pdf.get("has_javascript")),
            "pdf_auto_actions": len(pdf.get("auto_actions", [])),
            # Obfuscation
            "obfuscation_score": obf.get("score", 0),
            "obfuscation_techniques": obf.get("techniques", []),
        }
    else:
        ctx["script"] = {
            "type": None, "risk_score": 0, "stagers": [], "stager_count": 0, "decoded_payloads": 0,
            "vba_has_macros": False, "vba_auto_exec": False, "vba_suspicious": False, "vba_obfuscation_score": 0,
            "lnk_valid": False, "lnk_payloads": 0, "lnk_suspicious_patterns": 0,
            "pdf_has_javascript": False, "pdf_auto_actions": 0,
            "obfuscation_score": 0, "obfuscation_techniques": [],
        }
    
    # Supply chain (from v0.0.7; dependencies = URLs/external refs from LNK/Office/PDF)
    sc = ev.get("supply_chain")
    if isinstance(sc, dict):
        ctx["supply_chain"] = {
            "outdated_count": len(sc.get("outdated_libraries", [])),
            "risk_level": sc.get("risk_level"),
            "policy_reasons": sc.get("policy_reasons", []),
            "dependencies": sc.get("dependencies", []),
        }
    else:
        ctx["supply_chain"] = {"outdated_count": 0, "risk_level": None, "policy_reasons": [], "dependencies": []}

    return ctx

def _pick_profile(policy: Dict[str, Any], profile: str) -> Dict[str, Any]:
    """Собираем эффективную политику: thresholds берём из profiles[profile] либо из policy.thresholds; rules — верхнего уровня."""
    profs = (policy.get("profiles") or {})
    prof = (profs.get(profile) or {})
    thresholds = (prof.get("thresholds") or policy.get("thresholds") or {})
    rules = policy.get("rules") or []
    if not isinstance(rules, list):
        rules = []
    return {
        "thresholds": {
            "deny": int(thresholds.get("deny", 80)),
            "warn": int(thresholds.get("warn", 40)),
        },
        "rules": rules,
    }

# Critical errors that indicate incomplete analysis (false sense of security)
# If these errors are present, the decision should be at least "warn"
CRITICAL_ERROR_PATTERNS = (
    "die_error",           # DIE packer detection failed
    "cve_error",           # CVE scanning failed
    "cve_batch_error",     # Batch CVE scanning failed
    "vt_error",            # VirusTotal API error
    "vt_no_api_key",       # VT API key not configured
    "emulation_error",     # Speakeasy emulation failed
    "ti_error",            # Threat Intelligence failed
    "docker_error",        # Docker container failed
    "syft_error",          # Syft SBOM generation failed
    "grype_error",         # Grype vulnerability scan failed
)

def _check_critical_errors(ev: Dict[str, Any]) -> List[str]:
    """
    Check for critical analysis errors that indicate incomplete analysis.
    Returns list of found critical errors.
    """
    errors = ev.get("errors") or []
    if not isinstance(errors, list):
        errors = [str(errors)] if errors else []
    
    found_critical: List[str] = []
    for err in errors:
        err_str = str(err).lower()
        for pattern in CRITICAL_ERROR_PATTERNS:
            if pattern.lower() in err_str:
                found_critical.append(str(err))
                break
    
    return found_critical


def get_evidence_identity(ev: Dict[str, Any]) -> Optional[str]:
    """Identity для дифференциального скоринга: InternalName или OriginalFilename (тот же продукт, другая версия/хеш)."""
    pe = ev.get("pe") or {}
    if not isinstance(pe, dict):
        return None
    res = pe.get("resources") or {}
    ver = res.get("version") if isinstance(res, dict) else {}
    if isinstance(ver, dict):
        for key in ("InternalName", "OriginalFilename", "ProductName"):
            val = ver.get(key)
            if val and isinstance(val, str) and val.strip():
                return val.strip()
    return None


def evaluate_policy(
    ev: Dict[str, Any],
    policy: Dict[str, Any],
    profile: str = "dev",
    historical_risk_score: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Возвращает:
      {
        decision: 'allow'|'warn'|'deny',
        score: int,
        reasons: [str],    # "[rule-id] текст"
        matched: [rule-id],
        critical_errors: [str]  # v0.0.8: list of critical analysis errors
      }
    """
    eff = _pick_profile(policy, profile)
    ctx = _derive_ctx(ev)

    total_score = 0
    matched_ids: List[str] = []
    reasons: List[str] = []
    hard_effect = None  # 'deny', если сработало правило с then: deny

    for rule in eff["rules"]:
        rid = str(rule.get("id") or "")
        when = str(rule.get("when") or "").strip()
        if not when:
            continue
        try:
            cond = _eval_expr(when, ctx)
        except Exception as e:
            # Не валидное/небезопасное выражение — пишем ошибку, правило игнорируем
            reasons.append(f"[{rid}] policy_eval_error:{e}")
            continue
        if not cond:
            continue

        matched_ids.append(rid)
        effect = (rule.get("then") or rule.get("effect") or "score").lower()
        score = int(rule.get("score", 0))
        reason = str(rule.get("reason") or rid)

        if effect in ("deny", "block"):
            hard_effect = "deny"
            if score <= 0:
                score = 100  # жёсткий эффект
        elif effect in ("warn", "alert"):
            if score <= 0:
                score = 40

        total_score += max(0, score)
        reasons.append(f"[{rid}] {reason}")

    thr = eff["thresholds"]
    decision = "allow"
    if hard_effect == "deny" or total_score >= int(thr["deny"]):
        decision = "deny"
    elif total_score >= int(thr["warn"]):
        decision = "warn"

    # v0.0.8: Check for critical analysis errors
    # A "clean" report due to missing data is a false sense of security
    critical_errors = _check_critical_errors(ev)
    if critical_errors and decision == "allow":
        decision = "warn"
        for err in critical_errors:
            reasons.append(f"[incomplete-analysis] Critical error: {err}")
        # Add score penalty for incomplete analysis
        total_score += 30

    # Policy lockdown: if DIE or CVE scanners failed, decision MUST be at least WARN
    evidence_errors = ev.get("errors") or []
    if not isinstance(evidence_errors, list):
        evidence_errors = [str(evidence_errors)] if evidence_errors else []
    scanner_failures = [e for e in evidence_errors if isinstance(e, str) and (e.strip().startswith("die_") or e.strip().startswith("cve_"))]
    if scanner_failures and decision == "allow":
        decision = "warn"
        for err in scanner_failures[:5]:
            reasons.append(f"[scanner-failure] {err}")
        total_score += 40

    # VMProtect lockdown: Protector: VMProtect -> DENY (prod) or WARN (dev)
    # Especially strict when combined with high VirusTotal detections
    vmprotect_detected = False
    die_data = ev.get("die")
    if isinstance(die_data, dict):
        detects = die_data.get("detects") or []
        for d in detects:
            if isinstance(d, str) and "vmprotect" in d.lower():
                vmprotect_detected = True
                break
    if not vmprotect_detected:
        packers = (ctx.get("obfuscation") or {}).get("packer_families") or []
        vmprotect_detected = any("vmprotect" in str(p).lower() for p in packers)
    vt_malicious = 0
    vt_data = ev.get("vt")
    if isinstance(vt_data, dict):
        stats = vt_data.get("last_analysis_stats") or vt_data.get("stats") or {}
        vt_malicious = int(stats.get("malicious") or stats.get("malicious_count") or 0)
    high_vt = vt_malicious >= 5  # Configurable threshold
    if vmprotect_detected:
        if profile == "prod":
            decision = "deny"
            reasons.append("[vmprotect] Protector: VMProtect detected — DENY (prod)")
            if high_vt:
                reasons.append("[vmprotect] High VirusTotal detections — reinforced DENY")
            total_score = max(total_score, 100)
        elif profile == "dev" and decision == "allow":
            decision = "warn"
            reasons.append("[vmprotect] Protector: VMProtect detected — WARN (dev)")
            total_score += 50

    # Risk-based scoring (0–100): Hardening +10, CWE +30, DGA +50, No signature +20/+50 (PROD), High entropy +25
    risk_score = 0
    critical_risk_jump = False
    try:
        from ..scoring import (
            compute_risk_score,
            build_deny_justification,
            build_risk_summary,
            get_risk_reason_strings,
            get_risk_mitre_techniques,
            get_mitre_from_reasons,
            is_high_entropy_obfuscated,
            check_differential_risk,
            RISK_REVOKED_CERTIFICATE,
        )
        risk_score = compute_risk_score(ev, profile=profile)
        reasons.extend(get_risk_reason_strings(ev, profile))
        # MITRE ID: из evidence (get_risk_mitre_techniques) + из scoring_reasons (REASON_TO_MITRE_MAP)
        mitre_ids = list(dict.fromkeys(
            get_risk_mitre_techniques(ev, profile) + get_mitre_from_reasons(reasons)
        ))
        if mitre_ids:
            highlights = ev.get("highlights")
            if not isinstance(highlights, dict):
                ev["highlights"] = {}
                highlights = ev["highlights"]
            existing = list(highlights.get("mitre_techniques") or [])
            highlights["mitre_techniques"] = list(dict.fromkeys(existing + mitre_ids))
        total_score = max(total_score, risk_score)
        # RISK_REVOKED_CERTIFICATE (100) принудительно deny во всех профилях
        if risk_score >= RISK_REVOKED_CERTIFICATE:
            decision = "deny"
        elif hard_effect == "deny" or total_score >= int(thr["deny"]):
            decision = "deny"
        elif total_score >= int(thr["warn"]):
            decision = "warn"
        if historical_risk_score is not None and check_differential_risk(risk_score, historical_risk_score):
            critical_risk_jump = True
            reasons.append("[differential] Резкий рост риска относительно предыдущей версии — требуется Manual Review")
            if decision == "allow":
                decision = "warn"
                total_score = max(total_score, 60)
        if is_high_entropy_obfuscated(ev) and decision == "allow":
            decision = "warn"
            reasons.append("[entropy] High Risk: Obfuscated (entropy > 7.2) — требуется ручная проверка (manual review)")
            total_score = max(total_score, 50)
    except Exception:
        pass

    result = {
        "decision": decision,
        "score": int(total_score),
        "reasons": reasons,
        "matched": matched_ids,
        "critical_errors": critical_errors,
        "risk_score": risk_score,
        "critical_risk_jump": critical_risk_jump,
    }
    # Justification: все scoring_reasons должны попадать в итоговую строку, не затираясь
    if risk_score > 0:
        try:
            from ..scoring import build_risk_summary
            summary = build_risk_summary(ev, profile)
            reasons_str = "; ".join(str(r) for r in reasons[:15]) if reasons else ""
            result["justification"] = summary + (" Причины: " + reasons_str if reasons_str else "")
            # При вердикте ALLOW/WARN обоснование не должно начинаться с «Заблокировано:»
            if result["decision"] != "deny" and (result.get("justification") or "").strip().startswith("Заблокировано:"):
                rest = (result["justification"] or "").replace("Заблокировано:", "", 1).strip()
                result["justification"] = "Риск: " + (rest if rest else str(risk_score))
        except Exception:
            result["justification"] = f"Риск: {risk_score}. Проверьте reasons."
    if result["decision"] == "deny":
        try:
            from ..scoring import build_deny_justification
            deny_just = build_deny_justification(ev, result)
            if deny_just:
                result["justification"] = deny_just
            elif reasons:
                result["justification"] = "Заблокировано: " + "; ".join(str(r) for r in reasons[:15]) + "."
        except Exception:
            result["justification"] = "Заблокировано по результатам анализа."
    return result
