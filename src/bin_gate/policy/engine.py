from __future__ import annotations
from typing import Dict, Any, List
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
    for k in ("pe", "elf", "vt", "kes", "hashes", "meta", "cve", "reputation"):
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
        }
    else:
        ctx["obfuscation"] = {"reasons": [], "score": 0, "has_dyn_api_resolve": False}

    # --- v0.0.8 Advanced Malware Detection ---
    
    # Emulation results
    emu = ev.get("emulation")
    if isinstance(emu, dict):
        ctx["emulation"] = {
            "enabled": bool(emu.get("enabled")),
            "success": bool(emu.get("success")),
            "api_calls": emu.get("api_calls", []),
            "api_count": len(emu.get("api_calls", [])),
            "api_summary": emu.get("api_summary", {}),
            "mutexes": emu.get("mutexes", []),
            "mutex_count": len(emu.get("mutexes", [])),
            "techniques": emu.get("techniques", []),
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
    
    # Visual analysis (PE icon, resource entropy)
    vis = ev.get("visual")
    if isinstance(vis, dict):
        icon = vis.get("icon", {})
        res_ent = vis.get("resource_entropy", {})
        ctx["visual"] = {
            "icon_present": bool(icon.get("present")),
            "icon_mismatch": bool(icon.get("mismatch_detected")),
            "icon_mismatch_type": icon.get("mismatch_type"),
            "resource_suspicious": bool(res_ent.get("suspicious")),
            "max_resource_entropy": res_ent.get("max_resource_entropy", 0.0),
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
    
    # Supply chain (from v0.0.7)
    sc = ev.get("supply_chain")
    if isinstance(sc, dict):
        ctx["supply_chain"] = {
            "outdated_count": len(sc.get("outdated_libraries", [])),
            "risk_level": sc.get("risk_level"),
            "policy_reasons": sc.get("policy_reasons", []),
        }
    else:
        ctx["supply_chain"] = {"outdated_count": 0, "risk_level": None, "policy_reasons": []}

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

def evaluate_policy(ev: Dict[str, Any], policy: Dict[str, Any], profile: str = "dev") -> Dict[str, Any]:
    """
    Возвращает:
      {
        decision: 'allow'|'warn'|'deny',
        score: int,
        reasons: [str],    # "[rule-id] текст"
        matched: [rule-id]
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

    return {
        "decision": decision,
        "score": int(total_score),
        "reasons": reasons,
        "matched": matched_ids,
    }
