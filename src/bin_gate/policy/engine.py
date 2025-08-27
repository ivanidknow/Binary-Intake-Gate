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

_ALLOWED_VARS = {"pe", "elf", "vt", "kes", "hashes", "meta", "yara_families", "capa_tactics", "cve"}

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
_VAR_PATTERN = re.compile(
    r"""
    (?<!["'])                # грубо: не внутри кавычек
    \b
    (?P<var>pe|elf|vt|kes|hashes|meta|yara_families|capa_tactics|cve)
    (?:\.[A-Za-z_][A-Za-z0-9_]*)*
    \b
    """,
    re.VERBOSE,
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
    for k in ("pe", "elf", "vt", "kes", "hashes", "meta", "cve"):
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
