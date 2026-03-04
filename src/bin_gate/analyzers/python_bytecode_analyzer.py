# v3.0/v3.1: Deep Script Analysis — Python bytecode decompilation and dangerous-call detection
"""
Извлечение AST из .pyc через декомпилятор (uncompyle6/decompyle3).
Поиск опасных вызовов: eval, exec, os.system, subprocess с подозрительными аргументами.
v3.1: динамическая сборка кода (eval(base64.decode(...))) — T1027, декодирование первого слоя обфускации.
"""
from __future__ import annotations
import ast
import base64
import io
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Опасные имена для AST-поиска
DANGEROUS_BUILTINS = frozenset({"eval", "exec", "compile", "__import__"})
DANGEROUS_ATTR = frozenset({
    "system", "popen", "popen2", "popen3", "popen4",  # os / posix
    "call", "run", "Popen", "check_call", "check_output",  # subprocess
    "execfile",  # py2
})
SUSPICIOUS_ARG_PATTERNS = ("decode", "base64", "xor", "request", "input(", "getattr(", "format(")


def _decompile_pyc(path: Path, data: Optional[bytes] = None) -> Optional[str]:
    """Попытка декомпиляции .pyc через uncompyle6 или decompyle3. Возвращает исходный код или None."""
    raw = data
    if raw is None and path.exists():
        try:
            raw = path.read_bytes()
        except Exception:
            return None
    if not raw:
        return None
    # uncompyle6: decompile_file(version, filename, out)
    try:
        import uncompyle6.main
        out = io.StringIO()
        if data is not None:
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".pyc", delete=False) as f:
                f.write(raw)
                tmp_path = f.name
            try:
                uncompyle6.main.decompile_file(3.8, tmp_path, out)
                return out.getvalue()
            finally:
                import os
                os.unlink(tmp_path)
        else:
            uncompyle6.main.decompile_file(3.8, str(path), out)
            return out.getvalue()
    except Exception:
        pass
    try:
        import decompyle3
        out = io.StringIO()
        if data is not None:
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".pyc", delete=False) as f:
                f.write(raw)
                tmp_path = f.name
            try:
                decompyle3.decompile_file(tmp_path, out)
                return out.getvalue()
            finally:
                import os
                os.unlink(tmp_path)
        else:
            decompyle3.decompile_file(str(path), out)
            return out.getvalue()
    except Exception:
        pass
    return None


def _ast_find_dangerous_calls(tree: ast.AST) -> List[Dict[str, Any]]:
    """Обходит AST и собирает вызовы eval/exec/os.system/subprocess с контекстом аргументов."""
    findings: List[Dict[str, Any]] = []

    def _arg_snippet(node: ast.AST) -> str:
        try:
            if isinstance(node, ast.Constant):
                return repr(node.value)[:80]
            if isinstance(node, ast.Name):
                return node.id
            if isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Name):
                    return f.id + "(...)"
                if isinstance(f, ast.Attribute):
                    return (ast.unparse(f) if hasattr(ast, "unparse") else f.attr) + "(...)"
            if hasattr(ast, "unparse"):
                return ast.unparse(node)[:80]
        except Exception:
            pass
        return "<expr>"

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            name = None
            is_dangerous = False
            if isinstance(node.func, ast.Name):
                if node.func.id in DANGEROUS_BUILTINS:
                    name = node.func.id
                    is_dangerous = True
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr in DANGEROUS_ATTR:
                    name = getattr(node.func.value, "id", "") + "." + node.func.attr
                    is_dangerous = True
            if is_dangerous and name:
                args_snippets = [_arg_snippet(a) for a in node.args]
                suspicious = any(
                    p in " ".join(args_snippets).lower() for p in SUSPICIOUS_ARG_PATTERNS
                )
                findings.append({
                    "name": name,
                    "line": getattr(node, "lineno", None),
                    "arg_snippet": " ".join(args_snippets)[:200],
                    "suspicious_args": suspicious,
                })
            self.generic_visit(node)

    try:
        Visitor().visit(tree)
    except Exception:
        pass
    return findings


def _ast_find_dynamic_assembly(tree: ast.AST) -> List[Dict[str, Any]]:
    """
    Детекция динамической сборки кода: eval(base64.b64decode(...)), exec("".join(...)).
    Помечает как технику T1027; при возможности декодирует первый слой (base64).
    """
    findings: List[Dict[str, Any]] = []

    def _decode_first_layer(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute):
                if getattr(f.value, "id", "") == "base64" and f.attr in ("b64decode", "decode"):
                    for a in node.args:
                        if isinstance(a, ast.Constant) and isinstance(a.value, (str, bytes)):
                            try:
                                if isinstance(a.value, str):
                                    return base64.b64decode(a.value, validate=False).decode("utf-8", errors="replace")[:500]
                                return base64.b64decode(a.value).decode("utf-8", errors="replace")[:500]
                            except Exception:
                                pass
        return None

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Name):
                if node.func.id in ("eval", "exec", "compile"):
                    for a in node.args:
                        decoded = _decode_first_layer(a)
                        if decoded is not None or (isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) and "decode" in getattr(a.func, "attr", "")):
                            findings.append({
                                "technique": "T1027",
                                "dynamic_assembly": True,
                                "line": getattr(node, "lineno", None),
                                "decoded_first_layer": decoded,
                            })
                            break
            self.generic_visit(node)

    try:
        Visitor().visit(tree)
    except Exception:
        pass
    return findings


def analyze_python_bytecode(path: Path, data: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Анализ .pyc: декомпиляция → AST → поиск eval/exec/os.system/subprocess с подозрительными аргументами.
    Возвращает dict для evidence: script_eval_detected, python_bytecode.dangerous_calls, decompiled_ok.
    """
    out: Dict[str, Any] = {
        "decompiled_ok": False,
        "script_eval_detected": False,
        "dangerous_calls": [],
        "dynamic_assembly_detected": False,
        "dynamic_assembly_findings": [],
        "technique_hints": [],
        "error": None,
    }
    source = _decompile_pyc(path, data)
    if not source:
        out["error"] = "decompile_failed"
        return out
    out["decompiled_ok"] = True
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        out["error"] = f"ast_parse:{e}"
        return out
    dangerous = _ast_find_dangerous_calls(tree)
    out["dangerous_calls"] = dangerous
    out["script_eval_detected"] = any(
        c.get("name") in ("eval", "exec") or c.get("suspicious_args") for c in dangerous
    )
    # v3.1: динамическая сборка кода (eval(base64.decode(...))) — T1027
    dyn = _ast_find_dynamic_assembly(tree)
    out["dynamic_assembly_findings"] = dyn
    if dyn:
        out["dynamic_assembly_detected"] = True
        out["technique_hints"] = list(set(out.get("technique_hints", []) + ["T1027"]))
    return out
