# language_analyzer.py — определение языка/компилятора из DIE и YARA для скоринга и метаданных
# Результат записывается в ev["meta"]["language"]; экзотические языки (Nim, AutoIt) дают штраф в scoring.

from __future__ import annotations
from typing import Dict, Any, List, Optional

# Языки, считающиеся «экзотическими» для Enterprise (часто дропперы / нетипичный стек)
EXOTIC_LANGUAGES = frozenset({"nim", "autoit", "autohotkey", "zig"})

# Маппинг DIE compiler/packer names и YARA rule names → язык (v1.2 расширенный стек)
DIE_TO_LANGUAGE = {
    "rust": "Rust",
    "rustc": "Rust",
    "go": "Go",
    "golang": "Go",
    "python": "Python",
    "pyinstaller": "PyInstaller",
    "py2exe": "PyInstaller",
    "nuitka": "Nuitka",
    "nim": "Nim",
    "nimble": "Nim",
    "autoit": "AutoIt",
    "autohotkey": "AutoIt",
    "delphi": "Delphi",
    "borland": "Delphi",
    "freepascal": "FreePascal",
    "pascal": "Delphi",
    "zig": "Zig",
    "electron": "Electron",
    "node": "Electron",
    "msvc": "C/C++",
    "visual c": "C/C++",
    "gcc": "C/C++",
    "mingw": "C/C++",
    "clang": "C/C++",
    "dotnet": "C#/.NET",
    ".net": "C#/.NET",
    "c#": "C#/.NET",
    "confuserex": "C#/.NET",
}

YARA_RULE_TO_LANGUAGE = {
    "rust": "Rust",
    "go_": "Go",
    "golang": "Go",
    "pyinstaller": "PyInstaller",
    "py2exe": "PyInstaller",
    "python_pkg": "Python",
    "nuitka": "Nuitka",
    "nim": "Nim",
    "autoit": "AutoIt",
    "autohotkey": "AutoIt",
    "delphi": "Delphi",
    "freepascal": "FreePascal",
    "zig": "Zig",
    "electron": "Electron",
    "asar": "Electron",
    "node_": "Electron",
    "dotnet": "C#/.NET",
    "confuserex": "C#/.NET",
}


def _normalize(s: str) -> str:
    return (s or "").strip().lower()


def _match_die_to_language(name: str, detect_type: str) -> Optional[str]:
    name_lower = _normalize(name)
    if not name_lower:
        return None
    for key, lang in DIE_TO_LANGUAGE.items():
        if key in name_lower:
            return lang
    if _normalize(detect_type) == "compiler" and name_lower:
        return name.strip()  # fallback: raw compiler name
    return None


def _match_yara_to_language(rule_name: str, namespace: str) -> Optional[str]:
    r = _normalize(rule_name)
    ns = _normalize(namespace)
    for key, lang in YARA_RULE_TO_LANGUAGE.items():
        if key in r or key in ns:
            return lang
    if "rust" in r or "rust" in ns:
        return "Rust"
    if "go" in r or "golang" in ns:
        return "Go"
    if "pyinstaller" in r or "pyi" in r or "mei" in ns:
        return "PyInstaller"
    if "python" in r or "py_" in r:
        return "Python"
    if "zig" in r or "zig" in ns:
        return "Zig"
    if "electron" in r or "asar" in r or "node" in ns:
        return "Electron"
    if "delphi" in r or "borland" in r or "vcl" in r or "freepascal" in r:
        return "Delphi"
    if "confuserex" in r or "dotnet" in r:
        return "C#/.NET"
    return None


def infer_language(
    die_info: Optional[Dict[str, Any]] = None,
    yara_hits: Optional[List[Dict[str, Any]]] = None,
) -> Optional[str]:
    """
    Определяет язык/компилятор по DIE и YARA. Возвращает одно значение (приоритет: DIE compiler, затем YARA, затем DIE detects).
    """
    candidates: List[str] = []

    if die_info and isinstance(die_info, dict):
        compiler = die_info.get("compiler")
        if compiler and isinstance(compiler, str):
            candidates.append(compiler.strip())
        for d in die_info.get("detects") or []:
            if not isinstance(d, dict):
                continue
            dtype = d.get("type") or d.get("sType") or ""
            name = d.get("name") or d.get("sName") or ""
            if not name:
                continue
            lang = _match_die_to_language(name, dtype)
            if lang and lang not in candidates:
                candidates.append(lang)

    if yara_hits:
        for h in yara_hits:
            if not isinstance(h, dict):
                continue
            rule_name = h.get("rule") or ""
            namespace = h.get("namespace") or ""
            lang = _match_yara_to_language(rule_name, namespace)
            if lang and lang not in candidates:
                candidates.append(lang)

    # Приоритет: первый определённый (DIE compiler > DIE detects > YARA)
    return candidates[0] if candidates else None


def is_exotic_language(language: Optional[str]) -> bool:
    """True если язык в списке экзотических (Nim, AutoIt и т.д.) для штрафа в скоринге."""
    if not language or not isinstance(language, str):
        return False
    n = _normalize(language)
    return n in EXOTIC_LANGUAGES or any(
        n.startswith(ex) for ex in ("nim", "autoit", "autohotkey", "zig")
    )
