from __future__ import annotations
from pathlib import Path
import json, re
from typing import Dict, Any, List

def _slurp(p: Path) -> str:
    b = p.read_bytes()
    for enc in ("utf-8","utf-16le","cp1251","latin-1"):
        try: return b.decode(enc, errors="ignore")
        except Exception: continue
    return b.decode("latin-1", errors="ignore")

def _json(p: Path):
    try: return json.loads(_slurp(p))
    except Exception: return {}

def _kv_lines(txt: str) -> List[tuple[str,str]]:
    out = []
    for ln in txt.splitlines():
        m = re.match(r'^\s*([A-Za-z0-9_\-\.\/]+)\s*([=:= ]+)\s*([^\s#;]+)', ln)
        if m:
            out.append((m.group(1), m.group(3)))
    return out

def analyze(p: Path) -> Dict[str, Any] | None:
    name = p.name.lower()
    txt  = _slurp(p)

    # Python
    if name == "requirements.txt":
        deps = []
        for ln in txt.splitlines():
            m = re.match(r'^\s*([A-Za-z0-9_\-\.]+)\s*([=><!~]=+)\s*([A-Za-z0-9_\-\.]+)', ln)
            if m:
                deps.append({"name": m.group(1), "version": m.group(3)})
        return {"ecosystem": "PyPI", "deps": deps}

    if name in ("pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml"):
        # легкая эвристика: вытащим пары name/version
        deps = []
        for k,v in _kv_lines(txt):
            if k.lower().startswith(("name","version")): continue
            m = re.match(r'^([A-Za-z0-9_\-\.]+)(?:==|=|:)?([A-Za-z0-9_\-\.]+)?$', v)
            if m and m.group(1):
                deps.append({"name": k, "version": m.group(1)})
        return {"ecosystem": "PyPI", "deps": deps}

    # Node
    if name == "package.json":
        j = _json(p)
        deps = []
        for sec in ("dependencies","devDependencies","optionalDependencies"):
            for k,v in (j.get(sec) or {}).items():
                deps.append({"name": k, "version": str(v)})
        return {"ecosystem": "npm", "deps": deps}

    if name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        # слишком объёмные, оставим компактную заглушку
        return {"ecosystem": "npm", "deps": []}

    # Go
    if name == "go.mod":
        deps = []
        for ln in txt.splitlines():
            m = re.match(r'^\s*require\s+([A-Za-z0-9\-\._\/]+)\s+([v0-9\.\-+\w]+)', ln)
            if m:
                deps.append({"name": m.group(1), "version": m.group(2)})
        return {"ecosystem": "Go", "deps": deps}

    # Rust
    if name in ("cargo.toml","cargo.lock"):
        deps = []
        for k,v in _kv_lines(txt):
            if k.lower() == "version":
                continue
            if re.match(r'^[A-Za-z0-9_\-\.]+$', k):
                deps.append({"name": k, "version": v})
        return {"ecosystem": "crates.io", "deps": deps}

    # Java / JVM
    if name == "pom.xml":
        # очень упрощённый парсер artifactId/version из pom.xml
        deps = []
        for m in re.finditer(r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>', txt, re.I):
            deps.append({"name": f"{m.group(1)}:{m.group(2)}", "version": m.group(3)})
        return {"ecosystem": "Maven", "deps": deps}
    if name.startswith("build.gradle"):
        return {"ecosystem": "Gradle", "deps": []}

    # Ruby / PHP / .NET / Dart — простые заглушки
    if name in ("gemfile","gemfile.lock"):
        return {"ecosystem": "RubyGems", "deps": []}
    if name in ("composer.json","composer.lock"):
        j = _json(p) if name == "composer.json" else {}
        deps = []
        for sec in ("require","require-dev"):
            for k,v in (j.get(sec) or {}).items():
                deps.append({"name": k, "version": str(v)})
        return {"ecosystem": "Packagist", "deps": deps}
    if name.endswith(".csproj") or name.endswith(".vbproj") or name == "nuget.config":
        return {"ecosystem": "NuGet", "deps": []}
    if name in ("pubspec.yaml","pubspec.lock"):
        return {"ecosystem": "Pub", "deps": []}

    return None
