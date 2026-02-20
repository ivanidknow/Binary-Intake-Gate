# src/bin_gate/analyzers/python_pkg.py
from __future__ import annotations
import ast, base64, hashlib, io, json, os, re, sys, tarfile, zipfile, subprocess, shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
try:
    import tomllib  # py311+
except Exception:
    tomllib = None

# ------------------------- helpers -------------------------

PY_EXTS_BIN = {".pyd", ".so", ".dll"}
SDIST_EXTS = (".tar.gz", ".tgz", ".zip")
WHEEL_EXT = ".whl"

def _is_wheel(p: Path) -> bool:
    return p.suffix.lower() == WHEEL_EXT

def _is_sdist(p: Path) -> bool:
    s = p.name.lower()
    return s.endswith(".tar.gz") or s.endswith(".tgz") or s.endswith(".zip")

def _safe_tmp_dir(root: Path, tag: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    tmp = root / f"{tag}_{hashlib.sha256(os.urandom(16)).hexdigest()[:8]}"
    tmp.mkdir(parents=True, exist_ok=True)
    return tmp

def _sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256(); h.update(b); return h.hexdigest()

def _read_text(p: Path, enc: str = "utf-8") -> str:
    try:
        return p.read_text(encoding=enc, errors="replace")
    except Exception:
        return ""

def _find_bandit_exe() -> Optional[Path]:
    # 1) env override
    e = os.getenv("BIN_GATE_BANDIT")
    if e:
        ep = Path(e)
        if ep.is_file():
            return ep
    # 2) cwd\bandit.exe (как ты и планируешь)
    cwd = Path.cwd() / "bandit.exe"
    if cwd.is_file():
        return cwd
    # 3) по дереву от текущего файла вверх ищем bandit.exe
    here = Path(__file__).resolve()
    for parent in [here, *here.parents]:
        cand = parent / "bandit.exe"
        if cand.is_file():
            return cand
    # 4) в PATH
    w = shutil.which("bandit")
    if w:
        return Path(w)
    return None

# ----------------------- metadata/record --------------------

@dataclass
class WheelMeta:
    name: str = ""
    version: str = ""
    requires_python: str = ""
    requires_dist: List[str] = None
    root_is_purelib: Optional[bool] = None
    tags: List[str] = None
    entry_points: List[str] = None

def _parse_metadata_text(txt: str) -> Dict[str, List[str] | str]:
    out: Dict[str, Any] = {}
    for line in txt.splitlines():
        if not line or line[0].isspace() or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip(); v = v.strip()
        out.setdefault(k, [])
        out[k].append(v)
    return out

def _read_wheel_meta(dist_info: Path) -> WheelMeta:
    meta = WheelMeta(requires_dist=[], tags=[], entry_points=[])
    md = dist_info / "METADATA"
    wh = dist_info / "WHEEL"
    ep = dist_info.parent / (dist_info.name.replace(".dist-info", ".data")) / "data" / "entry_points.txt"

    if md.is_file():
        m = _parse_metadata_text(_read_text(md))
        meta.name = (m.get("Name") or [""])[0]
        meta.version = (m.get("Version") or [""])[0]
        meta.requires_python = (m.get("Requires-Python") or [""])[0]
        meta.requires_dist = list(m.get("Requires-Dist") or [])
    if wh.is_file():
        w = _parse_metadata_text(_read_text(wh))
        tags = w.get("Tag") or []
        meta.tags = list(tags)
        rip = (w.get("Root-Is-Purelib") or [""])[0].lower()
        if rip in ("true","false"):
            meta.root_is_purelib = (rip == "true")
    if ep.is_file():
        meta.entry_points = [ln.strip() for ln in _read_text(ep).splitlines() if ln.strip() and not ln.strip().startswith("#")]
    return meta

def _verify_record_whl(dist_info: Path, wheel_root: Path) -> Dict[str, Any]:
    rec = dist_info / "RECORD"
    res = {"record_ok": None, "mismatches": 0, "missing": 0}
    if not rec.is_file():
        res["record_ok"] = False
        return res
    mismatches = 0; missing = 0
    for line in _read_text(rec).splitlines():
        if not line:
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        rel = parts[0]
        digest = parts[1]  # like "sha256=base64digest"
        size_s = parts[2]
        fpath = wheel_root / rel
        if not fpath.exists():
            missing += 1
            continue
        # size
        try:
            size = int(size_s)
            if size != fpath.stat().st_size:
                mismatches += 1
                continue
        except Exception:
            # some rows for RECORD itself may have empty hash/size
            pass
        # hash
        if digest.startswith("sha256="):
            try:
                b64 = digest[len("sha256="):]
                want = base64.urlsafe_b64decode(b64 + "==")
                have = hashlib.sha256(fpath.read_bytes()).digest()
                if want != have:
                    mismatches += 1
            except Exception:
                mismatches += 1
    res["mismatches"] = mismatches
    res["missing"] = missing
    res["record_ok"] = (mismatches == 0 and missing == 0)
    return res

# --------------------------- extract ------------------------

def _extract_wheel(whl: Path, tmp_root: Path) -> Path:
    out = _safe_tmp_dir(tmp_root, "whl")
    with zipfile.ZipFile(whl, "r") as z:
        z.extractall(out)
    return out

def _extract_sdist(sd: Path, tmp_root: Path) -> Path:
    out = _safe_tmp_dir(tmp_root, "sdist")
    name = sd.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(sd, "r") as z:
            z.extractall(out)
    else:
        mode = "r:gz" if (name.endswith(".tar.gz") or name.endswith(".tgz")) else "r:*"
        with tarfile.open(sd, mode) as t:
            t.extractall(out)
    return out

# --------------------------- AST SAST -----------------------

class _AstVisitor(ast.NodeVisitor):
    def __init__(self):
        self.nesting = 0
        self.high = 0; self.medium = 0; self.low = 0
        self.rules: Dict[str,int] = {}

    def _hit(self, key: str, sev: str):
        self.rules[key] = self.rules.get(key, 0) + 1
        if sev == "high": self.high += 1
        elif sev == "medium": self.medium += 1
        else: self.low += 1

    def visit_FunctionDef(self, node): self.nesting += 1; self.generic_visit(node); self.nesting -= 1
    def visit_AsyncFunctionDef(self, node): self.nesting += 1; self.generic_visit(node); self.nesting -= 1
    def visit_ClassDef(self, node): self.nesting += 1; self.generic_visit(node); self.nesting -= 1

    def visit_Call(self, node: ast.Call):
        # Флаг "уровень модуля"
        top = (self.nesting == 0)

        def _name(n) -> str:
            if isinstance(n, ast.Name): return n.id
            if isinstance(n, ast.Attribute):
                return f"{_name(n.value)}.{n.attr}"
            return ""

        fn = _name(node.func)

        # Процессы/шелл
        if fn in ("os.system", "subprocess.run", "subprocess.call", "subprocess.Popen"):
            self._hit(f"{fn}@{'module' if top else 'deep'}", "high" if top else "medium")
        # Динамические импорты/генерация кода
        elif fn in ("eval","exec","compile","__import__","importlib.import_module","ast.parse"):
            self._hit(f"{fn}@{'module' if top else 'deep'}", "high" if top else "medium")
        # Сеть
        elif fn in ("urllib.request.urlopen","requests.get","requests.post","socket.socket","http.client.HTTPConnection"):
            self._hit(f"{fn}@{'module' if top else 'deep'}", "high" if top else "medium")
        # Нативные либы
        elif fn in ("ctypes.CDLL","ctypes.windll.LoadLibrary","ctypes.cdll.LoadLibrary"):
            self._hit(f"{fn}@{'module' if top else 'deep'}", "high" if top else "medium")

        self.generic_visit(node)

def _scan_ast(root: Path, size_limit_mb: int = 2) -> Dict[str, Any]:
    v = _AstVisitor()
    for p in root.rglob("*.py"):
        try:
            if p.stat().st_size > size_limit_mb * 1024 * 1024:
                continue
            src = p.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(src, filename=str(p))
            v.visit(tree)
        except Exception:
            continue
    rules_top = sorted(v.rules.items(), key=lambda kv: kv[1], reverse=True)[:10]
    return {
        "high": v.high, "medium": v.medium, "low": v.low,
        "rules_top": [f"{k}({c})" for k,c in rules_top],
    }

# -------------------------- Bandit --------------------------

def _run_bandit(root: Path, config: Optional[Path]) -> Dict[str, Any]:
    exe = _find_bandit_exe()
    if not exe:
        return {"enabled": False, "high": 0, "medium": 0, "low": 0, "rules_top": [], "error": "bandit_not_found"}
    cmd = [str(exe), "-r", str(root), "-f", "json", "-q"]
    if config and config.is_file():
        cmd += ["-c", str(config)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except Exception as e:
        return {"enabled": True, "high": 0, "medium": 0, "low": 0, "rules_top": [], "error": f"exec_error:{e}"}
    if p.returncode not in (0,1):  # 1 — findings
        return {"enabled": True, "high": 0, "medium": 0, "low": 0, "rules_top": [], "error": f"rc:{p.returncode} stderr:{p.stderr[:200]}"}
    try:
        data = json.loads(p.stdout or "{}")
    except Exception as e:
        return {"enabled": True, "high": 0, "medium": 0, "low": 0, "rules_top": [], "error": f"json_error:{e}"}
    results = data.get("results") or []
    sev_map = {"HIGH":"high","MEDIUM":"medium","LOW":"low"}
    counts = {"high":0,"medium":0,"low":0}
    rules: Dict[str,int] = {}
    for r in results:
        sev = sev_map.get(str(r.get("issue_severity","")).upper())
        if not sev: continue
        counts[sev] += 1
        tid = str(r.get("test_id") or "UNK")
        rules[tid] = rules.get(tid, 0) + 1
    rules_top = sorted(rules.items(), key=lambda kv: kv[1], reverse=True)[:10]
    return {"enabled": True, **counts, "rules_top": [f"{k}({c})" for k,c in rules_top]}

# --------------------- bin ext detection --------------------

def _detect_bin_ext(root: Path) -> Tuple[int, List[str]]:
    files = []
    for p in root.rglob("*"):
        if not p.is_file(): continue
        if p.suffix.lower() in PY_EXTS_BIN:
            try:
                files.append(str(p.relative_to(root)).replace("\\","/"))
            except Exception:
                files.append(str(p))
    return len(files), files

# --------------------------- public -------------------------

def analyze_python_pkg(path: Path,
                       *,
                       tmp_root: Optional[Path] = None,
                       enable_ast: bool = True,
                       enable_bandit: bool = True,
                       bandit_config: Optional[Path] = None,
                       verify_record: bool = True) -> Dict[str, Any]:
    """
    Возвращает evidence-словарь для human/markdown репортов и policy.
    Не исполняет код пакета.
    """
    p = Path(path)
    fmt = "wheel" if _is_wheel(p) else ("sdist" if _is_sdist(p) else None)
    if fmt is None:
        return {}

    tmp_root = tmp_root or Path(os.getenv("BIN_GATE_TMP", Path.cwd() / ".tmp_bin_gate"))
    extracted = _extract_wheel(p, tmp_root) if fmt == "wheel" else _extract_sdist(p, tmp_root)

    # ---- wheel metadata / RECORD
    wheel_meta = None
    record_info = {"record_ok": None, "mismatches": 0, "missing": 0}
    if fmt == "wheel":
        dist_infos = list(extracted.glob("*.dist-info"))
        if dist_infos:
            di = dist_infos[0]
            wheel_meta = _read_wheel_meta(di)
            if verify_record:
                record_info = _verify_record_whl(di, extracted)

    # ---- sdist build-system
    build_backend = None
    build_requires: List[str] = []
    if fmt == "sdist":
        pyproj = next((p for p in extracted.rglob("pyproject.toml") if p.is_file()), None)
        if pyproj and tomllib:
            try:
                data = tomllib.loads(_read_text(pyproj))
                bs = data.get("build-system") or {}
                build_backend = bs.get("build-backend") or None
                build_requires = list(bs.get("requires") or [])
            except Exception:
                pass

    # ---- SAST
    ast_findings = _scan_ast(extracted) if enable_ast else {"high":0,"medium":0,"low":0,"rules_top":[]}
    bandit_findings = _run_bandit(extracted, bandit_config) if enable_bandit else {"enabled":False,"high":0,"medium":0,"low":0,"rules_top":[]}

    # ---- binary extensions
    bin_cnt, bin_files = _detect_bin_ext(extracted)

    # ---- assemble evidence
    meta = {
        "name": wheel_meta.name if wheel_meta else "",
        "version": wheel_meta.version if wheel_meta else "",
        "requires_python": wheel_meta.requires_python if wheel_meta else "",
        "requires_dist": (wheel_meta.requires_dist if wheel_meta else []),
        "entry_points": (wheel_meta.entry_points if wheel_meta else []),
        "pure_python": (wheel_meta.root_is_purelib if wheel_meta and wheel_meta.root_is_purelib is not None else None),
        "build_backend": build_backend,
        "build_requires": build_requires,
        "format": fmt,
    }

    evidence = {
        "meta": {
            "name": p.name,
            "path": str(p),
            "container": {
                "type": "pythonpkg",
                "format": fmt,
                "path": str(p),
                "name": p.name,
            },
        },
        "python_pkg": {
            "meta": meta,
            "integrity": record_info,
            "sast": {
                "ast": ast_findings,
                "bandit": bandit_findings,
            },
            "extensions": {
                "count": bin_cnt,
                "files": bin_files,
            },
        },
    }
    return evidence

def can_handle_python_pkg(path: Path) -> bool:
    p = Path(path)
    return _is_wheel(p) or _is_sdist(p)
