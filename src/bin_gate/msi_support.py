# --- PATCH 2: src/bin_gate/msi_support.py — более надёжный поиск инструментов и fall-back ---
# заменяет соответствующие функции в твоём файле msi_support.py  :contentReference[oaicite:1]{index=1}

from __future__ import annotations
from typing import Tuple, Dict, List, Any, Optional, Callable
from pathlib import Path
import os, sys, shutil, tempfile, subprocess

# -------- robust subprocess with timeout (kills on timeout) --------

def _run_cmd(cmd: List[str], timeout: int = 25, env: Optional[Dict[str, str]] = None) -> tuple[int, str, str]:
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=(env or os.environ.copy()),
        )
        try:
            out, err = proc.communicate(timeout=timeout)
            return proc.returncode, out, err
        except subprocess.TimeoutExpired:
            try:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    proc.kill()
            except Exception:
                pass
            return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not found"
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {e}"

# -------- MSI helpers --------

OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"  # CFB (OLE) header

# Early triage: skip tiny files and media-only content (unless from MSI/archive)
MIN_FILE_SIZE = 512
SKIP_MEDIA_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff", ".tif",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".mp3", ".wav", ".ogg", ".flac", ".m4a", ".aac",
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".webm", ".flv",
    ".pdf", ".svg", ".eps", ".raw", ".cr2", ".nef",
})


def _skip_early_triage(p: Path) -> bool:
    """True = do not create Evidence for this file (too small or media-only)."""
    try:
        if p.stat().st_size < MIN_FILE_SIZE:
            return True
    except Exception:
        return True
    suf = p.suffix.lower()
    if suf in SKIP_MEDIA_EXTENSIONS:
        return True
    return False


def is_msi_file(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            head = f.read(8)
        return (head == OLE_MAGIC) or (p.suffix.lower() == ".msi")
    except Exception:
        return p.suffix.lower() == ".msi"

def _which_ex(name: str, env_var: Optional[str], candidates: List[Path]) -> Optional[str]:
    # 1) явный путь из ENV
    if env_var:
        env_path = os.getenv(env_var)
        if env_path and Path(env_path).exists():
            return env_path
    # 2) системный PATH
    w = shutil.which(name)
    if w:
        return w
    # 3) типовые каталоги (Windows) и рядом с exe/скриптом
    exe_dir = Path(getattr(sys, "frozen", False) and sys.executable or __file__).resolve()
    exe_dir = exe_dir.parent if exe_dir.is_file() else exe_dir
    cand = [exe_dir / name]
    cand += candidates
    for c in cand:
        try:
            if Path(c).exists():
                return str(c)
        except Exception:
            pass
    return None

def _collect_files(root: Path) -> List[Path]:
    return [q for q in root.rglob("*") if q.is_file()]


def annotate_evidence(ev_obj: Any, origin_of: Dict[Path, Dict[str, Any]]) -> None:
    """
    Если файл произошёл из MSI-контейнера, дополняем ev.meta['container'] метаданными MSI.
    Безопасно к отсутствию полей.
    """
    try:
        p = Path(getattr(ev_obj, "path", "") or getattr(ev_obj, "file", ""))
        cont = origin_of.get(p)
        if not cont:
            return
        meta = getattr(ev_obj, "meta", None)
        if not isinstance(meta, dict):
            meta = {}
            setattr(ev_obj, "meta", meta)
        meta.setdefault("container", cont)
    except Exception:
        pass

def cleanup_tmp_dirs(tmp_dirs: List[Path]) -> None:
    for d in tmp_dirs:
        try:
            import shutil
            shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass

def _read_msi_metadata(msi_path: Path, timeout: int) -> Dict[str, str]:
    """
    Возвращает ключевые свойства MSI (best-effort).
    Windows: lessmsi; Linux/macOS: msiinfo; иначе — {}.
    """
    meta: Dict[str, str] = {}
    debug = os.getenv("BIN_GATE_MSI_DEBUG") == "1"

    if os.name == "nt":
        lessmsi_name = "lessmsi.exe"
        lessmsi = _which_ex(
            lessmsi_name,
            env_var="BIN_GATE_LESSMSI",
            candidates=[
                Path(r"C:\Users\user\Desktop\appsec\bin_intake_gateway\lessmsi.exe"),
                Path(r"C:\Program Files\lessmsi\lessmsi.exe"),
                Path(r"C:\Program Files (x86)\lessmsi\lessmsi.exe"),
            ],
        )
        if lessmsi:
            code, out, err = _run_cmd([lessmsi, "l", str(msi_path), "-t", "Property"], timeout=timeout)
            if debug:
                print(f"[MSI][meta] lessmsi rc={code}", file=sys.stderr)
            if code == 0:
                for line in out.splitlines():
                    if "\t" in line:
                        k, v = line.split("\t", 1)
                        k, v = k.strip(), v.strip()
                        if k and v:
                            meta[k] = v
    else:
        msiinfo = _which_ex("msiinfo", env_var=None, candidates=[Path("/usr/bin/msiinfo"), Path("/usr/local/bin/msiinfo")])
        if msiinfo:
            code, out, _ = _run_cmd([msiinfo, "suminfo", str(msi_path)], timeout=timeout)
            if code == 0:
                for line in out.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        meta[k.strip()] = v.strip()
            code, out, _ = _run_cmd([msiinfo, "export", str(msi_path), "Property"], timeout=timeout)
            if code == 0:
                for line in out.splitlines():
                    if "\t" in line:
                        k, v = line.split("\t", 1)
                        k, v = k.strip(), v.strip()
                        if k and v:
                            meta[k] = v

    wanted = ("ProductName", "ProductVersion", "ProductCode", "Manufacturer", "UpgradeCode")
    return {k: meta.get(k, "") for k in wanted}

def _extract_msi(msi_path: Path, timeout: int) -> tuple[Path, List[Path]]:
    out_dir = Path(tempfile.mkdtemp(prefix="msi-"))
    tried: List[str] = []
    ok = False
    debug = os.getenv("BIN_GATE_MSI_DEBUG") == "1"

    # 1) 7z (кроссплатформенный быстрый вариант)
    seven = _which_ex(
        "7z.exe" if os.name == "nt" else "7z",
        env_var="BIN_GATE_7Z",
        candidates=([
            Path(r"C:\Program Files\7-Zip\7z.exe"),
            Path(r"C:\Program Files (x86)\7-Zip\7z.exe"),
        ] if os.name == "nt" else [])
    )
    if seven:
        tried.append(seven)
        code, _, err = _run_cmd([seven, "x", f"-o{str(out_dir)}", str(msi_path)], timeout=timeout)
        if debug:
            print(f"[MSI] 7z rc={code} err={err[:120] if err else ''}", file=sys.stderr)
        if code == 0 and any(out_dir.iterdir()):
            ok = True

    # 2) lessmsi (Windows)
    if (not ok) and os.name == "nt":
        less = _which_ex(
            "lessmsi.exe",
            env_var="BIN_GATE_LESSMSI",
            candidates=[
                Path(r"C:\ProgramData\chocolatey\bin\lessmsi.exe"),
                Path(r"C:\Program Files\lessmsi\lessmsi.exe"),
                Path(r"C:\Program Files (x86)\lessmsi\lessmsi.exe"),
            ],
        )
        if less:
            tried.append(less)
            code, _, err = _run_cmd([less, "x", str(msi_path), str(out_dir)], timeout=timeout)
            if debug:
                print(f"[MSI] lessmsi rc={code} err={err[:120] if err else ''}", file=sys.stderr)
            if code == 0 and any(out_dir.iterdir()):
                ok = True

    # 3) msiexec /a (Windows, opt-in: BIN_GATE_ENABLE_MSIEXEC=1)
    if (not ok) and os.name == "nt" and os.getenv("BIN_GATE_ENABLE_MSIEXEC", "0") == "1":
        tried.append("msiexec")
        code, _, err = _run_cmd(["msiexec", "/a", str(msi_path), "/qn", f"TARGETDIR={str(out_dir)}"], timeout=max(30, timeout))
        if debug:
            print(f"[MSI] msiexec rc={code} err={err[:120] if err else ''}", file=sys.stderr)
        if code == 0 and any(out_dir.iterdir()):
            ok = True

    # 4) msiextract (Linux/macOS)
    if not ok:
        msiextract = _which_ex("msiextract", env_var=None, candidates=[Path("/usr/bin/msiextract"), Path("/usr/local/bin/msiextract")])
        if msiextract:
            tried.append(msiextract)
            code, _, err = _run_cmd([msiextract, "--directory", str(out_dir), str(msi_path)], timeout=timeout)
            if debug:
                print(f"[MSI] msiextract rc={code} err={err[:120] if err else ''}", file=sys.stderr)
            if code == 0 and any(out_dir.iterdir()):
                ok = True

    if not ok:
        shutil.rmtree(out_dir, ignore_errors=True)
        raise RuntimeError(f"MSI extract failed (tried: {', '.join(tried) or 'none'})")

    return out_dir, _collect_files(out_dir)

def collect_targets_with_msi(
    root: Path,
    sniff_magic: Callable[[Path], Tuple[bool, str]],
    logger: Optional[Any] = None,
) -> Tuple[List[Path], List[Dict[str, Any]], Dict[Path, Dict[str, Any]], List[Path]]:
    msi_timeout = int(os.getenv("BIN_GATE_MSI_TIMEOUT", "25"))
    files: List[Path] = []
    containers: List[Dict[str, Any]] = []
    origin_of: Dict[Path, Dict[str, Any]] = {}
    tmp_dirs: List[Path] = []
    debug = os.getenv("BIN_GATE_MSI_DEBUG") == "1"

    if root.is_file():
        if is_msi_file(root):
            try:
                out_dir, inner = _extract_msi(root, timeout=msi_timeout)
                tmp_dirs.append(out_dir)
                meta = _read_msi_metadata(root, timeout=msi_timeout)
                containers.append({"path": str(root), "metadata": meta, "extracted": len(inner)})
                for q in inner:
                    is_bin, _ = sniff_magic(q)
                    if is_bin:
                        files.append(q)
                        origin_of[q] = {"type": "msi", "path": str(root), **meta}
                if logger:
                    logger.info(f"[MSI] {root.name}: extracted {len(inner)} file(s)")
            except Exception as e:
                if logger or debug:
                    print(f"[MSI] {root}: {e}", file=sys.stderr)
                # FALLBACK: добавим сам MSI, чтобы видно было в отчёте
                files.append(root)
        else:
            is_bin, _ = sniff_magic(root)
            if is_bin and not _skip_early_triage(root):
                files.append(root)
        return files, containers, origin_of, tmp_dirs

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() == ".msi" or is_msi_file(p):
            try:
                out_dir, inner = _extract_msi(p, timeout=msi_timeout)
                tmp_dirs.append(out_dir)
                meta = _read_msi_metadata(p, timeout=msi_timeout)
                containers.append({"path": str(p), "metadata": meta, "extracted": len(inner)})
                for q in inner:
                    is_bin, _ = sniff_magic(q)
                    if is_bin:
                        files.append(q)
                        origin_of[q] = {"type": "msi", "path": str(p), **meta}
                if logger:
                    logger.info(f"[MSI] {p.name}: extracted {len(inner)} file(s)")
            except Exception as e:
                if logger or debug:
                    print(f"[MSI] {p}: {e}", file=sys.stderr)
                # FALLBACK: всё равно учтём сам MSI
                files.append(p)
            continue

        is_bin, _ = sniff_magic(p)
        if is_bin and not _skip_early_triage(p):
            files.append(p)

    return files, containers, origin_of, tmp_dirs
