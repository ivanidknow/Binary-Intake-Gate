import os, io, sys, json, shutil, tempfile, subprocess, pathlib
from typing import Dict, List, Optional, Tuple

OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

def is_msi(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(8) == OLE_MAGIC and path.lower().endswith(".msi")
    except Exception:
        return False

def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def _run(cmd: List[str]) -> Tuple[int, str, str]:
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err

def extract_msi(msi_path: str, tmp_root: Optional[str] = None, prefer_tools: Optional[List[str]] = None) -> Tuple[str, List[str]]:
    """
    Возвращает (out_dir, files) — каталог распаковки и список вложенных файлов.
    Порядок попыток:
      Windows: lessmsi -> msiexec /a -> 7z
      Linux/macOS: msiextract -> 7z
    """
    out_dir = tempfile.mkdtemp(prefix="msi-", dir=tmp_root)
    tried = []

    # Windows
    if os.name == "nt":
        if _which("lessmsi"):
            tried.append("lessmsi")
            code, out, err = _run(["lessmsi", "x", msi_path, out_dir])
            if code == 0:
                return out_dir, _collect(out_dir)
        # Admin-install (иногда требует прав)
        tried.append("msiexec")
        code, out, err = _run(["msiexec", "/a", msi_path, "/qn", f"TARGETDIR={out_dir}"])
        if code == 0 and _collect(out_dir):
            return out_dir, _collect(out_dir)

    # Linux/macOS
    if _which("msiextract"):
        tried.append("msiextract")
        code, out, err = _run(["msiextract", "--directory", out_dir, msi_path])
        if code == 0:
            return out_dir, _collect(out_dir)

    # Фолбэк — 7z везде
    if _which("7z"):
        tried.append("7z")
        code, out, err = _run(["7z", "x", f"-o{out_dir}", msi_path])
        if code == 0:
            return out_dir, _collect(out_dir)

    # Не удалось
    shutil.rmtree(out_dir, ignore_errors=True)
    raise RuntimeError(f"MSI extract failed (tried: {', '.join(tried) or 'none'})")

def read_msi_metadata(msi_path: str) -> Dict[str, str]:
    """
    Лучший доступный способ получить Property/summary без инсталла.
    Windows: lessmsi l -t Property
    Linux:   msiinfo export / suminfo
    Фолбэк:  пусто.
    """
    meta: Dict[str, str] = {}
    if os.name == "nt" and _which("lessmsi"):
        code, out, err = _run(["lessmsi", "l", msi_path, "-t", "Property"])
        if code == 0:
            for line in out.splitlines():
                # Формат: PropertyName \t Value
                if "\t" in line:
                    k, v = line.split("\t", 1)
                    k, v = k.strip(), v.strip()
                    if k and v:
                        meta[k] = v
    elif _which("msiinfo"):
        # summary
        code, out, err = _run(["msiinfo", "suminfo", msi_path])
        if code == 0:
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    meta[k.strip()] = v.strip()
        # property table
        code, out, err = _run(["msiinfo", "export", msi_path, "Property"])
        if code == 0:
            for line in out.splitlines():
                if "\t" in line:
                    k, v = line.split("\t", 1)
                    k, v = k.strip(), v.strip()
                    if k and v:
                        meta[k] = v
    # Нормализуем ключи, которые нас волнуют
    wanted = ("ProductName", "ProductVersion", "ProductCode", "Manufacturer", "UpgradeCode")
    normalized = {k: meta.get(k, "") for k in wanted}
    return normalized

def _collect(root: str) -> List[str]:
    files: List[str] = []
    for dirpath, _, filenames in os.walk(root):
        for n in filenames:
            files.append(os.path.join(dirpath, n))
    return files
