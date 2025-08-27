from __future__ import annotations
from typing import Optional, Tuple, Dict
from pathlib import Path
import subprocess, shlex, os

ResolverResult = Tuple[Optional[str], Optional[str], Optional[str]]  # (ecosystem, package, version)

def _run(cmd: str) -> Tuple[int, str]:
    try:
        p = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=8)
        return p.returncode, (p.stdout or p.stderr or "").strip()
    except Exception as e:
        return 127, str(e)

def resolve_file_dpkg(p: Path) -> ResolverResult:
    # dpkg -S /path  → 'pkg: /path'
    rc, out = _run(f"dpkg -S {shlex.quote(str(p))}")
    if rc != 0 or ":" not in out:
        return None, None, None
    pkg = out.split(":")[0].strip()
    # dpkg-query -W -f='${Version}\n' pkg
    rc, ver = _run(f"dpkg-query -W -f=${{Version}} {shlex.quote(pkg)}")
    if rc != 0 or not ver:
        return None, None, None
    # Иногда нужен source-package; для OSV хватает bin-package.
    return "Debian", pkg, ver.strip()

def resolve_file_rpm(p: Path) -> ResolverResult:
    # rpm -qf /path → pkg-ver-rel
    rc, out = _run(f"rpm -qf {shlex.quote(str(p))} --qf '%{{NAME}} %{{VERSION}}-%{{RELEASE}}\\n'")
    if rc != 0 or not out:
        return None, None, None
    try:
        name, ver = out.split()[0], out.split()[1]
    except Exception:
        return None, None, None
    # ОС семейства RPM в OSV бывают разные; даём «RPM» и позволяем переопределить флагом
    return os.getenv("CVE_ECOSYSTEM", "RPM"), name, ver

def resolve_file_apk(p: Path) -> ResolverResult:
    # apk info -W /path → 'pkgname: /path'
    rc, out = _run(f"apk info -W {shlex.quote(str(p))}")
    if rc != 0 or ":" not in out:
        return None, None, None
    pkg = out.split(":")[0].strip()
    # apk info -e pkg → 'pkg-x.y.z-rN'
    rc, out2 = _run(f"apk info -e {shlex.quote(pkg)}")
    if rc != 0 or not out2:
        return None, None, None
    # версия после имени через '-'
    try:
        ver = out2.strip().split("-", 1)[1]
    except Exception:
        ver = None
    return "Alpine", pkg, ver

def resolve_file_pacman(p: Path) -> ResolverResult:
    # pacman -Qo /path → '/path is owned by pkg ver'
    rc, out = _run(f"pacman -Qo {shlex.quote(str(p))}")
    if rc != 0 or " is owned by " not in out:
        return None, None, None
    try:
        tail = out.split(" is owned by ", 1)[1]
        name, ver = tail.split(" ", 1)
        ver = ver.strip()
    except Exception:
        return None, None, None
    return "Arch", name, ver

def resolve_file_by_ecosystem(p: Path, mode: str) -> ResolverResult:
    mode = (mode or "auto").lower()
    if mode == "none":
        return None, None, None
    if mode in ("auto", "dpkg"):
        eco, name, ver = resolve_file_dpkg(p)
        if eco: return eco, name, ver
        if mode != "auto": return None, None, None
    if mode in ("auto", "rpm"):
        eco, name, ver = resolve_file_rpm(p)
        if eco: return eco, name, ver
        if mode != "auto": return None, None, None
    if mode in ("auto", "apk"):
        eco, name, ver = resolve_file_apk(p)
        if eco: return eco, name, ver
        if mode != "auto": return None, None, None
    if mode in ("auto", "pacman"):
        eco, name, ver = resolve_file_pacman(p)
        if eco: return eco, name, ver
    return None, None, None
