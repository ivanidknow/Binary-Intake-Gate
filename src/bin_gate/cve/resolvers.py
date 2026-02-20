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


from typing import List, Tuple, Optional

def resolve_elf_packages(
    elf_path: str,
    *,
    inventory: Optional[list] = None,
    user_map: Optional[dict] = None,
    ecosystem: Optional[str] = None,
    arch_hint: Optional[str] = None,
) -> List[Tuple[str, str, str, str, str]]:
    """
    Возвращает список кортежей:
      (pkg, ecosystem, version, arch, lib)
    lib — SONAME/имя библиотеки, от которой зависим.
    """
    try:
        # локальные импорты, чтобы избежать циклических зависимостей
        from ..analyzers.elf_deps import list_elf_shared_libs
        from .mapper import map_lib_to_package
        from .deb_index_resolver import resolve_debian_by_indexes
    except Exception:
        return []

    inventory = inventory or []
    user_map = user_map or {}

    # 1) соберём SONAME’ы у elf-файла
    try:
        sonames = list_elf_shared_libs(elf_path) or []
    except Exception:
        sonames = []

    out: List[Tuple[str, str, str, str, str]] = []

    # 2) по каждому SONAME пытаемся получить (eco, pkg, ver, arch)
    for so in sonames:
        eco = (ecosystem or "Debian")  # по умолчанию деб-семейство
        ver = ""
        pkg = None
        arch = (arch_hint or "amd64")

        # 2.1) сначала явный маппинг имен → пакет
        pkg = map_lib_to_package(so, ecosystem=eco, user_map=user_map)

        # 2.2) если не нашли — пробуем индекс Debian Contents/Packages
        if not pkg:
            try:
                ecoX, pkgX, verX, archX = resolve_debian_by_indexes(so, arch=arch)
            except Exception:
                ecoX = pkgX = verX = archX = None
            if ecoX and pkgX:
                eco, pkg, ver, arch = ecoX, pkgX, (verX or ""), (archX or arch)

        if not pkg:
            # ничего не нашли — пропускаем
            continue

        out.append((pkg, eco, str(ver or ""), str(arch or ""), so))

    return out


def ldconfig_map(timeout: int = 5) -> dict[str, list[str]]:
    try:
        out = subprocess.check_output(["ldconfig","-p"], timeout=timeout, text=True, errors="ignore")
    except Exception:
        return {}
    m = {}
    for line in out.splitlines():
        if " => " not in line: 
            continue
        left, path = line.split(" => ", 1)
        name = left.split()[0]
        m.setdefault(name, []).append(path.strip())
    return m

def resolve_file_dpkg(fpath: str, timeout: int = 5):
    """
    Возвращает кортеж (ecosystem, package, version, arch) для Debian/Ubuntu.
    При ошибке -> (None, None, None, None).
    """
    try:
        # Узнать, какой пакет владеет файлом
        # Примеры вывода: "libssl3:amd64: /usr/lib/x86_64-linux-gnu/libssl.so.3"
        owner_line = subprocess.check_output(
            shlex.split(f"dpkg -S {shlex.quote(fpath)}"),
            timeout=timeout, text=True, errors="ignore"
        ).strip()

        # Берём левую часть до двоеточия c путём
        # Возможны варианты: "libssl3:amd64" или просто "libssl3"
        owner_pkg_arch = owner_line.split(":", 1)[0].strip()
        if ":" in owner_pkg_arch:
            pkg_name = owner_pkg_arch.split(":", 1)[0]
            pkg_arch = owner_pkg_arch.split(":", 1)[1]
        else:
            pkg_name = owner_pkg_arch
            # вытащим arch из dpkg-query ниже
            pkg_arch = None

        # Запрос версии и архитектуры пакета
        info = subprocess.check_output(
            shlex.split(f"dpkg-query -W -f=${{Version}}\t${{Architecture}}\n {pkg_name}"),
            timeout=timeout, text=True, errors="ignore"
        ).strip()

        # На случай мультистрок — берём первую непустую
        for line in info.splitlines():
            line = line.strip()
            if not line:
                continue
            ver, arch = line.split("\t", 1)
            # если ранее было None, подставим актуальную
            if not pkg_arch:
                pkg_arch = arch
            return ("Debian", pkg_name, ver, pkg_arch)

    except Exception:
        pass

    return (None, None, None, None)

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
