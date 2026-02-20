# deb_index_resolver.py
import os, gzip, lzma, io, time, re, urllib.request

DEB_MIRROR = os.environ.get("DEB_MIRROR", "https://deb.debian.org/debian")
DEB_SUITE  = os.environ.get("DEB_SUITE",  "bookworm")        # поменяй при желании
DEB_COMP   = os.environ.get("DEB_COMP",   "main")            # main/non-free-firmware и т.п.
CACHE_DIR  = os.path.expanduser("~/.cache/bin-gate/debidx")

# arch -> multiarch triplet
TRIPLET = {
    "amd64": "x86_64-linux-gnu",
    "i386":  "i386-linux-gnu",
    "arm64": "aarch64-linux-gnu",
    "armhf": "arm-linux-gnueabihf",
    "armel": "arm-linux-gnueabi",
    "ppc64el": "powerpc64le-linux-gnu",
    "riscv64": "riscv64-linux-gnu",
}

def _dl(url, path, ttl=86400):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < ttl:
        return path
    with urllib.request.urlopen(url, timeout=30) as r:
        data = r.read()
    with open(path, "wb") as f:
        f.write(data)
    return path

def ensure_indexes(arch: str):
    contents_url = f"{DEB_MIRROR}/dists/{DEB_SUITE}/{DEB_COMP}/Contents-{arch}.gz"
    pkgs_url     = f"{DEB_MIRROR}/dists/{DEB_SUITE}/{DEB_COMP}/binary-{arch}/Packages.xz"
    contents_gz  = os.path.join(CACHE_DIR, f"Contents-{arch}.gz")
    pkgs_xz      = os.path.join(CACHE_DIR, f"Packages-{arch}.xz")
    _dl(contents_url, contents_gz)
    _dl(pkgs_url, pkgs_xz)
    return contents_gz, pkgs_xz

def _iter_contents(contents_gz_path):
    with gzip.open(contents_gz_path, "rb") as g:
        for raw in g:
            try:
                line = raw.decode("utf-8", "ignore").rstrip("\n")
            except Exception:
                continue
            # форматы: "path/to/file  pkg1,pkg2" или "path/to/file pkg"
            if not line or " " not in line:
                continue
            path, pkgs = line.split(None, 1)
            yield path, pkgs.split(",")

def _load_packages(pkgs_xz_path):
    # вернём {pkg: version}
    data = lzma.open(pkgs_xz_path, "rb").read().decode("utf-8", "ignore")
    out = {}
    cur = {}
    for line in io.StringIO(data):
        line = line.rstrip("\n")
        if not line:
            if cur.get("Package") and cur.get("Version"):
                out[cur["Package"]] = cur["Version"]
            cur = {}
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            cur[k.strip()] = v.strip()
        else:
            # продолжение поля — игнорируем для простоты
            pass
    if cur.get("Package") and cur.get("Version"):
        out[cur["Package"]] = cur["Version"]
    return out

def guess_paths_for_soname(soname: str, arch: str):
    # типичные кандидаты для Debian multiarch
    trip = TRIPLET.get(arch, arch)
    candidates = [
        f"usr/lib/{trip}/{soname}",
        f"lib/{trip}/{soname}",
        f"usr/lib/{soname}",
        f"lib/{soname}",
    ]
    return candidates

def resolve_debian_by_indexes(soname: str, arch: str):
    """
    Возвращает (ecosystem, package, version, arch) или (None, None, None, None)
    """
    try:
        contents_gz, pkgs_xz = ensure_indexes(arch)
        paths = set(guess_paths_for_soname(soname, arch))
        found_pkg = None
        for path, pkgs in _iter_contents(contents_gz):
            if path in paths:
                # берём первый пакет-владелец
                found_pkg = pkgs[0]
                break
        if not found_pkg:
            # иногда SONAME с symlink'ами: попробуем без major (libssl.so -> libssl.so.3)
            m = re.match(r"^(.+)\.so(\.\d+)?$", soname)
            if m:
                base = m.group(1)
                for path, pkgs in _iter_contents(contents_gz):
                    if path.endswith(f"/{base}.so") or path.endswith(f"/{base}.so."):
                        found_pkg = pkgs[0]
                        break
        if not found_pkg:
            return (None, None, None, None)
        versions = _load_packages(pkgs_xz)
        ver = versions.get(found_pkg)
        if not ver:
            return (None, None, None, None)
        return ("Debian", found_pkg, ver, arch)
    except Exception:
        return (None, None, None, None)
