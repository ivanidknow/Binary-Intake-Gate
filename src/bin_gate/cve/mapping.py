from __future__ import annotations
from typing import Dict, Any, List, Optional
import re, yaml
from pathlib import Path

# расширенный список популярных либ (ELF + DLL)
_DEFAULT_PATTERNS = [
    # crypto/tls
    {"match": r"^libssl\.so\.(?P<ver>[\d\.]+)$",      "package": "openssl"},
    {"match": r"^libcrypto\.so\.(?P<ver>[\d\.]+)$",   "package": "openssl"},
    {"match": r"^libgnutls\.so\.(?P<ver>[\d\.]+)$",   "package": "gnutls"},
    {"match": r"^libgcrypt\.so\.(?P<ver>[\d\.]+)$",   "package": "libgcrypt20"},
    {"match": r"^libmbedcrypto\.so\.(?P<ver>[\d\.]+)$","package": "mbedtls"},
    {"match": r"^libmbedtls\.so\.(?P<ver>[\d\.]+)$",  "package": "mbedtls"},
    {"match": r"^libkrb5\.so\.(?P<ver>[\d\.]+)$",     "package": "krb5"},
    {"match": r"^libssh2?\.so\.(?P<ver>[\d\.]+)$",    "package": "libssh2"},

    # compression
    {"match": r"^libz(?:lib)?\.so\.(?P<ver>[\d\.]+)$","package": "zlib"},
    {"match": r"^liblzma\.so\.(?P<ver>[\d\.]+)$",     "package": "xz"},
    {"match": r"^libzstd\.so\.(?P<ver>[\d\.]+)$",     "package": "zstd"},
    {"match": r"^libbz2\.so\.(?P<ver>[\d\.]+)$",      "package": "bzip2"},

    # http/transfer
    {"match": r"^libcurl\.so\.(?P<ver>[\d\.]+)$",     "package": "curl"},
    {"match": r"^libnghttp2\.so\.(?P<ver>[\d\.]+)$",  "package": "nghttp2"},
    {"match": r"^libidn2?\.so\.(?P<ver>[\d\.]+)$",    "package": "libidn2"},
    {"match": r"^libcares\.so\.(?P<ver>[\d\.]+)$",    "package": "c-ares"},
    {"match": r"^libbrotli(?:enc|dec)?\.so\.(?P<ver>[\d\.]+)$","package": "brotli"},

    # parsers
    {"match": r"^libxml2\.so\.(?P<ver>[\d\.]+)$",     "package": "libxml2"},
    {"match": r"^libxslt\.so\.(?P<ver>[\d\.]+)$",     "package": "libxslt"},
    {"match": r"^libexpat\.so\.(?P<ver>[\d\.]+)$",    "package": "expat"},
    {"match": r"^libyaml-?0?\.so\.(?P<ver>[\d\.]+)$", "package": "libyaml"},

    # images/db
    {"match": r"^libpng(?:16)?\.so\.(?P<ver>[\d\.]+)$","package": "libpng"},
    {"match": r"^libjpeg(|-turbo)\.so\.(?P<ver>[\d\.]+)$","package": "libjpeg-turbo"},
    {"match": r"^libtiff\.so\.(?P<ver>[\d\.]+)$",     "package": "tiff"},
    {"match": r"^libwebp\.so\.(?P<ver>[\d\.]+)$",     "package": "libwebp"},
    {"match": r"^libsqlite3\.so\.(?P<ver>[\d\.]+)$",  "package": "sqlite3"},
    {"match": r"^libprotobuf(?:lite)?\.so\.(?P<ver>[\d\.]+)$","package": "protobuf"},

    # PE / Windows DLLs (best-effort)
    {"match": r"^libcrypto[-_]?([0-9]+|[\d_]+)\.dll$", "package": "openssl"},
    {"match": r"^libssl[-_]?([0-9]+|[\d_]+)\.dll$",    "package": "openssl"},
    {"match": r"^libcurl\.dll$",                      "package": "curl"},
    {"match": r"^zlib1\.dll$",                        "package": "zlib"},
    {"match": r"^vcruntime\d{2,}\.dll$",              "package": "msvc"},
    {"match": r"^msvcp\d{2,}\.dll$",                  "package": "msvc"},
    {"match": r"^bcrypt\.dll$",                       "package": "bcrypt"},  # системная; CVE редко нужны
]

def load_patterns(path: Optional[Path]) -> List[Dict[str, Any]]:
    pats = list(_DEFAULT_PATTERNS)
    if path and Path(path).exists():
        try:
            doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
            for e in doc.get("patterns") or []:
                if isinstance(e, dict) and e.get("match") and e.get("package"):
                    pats.append(e)
        except Exception:
            pass
    return pats

def map_dep_to_package(name: str, version_guess: Optional[str], patterns: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for p in patterns:
        m = re.match(p["match"], name, flags=re.IGNORECASE)
        if m:
            ver = version_guess
            if "ver" in m.groupdict() and m.group("ver"):
                ver = m.group("ver").replace("_", ".")
            return {"name": p["package"], "version_guess": ver}
    return None
