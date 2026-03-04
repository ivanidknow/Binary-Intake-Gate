#!/usr/bin/env python3
"""
Загрузчик внешних баз YARA-сигнатур для bin-gate.
Источники: Yara-Rules/rules, Neo23x0/signature-base.
Использование: python -m bin_gate.rules.updater --sync
"""
from __future__ import annotations
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Репозитории: (short_name, url, path_inside_repo с .yar)
# Malpedia: при наличии API/доступа можно добавить агрегатор правил.
REPOS = [
    ("Yara-Rules", "https://github.com/Yara-Rules/rules.git", ""),  # Общая база малвари
    ("Neo23x0", "https://github.com/Neo23x0/signature-base.git", "yara"),  # APT, хакерские утилиты
]


def get_external_dir() -> Path:
    return Path(__file__).resolve().parent / "external"


def _run(cmd: list, cwd: Path | None = None) -> tuple[bool, str]:
    try:
        r = subprocess.run(
            cmd,
            cwd=cwd or None,
            capture_output=True,
            text=True,
            timeout=300,
        )
        out = (r.stdout or "").strip() + "\n" + (r.stderr or "").strip()
        return r.returncode == 0, out
    except Exception as e:
        return False, str(e)


def sync_repo(name: str, url: str, subdir: str, external_root: Path) -> bool:
    """Клонирует репозиторий во временную папку и копирует .yar* в external_root/name/."""
    target = external_root / name
    target.mkdir(parents=True, exist_ok=True)
    tmp = external_root / f".tmp_{name}"
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True, exist_ok=True)

    ok, out = _run(["git", "clone", "--depth", "1", url, str(tmp)])
    if not ok:
        print(f"[{name}] git clone failed: {out[:500]}", file=sys.stderr)
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)
        return False

    src_dir = tmp / subdir if subdir else tmp
    count = 0
    if src_dir.exists():
        for p in src_dir.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix.lower().startswith(".yar"):
                rel = p.relative_to(src_dir)
                dest = target / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy2(p, dest)
                    count += 1
                except Exception as e:
                    print(f"[{name}] copy {p}: {e}", file=sys.stderr)
    else:
        for p in tmp.rglob("*.yar*"):
            if not p.is_file():
                continue
            rel = p.relative_to(tmp)
            dest = target / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(p, dest)
                count += 1
            except Exception as e:
                print(f"[{name}] copy {p}: {e}", file=sys.stderr)

    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"[{name}] {count} rule files synced to {target}")
    return count > 0


def sync_all() -> int:
    external_root = get_external_dir()
    external_root.mkdir(parents=True, exist_ok=True)
    ok_count = 0
    for name, url, subdir in REPOS:
        if sync_repo(name, url, subdir, external_root):
            ok_count += 1
    return ok_count


def main() -> int:
    ap = argparse.ArgumentParser(description="Sync external YARA rule databases")
    ap.add_argument("--sync", action="store_true", help="Download and sync Yara-Rules and Neo23x0 into rules/external/")
    args = ap.parse_args()
    if not args.sync:
        ap.print_help()
        return 0
    n = sync_all()
    return 0 if n > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
