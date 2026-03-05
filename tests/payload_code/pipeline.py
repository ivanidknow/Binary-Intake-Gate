# tests/payload_code/pipeline.py — конвейер усложнения: обфускация, упаковка, энтропия
"""
Multi-stage Evasion: после компиляции опционально применяются:
- Obfuscation: XOR строк (на этапе исходника — заглушка; реальная обфускация в шаблонах).
- Packing: UPX/MPRESS (если доступны в PATH).
- Искусственные секции для энтропии > 7.2 — не меняем бинарник здесь (делается в artifact_factory overlay при необходимости).
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Optional

from .artifact_registry import ArtifactSpec
from .compiler_core import CompilerCore, CompileResult


def run_packer(path: Path, pack: str) -> bool:
    """Применяет упаковщик (upx/mpress) к path. Перезаписывает файл. Возвращает True при успехе."""
    if pack == "none":
        return True
    if pack == "upx":
        exe = shutil.which("upx")
        if not exe:
            return False
        try:
            subprocess.run([exe, "-q", str(path)], check=True, capture_output=True, timeout=60)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            return False
    if pack == "mpress":
        exe = shutil.which("mpress") or shutil.which("mpress.exe")
        if not exe:
            return False
        try:
            subprocess.run([exe, "-s", str(path)], check=True, capture_output=True, timeout=120)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            return False
    return False


def build_artifact(
    compiler: CompilerCore,
    spec: ArtifactSpec,
    out_path: Path,
    *,
    apply_pack: bool = False,
) -> CompileResult:
    """
    Собирает один артефакт: компиляция шаблона + опционально упаковка.
    apply_pack: при True вызывается run_packer(spec.pack).
    """
    res = compiler.compile_template(
        spec.template,
        out_path,
        link_extra=spec.link_extra if spec.link_extra else None,
    )
    if not res.success or not res.output_path:
        return res
    if apply_pack and spec.pack != "none":
        run_packer(res.output_path, spec.pack)
    return res
