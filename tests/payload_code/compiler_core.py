# tests/payload_code/compiler_core.py — кросс-платформенная сборка PE/ELF/Mach-O из C/C++
"""
CompilerCore: автоматизированное создание исполняемых файлов "с нуля" через компилятор (MinGW/GCC),
а не через struct.pack. Обеспечивает реальные системные вызовы и импорты для эмуляции и детекции.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

# Корень репозитория (tests/payload_code -> repo root)
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


@dataclass
class CompileResult:
    success: bool
    output_path: Optional[Path] = None
    stderr: str = ""
    stdout: str = ""
    error: Optional[str] = None


def _windows_gcc_fallback() -> Optional[str]:
    """
    На Windows, если gcc не найден в PATH, проверяем типичные каталоги MSYS2/MinGW.
    Возвращает полный путь к gcc.exe или None.
    """
    if sys.platform != "win32":
        return None
    # Порядок: ucrt64 (часто по умолчанию), mingw64, mingw32, clang64
    for subdir in ("ucrt64", "mingw64", "mingw32", "clang64"):
        for root in ("C:\\msys64", "C:\\msys2", os.path.expandvars("%MSYS2_ROOT%") or ""):
            if not root:
                continue
            exe = Path(root) / subdir / "bin" / "gcc.exe"
            if exe.exists():
                return str(exe)
    return None


def _find_compiler() -> Tuple[Optional[str], str]:
    """
    Ищет компилятор для целевой платформы: Windows -> gcc/mingw (PE), иначе gcc/clang (ELF/Mach-O).
    Сначала проверяет PATH (shutil.which), затем на Windows — каталоги MSYS2 (gcc.exe).
    Returns (path_to_compiler, target_platform).
    """
    target = "pe" if sys.platform == "win32" else ("mach-o" if sys.platform == "darwin" else "elf")
    # Сначала ищем в PATH: gcc в приоритете (в т.ч. из MSYS2, если уже в PATH)
    candidates = ["gcc", "gcc.exe", "x86_64-w64-mingw32-gcc", "i686-w64-mingw32-gcc"]
    for name in candidates:
        path = shutil.which(name)
        if path:
            return path, target
    # Windows: fallback — явный поиск в C:\msys64\...\bin\gcc.exe
    if sys.platform == "win32":
        fallback = _windows_gcc_fallback()
        if fallback:
            return fallback, target
    return None, target


class CompilerCore:
    """
    Движок компиляции: компилирует C/C++ исходник в исполняемый файл (PE на Windows, ELF/Mach-O на других ОС).
    Поддерживает опции обфускации (строки не трогаем в базовом ядре — это этап пайплайна).
    """

    def __init__(self, work_dir: Optional[Path] = None):
        self.work_dir = work_dir or tempfile.mkdtemp(prefix="payload_code_")
        self._compiler_path: Optional[str] = None
        self._target: str = "pe"

    def ensure_compiler(self) -> bool:
        """Проверяет наличие компилятора и запоминает путь."""
        path, target = _find_compiler()
        self._compiler_path = path
        self._target = target
        return path is not None

    @property
    def available(self) -> bool:
        if self._compiler_path is None:
            self.ensure_compiler()
        return self._compiler_path is not None

    def compile(
        self,
        source_path: Path,
        out_path: Path,
        *,
        extra_cflags: Optional[List[str]] = None,
        link_extra: Optional[List[str]] = None,
    ) -> CompileResult:
        """
        Компилирует один C/C++ файл в исполняемый файл.
        - Windows (PE): gcc -o out.exe source.c [-l...]
        - Linux (ELF): gcc -o out source.c
        - macOS (Mach-O): clang/gcc -o out source.c
        """
        if not self.available:
            return CompileResult(
                success=False,
                error="Compiler not found (install MinGW/GCC for PE, or GCC/clang for ELF/Mach-O)",
            )
        source_path = Path(source_path).resolve()
        if not source_path.exists():
            return CompileResult(success=False, error=f"Source not found: {source_path}")
        out_path = Path(out_path).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        cflags = list(extra_cflags or [])
        if self._target == "pe":
            # Минимальные флаги для PE: статическая линковка CRT по желанию не делаем, чтобы были импорты
            cflags.extend(["-O0", "-Wall", "-Wno-unused"])
        else:
            cflags.extend(["-O0", "-Wall", "-Wno-unused"])

        # Порядок для gcc: компилятор -o out [cflags] source.c [link_extra]; библиотеки в конце командной строки
        cmd = [self._compiler_path, "-o", str(out_path)] + cflags + [str(source_path)]
        if link_extra:
            cmd.extend(link_extra)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(source_path.parent),
                env=os.environ.copy(),
            )
            if proc.returncode != 0:
                return CompileResult(
                    success=False,
                    stderr=proc.stderr or "",
                    stdout=proc.stdout or "",
                    error=f"Compile failed with exit code {proc.returncode}",
                )
            if not out_path.exists():
                return CompileResult(success=False, error="Output file was not created")
            return CompileResult(
                success=True,
                output_path=out_path,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
            )
        except subprocess.TimeoutExpired:
            return CompileResult(success=False, error="Compilation timeout (120s)")
        except Exception as e:
            return CompileResult(success=False, error=str(e))

    def compile_template(
        self,
        template_name: str,
        out_path: Path,
        *,
        extra_cflags: Optional[List[str]] = None,
        link_extra: Optional[List[str]] = None,
    ) -> CompileResult:
        """
        Компилирует шаблон из tests/payload_code/templates/ по имени (например t1059_001_powershell.c).
        """
        # Поддержка и .c и без расширения
        base = template_name if template_name.endswith(".c") else f"{template_name}.c"
        path = _TEMPLATES_DIR / base
        if not path.exists():
            return CompileResult(success=False, error=f"Template not found: {path}")
        return self.compile(path, out_path, extra_cflags=extra_cflags, link_extra=link_extra)
