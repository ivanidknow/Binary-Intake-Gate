# archive_dispatcher.py
"""
Streaming archive expander with in-memory processing support.

Key features:
- Generator-based extraction: files yielded as soon as extracted
- In-memory processing for files < 50MB (configurable via BIN_GATE_MEMORY_THRESHOLD_MB)
- Parallel worker feeding: extracted files sent to workers immediately
- RAM disk optimization: uses /dev/shm or BIN_GATE_TMPDIR for large files
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple, Dict, Any, Generator
import os, sys, time, stat, json, shutil, zipfile, tarfile, tempfile, gzip, bz2, lzma, hashlib, io

from .memory_stream import (
    MemoryFile, create_memory_file, get_optimal_tmpdir,
    MEMORY_THRESHOLD_BYTES
)

# Опционально: 7z/rar
try:
    import py7zr  # pip install py7zr
except Exception:
    py7zr = None
try:
    import rarfile  # pip install rarfile
except Exception:
    rarfile = None

# Расширения, которые считаем архивами (ZIP-формат)
ZIPLIKE_EXTS = {
    ".zip", ".jar", ".apk", ".aab", ".whl", ".vsix",
    ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
    ".odt", ".ods", ".odp"
}
# TAR + производные, включая OVA (это TAR-контейнер)
TARLIKE_EXTS = {".tar", ".tgz", ".tar.gz", ".tbz", ".tar.bz2", ".txz", ".tar.xz", ".ova"}
SINGLE_COMPRESS_EXTS = {".gz", ".bz2", ".xz"}
SEVENZ_EXTS = {".7z"}
RAR_EXTS = {".rar"}

DEFAULT_ZIP_PASSWORDS = [b"infected", b"malware", b"password", b"1234", b"1111"]

def _lower_suffixes(path: Path) -> tuple[str, str]:
    """
    Возвращает ('все_суффиксы_склеенные', 'последний_суффикс') — оба в нижнем регистре.
    Примеры:
      file.tar.gz -> ('.tar.gz', '.gz')
      file.tgz    -> ('.tgz', '.tgz')
      file.ova    -> ('.ova', '.ova')
    """
    sfx_all = ''.join(path.suffixes).lower()
    last = (path.suffix or "").lower()
    return sfx_all, last

def is_potential_archive(path: os.PathLike | str) -> bool:
    """
    Быстрый предикат «похоже на архив»: по расширению и нескольким сигнатурам.
    """
    p = Path(path)
    sfx_all, last = _lower_suffixes(p)

    # Явные TAR-подобные сдвоенные суффиксы (.tar.gz/.tgz) и .ova
    if sfx_all in TARLIKE_EXTS:
        return True

    # Одинарный суффикс (zip/7z/rar/tar/ova/…)
    if last in (ZIPLIKE_EXTS | TARLIKE_EXTS | SEVENZ_EXTS | RAR_EXTS | SINGLE_COMPRESS_EXTS):
        return True

    # Магические байты (на случай отсутствия расширения)
    try:
        with open(p, "rb") as f:
            sig = f.read(8)
        if sig.startswith(b"PK\x03\x04"):        # zip
            return True
        if sig.startswith(b"\x1f\x8b"):          # gzip
            return True
        if sig.startswith(b"7z\xbc\xaf'\x1c"):   # 7z
            return True
        if sig.startswith(b"Rar!\x1a\x07"):      # rar
            return True
    except Exception:
        pass
    return False

def _safe_join(base: Path, *parts: str) -> Path:
    """
    Безопасная сборка пути: не даст выйти за пределы base (path traversal).
    """
    dest = base.joinpath(*parts).resolve()
    if not str(dest).startswith(str(base.resolve())):
        raise RuntimeError(f"Unsafe path escapes base: {dest}")
    return dest

def _is_dangerous_member(name: str) -> bool:
    """
    Блокируем абсолютные пути и попытки '..' внутри архивов.
    """
    if name.startswith(("/", "\\")):
        return True
    if ".." in name.replace("\\", "/").split("/"):
        return True
    return False

def _disallow_symlinks(path: Path) -> None:
    """
    Не позволяем складывать symlink как реальный файл.
    """
    try:
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode):
            raise RuntimeError(f"Symlink extraction blocked: {path}")
    except FileNotFoundError:
        return

@dataclass
class Task:
    """
    Единица результата распаковки — «дочерний» файл из архива.
    
    Supports both file-backed and in-memory storage:
    - path: Path to file on disk (may be None for memory-only)
    - memory_file: MemoryFile for in-memory data (preferred for < 50MB)
    - data: Direct bytes access (loads from disk if needed)
    """
    path: Optional[Path] = None
    origin_chain: tuple[Path, ...] = field(default_factory=tuple)
    depth: int = 0
    size: int = 0
    mime_hint: str = ""
    memory_file: Optional[MemoryFile] = None
    name: str = ""  # Original filename
    
    @property
    def is_memory(self) -> bool:
        """True if data is in memory (not on disk)."""
        return self.memory_file is not None and self.memory_file.is_memory
    
    @property
    def data(self) -> bytes:
        """Get raw bytes (from memory or disk)."""
        if self.memory_file:
            return self.memory_file.data
        if self.path and self.path.exists():
            return self.path.read_bytes()
        return b""
    
    @property
    def effective_path(self) -> Path:
        """Get path, creating temp file if memory-only."""
        if self.path:
            return self.path
        if self.memory_file:
            return self.memory_file.ensure_on_disk()
        raise ValueError("Task has no path or memory_file")
    
    def cleanup(self) -> None:
        """Release resources."""
        if self.memory_file:
            self.memory_file.cleanup()


MAX_CHILDREN_PER_ARCHIVE = 300


@dataclass
class ArchiveExpander:
    """
    Универсальный распаковщик для ZIP/TAR/7z/RAR и одиночных .gz/.bz2/.xz.

    Особенности:
      - Защита от path traversal и symlink.
      - Лимиты по сумме байт, количеству детей, времени на архив.
      - Лимит файлов на один архив (max_children_per_archive): при превышении — предупреждение и пропуск остальных.
      - Порог skip_extract_larger_mb: для TAR/OVA можно НЕ извлекать гигантские члены
        (например, .vmdk), а создать лёгкий .meta.json с метаданными.
    """
    max_depth: int = 2
    max_children: int = 5000
    max_children_per_archive: int = MAX_CHILDREN_PER_ARCHIVE
    max_expanded_size: int = 512 * 1024 * 1024
    per_archive_timeout: int = 90
    skip_extract_larger_mb: int = 0
    zip_passwords: Optional[Iterable[bytes]] = None
    keep_temp: bool = True
    verbose: bool = False

    temp_root: Path = field(default_factory=lambda: Path(tempfile.mkdtemp(prefix="archscan_")))
    tasks: List[Task] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=lambda: {
        "archives": 0,
        "children": 0,
        "bytes": 0,
        "skipped_encrypted": 0,
        "errors": 0,
        "long_path_remapped": 0,
        "skipped_large": 0,
    })

    # ---------- Вспомогательные ----------
    def _remap_long_path(self, base_dir: Path, depth_tag: str, member_name: str) -> str:
        """
        Для Windows: если итоговый путь > ~240 символов — заменить на __long__/<sha1>.<ext>.
        На *nix возвращает исходное имя.
        """
        if os.name != "nt":
            return member_name

        intended = (base_dir / depth_tag / member_name).resolve()
        if len(str(intended)) < 240:  # запас до 260
            return member_name

        tail = member_name.replace("\\", "/").split("/")[-1]
        _, ext = os.path.splitext(tail)
        h = hashlib.sha1(member_name.encode("utf-8", "ignore")).hexdigest()[:16]
        self.stats["long_path_remapped"] += 1
        return "__long__/" + h + ext

    def _check_limits(self, add_bytes=0, add_children=0):
        """
        Глобальные лимиты на сумму извлечённых байт и количество файлов.
        """
        self.stats["bytes"] += add_bytes
        self.stats["children"] += add_children
        if self.stats["bytes"] > self.max_expanded_size:
            raise RuntimeError("expanded size limit")
        if self.stats["children"] > self.max_children:
            raise RuntimeError("children limit")

    def _task(self, path: Path, chain: tuple[Path, ...], depth: int):
        """
        Регистрирует распакованный файл как задачу для последующего анализа.
        При превышении max_children_per_archive выбрасывает RuntimeError("per_archive_children_limit").
        """
        if getattr(self, "_current_archive_children", 0) >= self.max_children_per_archive:
            raise RuntimeError("per_archive_children_limit")
        _disallow_symlinks(path)
        sz = path.stat().st_size if path.exists() else 0
        self._check_limits(add_bytes=sz, add_children=1)
        self._current_archive_children = getattr(self, "_current_archive_children", 0) + 1
        self.tasks.append(Task(path=path, origin_chain=chain, depth=depth, size=sz))

    def cleanup(self) -> None:
        """
        Удалить временный каталог (если keep_temp=False).
        """
        if self.keep_temp:
            return
        try:
            shutil.rmtree(self.temp_root, ignore_errors=True)
        except Exception:
            pass

    # ---------- Публичный API ----------
    def expand(self, archive_path: os.PathLike | str) -> List[Task]:
        """
        Распаковать указанный архив и вернуть список дочерних задач (Task).
        Блокирующая версия - ждёт полной распаковки.
        """
        p = Path(archive_path)
        if not p.exists() or not p.is_file():
            return []
        try:
            self._expand_recursive(p, self.temp_root, 0, (p,))
        except Exception as e:
            self.stats["errors"] += 1
            print(f"[archive] ERROR {p}: {e}", file=sys.stderr)
        return self.tasks
    
    def stream_expand(self, archive_path: os.PathLike | str) -> Generator[Task, None, None]:
        """
        Streaming распаковка - yield Task сразу после извлечения файла.
        
        Позволяет начать анализ мгновенно, не дожидаясь полной распаковки.
        Воркеры могут забирать Task из генератора параллельно.
        
        Usage:
            for task in expander.stream_expand(archive_path):
                # task доступен сразу после извлечения
                worker_queue.put(task)
        """
        p = Path(archive_path)
        if not p.exists() or not p.is_file():
            return
        
        try:
            yield from self._stream_recursive(p, self.temp_root, 0, (p,))
        except Exception as e:
            self.stats["errors"] += 1
            print(f"[archive] ERROR {p}: {e}", file=sys.stderr)
    
    def _stream_recursive(
        self, archive: Path, out_dir: Path, depth: int, chain: tuple[Path, ...]
    ) -> Generator[Task, None, None]:
        """Recursive streaming extraction."""
        if depth > self.max_depth:
            return
        
        start = time.time()
        self.stats["archives"] += 1
        self._current_archive_children = 0
        
        _, last = _lower_suffixes(archive)
        
        try:
            if last in ZIPLIKE_EXTS or zipfile.is_zipfile(archive):
                yield from self._stream_zip(archive, out_dir, depth, chain, start)
            elif tarfile.is_tarfile(archive):
                yield from self._stream_tar(archive, out_dir, depth, chain, start)
            elif last in SEVENZ_EXTS and py7zr is not None:
                yield from self._stream_7z(archive, out_dir, depth, chain, start)
            elif last in RAR_EXTS and rarfile is not None:
                yield from self._stream_rar(archive, out_dir, depth, chain, start)
            elif last in SINGLE_COMPRESS_EXTS:
                yield from self._stream_single(archive, out_dir, depth, chain, start)
        except Exception as e:
            self.stats["errors"] += 1
            print(f"[archive] stream error {archive}: {e}", file=sys.stderr)
    
    def _create_task_from_data(
        self, name: str, data: bytes, chain: tuple[Path, ...], depth: int
    ) -> Task:
        """Create Task with in-memory or disk storage based on size."""
        size = len(data)
        
        if size <= MEMORY_THRESHOLD_BYTES:
            # In-memory storage
            mf = create_memory_file(name, data, chain, depth)
            return Task(
                path=None,
                origin_chain=chain,
                depth=depth,
                size=size,
                memory_file=mf,
                name=name,
            )
        else:
            # Disk storage (use optimal tmpdir)
            mf = create_memory_file(name, data, chain, depth, force_disk=True, base_dir=self.temp_root)
            return Task(
                path=mf.path,
                origin_chain=chain,
                depth=depth,
                size=size,
                memory_file=mf,
                name=name,
            )
    
    def _stream_zip(
        self, p: Path, out: Path, depth: int, chain: tuple[Path, ...], start: float
    ) -> Generator[Task, None, None]:
        """Streaming ZIP extraction."""
        pwds = list(self.zip_passwords or DEFAULT_ZIP_PASSWORDS)
        try:
            with zipfile.ZipFile(p) as z:
                for zi in z.infolist():
                    if time.time() - start > self.per_archive_timeout:
                        break
                    
                    name = zi.filename
                    if _is_dangerous_member(name) or name.endswith("/"):
                        continue
                    
                    if self._current_archive_children >= self.max_children_per_archive:
                        print(f"[archive] WARNING: {p.name}: reached {self.max_children_per_archive} limit", file=sys.stderr)
                        break
                    
                    data = None
                    try:
                        with z.open(zi) as src:
                            data = src.read()
                    except RuntimeError as e:
                        if "password" in str(e).lower():
                            for pwd in pwds:
                                try:
                                    with z.open(zi, pwd=pwd) as src:
                                        data = src.read()
                                        break
                                except Exception:
                                    continue
                            if data is None:
                                self.stats["skipped_encrypted"] += 1
                                continue
                        else:
                            raise
                    
                    if data is None:
                        continue
                    
                    # Create task (memory or disk based on size)
                    task = self._create_task_from_data(name, data, chain + (p,), depth + 1)
                    self._current_archive_children += 1
                    self.stats["children"] += 1
                    self.stats["bytes"] += len(data)
                    
                    # Yield immediately for parallel processing
                    yield task
                    
                    # Check for nested archives
                    if depth + 1 <= self.max_depth:
                        # Need path on disk for nested archive extraction
                        task_path = task.effective_path
                        if is_potential_archive(task_path):
                            yield from self._stream_recursive(task_path, out, depth + 1, chain + (p,))
        except Exception as e:
            self.stats["errors"] += 1
            print(f"[archive] stream_zip error {p}: {e}", file=sys.stderr)
    
    def _stream_tar(
        self, p: Path, out: Path, depth: int, chain: tuple[Path, ...], start: float
    ) -> Generator[Task, None, None]:
        """Streaming TAR extraction."""
        try:
            with tarfile.open(p, "r:*") as tf:
                for ti in tf:
                    if time.time() - start > self.per_archive_timeout:
                        break
                    if not ti.isfile():
                        continue
                    if _is_dangerous_member(ti.name):
                        continue
                    
                    if self._current_archive_children >= self.max_children_per_archive:
                        print(f"[archive] WARNING: {p.name}: reached {self.max_children_per_archive} limit", file=sys.stderr)
                        break
                    
                    # Handle large files
                    if self.skip_extract_larger_mb > 0 and ti.size > self.skip_extract_larger_mb * 1024 * 1024:
                        meta = {
                            "skipped": True,
                            "archive": str(p),
                            "member": ti.name,
                            "member_size": ti.size,
                            "reason": "over_limit",
                        }
                        meta_bytes = json.dumps(meta, ensure_ascii=False).encode("utf-8")
                        task = self._create_task_from_data(ti.name + ".meta.json", meta_bytes, chain + (p,), depth + 1)
                        self.stats["skipped_large"] += 1
                        yield task
                        continue
                    
                    f = tf.extractfile(ti)
                    if not f:
                        continue
                    data = f.read()
                    
                    task = self._create_task_from_data(ti.name, data, chain + (p,), depth + 1)
                    self._current_archive_children += 1
                    self.stats["children"] += 1
                    self.stats["bytes"] += len(data)
                    
                    yield task
                    
                    # Nested archives
                    if depth + 1 <= self.max_depth:
                        task_path = task.effective_path
                        if is_potential_archive(task_path):
                            yield from self._stream_recursive(task_path, out, depth + 1, chain + (p,))
        except Exception as e:
            self.stats["errors"] += 1
            print(f"[archive] stream_tar error {p}: {e}", file=sys.stderr)
    
    def _stream_7z(
        self, p: Path, out: Path, depth: int, chain: tuple[Path, ...], start: float
    ) -> Generator[Task, None, None]:
        """Streaming 7z extraction (requires py7zr)."""
        if py7zr is None:
            return
        try:
            with py7zr.SevenZipFile(p, "r") as z:
                for name, bio in z.read().items():
                    if self._current_archive_children >= self.max_children_per_archive:
                        break
                    
                    data = bio.read() if hasattr(bio, "read") else bio
                    if isinstance(data, io.BytesIO):
                        data = data.getvalue()
                    
                    task = self._create_task_from_data(name, data, chain + (p,), depth + 1)
                    self._current_archive_children += 1
                    self.stats["children"] += 1
                    self.stats["bytes"] += len(data)
                    
                    yield task
                    
                    if depth + 1 <= self.max_depth:
                        task_path = task.effective_path
                        if is_potential_archive(task_path):
                            yield from self._stream_recursive(task_path, out, depth + 1, chain + (p,))
        except Exception as e:
            self.stats["errors"] += 1
            print(f"[archive] stream_7z error {p}: {e}", file=sys.stderr)
    
    def _stream_rar(
        self, p: Path, out: Path, depth: int, chain: tuple[Path, ...], start: float
    ) -> Generator[Task, None, None]:
        """Streaming RAR extraction (requires rarfile)."""
        if rarfile is None:
            return
        try:
            with rarfile.RarFile(p) as rf:
                for ri in rf.infolist():
                    if ri.isdir():
                        continue
                    if _is_dangerous_member(ri.filename):
                        continue
                    if self._current_archive_children >= self.max_children_per_archive:
                        break
                    
                    with rf.open(ri) as src:
                        data = src.read()
                    
                    task = self._create_task_from_data(ri.filename, data, chain + (p,), depth + 1)
                    self._current_archive_children += 1
                    self.stats["children"] += 1
                    self.stats["bytes"] += len(data)
                    
                    yield task
                    
                    if depth + 1 <= self.max_depth:
                        task_path = task.effective_path
                        if is_potential_archive(task_path):
                            yield from self._stream_recursive(task_path, out, depth + 1, chain + (p,))
        except Exception as e:
            self.stats["errors"] += 1
            print(f"[archive] stream_rar error {p}: {e}", file=sys.stderr)
    
    def _stream_single(
        self, p: Path, out: Path, depth: int, chain: tuple[Path, ...], start: float
    ) -> Generator[Task, None, None]:
        """Streaming single-file compression (.gz, .bz2, .xz)."""
        opener = gzip.open if p.suffix.lower() == ".gz" else bz2.open if p.suffix.lower() == ".bz2" else lzma.open
        try:
            with opener(p, "rb") as src:
                data = src.read()
            
            task = self._create_task_from_data(p.stem, data, chain + (p,), depth + 1)
            self._current_archive_children += 1
            self.stats["children"] += 1
            self.stats["bytes"] += len(data)
            
            yield task
        except Exception as e:
            self.stats["errors"] += 1
            print(f"[archive] stream_single error {p}: {e}", file=sys.stderr)

    # ---------- Реализации распаковки ----------
    def _expand_recursive(self, archive: Path, out_dir: Path, depth: int, chain: tuple[Path, ...]) -> None:
        if depth > self.max_depth:
            return
        start = time.time()
        self.stats["archives"] += 1
        self._current_archive_children = 0

        _, last = _lower_suffixes(archive)

        try:
            if last in ZIPLIKE_EXTS or zipfile.is_zipfile(archive):
                self._expand_zip(archive, out_dir, depth, chain, start)
            elif tarfile.is_tarfile(archive):
                # включает .tar, .tar.gz, .tgz, .ova и т.д.
                self._expand_tar(archive, out_dir, depth, chain, start)
            elif last in SEVENZ_EXTS and py7zr is not None:
                self._expand_7z(archive, out_dir, depth, chain, start)
            elif last in RAR_EXTS and rarfile is not None:
                self._expand_rar(archive, out_dir, depth, chain, start)
            elif last in SINGLE_COMPRESS_EXTS:
                self._expand_single(archive, out_dir, depth, chain, start)
            else:
                # Неизвестный формат — молча пропускаем
                return
        except Exception as e:
            self.stats["errors"] += 1
            print(f"[archive] expand error {archive}: {e}", file=sys.stderr)

    def _expand_zip(self, p: Path, out: Path, depth: int, chain: tuple[Path, ...], start: float):
        pwds = list(self.zip_passwords or DEFAULT_ZIP_PASSWORDS)
        try:
            with zipfile.ZipFile(p) as z:
                for zi in z.infolist():
                    if time.time() - start > self.per_archive_timeout:
                        raise RuntimeError("zip timeout")

                    name = zi.filename
                    if _is_dangerous_member(name) or name.endswith("/"):
                        continue

                    data = None
                    try:
                        with z.open(zi) as src:
                            data = src.read()
                    except RuntimeError as e:
                        if "password" in str(e).lower():
                            for pwd in pwds:
                                try:
                                    with z.open(zi, pwd=pwd) as src:
                                        data = src.read()
                                        break
                                except Exception:
                                    continue
                            if data is None:
                                self.stats["skipped_encrypted"] += 1
                                continue
                        else:
                            raise

                    rel = self._remap_long_path(out, f"{p.stem}_d{depth}", name)
                    target = _safe_join(out, f"{p.stem}_d{depth}", rel)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with open(target, "wb") as dst:
                        dst.write(data)

                    self._task(target, chain + (p,), depth + 1)

                    if depth + 1 <= self.max_depth and is_potential_archive(target):
                        self._expand_recursive(target, out, depth + 1, chain + (p,))
        except RuntimeError as e:
            if "per_archive_children_limit" in str(e):
                print(f"[archive] WARNING: {p.name}: exceeded {self.max_children_per_archive} files per archive, skipping rest", file=sys.stderr)
            else:
                raise

    def _expand_tar(self, p: Path, out: Path, depth: int, chain: tuple[Path, ...], start: float):
        try:
            with tarfile.open(p, "r:*") as tf:
                for ti in tf:
                    if time.time() - start > self.per_archive_timeout:
                        raise RuntimeError("tar timeout")
                    if not ti.isfile():
                        continue
                    if _is_dangerous_member(ti.name):
                        continue

                    # Порог на большие файлы (например, .vmdk) — создаём лёгкий плейсхолдер
                    if self.skip_extract_larger_mb > 0 and ti.size > self.skip_extract_larger_mb * 1024 * 1024:
                        rel = self._remap_long_path(out, f"{p.stem}_d{depth}", ti.name + ".meta.json")
                        target = _safe_join(out, f"{p.stem}_d{depth}", rel)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        meta = {
                            "skipped": True,
                            "archive": str(p),
                            "member": ti.name,
                            "member_size": ti.size,
                            "reason": "over_limit",
                            "limit_mb": self.skip_extract_larger_mb,
                        }
                        with open(target, "w", encoding="utf-8") as dst:
                            json.dump(meta, dst, ensure_ascii=False, indent=2)
                        self.stats["skipped_large"] += 1
                        self._task(target, chain + (p,), depth + 1)
                    else:
                        f = tf.extractfile(ti)
                        if not f:
                            continue
                        data = f.read()

                        rel = self._remap_long_path(out, f"{p.stem}_d{depth}", ti.name)
                        target = _safe_join(out, f"{p.stem}_d{depth}", rel)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with open(target, "wb") as dst:
                            dst.write(data)

                        self._task(target, chain + (p,), depth + 1)

                    # Рекурсивно раскрываем вложенные архивы
                    if depth + 1 <= self.max_depth and is_potential_archive(target):
                        self._expand_recursive(target, out, depth + 1, chain + (p,))
        except RuntimeError as e:
            if "per_archive_children_limit" in str(e):
                print(f"[archive] WARNING: {p.name}: exceeded {self.max_children_per_archive} files per archive, skipping rest", file=sys.stderr)
            else:
                raise

    def _expand_7z(self, p: Path, out: Path, depth: int, chain: tuple[Path, ...], start: float):
        if py7zr is None:
            return
        try:
            base = _safe_join(out, f"{p.stem}_d{depth}")
            with py7zr.SevenZipFile(p, "r") as z:
                z.extractall(path=base)
            for r, _, files in os.walk(base):
                for fn in files:
                    child = Path(r) / fn
                    self._task(child, chain + (p,), depth + 1)
                    if depth + 1 <= self.max_depth and is_potential_archive(child):
                        self._expand_recursive(child, out, depth + 1, chain + (p,))
        except RuntimeError as e:
            if "per_archive_children_limit" in str(e):
                print(f"[archive] WARNING: {p.name}: exceeded {self.max_children_per_archive} files per archive, skipping rest", file=sys.stderr)
            else:
                raise

    def _expand_rar(self, p: Path, out: Path, depth: int, chain: tuple[Path, ...], start: float):
        if rarfile is None:
            return
        try:
            base = _safe_join(out, f"{p.stem}_d{depth}")
            with rarfile.RarFile(p) as rf:
                for ri in rf.infolist():
                    if ri.isdir():
                        continue
                    if _is_dangerous_member(ri.filename):
                        continue
                    target = _safe_join(base, ri.filename)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with rf.open(ri) as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    self._task(target, chain + (p,), depth + 1)
                    if depth + 1 <= self.max_depth and is_potential_archive(target):
                        self._expand_recursive(target, out, depth + 1, chain + (p,))
        except RuntimeError as e:
            if "per_archive_children_limit" in str(e):
                print(f"[archive] WARNING: {p.name}: exceeded {self.max_children_per_archive} files per archive, skipping rest", file=sys.stderr)
            else:
                raise

    def _expand_single(self, p: Path, out: Path, depth: int, chain: tuple[Path, ...], start: float):
        opener = gzip.open if p.suffix.lower() == ".gz" else bz2.open if p.suffix.lower() == ".bz2" else lzma.open
        base = _safe_join(out, f"{p.stem}_d{depth}")
        base.mkdir(parents=True, exist_ok=True)
        target = base / p.stem
        with opener(p, "rb") as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst)
        self._task(target, chain + (p,), depth + 1)
