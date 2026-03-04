# streaming_reader.py — безопасное чтение «раздутых» файлов для предотвращения OOM (v2.0)
# Для файлов > 200 МБ: только заголовки, Entry Point, импорты, оверлей — без загрузки padding в память.

from __future__ import annotations
from pathlib import Path
from typing import Optional, Tuple

# Порог размера для «ленивого» режима (не загружать весь файл в память)
GIANT_FILE_THRESHOLD_BYTES = 200 * 1024 * 1024  # 200 MB


def is_giant_file(path: Path, threshold: int = GIANT_FILE_THRESHOLD_BYTES) -> bool:
    """Возвращает True, если размер файла превышает порог (по умолчанию 200 МБ)."""
    try:
        return path.stat().st_size > threshold
    except OSError:
        return False


def read_head(path: Path, size: int = 1024 * 1024) -> bytes:
    """Читает только первые size байт файла (без загрузки всего в память)."""
    with path.open("rb") as f:
        return f.read(size)


def read_tail(path: Path, size: int = 2 * 1024 * 1024) -> bytes:
    """Читает последние size байт файла (оверлей и т.д.)."""
    total = path.stat().st_size
    if total <= size:
        return path.read_bytes()
    with path.open("rb") as f:
        f.seek(max(0, total - size))
        return f.read()


def read_pe_lazy(
    path: Path,
    header_size: int = 64 * 1024,
    overlay_tail_size: int = 4 * 1024 * 1024,
) -> Tuple[bytes, Optional[bytes], bool]:
    """
    Для PE-подобного файла при «гигантском» размере читает только:
    - заголовки (первые header_size байт),
    - оверлей (последние overlay_tail_size байт).
    Возвращает (head_bytes, overlay_bytes, is_giant).
    Если файл не гигантский — overlay_bytes = None (можно прочитать файл целиком снаружи).
    """
    try:
        total = path.stat().st_size
    except OSError:
        return (b"", None, False)
    is_giant = total > GIANT_FILE_THRESHOLD_BYTES
    head = read_head(path, header_size)
    overlay: Optional[bytes] = None
    if is_giant:
        overlay = read_tail(path, overlay_tail_size)
    return (head, overlay, is_giant)


def open_stream(path: Path, chunk_size: int = 1024 * 1024):
    """
    Итератор по чанкам файла для безопасного чтения без OOM.
    Файл закрывается после завершения итерации.
    Использование: for chunk in open_stream(path): ...
    """
    path = Path(path)

    def _gen():
        with path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    return
                yield chunk

    return _gen()
