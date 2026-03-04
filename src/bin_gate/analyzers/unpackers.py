# unpackers.py — встроенные распаковщики: UPX, PyInstaller/Nuitka PYZ, MSI CustomAction, SFX (v1.2)
from __future__ import annotations
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# PyInstaller: MEI\x0c, PYZ magic
MEI_MAGIC = b"MEI\x0c"
PYZ_MAGIC = b"PYZ\x00"
PYINSTALLER_MAGIC = b"PyInstaller"


def unpack_upx(path: Path, timeout_sec: int = 30) -> Optional[Path]:
    """
    Распаковка UPX. Вызывает upx -d если доступен; иначе возвращает None.
    Копирует файл во временный, распаковывает в -o, возвращает путь к распакованному.
    Вызывающий должен удалить временный файл после использования (worker делает unlink).
    """
    path = Path(path)
    if not path.exists() or not path.is_file():
        return None
    upx_bin = shutil.which("upx")
    if not upx_bin:
        return None
    try:
        out_fd, out_path = tempfile.mkstemp(suffix=".unpacked", prefix="bin_gate_upx_")
        import os
        try:
            os.close(out_fd)
            out_p = Path(out_path)
            shutil.copy2(path, out_p)
            proc = subprocess.run(
                [upx_bin, "-d", str(out_p)],
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
            if proc.returncode != 0 or not out_p.exists():
                out_p.unlink(missing_ok=True)
                return None
            return out_p
        except Exception:
            Path(out_path).unlink(missing_ok=True)
            raise
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def extract_pyinstaller_pyz(path: Path, max_bytes: int = 10 * 1024 * 1024) -> List[Tuple[str, bytes]]:
    """
    Распаковщик первого уровня PyInstaller/Nuitka: поиск PYZ/MEI и извлечение сырых блоков
    для последующего статического анализа Python-слоя. Возвращает список (имя, данные).
    """
    path = Path(path)
    if not path.exists() or not path.is_file():
        return []
    try:
        data = path.read_bytes()
    except Exception:
        return []
    if len(data) > max_bytes:
        data = data[:max_bytes]
    out: List[Tuple[str, bytes]] = []
    off = 0
    idx = 0
    while True:
        pos = data.find(PYZ_MAGIC, off)
        if pos < 0:
            pos = data.find(MEI_MAGIC, off)
        if pos < 0:
            pos = data.find(PYINSTALLER_MAGIC, off)
        if pos < 0:
            break
        end = min(pos + 256 * 1024, len(data))
        chunk = data[pos:end]
        out.append((f"pyz_mei_block_{idx}", chunk))
        idx += 1
        off = pos + 1
    return out


def get_msi_custom_actions(path: Path) -> List[Dict[str, Any]]:
    """
    Глубокий разбор MSI: извлечение CustomAction для поиска запускаемых бинарных DLL.
    Возвращает список записей {action_id, type, source, target} (best-effort).
    При отсутствии парсера CustomAction таблицы возвращает [].
    """
    path = Path(path)
    if not path.exists() or path.suffix.lower() != ".msi":
        return []
    try:
        from .. import msi_support
        meta = getattr(msi_support, "get_msi_metadata", lambda p: {})(path)
        if not meta:
            return []
        custom = meta.get("CustomActions") or meta.get("custom_actions") or []
        if isinstance(custom, list):
            return [c for c in custom if isinstance(c, dict)]
        return []
    except Exception:
        return []


def is_sfx_archive(path: Path) -> bool:
    """
    Определение самораспаковывающихся архивов (WinRAR/7z), имитирующих инсталляторы.
    """
    path = Path(path)
    if not path.exists() or not path.is_file():
        return False
    try:
        head = path.read_bytes()[:32]
    except Exception:
        return False
    if b"Rar!\x1a\x07" in head[:8] or head[:4] == b"Rar!":
        return True
    if head[:4] == b"7z\xbc\xaf":
        return True
    if b"7z\xbc\xaf\x27\x1c" in head[:8]:
        return True
    return False
