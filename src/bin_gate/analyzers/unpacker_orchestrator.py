# unpacker_orchestrator.py — диспетчеризация распаковки: UPX/MPRESS → статический распаковщик; Themida/VMProtect → Speakeasy aggressive_emulation
from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

# Пакеры с статической распаковкой
STATIC_UNPACK_PACKERS = frozenset({"upx", "mpress"})
# Протекторы для агрессивной эмуляции (Speakeasy, extended timeout/max_api_calls)
AGGRESSIVE_EMULATION_PROTECTORS = frozenset({"themida", "vmprotect", "enigma", "obsidium"})


def _normalize_packer(name: str) -> str:
    return (name or "").strip().lower()


def get_packer_families(die_info: Optional[Dict[str, Any]], obfuscation: Optional[Dict[str, Any]]) -> List[str]:
    """Собирает список семейств упаковщиков/протекторов из DIE и obfuscation."""
    families: List[str] = []
    if die_info and isinstance(die_info, dict):
        for d in die_info.get("detects") or []:
            if not isinstance(d, dict):
                continue
            name = d.get("name") or d.get("sName") or ""
            dtype = (d.get("type") or d.get("sType") or "").lower()
            if name and dtype in ("packer", "protector", "cryptor"):
                families.append(_normalize_packer(name))
        pf = die_info.get("packer_families") or []
        families.extend(_normalize_packer(str(p)) for p in pf)
    if obfuscation and isinstance(obfuscation, dict):
        for p in obfuscation.get("packer_families") or []:
            families.append(_normalize_packer(str(p)))
    return list(dict.fromkeys(families))


def get_unpack_decision(
    path: Path,
    die_info: Optional[Dict[str, Any]] = None,
    obfuscation: Optional[Dict[str, Any]] = None,
    packer_families_override: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Решение по распаковке на основе DIE/obfuscation.
    Возвращает:
      action: "static_unpack" | "aggressive_emulation" | None
      unpacked_path: путь к распакованному файлу (если action=static_unpack и распаковка выполнена)
      aggressive_emulation: True если нужна эмуляция с extended timeout/max_api_calls
      packer_families: список обнаруженных семейств
    """
    path = Path(path)
    families = packer_families_override if packer_families_override is not None else get_packer_families(die_info, obfuscation)
    decision: Dict[str, Any] = {
        "action": None,
        "unpacked_path": None,
        "aggressive_emulation": False,
        "packer_families": families,
    }
    for p in families:
        if p in STATIC_UNPACK_PACKERS:
            decision["action"] = "static_unpack"
            break
        if p in AGGRESSIVE_EMULATION_PROTECTORS:
            decision["aggressive_emulation"] = True
            if decision["action"] is None:
                decision["action"] = "aggressive_emulation"
            break
    if decision["action"] == "static_unpack" and path.exists():
        if "upx" in families:
            try:
                from .unpackers import unpack_upx
                unpacked = unpack_upx(path, timeout_sec=25)
                if unpacked:
                    decision["unpacked_path"] = str(unpacked)
            except Exception:
                pass
        # MPRESS: статический распаковщик не реализован — оставляем unpacked_path=None
    return decision


def apply_unpack_decision_for_yara(
    path: Path,
    die_info: Optional[Dict[str, Any]] = None,
    obfuscation: Optional[Dict[str, Any]] = None,
) -> Tuple[Path, Optional[Path]]:
    """
    Для пайплайна YARA: возвращает (path_for_yara, temp_path_to_cleanup).
    Если статическая распаковка успешна — path_for_yara = unpacked_path, иначе исходный path.
    temp_path_to_cleanup — распакованный файл, который нужно удалить после использования.
    """
    decision = get_unpack_decision(path, die_info=die_info, obfuscation=obfuscation)
    if decision.get("unpacked_path") and Path(decision["unpacked_path"]).exists():
        return Path(decision["unpacked_path"]), Path(decision["unpacked_path"])
    return path, None
