# rules — внешние базы YARA-сигнатур и загрузчик
from pathlib import Path

def get_external_rules_dir() -> Path:
    """Корневая директория внешних правил (rules/external/)."""
    return Path(__file__).resolve().parent / "external"
