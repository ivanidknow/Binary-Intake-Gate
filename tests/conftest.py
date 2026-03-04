# tests/conftest.py — pytest fixtures and artifact generation
from __future__ import annotations
import os
import sys
from pathlib import Path

import pytest

# Корень репозитория: для import bin_gate и import tests
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
for p in (REPO_ROOT, SRC):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
os.chdir(REPO_ROOT)


@pytest.fixture(scope="session")
def artifacts_dir(tmp_path_factory):
    """Временная директория для тестовых артефактов (очищается после сессии)."""
    return tmp_path_factory.mktemp("artifacts")


@pytest.fixture(scope="session")
def built_artifacts(artifacts_dir):
    """Генерирует все семплы и возвращает словарь name -> path."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "artifact_factory", REPO_ROOT / "tests" / "artifact_factory.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_all(Path(artifacts_dir))
