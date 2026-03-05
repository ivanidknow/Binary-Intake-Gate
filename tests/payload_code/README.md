# Payload-as-Code — реальная компиляция артефактов для QA

Архитектура замены оверлеев на **компилируемый C/C++ код** для 100% покрытия матрицы MITRE ATT&CK.

## Структура

- **compiler_core.py** — CompilerCore: поиск MinGW/GCC, сборка PE (Windows) / ELF (Linux) / Mach-O (macOS).
- **artifact_registry.py** — ArtifactRegistry: сопоставление `test_id` (например `t1055_004`) с C-шаблоном, параметрами упаковки (UPX/MPRESS) и обфускации.
- **pipeline.py** — конвейер: компиляция + опционально упаковка (run_packer).
- **templates/** — C-исходники по техникам (Execution, Persistence, Defense Evasion, Credential Access).

## Масштаб 250+

При наличии **gcc/mingw** в PATH реестр (32 базовых шаблона + 44 pack-варианта upx/mpress + 49 алиасов + 9 комбо) даёт **125+** скомпилированных артефактов; вместе с **147** legacy overlay получается **250+** уникальных артефактов. Без компилятора `make artifacts` создаёт только 147 legacy.

## Добавление сценария

1. Создать файл в `templates/`, например `t1055_004_apc_injection.c`, с реальными вызовами API (QueueUserAPC, NtQueueApcThread и т.д.).
2. В `artifact_registry.py` в `_registry_list()` добавить:
   ```python
   ArtifactSpec("t1055_004_apc_injection", "T1055.004", "t1055_004_apc_injection.c", link_extra=[]),
   ```
3. Запустить `make artifacts` или `python -c "from pathlib import Path; import sys; sys.path.insert(0, 'tests'); from artifact_factory import build_all; build_all(Path('tests/artifacts'))"` из корня репозитория.

При наличии компилятора (gcc/mingw) артефакт будет собран из C и подставлен в `build_all` по ключу `t1055_004_apc_injection`.

## Конвейер усложнения

- **Obfuscation:** динамическое скрытие импортов (GetProcAddress по хэшам), XOR/AES строк — реализуется в самом шаблоне или отдельным этапом препроцессора.
- **Packing:** в ArtifactSpec задаётся `pack="upx"` или `"mpress"`; pipeline.run_packer вызывается после компиляции при `apply_pack=True`.
- **Энтропия:** искусственные секции или оверлей в artifact_factory при необходимости.

## Тесты

- `test_payload_code_behavioral_artifacts` — проверяет наличие поведенческих артефактов (emulation.api_calls/techniques, memory_dump_analysis).
- `test_attack_storyline_combo_risk` — проверяет комбо-риски: 2+ техники в одном артефакте (attack_storyline или несколько technique_hints).

Требование: шлюз должен «раздеть» артефакт до исходного состояния в памяти и выдать DENY при обнаружении.
