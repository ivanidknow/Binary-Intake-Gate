# Binary Intake Gate — сборка и тесты
.PHONY: test test-security clean clean-artifacts artifacts

# Директория тестовых артефактов (генерируется и удаляется при test-security)
TEST_ARTIFACTS_DIR ?= tests/artifacts

test:
	pytest tests/ -v --tb=short -x

# Запуск security/methodology тестов (семплы генерируются во временной директории pytest)
test-security:
	pytest tests/test_methodology.py -v --tb=short
	$(MAKE) clean-artifacts

# Только сгенерировать артефакты. Legacy overlay всегда; при наличии gcc/mingw добавляется Payload-as-Code (цель 250+).
artifacts:
	python -c "import sys; from pathlib import Path; sys.path.insert(0, 'tests'); from artifact_factory import build_all; paths = build_all(Path('$(TEST_ARTIFACTS_DIR)')); n=len(paths); print(n, 'artifacts'); print('250+ target:', 'OK' if n>=250 else 'Need gcc/mingw for Payload-as-Code to reach 250+')"
	@echo "Artifacts written to $(TEST_ARTIFACTS_DIR)"

# Удаление сгенерированных тестовых артефактов
clean-artifacts:
	python -c "import shutil; from pathlib import Path; p=Path('$(TEST_ARTIFACTS_DIR)'); shutil.rmtree(p, ignore_errors=True); print('Cleaned', p)"

clean: clean-artifacts
	rm -rf build/ dist/ *.egg-info .eggs
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
