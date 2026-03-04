# Binary Intake Gate

**Fast Binary Ingest Filter with 85+ MITRE ATT&CK Techniques coverage.**

Единая точка контроля для оценки бинарных файлов и пакетов при приёме в репозиторий, в PR и при релизах. Быстрая статическая проверка (due-diligence) без обязательного запуска кода, с политиками по профилям (dev/staging/prod) и отчётами в Markdown, человекочитаемом виде (RU) и SARIF.

---

## 1. Зачем эта тулза и кому она подойдёт

**Зачем:** перед допуском артефактов в сборку или прод нужно быстро ответить: файл подписан и без известных уязвимостей? Нет ли признаков упаковки, обфускации, маскировки под документ? Нет ли секретов, вредоносных сигнатур или отозванной подписи? Binary Intake Gate даёт один запуск по файлу или директории и на выходе — вердикт (allow / warn / deny), уровень риска 0–100 и обоснование.

**Кому подойдёт:**

- **DevSecOps / SRE** — встроить шлюз в пайплайн приёма бинарников и инсталляторов (PE, ELF, MSI, архивы); выход в CI по коду возврата и SARIF.
- **Security-команды** — проверка hardening (ASLR, DEP, CFG, HVCI), подписей и отзыва сертификатов, поиск секретов и CVE по SBOM.
- **Аналитики** — YARA, DIE, опционально capa и эмуляция; репутация через VirusTotal; человекочитаемый отчёт на русском с обоснованием вердикта.

Офлайн-режим (`--no-network`) и кэш по SHA-256 позволяют использовать тулзу в изолированных средах.

---

## 2. Методики и средства

Ниже — что проверяется и какими инструментами это делается.

| Область | Методика | Средство |
|--------|----------|----------|
| **Идентификация и целостность** | Хэши (SHA-256, MD5), энтропия файла/секций | Встроено (hashes, entropy) |
| **Hardening (PE)** | ASLR, DEP, CFG, HighEntropyVA, SafeSEH, CET (IBT/Shadow Stack), Load Config | pefile, `pe_hardening.py` |
| **Hardening (PE, Enterprise)** | HVCI (/INTEGRITYCHECK, W^X, релокации), WDAC/AppLocker bypass (LOLBins, эвристики загрузчика) | `pe_hardening.py` |
| **Hardening (ELF)** | PIE, NX, RELRO, Canary, RPATH/RUNPATH, CET | pyelftools, `elf_checksec.py` |
| **Подпись (PE)** | Наличие Authenticode, цепочка, метка времени | PowerShell (Windows), `signing_trust.py` |
| **Отзыв сертификата** | OCSP-проверка при наличии подписи | `signing_trust.py` (cryptography), скоринг +100 при revoked |
| **Проверка цепочки (не-Windows)** | Верификация Authenticode без PowerShell | osslsigncode |
| **Упаковщики / протекторы** | Детекция упаковщиков, компиляторов, VMProtect и др. | Docker: Detect It Easy (`horsicq/detectiteasy`) |
| **Сигнатуры и техники** | YARA (в т.ч. внешние базы Yara-Rules, Neo23x0), техники ATT&CK из метаданных | yara-python, `yara_scan.py`, `rules/updater.py` |
| **Глубокий анализ техник** | capa (по умолчанию выключен) | capa CLI, `--deep-capa` |
| **CVE по зависимостям** | SBOM → сканирование уязвимостей | Docker: Syft + Grype (`anchore/syft`, `anchore/grype`) |
| **Binary SCA (CWE)** | Статический анализ кода на CWE (buffer overflows, UAF и др.) | Docker: `fkiecad/cwe_checker` |
| **Поиск секретов** | Паттерны AWS, GitHub, Slack, ключи и т.д.; в т.ч. в оверлее PE | Gitleaks (Docker, `zricethezav/gitleaks`) + regex fallback |
| **Репутация** | Детекции, песочница, поведения по хэшу | VirusTotal API (опционально Playwright для загрузки) |
| **Политика и риск** | Правила CEL-стиля, пороги deny/warn, числовой риск 0–100, обоснование блокировки | `policy/engine.py`, `scoring.py` |
| **Эмуляция (опционально)** | Запуск PE в Speakeasy, дамп памяти, YARA/CVE по дампу | speakeasy-emulator или Docker-образ `bin-gate-emulation` |
| **Отчёты** | Краткий MD, человекочитаемый (RU) с обоснованием вердикта, HVCI/WDAC, секреты, CWE, SARIF | `reporters/` |

Docker используется для DIE, Syft, Grype, CWE checker и Gitleaks; при недоступности демона сканирование завершается с ошибкой (Hard Fail). Локальная эмуляция и capa опциональны.

---

## 3. Что нужно для сборки и как использовать

### Требования

- **Python** 3.10+ (рекомендуется 3.10–3.13)
- **Docker** — обязателен для DIE (Detect It Easy), CWE checker, CVE (Syft/Grype), Gitleaks
- **VirusTotal API Key** — опционально; для репутации и поведений по хэшу (переменная `VT_API_KEY` или `.env`)
- Опционально: capa (при `--deep-capa`), Playwright (для VT UI upload), oletools (глубокий разбор Office/макросов), speakeasy-emulator (локальная эмуляция)

### Сборка

**Вариант A — только установка пакета (рекомендуется для разработки):**

```bash
git clone <repo>
cd bin_intake_gateway
pip install -e .
# опционально: pip install -e ".[test]"   # для pytest
# опционально: pip install -e ".[emulation,oletools,visual,threatintel]"
```

После установки доступны команды `bin-gate` и `bin-gate-rules-sync`.

**Вариант B — полная сборка (Windows, PowerShell):**

Скрипт `build.ps1` собирает все компоненты:

1. **Python-пакет** — wheel в `dist/`, установка в режиме editable.
2. **bin-gate.exe** — один исполняемый файл в корне проекта (PyInstaller).
3. **Docker-образ эмуляции** — `bin-gate-emulation:latest` (если Docker доступен).

```powershell
.\build.ps1
```

В конце выводится итог: package, exe, Docker-образ. Запуск: `.\bin-gate.exe scan <путь>` или `bin-gate scan <путь>`.

**Синхронизация внешних YARA-правил (опционально):**

```bash
bin-gate-rules-sync --sync
# или: python -m bin_gate.rules.updater --sync
```

Требуются `git` и сеть; правила попадают в `src/bin_gate/rules/external/`.

### Быстрый старт

**Минимальный запуск (офлайн, без сети):**

```bash
bin-gate scan ./examples \
  --policy policy/policy.example.yaml \
  --no-network \
  --out report.md --human-out human_report.md
```

**С VirusTotal (только lookup по хэшу):**

```bash
export VT_API_KEY=...   # Windows PowerShell: $env:VT_API_KEY="..."
bin-gate scan ./examples \
  --policy policy/policy.example.yaml \
  --out report.md --human-out human_report.md
```

**С CVE (Syft + Grype через Docker):**

```bash
bin-gate scan ./examples \
  --policy policy/policy.example.yaml \
  --out report.md --human-out human_report.md
# Перед первым CVE-сканом: bin-gate cve-update
```

**Проверка готовности Docker и образов:**

```bash
bin-gate cve-check
bin-gate cve-check --pull   # подтянуть недостающие образы
```

### Основные флаги

| Назначение | Флаги |
|------------|--------|
| Политика и профиль | `--policy FILE`, `--profile dev\|staging\|prod` |
| Офлайн | `--no-network` |
| Отчёты | `--out report.md`, `--human-out human_report.md`, `--sarif-out file.sarif.json` |
| Вердикт и выход | `--fail-on none\|warn\|deny` |
| CVE | `--no-cve`, `--no-cve-update`, `--cve-timeout N` |
| DIE | `--no-die`, `--die-timeout N` |
| YARA | `--no-yara`, `--yara-rules DIR`, `--yara-timeout N` |
| capa | `--no-capa`, `--deep-capa`, `--capa-timeout N` |
| VirusTotal | `--no-vt`, `--vt-upload` (opt-in) |
| Эмуляция | `--emulation`, `--emulation-timeout N` |

Полный список: `bin-gate scan --help`.

### Конфигурация (.env)

Скопируйте `.env.example` в `.env` и при необходимости задайте:

- `VT_API_KEY` — для VirusTotal
- `BIN_GATE_PROFILE` — профиль по умолчанию (dev)
- `BIN_GATE_GITLEAKS` — 1/0 (включить/выключить Gitleaks для секретов)
- `BIN_GATE_PROJECT_ROOT` — корень проекта (для отчёта Gitleaks и логов)

Остальные переменные см. в `.env.example` и в `CURSOR.md`.

---

## Отчёты

- **report.md** — краткая сводка по файлам (хэши, hardening, YARA/DIE, VT, CVE, решение политики).
- **human_report.md** — развёрнутый отчёт (RU): уровень риска, обоснование вердикта, HVCI-совместимость, предупреждения WDAC/AppLocker, поиск секретов, CWE, матрица MITRE ATT&CK, при эмуляции — блок по дампу памяти.
- **SARIF** — для интеграции с платформами статического анализа (например, GitHub Code Scanning).

### Пример человекочитаемого отчёта (Human Report) при вердикте DENY

При блокировке файла (risk ≥ порога deny) в отчёте выводится блок **ПРОВЕРКА** с уровнем риска и обоснованием:

```markdown
# ПРОВЕРКА

Уровень риска: 100 (критический)
████████████████████████████████████████ 100%

## Обоснование вердикта

Заблокировано: обнаружена вредоносная сигнатура в дампе памяти (YARA); критическое несоответствие: файл маскируется под документ, являясь исполняемым; отсутствие hardening (ASLR/DEP/CFG); нет цифровой подписи.

Вредоносное ПО в памяти: Да, Секреты: Нет, Маскировка: Да, Уязвимости: Нет. Причины: КРИТИЧЕСКАЯ УГРОЗА: обнаружена сигнатура вредоносного ПО в дампе памяти; ...
```

Обоснование собирается из `scoring_reasons` и `build_deny_justification`; причины, связанные с дампом памяти и маскировкой, выводятся первыми.

---

## Платформы

Windows и Linux (x86_64). Для полного функционала нужен Docker; capa и Playwright (VT UI) опциональны.

---

## Лицензия и контрибьюция

См. файл LICENSE. PR и issues приветствуются: исправления, новые правила YARA/capa, доработки политик и профилей.
