# CURSOR.md — Binary Intake Gate

Документ описывает проект **таким, как он реализован в коде**: миссию, методики анализа, стек, архитектуру прохождения файла через шлюз, контекст DevSecOps и стандарты кодирования.

---

## Project Mission

**Binary Intake Gate** — единая точка контроля (шлюз) для оценки бинарных файлов и пакетов при приёме в репозиторий, в PR и при релизах. Проект выполняет **быструю статическую проверку** (due-diligence) артефактов: идентификация, целостность, проверки защищённости (hardening), сигнатуры, поведенческие признаки (YARA/capa), репутация через VirusTotal, поиск CVE по SBOM (Syft + Grype), профильная политика (dev/staging/prod) и формирование отчётов (Markdown, человекочитаемый RU, SARIF, GitHub Checks).

Цель — дать один инструмент для оценки PE/ELF (и смежных форматов: MSI, архивы, манифесты, скрипты, документы) без обязательного динамического анализа, с возможностью работы офлайн (кэш по SHA-256) и интеграции в CI/CD.

---

## Core Methodologies

Критически важный раздел: ниже перечислены **реально реализованные** методики анализа в коде.

### 1. Статический анализ заголовков и структуры

- **PE (Windows):** модуль `pe_hardening.py` — разбор заголовков PE (DllCharacteristics, Optional Header, секции). Проверяются: ASLR (DYNAMIC_BASE), DEP (NX_COMPAT), CFG (GUARD_CF), высокоэнтропийный VA; наличие RWX-секций и overlay; категории импортов (memory, proc_thread, network, registry, debug_sym и т.д.); признаки динамического резолва API (GetProcAddress, LoadLibrary). Подпись Authenticode проверяется через PowerShell `Get-AuthenticodeSignature` (Windows) или разбор Data Directory (DIR_SECURITY). **Recursive Import Scanner:** функции `get_imported_dlls_quick(path)` (лёгкое извлечение списка импортируемых DLL) и `recursive_import_scanner(scanned_file_path, imported_names, kind)` — поиск связанных .dll (PE) или .so (ELF) в той же директории для добавления в очередь анализа с тегом `origin_dependency` (управляется из CLI после сбора целей; отключение: `--no-recursive-imports`).
- **ELF:** модуль `elf_checksec.py` (pyelftools) — PIE (DF_1_PIE / ET_DYN), NX, RELRO (full/partial/none), Canary, RPATH/RUNPATH (в т.ч. небезопасные пути), TEXTREL, RWX-сегменты, Fortify, CET (IBT/SHSTK), stripped, build-id, soname, needed.
- **Mach-O:** модуль `macho_checksec.py` — проверки защищённости для macOS-бинарников.

#### Enterprise Hardening (v0.0.7)

Расширенные проверки защищённости уровня Enterprise:

**PE (Windows) — Extended Checks:**
| Проверка | Описание | Поле в Evidence |
|----------|----------|-----------------|
| **CET Shadow Stack** | Intel Control-flow Enforcement Technology — защита от ROP/JOP атак через shadow stack | `pe.hardening.cet_shstk` |
| **CET IBT** | Indirect Branch Tracking — контроль непрямых переходов | `pe.hardening.cet_ibt` |
| **ACG** | Arbitrary Code Guard — запрет генерации динамического кода (VirtualProtect → RWX) | `pe.hardening.acg` |
| **SafeSEH** | Safe Structured Exception Handling (x86) — таблица валидных SEH-обработчиков | `pe.hardening.safeseh`, `pe.hardening.safeseh_count` |
| **GS Cookie (/GS)** | Stack Buffer Overrun Detection — SecurityCookie в Load Config | `pe.hardening.gs_cookie` |
| **UAC Manifest** | Requested Execution Level (asInvoker/highestAvailable/requireAdministrator) | `pe.resources.uac_level`, `pe.resources.uac_admin_required` |
| **Overlay Analysis** | Данные после последней секции PE — размер, энтропия, флаг suspicious (entropy > 7.0) | `pe.overlay.{present, size, entropy, suspicious}` |
| **Policy Flags** | Process Creation Mitigation Policy из Load Config | `pe.hardening.policy_flags` |
| **Enclave Config** | SGX Enclave configuration pointer | `pe.hardening.enclave_config` |

**ELF (Linux) — Extended Checks:**
| Проверка | Описание | Поле в Evidence |
|----------|----------|-----------------|
| **CET (IBT/SHSTK)** | Proper parsing of `.note.gnu.property` section for x86/x64 | `elf.cet.{ibt, shstk}` |
| **Full RELRO** | Строгое различие Partial vs Full RELRO (BIND_NOW в DT_FLAGS_1) | `elf.hardening.relro_full` |
| **BTI (ARM)** | Branch Target Identification для ARM64 бинарников | `elf.hardening.bti` |
| **PAC (ARM)** | Pointer Authentication Code для ARM64 | `elf.hardening.pac` |
| **Architecture** | Определение архитектуры (x86, x64, arm, arm64, mips, etc.) | `elf.arch` |

**.NET Assembly Intelligence (`dotnet_intel.py`):**
| Проверка | Описание | Поле в Evidence |
|----------|----------|-----------------|
| **Strong Name** | Наличие и валидность Strong Name signature | `dotnet.strong_name.{present, signed, delay_signed}` |
| **Authenticode** | Code signing (Windows PowerShell) | `dotnet.authenticode.{present, valid, publisher}` |
| **Anti-Tamper** | Детекция упаковщиков/обфускаторов (.NET Reactor, ConfuserEx, etc.) | `dotnet.anti_tamper.{suspected, packer_detected}` |
| **Obfuscator Detection** | Сигнатуры известных обфускаторов (20+ инструментов) | `dotnet.obfuscators` |
| **High Entropy** | Секции с энтропией > 7.2 (признак упаковки) | `dotnet.anti_tamper.high_entropy` |
| **P/Invoke** | Вызовы нативных DLL (kernel32, ntdll, etc.) | `dotnet.p_invoke` |
| **Mixed Mode** | Сборка содержит как managed, так и native код | `dotnet.mixed_mode` |

Эти методики дают быстрый ответ по «закалённости» бинарника без запуска кода.

### Advanced Malware Detection (v0.0.8)

Расширенные возможности детекции вредоносного ПО:

#### 1. Эмуляция (Speakeasy Integration)

**Модуль `emulation.py`** — эмуляция PE файлов в памяти без выполнения кода:

| Функция | Описание | Поле в Evidence |
|---------|----------|-----------------|
| **API Hooking** | Перехват вызовов Windows API во время эмуляции | `emulation.api_calls`, `emulation.api_summary` |
| **Mutex Detection** | Обнаружение создаваемых мьютексов (IoC для кампаний) | `emulation.mutexes` |
| **File Operations** | Файлы, создаваемые/читаемые/записываемые малварью | `emulation.files.{created, read, written}` |
| **Registry Changes** | Изменения реестра (persistence, evasion) | `emulation.registry` |
| **Network Activity** | Сетевые соединения (C2 detection) | `emulation.network` |
| **Shellcode Detection** | Детекция шелл-кода в памяти | `emulation.shellcode.{detected, info}` |
| **Technique Mapping** | Маппинг API в ATT&CK техники | `emulation.techniques` |
| **Memory Dump Path** | Путь к .dmp (дамп памяти после эмуляции) для CVE/SBOM | `emulation.memory_dump_path` |

**Memory-aided SBOM:** после успешной эмуляции дамп памяти процесса (image base + mapped pages) записывается во временный `.dmp` файл (`get_memory_dumps()` или fallback `get_mem_maps()` + `mem_read()` по регионам). Путь сохраняется в `emulation.memory_dump_path`. Оркестратор передаёт в CVE-сканер **дамп** (а не исходный файл), если дамп существует; при обнаружении VMProtect приоритет CVE всегда отдаётся дампу. Порядок выполнения: в **sequential** режиме batch CVE (Syft+Grype) запускается **после** цикла по файлам (после DIE и эмуляции), чтобы эмуляция успела создать дампы; затем для каждого файла с дампом вызывается `collect_cve_for_file(dump_path, ev)` — Syft/Grype сканируют дамп и извлекают библиотеки из распакованного образа. Найденные библиотеки из дампа пишутся в **cli_debug.log**: `[cve_collector] emulation dump: libraries extracted (N): lib1@ver, lib2@ver, ...` (до 50 записей, при большем числе — «… +M more»).

**Docker-эмуляция:** при ошибке локального Speakeasy (например, «fail to load the dynamic library» на Windows) можно запускать эмуляцию в контейнере: `BIN_GATE_EMULATION_DOCKER=1`. Образ собирается командой `bin-gate emulation-build`; дамп из контейнера передаётся на хост в base64 по stdout и сохраняется во временный файл.

**CLI флаги:**
- `--emulation` — включить эмуляцию (по умолчанию выключена, CPU-intensive)
- `--emulation-timeout N` — таймаут эмуляции в секундах (default: 60)

**Требования:** `speakeasy-emulator>=1.5` (optional dependency)

```bash
pip install binary-intake-gate[emulation]
bin-gate scan ./sample.exe --emulation
```

#### 2. Threat Intelligence Integration

**Модуль `threat_intel.py`** — интеграция с threat feeds и DGA detection:

| Функция | Описание | Поле в Evidence |
|---------|----------|-----------------|
| **IOC Extraction** | Извлечение доменов, IP, URL, email из строк | `threat_intel.iocs.{domains, ips, urls, emails}` |
| **URLHaus Check** | Проверка URL против URLHaus malware feed | `threat_intel.ti_matches.urlhaus` |
| **Abuse.ch Check** | Проверка IP против Feodo Tracker C2 blocklist | `threat_intel.ti_matches.abusech` |
| **DGA Detection** | Entropy и N-gram анализ для детекции DGA доменов | `threat_intel.dga.{suspects, score, count}` |
| **Risk Level** | Агрегированный уровень риска (low/medium/high/critical) | `threat_intel.risk_level` |

**DGA Detection эвристики:**
- Shannon entropy > 3.5
- Consonant/vowel ratio > 3.0
- Unusual N-gram score > 0.6
- Digit-letter mixing
- Suspicious TLDs (tk, ml, ga, xyz, etc.)
- Absence of vowels

**CLI флаги:**
- `--ti` — включить threat intelligence (по умолчанию выключена)
- `--ti-timeout N` — таймаут TI запросов (default: 30)
- `--no-dga` — отключить DGA detection

**Требования:** `requests>=2.32` (optional dependency)

```bash
pip install binary-intake-gate[threatintel]
bin-gate scan ./sample.exe --ti
```

#### 3. Visual & Resource Analysis (PE)

**Расширение `pe_hardening.py`** — анализ иконок и ресурсов PE:

| Функция | Описание | Поле в Evidence |
|---------|----------|-----------------|
| **Icon Extraction** | Извлечение main icon из PE resources | `visual.icon.{present, size}` |
| **Icon dHash** | Perceptual hash (dHash) иконки для сравнения | `visual.icon.dhash` |
| **Icon Mismatch Detection** | Детекция masquerading (exe с PDF иконкой) | `visual.icon.{mismatch_detected, mismatch_type}` |
| **Resource Entropy** | Энтропия RT_RCDATA и RT_VERSION | `visual.resource_entropy.{max_resource_entropy, suspicious}` |
| **High Entropy RCDATA** | Детекция encrypted/packed payloads в ресурсах | `visual.resource_entropy.rcdata_high_entropy` |

**Icon Mismatch триггеры:**
- Filename содержит `.pdf`, `.doc`, `.jpg` но расширение `.exe`
- Icon hash совпадает с известными document icons
- Executable с icon типа folder/document

**Требования:** `Pillow>=10.0` для dHash (optional)

```bash
pip install binary-intake-gate[visual]
```

#### 4. Deep Script & Office Analysis

**Модуль `office_pdf_lnk.py`** — глубокий анализ документов и скриптов:

| Функция | Описание | Поле в Evidence |
|---------|----------|-----------------|
| **VBA Macro Analysis** | oletools (olevba) для деобфускации макросов | `script_analysis.vba.{has_macros, auto_exec, obfuscation_score}` |
| **VBA IOC Extraction** | AutoExec triggers, suspicious keywords | `script_analysis.vba.iocs` |
| **LNK Parsing** | Robust парсер Windows shortcuts | `script_analysis.lnk.{command_line, arguments}` |
| **LNK Payload Extraction** | Base64/Hex payloads в command line | `script_analysis.lnk.{payloads, decoded_payloads}` |
| **Stager Detection** | powershell -enc, certutil, mshta, etc. | `script_analysis.stagers` |
| **PDF JavaScript** | Детекция embedded JS и auto-actions | `script_analysis.pdf.{has_javascript, auto_actions}` |
| **Supply Chain Dependencies** | URL и внешние ресурсы из LNK/Office/PDF + из Speakeasy (decoded_strings, network, files) | `supply_chain.dependencies` (type, value, source) |

**Обнаруживаемые stagers:**
- PowerShell encoded commands (`-enc`, `-encodedcommand`)
- Download cradles (DownloadString, DownloadFile, WebClient)
- Certutil decode/urlcache
- Bitsadmin transfer
- Mshta (vbscript:/javascript:)
- Rundll32 (javascript:)
- Regsvr32 scrobj
- WMIC process call

**Модуль `source_scripts.py`** — анализ исходных скриптов:

| Функция | Описание | Поле в Evidence |
|---------|----------|-----------------|
| **Multi-language Support** | Python, PowerShell, Bash, Batch, VBS, JS | `script_analysis.basic.externals` |
| **Obfuscation Detection** | Chr concat, Base64, hex strings, short vars | `script_analysis.obfuscation.{score, techniques}` |
| **Payload Extraction** | Автоматическое декодирование Base64 payloads | `script_analysis.decoded_payloads` |
| **Risk Scoring** | Агрегированная оценка риска скрипта | `script_analysis.risk_score` |

**Требования:** `oletools>=0.60` (optional)

```bash
pip install binary-intake-gate[oletools]
```

#### 5. Policy Engine Extensions (v0.0.8)

Новые переменные для CEL-like правил политики:

```yaml
# Emulation-based rules
- id: emu-shellcode
  when: emulation.shellcode_detected == true
  then: deny
  reason: "Shellcode detected during emulation"

- id: emu-suspicious-api
  when: emulation.api_count > 100 && "VirtualAllocEx" in emulation.api_summary
  score: 30
  reason: "Suspicious API pattern (process injection)"

# Threat Intel rules  
- id: ti-c2-ip
  when: threat_intel.abusech_count > 0
  then: deny
  reason: "Known C2 IP detected"

- id: ti-dga
  when: threat_intel.dga_count >= 3
  score: 25
  reason: "Multiple DGA domains detected"

# Visual analysis rules
- id: vis-icon-mismatch
  when: visual.icon_mismatch == true
  score: 40
  reason: "Icon masquerading detected"

- id: vis-resource-payload
  when: visual.resource_suspicious == true && visual.max_resource_entropy > 7.5
  score: 30
  reason: "Encrypted payload in resources"

# Script analysis rules
- id: script-vba-macro
  when: script.vba_has_macros == true && script.vba_auto_exec == true
  score: 35
  reason: "Auto-executing VBA macro"

- id: script-stager
  when: script.stager_count > 0
  score: 50
  reason: "Stager/downloader detected"

- id: script-lnk-payload
  when: script.lnk_payloads > 0
  score: 45
  reason: "Encoded payload in LNK"
```

**Доступные policy переменные (v0.0.8):**

| Переменная | Тип | Описание |
|------------|-----|----------|
| `emulation.enabled` | bool | Эмуляция включена |
| `emulation.api_count` | int | Количество перехваченных API |
| `emulation.mutex_count` | int | Количество созданных мьютексов |
| `emulation.shellcode_detected` | bool | Обнаружен шелл-код |
| `emulation.techniques` | list | ATT&CK техники из эмуляции |
| `threat_intel.risk_level` | str | low/medium/high/critical |
| `threat_intel.dga_count` | int | Количество DGA доменов |
| `threat_intel.urlhaus_count` | int | URLHaus matches |
| `threat_intel.abusech_count` | int | Abuse.ch matches |
| `visual.icon_mismatch` | bool | Детектирован icon mismatch |
| `visual.resource_suspicious` | bool | High entropy resources |
| `script.vba_has_macros` | bool | Документ содержит макросы |
| `script.vba_auto_exec` | bool | Макросы с auto-execution |
| `script.stager_count` | int | Количество обнаруженных stagers |
| `script.lnk_payloads` | int | Encoded payloads в LNK |
| `script.obfuscation_score` | int | Уровень обфускации скрипта |
| `supply_chain.dependencies` | list | URL и внешние ресурсы из LNK/Office/PDF и из Speakeasy (decoded_strings, network, files) — type, value, source |

**VMProtect lockdown (жёсткое правило в движке):** при обнаружении «Protector: VMProtect» в DIE (поле detects) или в obfuscation.packer_families для профиля **prod** решение принудительно **deny**; при высоких детекциях VirusTotal (malicious ≥ 5) — дополнительная причина. Для профиля **dev** при VMProtect выставляется **warn**, если иначе было бы allow.

### 2. Поиск техник и сигнатур: YARA + DIE (быстрый режим) и capa (глубокий)

**Архитектура (v0.0.5):** Для повышения скорости анализа техники ATT&CK теперь извлекаются из **YARA метаданных** и **DIE детектов** по умолчанию. Тяжёлый `capa` отключён — используется только при флаге `--deep-capa` или `ENABLE_DEEP_CAPA=1`.

- **YARA (основной источник техник):** `yara_scan.py` — компиляция правил из директории (или встроенные минимальные правила для упаковщиков PE/ELF), сканирование файла с таймаутом, лимитом размера и ограничением числа совпадений.
  - **Извлечение техник из meta:** парсинг полей `meta.technique`, `meta.attack`, `meta.mitre`, `meta.tactic`, `meta.capability` из YARA-правил.
  - **Keyword-based detection:** автоматический маппинг имён правил в техники ATT&CK (например, `PACKER_*` → `defense-evasion`, `*persistence*` → `persistence`).
  - **Функция `extract_all_techniques(yara_hits)`:** агрегирует все техники и формирует `(techniques, rule_hits)` для `Evidence.capa`.
  - Результат: `ev.yara[].techniques`, `ev.capa.techniques` (merged from YARA+DIE).

- **DIE (Detect It Easy) — второй источник техник:**
  - При обнаружении packer/protector/cryptor автоматически добавляется `defense-evasion`.
  - Функция `extract_techniques_from_die(die_result)` возвращает `(techniques, rule_hits)`.
  - Findings добавляются в `Evidence.capa.rule_hits` с префиксом `DIE:` (например, `DIE:packer:UPX`, `DIE:protector:VMProtect`).

- **capa (глубокий режим, отключён по умолчанию):**
  - `capa_analyzer.py` с флагом `ENABLE_DEEP_CAPA` (default: False).
  - При `--deep-capa` или `ENABLE_DEEP_CAPA=1` — вызов внешнего бинарника `capa -j --quiet`.
  - При таймауте или отсутствии capa — fallback на YARA+DIE данные.
  - Результат мержится с предсобранными техниками из YARA/DIE.

**Результат в Evidence:**
```python
ev.capa = {
    "techniques": ["defense-evasion", "persistence", ...],  # merged YARA + DIE (+ capa при --deep-capa)
    "rule_hits": ["YARA:PACKER_UPX", "DIE:packer:upx", ...],
    "source": "yara_die" | "capa" | "yara_die_fallback"
}
```

Эта архитектура даёт **секунды на файл** вместо минут, сохраняя информацию о техниках для политик (`capa_tactics`).

### 3. Проверка подписей и доверия

- **signing_trust.py:** лёгкая проверка наличия таблицы подписи Authenticode в PE (DIR_SECURITY, размер).
- **pe_hardening.py:** полная проверка подписи через PowerShell (Status, SignerCertificate, TimeStamperCertificate) на Windows; на не-Windows — только наличие блока подписи.

Используется в политиках для «packed and unsigned» и общих правил по доверию.

### 4. Строки и обфускация

- **DIE (Detect It Easy):** `die_scanner.py` — контейнеризированное решение для детекции упаковщиков, компиляторов и протекторов через Docker (`horsicq/detectiteasy:latest`).
  > **Note:** DIE заменил устаревший FLOSS (floss_runner.py deprecated, не используется).
  - **Парсинг вывода diec:** разбор только JSON-объектов через `re.findall(r'(\\{.*?\\})', stdout, re.DOTALL)` в `_extract_json_blocks()` — строки вида `/usr/bin/diec:` или `/target/file:` не попадают в кандидаты и не ломают `json.loads()`. Для вложенного JSON при неудачном парсе — fallback `_extract_one_balanced_block()`. `_parse_die_stdout_single()` / `_parse_die_stdout_batch()` с привязкой пути к блоку через `_path_line_before()`.
  - **Batch Mode (по умолчанию):** один вызов `diec -j -r /target` для рекурсивного сканирования всей директории вместо N вызовов на файл.
    - `pre_scan_die(directory)` — выполняется перед основным циклом анализа.
    - `DieBatchMap` — класс для индексации результатов по путям файлов; разбор вывода через `_parse_die_stdout_batch()`.
    - `get_die_info(path)` — быстрый lookup данных для конкретного файла.
    - **Результат:** 1 Docker-контейнер вместо N, время DIE-этапа сокращается в разы.
  - **Per-file Mode:** запуск `docker run --rm -v ${FILE}:/target/file:ro horsicq/detectiteasy diec -j /target/file` при `--die-no-batch`; парсинг через `_parse_die_stdout_single()`.
  - **Результат:** JSON с детектами (packer/compiler/protector/installer), энтропией по секциям.
  - **Интеграция:** автоматическое обновление `evidence.die`, `evidence.obfuscation`, `evidence.yara_families` (добавление "packers" при обнаружении). Детект «Protector: VMProtect» учитывается движком политик (см. VMProtect lockdown ниже).
  - **Fallback:** при недоступности Docker — встроенный Python-алгоритм извлечения ASCII-строк и базовое определение упаковщиков по сигнатурам в бинарнике.
  - **CLI:** `--no-die` отключает DIE-анализ, `--die-no-batch` отключает batch-режим.
- **obfuscation.py:** эвристики обфускации: соотношение ASCII/UTF-16 строк к размеру файла, энтропия секций, признаки упаковщиков по именам секций, антиотладочные/анти-VM строки, динамический резолв API, маркеры инъекций (VirtualProtect, WriteProcessMemory, CreateRemoteThread). Результат — единый блок `obfuscation` (reasons, score, packed_suspect, has_dyn_api_resolve и т.д.). DIE-детекты мержатся в этот блок.
- **packers_detect.py:** вывод списка упаковщиков по YARA-попаданиям (family); результат мержится с obfuscation и DIE (packer_families, score).

Это даёт быструю оценку «подозрительности» по строкам и структуре без выполнения кода, с точным определением типа упаковщика/протектора.

### 5. Интеграция с внешними API и кэшем

- **VirusTotal:** модули `virustotal.py`, `virustotal_client.py`, `vt_full.py`, `vt_playwright.py`, `virustotal_upload.py`. Lookup по SHA-256 (REST API), получение полных метрик и поведений (behaviours); при пустом кэше/отсутствии хэша — опциональная загрузка файла (API или Playwright UI). Поведения нормализуются в канонический вид (processes, commands, network, files, registry, mutexes, MITRE). Результат кэшируется в SQLite по SHA-256 с TTL.
  - **VT только для исполняемых файлов:** запросы к VirusTotal выполняются только для нативных бинарников и инсталляторов. Фильтрация осуществляется по типу файла (PE, ELF, Mach-O) и расширениям из `VT_EXECUTABLE_EXTS` (`.exe`, `.dll`, `.sys`, `.ocx`, `.drv`, `.elf`, `.so`, `.ko`, `.dylib`, `.bundle`, `.bin`, `.out`, `.msi`). Функция `_is_vt_candidate(kind, sfx)` в `cli.py` определяет, нужно ли делать запрос к VT.
  - **In-memory кэш behaviours:** `_behaviours_run_cache` в `virustotal_client.py` — кэш в рамках одного запуска. Гарантирует один GET-запрос `/behaviours` на хэш за всю сессию; повторные вызовы возвращают закэшированные данные без сети.
  - **Rate-limit retry:** при 429 ошибках — до 3 ретраев с backoff (15 * attempt секунд).
- **CVE/Vulnerability Scanning (Syft + Grype):** `cve/collector.py` — контейнеризированное сканирование через Docker:
  - **Обновление базы перед сканом:** перед каждым запуском проверки CVE выполняется обновление базы Grype (аналог `bin-gate cve-update`): pull образа при необходимости и `grype db update`. Таймаут задаётся `--cve-update-timeout` (default 600 с); `--no-cve-update` отключает обновление перед сканом.
  - **Memory-aided SBOM:** оркестратор передаёт в `collect_cve_for_file` путь к дампу памяти эмуляции (`emulation.memory_dump_path`), если дамп существует; при VMProtect приоритет CVE всегда у дампа. Syft/Grype сканируют дамп (распакованное содержимое), а не исходный бинарник. При скане дампа в **cli_debug.log** пишется строка `[cve_collector] emulation dump: libraries extracted (N): lib1@ver, ...` (библиотеки из SBOM по дампу).
  - **Map dynamic dependencies to vulnerability scan (Memory-Injection CVE):** если Syft вернул 0 компонентов, но в `ev["supply_chain"]["dependencies"]` есть записи с `type: "dynamic_lib"` (DLL из эмуляции), в **cve/collector.py** формируется **минимальный CycloneDX JSON вручную** (`bomFormat`, `specVersion`, `version`, `components`), каждая DLL — component типа `library`, версия `UNKNOWN`; этот синтетический SBOM передаётся в Grype. В `notes` — `cve_sbom:injected_dynamic_lib_from_supply_chain`; в **cli_debug.log** — `[cve_collector] Injecting {N} libraries from emulation into Grype scan.`
  - **Порядок CVE и эмуляции:** в **параллельном** режиме batch CVE выполняется в начале (pre-scan); в **sequential** режиме batch CVE запускается **после** цикла по файлам (после DIE и эмуляции), чтобы дампы успели создаться; затем для каждого evidence с дампом вызывается `collect_cve_for_file(dump_path, ev)` для сбора библиотек и CVE по дампу, остальные файлы получают CVE из batch-результата.
  - **Batch Mode (по умолчанию):** один вызов Syft + один вызов Grype для всей директории вместо N вызовов на файл.
    - В **parallel:** `pre_scan_vulnerabilities(directory)` — перед основным циклом (после обновления базы, если не `--no-cve-update`).
    - В **sequential:** batch CVE вызывается после цикла по файлам; для файлов с `emulation.memory_dump_path` CVE берётся из `collect_cve_for_file(dump_path, ev)` (Syft по дампу → библиотеки → Grype).
    - `BatchVulnerabilityMap` — индексация результатов по путям; `get_results_for_file(path)` — lookup для файла.
    - **Результат:** 2 контейнера вместо 2×N; в sequential эмуляция идёт до CVE, библиотеки из дампа логируются в cli_debug.log.
  - **Syft (`anchore/syft:latest`):** генерация SBOM (Software Bill of Materials) в формате CycloneDX JSON. Автоматически определяет тип файла (PE, ELF, архив) и извлекает зависимости. **Для дампов (.dmp):** в `collect_cve_for_file` создаётся временная копия с расширением `.exe` (`temp_dump_for_syft_*.exe`), копируется в неё содержимое дампа и в контейнер передаётся этот путь; после скана временный файл удаляется. В команду Syft для дампа/маскированного .exe добавляются: `--select-catalogers +pe-binary-package-cataloger`, `+binary-classifier-cataloger` (поиск по импортам и по сигнатурам библиотек в теле бинарника), `--exclude-binary-packages-with-file-ownership-overlap=false` (не отбрасывать библиотеки, выглядящие как часть основного файла); для прямого .dmp также `--scope all-layers`.
  - **Grype (`anchore/grype:latest`):** сканирование SBOM на известные уязвимости. Результат нормализуется в формат `Evidence.cve` (summary по severity, items с vulns). При неудачном обновлении базы (network unreachable, таймаут, ошибка) выставляется `BIN_GATE_GRYPE_OFFLINE=1`, и при следующем запуске скана Grype вызывается с флагом **`--offline`** (используется только локальная БД).
  - **ContainerVulnerabilityScanner:** класс для управления Docker-контейнерами. Автоматический `docker pull` при первом запуске (если не `BIN_GATE_NO_AUTO_PULL=1`), `--rm` для очистки контейнеров, `--network none` для Grype (офлайн после обновления базы).
  - **CLI-команды:** `bin-gate cve-update` (обновление базы Grype), `bin-gate cve-check` (проверка готовности Docker/образов).
  - **Fallback:** при ошибке batch-скана — `cve_batch_failed` в `evidence.errors` для всех файлов. Флаг `--cve-no-batch` включает per-file режим.
  - При недоступности Docker — ошибка записывается в `evidence.errors`, скан других файлов продолжается.

  **Enterprise: Supply Chain Risk Detection (v0.0.7):**
  - **Outdated Critical Libraries:** постобработка SBOM для детекции устаревших версий критических библиотек (zlib, openssl, glibc, curl, log4j, и др.).
  - **`CRITICAL_LIBRARY_THRESHOLDS`:** словарь с минимальными безопасными версиями для 30+ библиотек (C/C++, Java, Python, JavaScript, Go).
  - **`check_outdated_critical_libraries(components)`:** функция проверки компонентов SBOM против порогов.
  - **Policy Reasons:** при обнаружении критических/high рисков добавляются в `policy_reasons` (например, `supply_chain_risk:openssl<3.0.0`).
  - **Referenced URLs / External Resources (LNK, Office, PDF):** модуль `office_pdf_lnk.py` в `analyze_deep` извлекает все URL и внешние ссылки (target_path, working_dir, icon_location, URLs из command line для LNK; urls и suspicious_objects для PDF; IOCs из VBA для Office). Они записываются в `evidence.supply_chain.dependencies` как `[{type, value, source}]`; в контексте политики доступны как `ctx.supply_chain.dependencies`.
  - **Speakeasy (эмуляция):** в `run_one_file.py` после эмуляции в `supply_chain.dependencies` дописываются: URL из `emulation.decoded_strings`, URL из `emulation.network`, пути из `emulation.files` (type `file_ref`). В **orchestrate.py** после завершения эмуляции и **до этапа CVE** вызывается `_extract_dll_names_from_emulation`: имена DLL (паттерн `.*\.dll`) из `api_summary` и `decoded_strings` сохраняются в `evidence.supply_chain.dependencies` с `type: "dynamic_lib"`, source: `emulation_speakeasy_strings`. Эти зависимости до начала CVE-сканирования доступны для синтетического SBOM в коллекторе.
  - **Результат в Evidence:**
    ```python
    ev.supply_chain = {
        "outdated_libraries": [
            {"library": "openssl", "current_version": "1.1.1", "min_safe_version": "3.0.0", "risk": "critical", ...}
        ],
        "policy_reasons": ["supply_chain_risk:openssl<3.0.0"],
        "risk_level": "critical",  # highest risk from any library
        "dependencies": [{"type": "url", "value": "https://...", "source": "pdf_analysis"}, {"type": "url", "value": "...", "source": "emulation_decoded_strings"}, {"type": "file_ref", "value": "...", "source": "emulation_files_created"}, {"type": "dynamic_lib", "value": "kernel32.dll", "source": "emulation_speakeasy_strings"}, ...]
    }
    ```
  - **Пример критических библиотек:**
    | Библиотека | Min Safe | CVE Examples | Risk |
    |------------|----------|--------------|------|
    | openssl | 3.0.0 | CVE-2022-3602, CVE-2014-0160 | critical |
    | glibc | 2.35 | CVE-2023-4911 (Looney Tunables) | critical |
    | log4j | 2.17.1 | CVE-2021-44228 (Log4Shell) | critical |
    | zlib | 1.2.12 | CVE-2022-37434 | high |
    | curl | 8.0.0 | CVE-2023-38545 (SOCKS5) | high |
- **Кэш:** `cache/sqlite_cache.py` — ключ (source, sha256), значение JSON, TTL по времени создания. Используется для VT (vt_full), чтобы не повторять запросы при повторных сканах.

Эти методики добавляют репутационный и CVE-контекст при минимальном количестве сетевых вызовов за счёт кэша и throttle.

### 6. Дополнительные анализаторы (реально присутствующие в коде)

- **Хэши и энтропия:** `hashes.py`, `entropy.py` — SHA-256 и др., энтропия файла и секций PE/ELF.
- **Манифесты зависимостей:** `manifests.py` — разбор requirements.txt, package.json, go.mod, Cargo.toml, pom.xml и т.д.
- **Python-пакеты:** `python_pkg.py` — разбор wheel/sdist, метаданные, опционально Bandit (SAST) и проверка RECORD.
- **Архивы и контейнеры:** `archive_dispatcher.py` — распаковка различных форматов:
  - ZIP-like: `.zip`, `.jar`, `.apk`, `.aab`, `.whl`, `.vsix`, `.docx`, `.xlsx`, `.pptx`, `.docm`, `.xlsm`, `.pptm`, `.odt`, `.ods`, `.odp`
  - TAR-like: `.tar`, `.tgz`, `.tar.gz`, `.tbz`, `.tar.bz2`, `.txz`, `.tar.xz`, `.ova` (OVA — TAR-контейнер)
  - Single compression: `.gz`, `.bz2`, `.xz`
  - 7z/RAR: `.7z`, `.rar` (при наличии py7zr/rarfile)
  - Лимиты по глубине вложенности, числу файлов и размеру; безопасная сборка путей (`_safe_join`) без path traversal и симлинков.
  - Поддержка паролей для защищённых ZIP (default: infected, malware, password, 1234, 1111).
  - MSI: `msi_support.py`, `extractors/msi.py` — сбор целей из MSI, аннотация evidence контейнером.
- **Документы и скрипты:** `office_pdf_lnk.py`, `powershell_analyzer.py`, `source_scripts.py`, `webshell_scan.py`, `jar_apk_analyzer.py`, `dotnet_intel.py`, `ovf_ova.py` — специализированная обработка по расширению/типу.
- **Секреты:** `secrets_scan.py` — поиск по regex (AWS keys, GitHub token, private keys и т.д.) в первых N байтах файла.
- **Репутация по ключевым словам:** `reputation_scan.py` — сканирование по YAML-правилам (термины/регулярки).

Все перечисленные методики направлены на **быстрый статический анализ** EXE, MSI, ELF, архивов и смежных артефактов без запуска кода, с возможностью офлайн-режима (--no-network) и кэширования VT.

---

## Tech Stack & Architecture

### Используемые технологии (из кода и pyproject.toml)

- **Язык:** Python 3.10+ (до 3.14).
- **Версия проекта:** 0.0.8 (binary-intake-gate).
- **Бинарники/зависимости:** YARA (yara-python), capa (CLI, опционально при `--deep-capa`), DIE (Docker: `horsicq/detectiteasy`), Syft/Grype (Docker: `anchore/syft`, `anchore/grype`), Bandit (опционально, SAST для Python-пакетов).
- **Библиотеки:** pathlib, dataclasses, argparse, subprocess, re, json, sqlite3; для PE/ELF/Mach-O — pefile, pyelftools (elftools), lief (по контексту); YAML (policy), requests (VT API); опционально: packaging (pythonpkg), py7zr, rarfile (архивы), Playwright (VT UI).
- **Сборка:** PyInstaller (`bin-gate.spec`, `build.ps1`). Spec-файл настроен на сборку из `src/` директории с правильным `pathex` для гарантии включения актуального кода.
- **Конфигурация:** YAML-политики (policy.example.yaml), профили dev/staging/prod, пороги deny/warn.
- **Секреты и переменные окружения:** файл `.env.example` содержит шаблон всех переменных. Скопировать в `.env` и заполнить (`.env` в `.gitignore`).

### Конфигурация через .env

Проект поддерживает конфигурацию через переменные окружения. Файл `.env.example` содержит полный список с документацией:

| Переменная | Описание | Default |
|------------|----------|---------|
| `VT_API_KEY` | API ключ VirusTotal (обязателен для VT) | — |
| `VT_TIMEOUT_SEC` | Таймаут запросов к VT | 20 |
| `VT_REQUESTS_PER_MINUTE` | Rate limit (Public API = 4) | 3 |
| `CAPA_RULES_DIR` | Путь к capa-rules | — |
| `ENABLE_DEEP_CAPA` | Включить глубокий capa анализ | 0 |
| `YARA_RULES_DIR` | Путь к YARA правилам | — |
| `BIN_GATE_WORKERS` | Количество параллельных воркеров | 4 |
| `BIN_GATE_PROFILE` | Профиль политики (dev/staging/prod) | dev |
| `BIN_GATE_NO_AUTO_PULL` | Не тянуть Docker-образы при старте (1 = не делать pull за манифестами) | 0 |
| `BIN_GATE_HUMAN_OUT_DEFAULT` | Путь к human-отчёту по умолчанию (если не задан `--human-out`) | — |
| `BIN_GATE_GRYPE_OFFLINE` | Принудительно запускать Grype с `--offline` (устанавливается автоматически при ошибке обновления БД) | — |

**Advanced Malware Detection (v0.0.8):**

| Переменная | Описание | Default |
|------------|----------|---------|
| `BIN_GATE_ENABLE_EMULATION` | Включить Speakeasy эмуляцию PE | 0 |
| `BIN_GATE_EMULATION_TIMEOUT` | Таймаут эмуляции (секунды) | 60 |
| `BIN_GATE_EMULATION_MAX_MB` | Макс. размер файла для эмуляции (MB) | 50 |
| `BIN_GATE_EMULATION_DOCKER` | Запускать эмуляцию в Docker (fallback при ошибке локального Speakeasy, напр. Windows) | 0 |
| `BIN_GATE_ENABLE_TI` | Включить Threat Intelligence | 0 |
| `BIN_GATE_TI_TIMEOUT` | Таймаут TI запросов (секунды) | 30 |
| `BIN_GATE_TI_CACHE_TTL` | TTL кэша TI feeds (часы) | 24 |
| `BIN_GATE_DISABLE_DGA` | Отключить DGA detection | 0 |
| `BIN_GATE_ENABLE_DEEP_SCRIPT` | Глубокий анализ скриптов (oletools) | 0 |
| `BIN_GATE_ENABLE_VISUAL` | Анализ PE иконок/ресурсов | 1 |

**CLI приоритет:** Флаги CLI (напр. `--emulation`) имеют приоритет над env переменными. Флаги `--no-*` (напр. `--no-emulation`) полностью отключают функцию.

Полный список см. в `.env.example`.

### Архитектура прохождения файла через шлюз (intake)

1. **Вход:** команда `bin-gate scan <path>`; путь — файл или директория. Сбор целей: `collect_targets_with_msi` + `sniff_magic` (магические байты MZ/ELF/Mach-O и расширения из BINARY_EXTS). MSI обрабатываются отдельно (распаковка/листинг), результаты помечаются контейнером. После распаковки архивов (если не `--no-archives`) выполняется **Recursive Import Scanning** (если не `--no-recursive-imports`): для каждого PE/ELF из списка целей извлекаются импортируемые DLL/библиотеки (`get_imported_dlls_quick` для PE, `list_elf_shared_libs` для ELF), в той же директории ищутся соответствующие `.dll`/`.so`; найденные пути добавляются в список целей с тегом `origin_dependency` и привязкой к родительскому файлу в `origin_of`. При запуске stdout/stderr перенаправляются в `cli_debug.log`.

2. **Автоматическая проверка контейнеров:** после валидации Docker проверяются необходимые образы:
   - Если CVE включен (не `--no-cve`): проверяются образы Syft и Grype
   - Если DIE включен (не `--no-die`): проверяется образ DIE
   - Недостающие образы автоматически загружаются (если не `--no-auto-pull`)
   - При ошибке загрузки — предупреждение, но scan продолжается с уменьшенной функциональностью

3. **Опциональная распаковка архивов:** если не `--no-archives`, для каждого файла, распознанного как архив (`is_potential_archive`), вызывается `ArchiveExpander`. Функция `is_potential_archive` проверяет расширения (ZIPLIKE_EXTS, TARLIKE_EXTS, SEVENZ_EXTS, RAR_EXTS) и магические байты (PK, 7z, Rar!). Распакованные файлы добавляются в список целей с цепочкой происхождения (`origin_chain`). Лимиты: глубина вложенности, макс. число файлов, макс. размер, таймаут на архив.

5. **Pre-scan (Batch Mode):** перед основным циклом выполняются batch-операции **только в параллельном режиме**:
   - **CVE DB update:** при включённом CVE и без `--no-cve-update` — обновление базы Grype (таймаут `--cve-update-timeout`).
   - **Batch CVE (только при parallel):** `pre_scan_vulnerabilities(root)` вызывается в начале; при **sequential** batch CVE выполняется **после** цикла по файлам (после DIE и эмуляции), чтобы дампы эмуляции успели создаться и использоваться для Syft/Grype по распакованному образу.
   - **Batch DIE:** `pre_scan_die(root)` — один `diec -j -r` для рекурсивного сканирования; результат в `DieBatchMap`.
   - В sequential: эмуляция → дампы → затем batch CVE и для файлов с дампом — `collect_cve_for_file(dump_path, ev)` (библиотеки из дампа логируются в cli_debug.log).

6. **Параллельный анализ файлов:** `orchestrate.py` использует `ProcessPoolExecutor` для CPU-bound операций.
   - **Workers:** количество воркеров настраивается через `--workers` (default: 4) или env `BIN_GATE_WORKERS`.
   - **Batching:** файлы < 100 KB группируются в батчи по 50 штук для снижения накладных расходов на создание процессов.
   - **Thread-safe logging:** запись в `cli_debug.log` через `_thread_safe_log()` с lock.
   - **Profiling:** топ-10 самых медленных файлов записываются в лог с указанием узкого места (capa/YARA/etc).

7. **Цикл по файлам:** для каждого пути вызывается `sniff_magic` → определение типа (PE, ELF, MACHO, EXT, MANIFEST). Создаётся объект `Evidence` (`new_evidence`), заполняются `meta` (path, name, type, size). К evidence привязывается происхождение (MSI/архив) через `annotate_evidence`.

8. **Обязательные метрики:** хэши (`compute_hashes`), энтропия файла (`file_entropy`). Ошибки пишутся в `evidence.errors`.

9. **Ветвление по типу и расширению:**
   - Python-пакет (wheel/sdist): `analyze_python_pkg` (метаданные, опционально Bandit, RECORD).
   - PE: `analyze_pe_hardening`, энтропия секций.
   - ELF: `analyze_elf_checksec`, энтропия секций.
   - Mach-O: `analyze_macho_checksec`.
   - PowerShell: `analyze_powershell`; скрипты (sh/py/bat и т.д.): `analyze_source_script`; манифесты: `analyze_manifest`; офис/PDF/LNK: `analyze_office_pdf_lnk`; OVF/MF: `analyze_ovf`/`parse_mf`; JAR/APK/ZIP: `analyze_jar_apk`; веб-шеллы: `analyze_webshell`; секреты: `analyze_secrets`.
   - Для PE/ELF: YARA (`run_yara`) → DIE (`run_die`) → техники (`extract_yara_techniques`, `extract_techniques_from_die`) → capa (merged, по умолчанию только YARA+DIE); детекция упаковщиков по YARA (`detect_packers_from_yara`), обфускация (`analyze_obfuscation`), репутация (`run_reputation_scan` при наличии правил). Счётчики DIE/PowerShell/source передаются в YARA как externals.
   - CVE: `collect_cve_for_file` запускает Docker-контейнеры Syft (SBOM) + Grype (vuln scan). Для дампа эмуляции (.dmp) создаётся временная копия .exe для Syft; в scan передаётся `evidence` для подстановки `supply_chain.dependencies` (type `dynamic_lib`) в SBOM при 0 компонентов. Grype сканирует итоговый SBOM. Для архивов передаётся путь к распакованной директории.

10. **VirusTotal:** запросы к VT выполняются **только для исполняемых файлов** (PE/ELF/Mach-O или расширение из `VT_EXECUTABLE_EXTS`). При наличии SHA-256 и без `--no-vt`:
   - Фильтрация: `_is_vt_candidate(kind, sfx)` проверяет, что файл — нативный бинарник/инсталлятор.
   - In-memory кэш: `_behaviours_run_cache` гарантирует один GET `/behaviours` на хэш за запуск.
   - SQLite кэш: проверка `cache.get("vt_full", sha256, ttl)`.
   - При промахе и без `--no-network` — lookup, при необходимости загрузка (API или UI, флаг `--vt-upload`).
   - Поведения нормализуются; при пустых данных — опциональный запрос через Playwright UI.
   - Результат кладётся в кэш, в evidence попадает `vt`.

11. **Политика:** для каждого evidence вызывается `evaluate_policy(ev_dict, policy, profile)`. Движок в `policy/engine.py`: CEL-подобные выражения (when) с безопасным доступом к pe, elf, vt, die, yara_families, capa_tactics, cve, reputation, obfuscation, supply_chain (в т.ч. dependencies); правила с score или then: deny/warn. После применения правил выполняется **VMProtect lockdown:** при обнаружении «Protector: VMProtect» в DIE (detects) или в obfuscation.packer_families для профиля **prod** решение принудительно **deny** (при высоких детекциях VirusTotal — усиление); для **dev** — **warn**, если иначе было бы allow. Итог: decision (allow/warn/deny), score, reasons, matched. Результат записывается в `ev_dict["policy"]`.

12. **Постобработка:** сверка MF-манифестов с хэшами, проверка OVF references (missing/size_mismatch).

13. **Выход:** `write_markdown_report` (report.md), опционально `write_human_report` (путь из `--human-out` или `BIN_GATE_HUMAN_OUT_DEFAULT`), `write_sarif_report`, GitHub Step Summary и аннотации. В **human-отчёте** (reporters/human.py): блок *«Обнаружено в памяти (Dynamic Load)»* — список DLL из `supply_chain.dependencies` (type `dynamic_lib`, из эмуляции); при вердикте DENY и наличии VMProtect и скрытых библиотек из эмуляции выводится обоснование: *«Вердикт DENY вызван в том числе наличием VMProtect и скрытых библиотек, выявленных при эмуляции.»* Код возврата задаётся флагом `--fail-on` (none/warn/deny).

### Ключевые CLI-флаги

- `--no-vt` — полностью отключить VirusTotal (lookup, behaviours, upload).
- `--vt-upload` — разрешить загрузку файла в VT (opt-in; по умолчанию только lookup).
- `--vt-debug` — добавить отладочные карточки VT в отчёт.
- `--no-network` — офлайн-режим (кэш only, без сетевых запросов).
- `--no-archives` — не распаковывать архивы.
- `--no-cve` — отключить CVE-сканирование (Syft/Grype).
- `--cve-no-batch` — отключить batch-режим CVE (запускать Syft+Grype для каждого файла отдельно).
- `--cve-timeout` — таймаут Docker-контейнера CVE (по умолчанию 120 сек).
- `--cve-update-timeout N` — таймаут обновления базы Grype перед CVE-сканом (default 600 с); 0 — не обновлять.
- `--no-cve-update` — не обновлять базу Grype перед сканом.
- `--no-recursive-imports` — не добавлять связанные .dll/.so из той же директории в очередь анализа.
- `--no-die` — отключить DIE-анализ упаковщиков/компиляторов.
- `--die-timeout` — таймаут Docker-контейнера DIE (по умолчанию 60 сек).
- `--die-no-batch` — отключить batch-режим DIE (запускать per-file вместо рекурсивного).
- `--no-auto-pull` — отключить автоматическую загрузку Docker образов. Env: `BIN_GATE_NO_AUTO_PULL=1` (в .env можно выставить для офлайн/ограниченной сети).
- `--human-out PATH` — путь к human-отчёту (Markdown, RU). Default: env `BIN_GATE_HUMAN_OUT_DEFAULT`; явный `--human-out` имеет приоритет над env.
- `--no-capa` — отключить извлечение техник (YARA+DIE по умолчанию).
- `--deep-capa` — включить глубокий анализ через capa (медленный, по умолчанию выключен).
- `--no-parallel` — отключить параллельный анализ (ProcessPoolExecutor).
- `--workers N` — количество параллельных воркеров (default: 4, env: `BIN_GATE_WORKERS`).
- `--fail-on {none,warn,deny}` — код возврата при warn/deny.
- `--profile {dev,staging/prod}` — профиль политики.

**v0.0.8 Advanced Malware Detection:**
- `--emulation` — включить Speakeasy эмуляцию (CPU-intensive, по умолчанию выключена). Env: `BIN_GATE_ENABLE_EMULATION=1`
- `--no-emulation` — отключить эмуляцию (приоритет над env).
- `--emulation-timeout N` — таймаут эмуляции в секундах (default: 60). Env: `BIN_GATE_EMULATION_TIMEOUT`
- `--emulation-max-mb N` — макс. размер файла для эмуляции (default: 50 MB). Env: `BIN_GATE_EMULATION_MAX_MB`
- `--ti` — включить Threat Intelligence (URLHaus, Abuse.ch, DGA). Env: `BIN_GATE_ENABLE_TI=1`
- `--no-ti` — отключить TI (приоритет над env).
- `--ti-timeout N` — таймаут TI запросов (default: 30). Env: `BIN_GATE_TI_TIMEOUT`
- `--no-dga` — отключить DGA detection. Env: `BIN_GATE_DISABLE_DGA=1`
- `--deep-script` — включить глубокий анализ скриптов и документов (oletools). Env: `BIN_GATE_ENABLE_DEEP_SCRIPT=1`
- `--no-deep-script` — отключить deep script analysis (приоритет над env).
- `--visual` — включить анализ PE иконок/ресурсов (по умолчанию включен). Env: `BIN_GATE_ENABLE_VISUAL=1`
- `--no-visual` — отключить visual analysis.

### CLI-команды для CVE и эмуляции

- `bin-gate cve-check` — проверка готовности (Docker, образы Syft/Grype).
- `bin-gate cve-check --pull` — проверка + автоматический pull недостающих образов.
- `bin-gate cve-update` — обновление базы уязвимостей Grype. То же обновление выполняется автоматически перед каждым CVE-сканом (если не задано `--no-cve-update`).
- `bin-gate emulation-build` — сборка Docker-образа для эмуляции (Speakeasy в контейнере); используется при `BIN_GATE_EMULATION_DOCKER=1`.

Центральная структура данных — **Evidence** (dataclass):

| Поле | Тип | Описание |
|------|-----|----------|
| `meta` | dict | Метаданные файла (path, name, type, size) |
| `pe` | dict | PE hardening результаты (Enterprise checks) |
| `elf` | dict | ELF checksec результаты (Enterprise checks) |
| `hashes` | dict | SHA-256, MD5, SHA-1 |
| `entropy` | dict | Энтропия файла и секций |
| `capa` | dict | Техники ATT&CK (YARA+DIE или capa) |
| `yara` | list | YARA hits |
| `vt` | dict | VirusTotal данные |
| `die` | dict | Detect It Easy результаты |
| `obfuscation` | dict | Обфускация (score, reasons) |
| `strings` / `strings_summary` | dict | Строки и их сводка |
| `reputation` | dict | Репутационный анализ |
| `overlay` | dict | PE overlay анализ (v0.0.7) |
| `dotnet` | dict | .NET assembly intelligence (v0.0.7) |
| `supply_chain` | dict | Supply chain risk (v0.0.7); включает `dependencies` (URL/внешние ресурсы из LNK/Office/PDF и из эмуляции Speakeasy) |
| `hardening_summary` | dict | Агрегированный hardening статус |
| `policy_reasons` | list | Policy decision audit trail |
| **`emulation`** | dict | **Speakeasy эмуляция (v0.0.8)** |
| **`threat_intel`** | dict | **Threat Intelligence данные (v0.0.8)** |
| **`visual`** | dict | **Icon и resource analysis (v0.0.8)** |
| **`script_analysis`** | dict | **Deep script/office analysis (v0.0.8)** |
| `errors` | list | Ошибки анализа |

В процессе скана в объект добавляются и другие атрибуты (например, manifest, python_pkg, docscripts); финальный отчёт строится по списку словарей evidence (ev.to_dict() + policy).

---

## Professional Context

- **DevSecOps:** шлюз встроен в пайплайн приёма артефактов: один запуск по директории или файлу, выход — отчёт и решение политики (allow/warn/deny). Поддержка профилей (dev/staging/prod) и порогов позволяет ужесточать требования к prod. Флаг `--fail-on` даёт возможность падать по CI при warn/deny. SARIF и GitHub Checks (step summary, annotations) позволяют интегрировать результаты в системы код-сканирования и PR-чеклисты.

- **Уровень Middle:** реализованы не разовые скрипты, а целостный контур: единая точка входа (CLI), разделение анализаторов, политика с объяснимыми правилами, кэш по хэшу, офлайн-режим, несколько форматов отчётов. Используются общепринятые инструменты (YARA, DIE, capa, Syft/Grype, VirusTotal) и структурированные данные (Evidence, policy YAML). Типизация и обработка ошибок (см. ниже) доведены до уровня, пригодного для поддержки и расширения правил и интеграций.

---

## Coding Standards & Patterns

Следующие правила прослеживаются в коде проекта.

- **Обработка ошибок:** анализаторы и интеграции не роняют пайплайн: исключения перехватываются в блоке try/except, сообщение об ошибке добавляется в `evidence.errors` (например, `pe_error:...`, `capa_error:...`, `vt_http_error:...`). Возвращаемые структуры содержат поле `errors: []` (capa, pe_hardening, elf_checksec и др.). Критичные сбои (например, отсутствие capa) фиксируются как ошибка в результате, сканирование остальных файлов продолжается.
  - **VT Playwright UI scraping:** в `vt_playwright.py` вызовы `_extract_block_texts` обёрнуты в try/except, чтобы таймауты и отсутствие элементов на странице VT не прерывали скан. При ошибке возвращается пустой набор данных и `vt_ui_extract_error:...`.
  - **VT Rate-limit (429):** при 429 ошибках — до 3 ретраев с exponential backoff; при исчерпании — `vt_429_rate_limit_give_up` в errors.

- **Типизация:** используется аннотация типов (`from __future__ import annotations`), `pathlib.Path`, `Dict`, `List`, `Optional`, `Tuple` из `typing`. Функции возвращают явные структуры (dict с известными ключами). Evidence оформлен как `@dataclass` с полями и `to_dict()` через `asdict`.

- **Безопасность движка правил:** в `policy/engine.py` выражения политики не выполняются как произвольный код: строка when преобразуется в ограниченное подмножество Python (логика, сравнения, in, доступ по точкам к разрешённым переменным), затем разбирается через `ast.parse` и проверяется узлами `_SAFE_NODES`; обращение к данным идёт через `_get_path(ctx, dotted)`. Это минимизирует риски инъекции в политике.

- **Логирование и отладка:**
  - **cli_debug.log:** stdout/stderr перенаправляются в `cli_debug.log` при запуске CLI. `_cli_dbg(msg)` — префикс `[cli_dbg]` (VT, human report path, batch CVE). Эмуляция: `[emu_dbg] Attempting emulation for <path>...` в `run_one_file.py`; при дампе — `[emu_dbg] dump: starting extraction.` / `dump: bytes written: N`. CVE при скане дампа эмуляции: `[cve_collector] emulation dump: libraries extracted (N): lib1@ver, lib2@ver, ...` (до 50, затем «… +M more»). При отсутствии пути к дампу в результат/лог попадает `reason=...` (`dump_failure_reason` / `get_last_dump_reason()`).
  - **vt_debug.log:** отдельный лог для VT через `vt_debug_log(msg)` в `virustotal_client.py` (ENTER/FETCH/EXIT, кэш, 429).
  - **evidence.errors:** ошибки накапливаются в `evidence.errors` (формат `domain_error:...`), не прерывая сканирование остальных файлов.
  - **--vt-debug:** опциональный флаг для вывода отладочных карточек VT в отчёте.
  - Сообщения в коде часто имеют доменный префикс (`pe_error:...`, `capa_error:...`, `vt_http_error:...`).

- **Внешние вызовы:** subprocess/Docker для capa, YARA, DIE, Syft, Grype, Bandit, PowerShell — с таймаутами и лимитами размера файла, чтобы тяжёлые файлы не блокировали скан. Сетевые запросы (VT) — с throttle (min_interval), таймаутами и повторными попытками. Работа с путями в архивах — через безопасную сборку (`_safe_join`), блокировка path traversal и симлинков в распаковщике.

- **Конфигурация:** пути к правилам и ключи задаются через CLI и переменные окружения (CAPA_RULES_DIR, YARA_RULES_DIR, VT_API_KEY, CVE_ECOSYSTEM и т.д.), что удобно для CI и разных сред без изменения кода.

- **Секреты:** VT API ключ и другие чувствительные данные **НЕ хранятся в коде**. Используется `.env` файл (шаблон: `.env.example`), который добавлен в `.gitignore`.

---

## Project Structure

```
bin_intake_gateway/
├── src/bin_gate/           # Основной код
│   ├── analyzers/          # Анализаторы (PE, ELF, YARA, DIE, capa, etc.)
│   │   ├── pe_hardening.py     # PE hardening checks (Enterprise)
│   │   ├── elf_checksec.py     # ELF checksec (Enterprise)
│   │   ├── dotnet_intel.py     # .NET assembly intelligence
│   │   ├── die_scanner.py      # Detect It Easy (Docker)
│   │   ├── yara_scan.py        # YARA scanning
│   │   ├── capa_analyzer.py    # capa (optional, deep mode)
│   │   ├── archive_dispatcher.py # Archive extraction (streaming)
│   │   ├── memory_stream.py    # In-memory file processing
│   │   └── ...                 # Остальные анализаторы
│   ├── integrations/       # Внешние API (VirusTotal, Playwright)
│   ├── cve/                # CVE scanning (Syft + Grype)
│   │   └── collector.py        # ContainerVulnerabilityScanner, Supply Chain Risk
│   ├── cache/              # SQLite кэш
│   ├── policy/             # Движок политик
│   ├── reporters/          # Генераторы отчётов (MD, SARIF, GitHub)
│   ├── extractors/         # Распаковщики (MSI, архивы)
│   ├── docker_utils.py     # Docker management (Hard Fail, volume caching)
│   ├── orchestrate.py      # Parallel analysis (ProcessPoolExecutor)
│   ├── evidence.py         # Evidence dataclass
│   └── cli.py              # Точка входа CLI
├── rules/                  # YARA правила
├── policy/                 # YAML политики
├── .env.example            # Шаблон переменных окружения
├── .gitignore              # Исключения из git
├── pyproject.toml          # Метаданные проекта
├── build.ps1               # Скрипт сборки PyInstaller
└── CURSOR.md               # Эта документация
```

### .gitignore

Исключены из репозитория:
- **Логи:** `*.log`, `cli_debug.log`, `vt_debug.log`
- **Отчёты:** `report.md`, `report.json`, `human_report.md`, `*.sarif`
- **Сборка:** `build/`, `dist/`, `*.exe`, `*.spec`
- **Секреты:** `.env`, `.env.local` (но НЕ `.env.example`)
- **Временные:** `.tmp_bin_gate/`, `__pycache__/`
- **Тестовые примеры:** `examples/` (большие бинарники)

---

## Performance Tuning

Рекомендации для максимальной производительности анализа.

### 1. RAM Disk для временных файлов

Для максимальной скорости выделите `/dev/shm` (Linux) или создайте RAM disk для `TMPDIR`:

```bash
# Linux: использовать /dev/shm (обычно уже tmpfs)
export BIN_GATE_TMPDIR=/dev/shm

# Или создать dedicated tmpfs
sudo mount -t tmpfs -o size=2G tmpfs /mnt/ramdisk
export BIN_GATE_TMPDIR=/mnt/ramdisk
```

**Модуль `memory_stream.py`** — обработка файлов в памяти:
- Файлы < 50 MB обрабатываются **в памяти** (BytesIO) без записи на диск
- `MemoryFile` dataclass — унифицированный интерфейс для in-memory и disk файлов
- `create_memory_file()` — автоматический выбор storage на основе размера
- `get_optimal_tmpdir()` — приоритет: `BIN_GATE_TMPDIR` → `/dev/shm` → стандартный tempdir
- Порог настраивается: `BIN_GATE_MEMORY_THRESHOLD_MB=50`

### 2. Docker Volume Caching

Проект автоматически создаёт Docker volumes для кэширования:
- `bin-gate-grype-db` — база уязвимостей Grype (~300 MB)
- `bin-gate-syft-cache` — кэш Syft
- `bin-gate-die-cache` — сигнатуры DIE

Это избавляет от проверки обновлений при каждом запуске.

```bash
# Просмотр volumes
docker volume ls | grep bin-gate

# Принудительное обновление базы Grype
bin-gate cve-update
```

### 3. Docker — обязательная зависимость

Docker **ОБЯЗАТЕЛЕН** для работы. При недоступности демона — **Hard Fail** (exit code 10).

**Модуль `docker_utils.py`** — централизованное управление Docker:
- `check_docker_available()` — проверка доступности демона
- `validate_docker_at_startup()` — валидация при старте CLI (Hard Fail)
- `ensure_cache_volumes()` — создание volumes для кэширования
- `pull_image()`, `image_exists()` — управление образами
- `DockerNotAvailableError` — исключение для Hard Fail

```bash
# Проверка готовности
bin-gate cve-check

# Pull всех образов заранее
bin-gate cve-check --pull
```

### 4. Streaming Archive Extraction

`ArchiveExpander` работает как **генератор**: файлы передаются воркерам **сразу после извлечения**, не дожидаясь полной распаковки архива.

```python
# Streaming mode (рекомендуется)
for task in expander.stream_expand(archive_path):
    worker_queue.put(task)  # Мгновенная передача в воркер
```

### 5. Параллелизация

| Параметр | Default | Описание |
|----------|---------|----------|
| `--workers` | 4 | Количество параллельных воркеров |
| `BIN_GATE_WORKERS` | 4 | То же через env |
| `--no-parallel` | false | Отключить параллелизм |

Рекомендуется: `--workers` = CPU cores - 1

### 6. Batch режимы (минимум Docker-контейнеров)

| Операция | Без Batch | С Batch | Экономия |
|----------|-----------|---------|----------|
| CVE (Syft+Grype) | 2×N контейнеров | 2 контейнера | ~95% |
| DIE | N контейнеров | 1 контейнер | ~95% |

Флаги отключения: `--cve-no-batch`, `--die-no-batch`

### 7. Оптимальная конфигурация

```bash
# Максимальная производительность
export BIN_GATE_TMPDIR=/dev/shm
export BIN_GATE_WORKERS=7  # CPU cores - 1
export BIN_GATE_MEMORY_THRESHOLD_MB=100

bin-gate scan ./targets --workers 7
```

Ожидаемая скорость: **17+ файлов за < 60 секунд** (без учёта VirusTotal).

---

Итог: проект описан по фактической реализации; акцент сделан на методиках безопасности (статический анализ, YARA/DIE/capa, подписи, VT, CVE через Syft/Grype, политики, эмуляция, threat intelligence, visual analysis) и на том, как они обеспечивают комплексный анализ бинарников и артефактов в контуре intake/DevSecOps. Версия 0.0.8 расширяет возможности детекции вредоносного ПО: Speakeasy эмуляция (в т.ч. дамп памяти для CVE/SBOM), интеграция с threat feeds (URLHaus, Abuse.ch), DGA detection, icon masquerading, oletools VBA, LNK parsing с payload extraction. Supply chain: URL и внешние ресурсы из LNK/Office/PDF и Speakeasy; в **orchestrate.py** после эмуляции и **до CVE** вызывается `_extract_dll_names_from_emulation`, DLL попадают в `supply_chain.dependencies` (type `dynamic_lib`). **Memory-Injection CVE:** при 0 компонентов Syft в **cve/collector.py** формируется минимальный CycloneDX JSON (синтетический SBOM), передаётся в Grype; в cli_debug.log — `[cve_collector] Injecting {N} libraries from emulation into Grype scan.` Для дампов: маскировка .dmp как .exe для Syft, каталогизаторы pe-binary и binary-classifier. Human-отчёт: блок *«Обнаружено в памяти (Dynamic Load)»* (DLL из эмуляции); при DENY из-за VMProtect и скрытых библиотек — явное обоснование в отчёте. Sequential: batch CVE после цикла (после эмуляции); логи: `[cve_collector] emulation dump: libraries extracted (N): ...`, `[emu_dbg] dump: starting extraction.` / `dump: bytes written: N`. Docker-эмуляция: `BIN_GATE_EMULATION_DOCKER=1`, `bin-gate emulation-build`.
