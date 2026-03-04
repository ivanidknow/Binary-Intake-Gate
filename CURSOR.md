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
| **CET Shadow Stack** | Intel Control-flow Enforcement Technology — защита от ROP/JOP атак через shadow stack (Extended DLL Characteristics) | `pe.hardening.cet_shstk` |
| **CET IBT** | Indirect Branch Tracking — контроль непрямых переходов; парсинг **Load Config** (`IMAGE_LOAD_CONFIG_DIRECTORY`), флаги GuardFlags (IMAGE_GUARD_RF_INSTRUMENTED, RF_ENABLE, RF_STRICT) | `pe.hardening.cet_ibt` |
| **ACG** | Arbitrary Code Guard — запрет генерации динамического кода (VirtualProtect → RWX) | `pe.hardening.acg` |
| **SafeSEH** | Safe Structured Exception Handling (x86) — таблица валидных SEH-обработчиков | `pe.hardening.safeseh`, `pe.hardening.safeseh_count` |
| **GS Cookie (/GS)** | Stack Buffer Overrun Detection — SecurityCookie в Load Config | `pe.hardening.gs_cookie` |
| **UAC Manifest** | Requested Execution Level (asInvoker/highestAvailable/requireAdministrator) | `pe.resources.uac_level`, `pe.resources.uac_admin_required` |
| **Overlay Analysis** | Данные после последней секции PE — размер, энтропия, флаг suspicious (entropy > 7.0) | `pe.overlay.{present, size, entropy, suspicious}` |
| **HVCI compatible** | /INTEGRITYCHECK (DllCharacteristics 0x0080) + нет W^X секций + наличие релокаций | `pe.hardening.hvci_compatible` |
| **WDAC/AppLocker bypass** | LOLBins по именам в строках (certutil, mshta, rundll32, …) + эвристики загрузчика (VirtualAlloc + WriteProcessMemory/CreateRemoteThread, ordinal imports) | `pe.wdac_bypass.{lolbins_detected, loader_heuristics, suspect}` |
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

**Memory-aided SBOM:** после успешной эмуляции дамп памяти процесса (image base + mapped pages) записывается во временный `.dmp` файл (`get_memory_dumps()` или fallback `get_mem_maps()` + `mem_read()` по регионам). Путь сохраняется в `emulation.memory_dump_path`. Оркестратор передаёт в CVE-сканер **дамп** (а не исходный файл), если дамп существует; при обнаружении VMProtect приоритет CVE всегда отдаётся дампу.

**Deep Memory Scan (второй круг):** в `orchestrate.py` сразу после мержа supply_chain из эмуляции выполняется повторный анализ по дампу: для каждого evidence с существующим `emulation.memory_dump_path` вызываются **run_yara(dump_path)** и **run_cwe_checker(dump_path)**. Результаты сохраняются в **`ev["memory_dump_analysis"]`** (`yara`, `cwe`, `dump_path`). **Fallback EICAR:** если YARA не вернула хитов (например, yara-python не установлен), но в дампе присутствует строка `EICAR-STANDARD-ANTIVIRUS-TEST-FILE`, в `memory_dump_analysis.yara` добавляется синтетический хит **EICAR_Test** для верификации цепочки эмуляция → дамп → детект. Находки в дампе **критически влияют на вердикт:** в скоринге добавляется **RISK_MALWARE_IN_MEMORY = 80**, в reasons — «КРИТИЧЕСКАЯ УГРОЗА: Вредоносная сигнатура обнаружена в дампе памяти (Deep Memory Scan)»; при итоговом score ≥ порога deny решение становится **deny**. В human-отчёте блок **«[MEMORY DUMP] Анализ дампа памяти»** выводит YARA-совпадения и CWE-находки по дампу.

Порядок выполнения: в **sequential** режиме batch CVE (Syft+Grype) запускается **после** цикла по файлам (после DIE и эмуляции), чтобы эмуляция успела создать дампы; затем для каждого файла с дампом вызывается `collect_cve_for_file(dump_path, ev)` — Syft/Grype сканируют дамп и извлекают библиотеки из распакованного образа. Найденные библиотеки из дампа пишутся в **cli_debug.log**: `[cve_collector] emulation dump: libraries extracted (N): lib1@ver, lib2@ver, ...` (до 50 записей, при большем числе — «… +M more»).

**Docker-эмуляция:** при ошибке локального Speakeasy (например, «fail to load the dynamic library» на Windows) можно запускать эмуляцию в контейнере: `BIN_GATE_EMULATION_DOCKER=1`. Образ собирается командой `bin-gate emulation-build`; дамп из контейнера передаётся на хост в base64 по stdout и сохраняется во временный файл. **Скрипт эмуляции** (`docker/emulation/run_emulation.py`): по умолчанию `Speakeasy(debug=False)` и `se.debug = False` перед `se.run_module()`, чтобы не переполнять stdout и не мешать возврату результата из Docker.

**Binary fingerprinting (LIEF в контейнере):** в `run_emulation.py` для каждой загруженной DLL вызывается `extract_metadata(path)` (lief): версия из resources/optional_header и MD5 исполняемых секций. В stdout выводится маркер `!!!MODULE_INFO!!!:name=<dll>|ver=<version>|hash=<hash>`. На хосте `docker_utils` парсит этот формат и заполняет `report_dict["module_details"]` / `detailed_modules`. В `EmulationResult` доступны `module_details` и `detailed_modules`; CVE-коллектор и human-отчёт подставляют реальные версии DLL в SBOM и в таблицу зависимостей (колонка «Библиотека» с версией, напр. `zlib1.dll (v1.2.11)`).

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

#### 2.1 External OSINT & Reputation Feed (v3.2)

**Модуль `osint_analyzer.py`** — извлечение сетевых IoC из строк бинарника и логов Speakeasy, обогащение через внешние API и влияние на скоринг:

| Функция | Описание | Поле в Evidence |
|---------|----------|-----------------|
| **IoC Extraction** | IP, домены, URL из PE-строк, emulation decoded_strings/network | `osint.iocs`, `osint.risk_level` |
| **AbuseIPDB** | Репутация IP (при наличии ключа): abuseConfidenceScore ≥ 75 → C2 | `osint.c2_detected`, `osint.c2_ips`, `osint.ip_reputation` |
| **Whois/ASN** | Владелец и ASN; подозрительный хостинг (VPS, bulletproof) → suspicion | `osint.suspicious_asn`, `osint.suspicious_asn_ips` |

**Переменные окружения:**
- `ABUSEIPDB_API_KEY` — ключ AbuseIPDB (если не задан, обогащение IP через AbuseIPDB отключено)
- `BIN_GATE_OSINT_MAX_IPS_ENRICH` — лимит IP для обогащения (по умолчанию 20)
- `BIN_GATE_OSINT_ABUSEIPDB` — 1/true для включения AbuseIPDB
- `BIN_GATE_OSINT_ASN` — 1/true для включения Whois/ASN проверок

**Сертификаты и издатель (v3.2):** модуль `signing_trust.py` — полная цепочка до корневого CA, проверка CRL/OCSP и список скомпрометированных сертификатов (`BIN_GATE_STOLEN_CERT_LIST`). В `pe_hardening.py`: `uncertain_publisher` (издатель не в списке известных), `stolen_cert_detected` (отзыв или список). Эти флаги влияют на скоринг: **RISK_UNCERTAIN_PUBLISHER**, **RISK_STOLEN_CERT**.

**Supply Chain Guard (v3.2):** модуль `supply_chain_guard.py` — сравнение хэшей с известными OSS-релизами (`BIN_GATE_OSS_HASHES_JSON`), детекция typosquatting по именам зависимостей. Результат в `evidence.supply_chain_guard`; при `tampering_suspected` выставляется `pe.behavior_hints.supply_chain_tampering` и применяется **RISK_SUPPLY_CHAIN_TAMPERING**.

**Константы скоринга (v3.2):**
- **RISK_EXTERNAL_C2_MATCH** = 60 (блок при детекции C2 по внешнему фидбеку)
- **RISK_SUSPICIOUS_ASN** = 25
- **RISK_UNCERTAIN_PUBLISHER** = 15
- **RISK_SUPPLY_CHAIN_TAMPERING** = 80 (существующая константа; срабатывает при supply_chain_guard или иных признаках подмены)

Итоговый риск и причины (get_risk_reason_strings / build_risk_summary) учитывают osint (C2/ASN), подпись (издатель/украденный сертификат) и supply_chain_guard.

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

---

### v3.0: Deep & Recursive Inspection

Переход от анализа «поверхности» артефакта к анализу **внутренностей**: многослойная распаковка, глубокий разбор скриптов и медиа, потоковый анализ гигантских файлов.

#### 1. Многослойный рекурсивный Unpacker ✅ Добавлено

| Компонент | Описание |
|-----------|----------|
| **orchestrate.py** | После основного прогона воркеров и batch DIE вызывается **`_recursive_unpack_loop`**. Для каждого evidence с дампом памяти (`emulation.memory_dump_path`) и признаками упаковки или высокой энтропии (file entropy > 7.2) запускается повторный анализ по пути дампа; глубина рекурсии ограничена **3** уровнями (`RECURSIVE_UNPACK_MAX_DEPTH`). Результаты слоёв сохраняются в `ev["recursive_unpack_layers"]`, `ev["unpack_depth"]`. |
| **emulation.py** | **adaptive_timeout:** при детекции коммерческого протектора (VMProtect/Themida) эмуляция повторяется с увеличенным `max_api_calls` (шаг ×2, жёсткий предел `ADAPTIVE_MAX_API_CALLS_HARD_LIMIT`), пока не будет получен дамп памяти или отчёт с API-суммари (переход на «чистый» код / OEP) или не достигнут предел. |

Скоринг: **RISK_DEEP_OBFUSCATION_LAYERS (+60)** при `unpack_depth >= 3` или при 3+ элементах в `recursive_unpack_layers`.

#### 2. Deep Script Analysis (Python & Lua) ✅ Добавлено

| Модуль | Описание |
|--------|----------|
| **python_bytecode_analyzer.py** | Интеграция с декомпилятором (uncompyle6/decompyle3): извлечение AST из .pyc, поиск опасных вызовов (**eval**, **exec**, **os.system**, **subprocess**) в контексте подозрительных аргументов (decode, base64, request и т.д.). Результат: `evidence["python_bytecode"]`, `evidence["script_eval_detected"]` для скоринга **RISK_SCRIPT_EVAL_DETECTED (+35)**. |
| **lua_analyzer.py** | Анализ Lua-байткода: сканирование на **package.loadlib**, **ffi.load**, пути к .dll/.so; при наличии внешнего декомпилятора (unluac/luadec) — разбор исходного кода. Результат: `evidence["lua_bytecode"]` с полями `dynlib_loading`, `suspicious`. |

Опциональная зависимость: `uncompyle6` для Python bytecode (`pip install binary-intake-gate[python-bytecode]`).

#### 3. Advanced Stego-Scanner (Media & Metadata) ✅ Добавлено

| Модуль | Описание |
|--------|----------|
| **stego_detector.py** | Расширение за пределы LSB: **JPEG** — сегменты APP0–APP15 и COM на высокую энтропию или исполняемый код (MZ/PE); **PNG** — IDAT и кастомные чанки (tEXt, zTXt); **Resource Mapping** — порядок функций в IAT (Import Address Table): если порядок нетипичен для компилятора (например, kernel32 не в первой тройке DLL при множестве импортов), помечается как **T1027.003**. Результат: `evidence["suspicious_media_metadata"]`, `evidence["steganography"]["advanced"]` → **RISK_SUSPICIOUS_MEDIA_METADATA (+40)**. |

Существующий LSB-анализ в `steganography.py` (иконки/BMP) по-прежнему выполняется для PE.

#### 4. Streaming Entropy & YARA (Anti-Padding) ✅ Добавлено

| Модуль | Описание |
|--------|----------|
| **streaming_scanner.py** | Движок чтения файла **порциями по 1 МБ**: строится карта энтропии всего файла; участки с энтропией **> 6.0** считаются «островами» и принудительно отправляются на **YARA** (сканирование по буферу через `run_yara_on_data`). **Performance:** промежуточный вердикт **«Clean»** за 5 с при валидных заголовках и Entry Point — полная карта энтропии и острова тогда не строятся. Основной файл не загружается целиком в RAM. Результат: `evidence["streaming_scan"]` (early_verdict, entropy_map_len, islands, yara_island_hits); хиты островов дополняют `evidence["yara"]`. |

Используется при **is_giant** (файл > 200 МБ) в ветке aggressive_skip.

#### 5. Scoring & Evidence (v3.0) ✅ Добавлено

Добавленные веса рисков:

- **RISK_DEEP_OBFUSCATION_LAYERS** (+60) — 3+ уровня вложенности распаковки/обфускации.
- **RISK_SUSPICIOUS_MEDIA_METADATA** (+40) — подозрительные метаданные медиа (JPEG/PNG/IAT, T1027.003).
- **RISK_SCRIPT_EVAL_DETECTED** (+35) — динамическое выполнение кода в скриптах (eval/exec/os.system).

Причины DENY и маппинг в MITRE (get_risk_reason_strings, REASON_TO_MITRE_MAP) дополнены соответствующими формулировками и техниками (T1027.003, T1059).

**Статус подтехник v3.0:** ✅ Добавлено (рекурсивный unpacker, adaptive_timeout, Python/Lua bytecode, stego_detector, streaming_scanner, combo-risk, child artifacts по дампу, early Clean verdict).

---

### Attack Chain Analysis

Корреляция техник MITRE в цепочки атак и автоматизация повторного анализа дампов памяти.

#### Combo-Risk (scoring.py)

**Понятие «Комбо-риска»:** если в одном файле найдены техники из **разных стадий MITRE** (например, Credential Access + Exfiltration, Defense Evasion + Collection), к итоговому счёту добавляется **бонусный штраф +40** (`RISK_ATTACK_CHAIN_COMBO`).

- Тактики собираются из: capa (`attck_by_tactic`, `tactics`/`techniques`), emulation `techniques`, PE/document `technique_hints`.
- Маппинг ID техник в тактики: `TECHNIQUE_TO_TACTIC` (credential-access, exfiltration, defense-evasion, collection, execution и т.д.).
- Функция **`_get_ev_tactics(ev)`** возвращает множество тактик; при `len(tactics) >= 2` применяется комбо-штраф.
- В обосновании DENY: строка **«Цепочка атак (несколько стадий MITRE в одном файле)»**.

#### Recursive Feedback Loop (orchestrate.py)

**Любой результат Deep Memory Scan (дамп памяти)** автоматически:

1. Помечается как **Child Artifact** в `ev["child_artifacts"]`: `{ path, type: "memory_dump", parent_path, yara, secrets }`.
2. Проходит через **YaraScanner** (уже в блоке Deep Memory Scan) и **SecretScanner** (`analyze_secrets(dump_path)`) **без повторной эмуляции**.
3. Результаты сохраняются в `ev["memory_dump_analysis"]`: `yara`, `cwe`, `secrets`, `dump_path`.

Дамп не попадает в основной пул файлов для эмуляции — только YARA + CWE + Secrets.

#### Performance: StreamingScanner early verdict

**StreamingScanner** для гигантских файлов выдаёт **промежуточный вердикт «Clean»** уже через **5 секунд** (`EARLY_VERDICT_TIMEOUT_SEC`), если:

- Заголовки (PE/ELF) и **Entry Point** не вызывают подозрений (функция **`quick_header_verdict`**).
- Для PE: EP должен попадать в секцию `.text`/code; для ELF — базовая валидация заголовков.

При вердикте **«Clean»** полная карта энтропии и сканирование островов YARA **не выполняются** (ранний выход из `streaming_entropy_and_yara`), что ускоряет анализ гигантских файлов.

---

### Behavioral Correlation & Attack Storylines (v3.1)

Связывание разрозненных событий в логические сценарии Kill Chain и новые веса за связки техник.

#### Attack Storyline Engine (scoring.py & behavioral_graph.py) ✅ Добавлено

**Комбо-пары с фиксированными весами:**

| Связка техник | Описание | Штраф |
|---------------|----------|--------|
| **T1204 + T1562** | Initial Access (User Execution) + Defense Evasion | +30 |
| **T1003 + T1020** | Credential Access + Exfiltration (критично) | +50 |
| **T1082 + T1021** | Discovery (System Info) + Lateral Movement | +40 |

- Модуль **`behavioral_graph.py`**: `_collect_technique_bases(ev)`, **`compute_storyline_combo_score(ev)`** — возвращает (бонусный счёт, список причин). Пары заданы в **`STORYLINE_COMBO_PAIRS`**.
- В **scoring.py** результат комбо-пар добавляется к итоговому счёту; при наличии конкретной пары общий комбо +40 не дублируется.
- **Детекция Staged Execution:** **`detect_staged_execution(ev)`** — если артефакт (LNK/офис) загружает скрипт (stagers), а в техниках есть инъекция (T1055), формируется граф атаки **`ev["attack_storyline"]`** (nodes, edges) для итогового отчёта.

#### Recursive Feedback Loop (orchestrate.py) ✅ Добавлено

- **Child Artifact Analysis:** дамп памяти (.dmp) идёт через YARA, CWE, SecretScanner с **наследованием контекста** (`inherited_context.parent_path`, `no_re_emulation`). В **`child_artifacts`** сохраняются также **cwe** и **inherited_context**.
- **Context Propagation:** при обнаружении критической малвари в дампе в **scoring** добавляется причина **«Заблокировано на основе анализа содержимого памяти»**; вердикт DENY автоматически относится к исходному упакованному файлу (родителю).

#### Deep Script Decompilation (python_bytecode_analyzer.py) ✅ Добавлено

- **Динамическая сборка кода:** если скрипт конструирует строки из частей (например, **eval(base64.b64decode(...))**), помечается как техника **T1027** и **`dynamic_assembly_detected`**.
- **Декодирование первого слоя:** при наличии аргумента-константы в вызове base64.b64decode результат декодирования сохраняется в **`decoded_first_layer`** (до 500 символов).
- Поле **`technique_hints`** из Python bytecode мержится в **`evidence.technique_hints`** для скоринга.

#### Performance: Parallel Emulation (emulation.py) ✅ Добавлено

- **Лимит контейнеров:** одновременно запускается не более **`EMULATION_MAX_CONCURRENT`** (по умолчанию 2) контейнеров эмуляции. Переменные: **`BIN_GATE_EMULATION_MAX_CONCURRENT`**, **`BIN_GATE_EMULATION_SLOT_TIMEOUT`** (ожидание слота в секундах).
- Реализация через **слоты** в каталоге `tempdir/bin_gate_emulation_slots`: захват слота (**`_emulation_slot_acquire`**) перед **`run_emulation_container`**, освобождение (**`_emulation_slot_release`**) в **finally**. Анализ пакета из N файлов не создаёт N одновременных контейнеров — не более 2 (или заданного лимита), что снижает перегрузку CPU.

**Статус инфраструктурных задач v3.1:** ✅ Добавлено (Attack Storyline Engine, комбо-пары, Staged Execution граф, Child Artifact контекст, propagation DENY, dynamic_assembly T1027, лимит контейнеров эмуляции).

#### Enterprise Optimization: Analysis Profiles (Fast / Balanced / Deep)

Интенсивность проверки задаётся переменной **`ANALYSIS_PROFILE`** или флагом **`--analysis-profile`** (значения: `fast`, `balanced`, `deep`). Модуль **`profiles.py`**: `get_analysis_profile(args)`, `apply_analysis_profile_to_options()`, `recursive_unpack_max_for_profile()`, `should_run_cve_for_profile()`.

| Профиль | Цель | Эмуляция | CVE (Syft/Grype) | Рекурсивная распаковка | Остальное |
|--------|------|----------|-------------------|-------------------------|-----------|
| **Fast** (CI/PR) | &lt; 15 сек | Выкл | Выкл | 0 | Статика PE, YARA (основные), секреты (Regex), репутация, VT |
| **Balanced** (default) | 30–60 сек | По флагу/опции | Вкл | до 3 уровней | Стандартный набор |
| **Deep** (Release/Audit) | Макс. глубина | Вкл, таймаут 120+ | Вкл | до 5 уровней | Глубокий стего, все дампы памяти |

- **Кэш по профилю:** при сохранении в кэш в evidence пишется `_cache_analysis_profile`. При загрузке результат используется только если кэшированный профиль не «мельче» запрошенного (Deep можно использовать для Balanced/Fast, Balanced — для Fast).
- **VMProtect catch-up** и фаза CVE в `orchestrate` не выполняются для профиля Fast.

#### Short-circuit (Быстрый отказ)

Если **статический** этап уже выявил критическую угрозу, дальнейший анализ (эмуляция) для этого файла **не запускается** — вердикт формируется по статике (DENY). В **`run_one_file.py`** после YARA/PE/secrets вызывается **`_static_critical_deny(out)`**:
- YARA-хит из namespace/category **malware** → `short_circuit_deny = True`
- Отозванная подпись PE (`pe.signature.revoked === true`) → `short_circuit_deny = True`

При `out["short_circuit_deny"]` эмуляция Speakeasy для этого артефакта пропускается; политика и обоснование DENY строятся по уже собранному evidence.

#### Интеграция в CI (GitHub Actions / GitLab CI)

**GitHub Actions** — быстрый проход в PR, полный — на main/release:

```yaml
# .github/workflows/bin-gate.yml
name: Binary Intake Gate
on:
  push:
    branches: [main]
  pull_request:
    paths: ['artifacts/**', 'dist/**', '*.exe', '*.dll']
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install binary-intake-gate[emulation]
      - name: Fast scan (PR)
        if: github.event_name == 'pull_request'
        run: bin-gate scan ./artifacts --analysis-profile fast --fail-on deny
        env:
          ANALYSIS_PROFILE: fast
      - name: Deep scan (release)
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        run: bin-gate scan ./artifacts --analysis-profile deep --emulation --fail-on warn
        env:
          ANALYSIS_PROFILE: deep
          VT_API_KEY: ${{ secrets.VT_API_KEY }}
```

**GitLab CI** — аналогично, переменная `ANALYSIS_PROFILE` в `variables` или в `script`:

```yaml
# .gitlab-ci.yml (фрагмент)
bin-gate-fast:
  stage: test
  script:
    - pip install binary-intake-gate
    - bin-gate scan ./build --analysis-profile fast --fail-on deny
  variables:
    ANALYSIS_PROFILE: fast
```

#### 5. Binary SCA (CWE Checker)

**Модуль `docker_utils.py`** — интеграция **fkiecad/cwe_checker** для статического анализа бинарного кода на уязвимости CWE (buffer overflows, use-after-free и т.д.):

| Функция | Описание | Поле в Evidence |
|---------|----------|-----------------|
| **run_cwe_checker(path)** | Монтирование **родительской папки** как `/share:ro`; команда `docker run --rm -v {v_mount} {CWE_CHECKER_IMAGE} /share/<name> --json` | — |
| **Результат** | Парсинг JSON: регулярное выражение `\[\s*\{.*\}\s*\]` (re.DOTALL) по stdout, разбор найденного блока; stderr при returncode≠0 — в консоль `[DOCKER_ERROR]` и в поле `stderr` результата | `ev["cwe_analysis"]` = `{findings: [], error: str\|null, return_code: int, stderr: str}` |

**Оркестрация (`orchestrate.py`):** в **самом конце** `run_parallel_scan` (перед кэшированием и `return evidences`) выполняется **FINAL MANDATORY CWE STAGE** в одном основном процессе:
- Вывод в консоль: `!!! FINAL MANDATORY CWE STAGE START !!!` (с разделителем `=`).
- Для каждого `ev`: `target = Path(ev["meta"]["path"])` (при отсутствии meta/path — skip); вывод `[CWE_CHECK] Processing: <target.name>`; `ev["cwe_analysis"] = run_cwe_checker(target)`.
- Вызов CWE **не** выполняется внутри воркеров (`_analyze_file_parallel` и т.п.) — только в финальном цикле.

**Старт:** в `validate_docker_at_startup()` выполняется принудительный `pull_image(CWE_CHECKER_IMAGE)`; при неудаче выбрасывается `DockerImageNotFoundError`. Образ: `CWE_CHECKER_IMAGE = "fkiecad/cwe_checker:latest"`.

**Human-отчёт (`reporters/human.py`):** в блоке «4) Уязвимости зависимостей» вызывается `_append_cwe_section(lines, evidences)`:
- Если ни у одного evidence нет `cwe_analysis` (dict) — строка «Данные не поступили в отчет» и заголовок «ОШИБКА: ДАННЫЕ CWE НЕ ПЕРЕДАНЫ В РЕПОРТЕР».
- Если `cwe_analysis` отсутствует или равен None — **«— *Binary SCA*: КРИТИЧЕСКАЯ ОШИБКА: Код анализатора не был вызван. Проверьте инсталляцию пакета.»**, затем «Сканер не был запущен оркестратором».
- Если findings пустые, но в объекте cwe есть `error` — строка **«— *CWE*: Техническая ошибка ({cwe['error']}).»**
- При наличии находок: строка «— *Binary SCA*: Найдено {count} потенциальных CWE», затем **таблица** (№ | CWE / Описание | Критичность); критические CWE помечаются **CRITICAL**.

**Отладка:** в `run_cwe_checker` — вывод длины stdout `[DOCKER_CWE] Raw stdout length`; при returncode≠0 — `[DOCKER_ERROR] cwe_checker failed: <stderr>` в консоль.

#### 6. Policy Engine Extensions (v0.0.8)

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
| **v2.0** `steganography.detected` | bool | Стеганография (LSB высокая энтропия в иконках/BMP) |
| **v2.0** `binary_padding.detected` | bool | Файл > 200 МБ, ленивый анализ (T1027.001) |
| **v2.0** `tauri_webview_smuggling.detected` | bool | Архив с assets/*.js высокой энтропии (T1027.006) |
| **v2.0** `meta.route_jar_in_pe` | bool | JAR-in-EXE (Launch4j), маршрутизация на байт-код |

**VMProtect lockdown (жёсткое правило в движке):** при обнаружении «Protector: VMProtect» в DIE (поле detects) или в obfuscation.packer_families для профиля **prod** решение принудительно **deny**; при высоких детекциях VirusTotal (malicious ≥ 5) — дополнительная причина. Для профиля **dev** при VMProtect выставляется **warn**, если иначе было бы allow.

#### 6.1 Risk-Based Scoring (0–100) и обоснование DENY

Модуль **`scoring.py`** реализует числовой скоринг риска 0–100 (с учётом профиля окружения) и автоматическое обоснование блокировки:

| Фактор | Добавка к риску |
|--------|------------------|
| Hardening missing (ASLR/DEP/CFG, RELRO) | +10 |
| CWE обнаружены (Double Free, UAF, Format String и др.) | +30 |
| DGA обнаружены | +50 |
| Нет цифровой подписи (PE) **в DEV** | +20 |
| Нет цифровой подписи (PE) **в PROD** | +50 |
| Высокая энтропия (> 7.2) — обфускация | +25 |
| Совпадение с URLHaus | +40 |
| **Visual masquerading** (иконка документа или расширение документа при PE) | +20 |
| **Defense Evasion** — более 3 техник в категории (capa) | +15 |
| **Anti-VM / Anti-Analysis** (CPUID, RDTSC, гипервизор; capa/rule_hits) | +15 |
| **Persistence Logic** (строки автозагрузки: Run/RunOnce/Winlogon/Services/Task Scheduler) | +15 |
| **Ordinal imports** (скрытые импорты по ординалам; PE) | +10 |
| **Sneaky Network / DoH** (признаки DoH без контекста браузера) | +20 |
| **Секреты обнаружены** (AWS keys, токены, private keys — `secrets_scan.py`) | +15 |
| **YARA malware** (находка из внешней базы Yara-Rules/Neo23x0 или категория malware) | +70 |
| **Вредоносная сигнатура в дампе памяти** (Deep Memory Scan: `memory_dump_analysis.yara` не пуст) | +80 |
| **Отозванный сертификат подписи** (PE: `pe.signature.revoked === true`, OCSP/CRL) | +100 |
| **v2.0 Стеганография (T1027.003)** — LSB высокая энтропия в иконках/BMP (`steganography.detected`) | +50 |
| **v2.0 Экзотический рантайм Swift/Ruby/Lua** (embedded; `meta.language` in swift/ruby/lua) | +25 |
| **v2.0 Бинарный padding (T1027.001)** — файл > 200 МБ, ленивый анализ (`binary_padding.detected`) | +30 |
| **v2.0 Tauri/WebView smuggling (T1027.006)** — архив с assets/*.js высокой энтропии | +25 |
| **v2.0 Custom Cryptor (T1027.013)** — цепочка GetVolumeInformation → XOR → VirtualAlloc | +35 |
| **v3.0 Deep obfuscation layers** — 3+ уровня распаковки/обфускации (`unpack_depth`, `recursive_unpack_layers`) | +60 |
| **v3.0 Suspicious media metadata (T1027.003)** — JPEG/PNG/IAT аномалии (`suspicious_media_metadata`) | +40 |
| **v3.0 Script eval detected** — динамическое выполнение кода в скриптах (eval/exec) (`script_eval_detected`) | +35 |

#### v3.0: Deep & Recursive Inspection

Переход от анализа «поверхности» артефакта к анализу «внутренностей»: многослойная распаковка, глубокий анализ байт-кода скриптов, расширенная стеганография и потоковый анализ гигантских файлов.

| Компонент | Описание | Evidence / Скоринг |
|-----------|----------|---------------------|
| **Recursive Unpack** | После первого этапа (UPX/дамп памяти) при признаках упаковки или энтропии > 7.2 — повторный анализ до 3 уровней | `recursive_unpack_layers`, `unpack_depth`; RISK_DEEP_OBFUSCATION_LAYERS +60 при 3+ слоях |
| **Adaptive Timeout (Emulation)** | Для VMProtect/Themida — увеличение max_api_calls до дампа/OEP или жёсткого предела | Эмуляция с повторными запусками при отсутствии дампа |
| **Python Bytecode** | Декомпиляция .pyc (uncompyle6), AST, поиск eval/exec/os.system/subprocess с подозрительными аргументами | `python_bytecode.dangerous_calls`, `script_eval_detected`; RISK_SCRIPT_EVAL_DETECTED +35 |
| **Lua Bytecode** | Сканирование/декомпиляция Lua на loadlib, ffi.load, загрузку динамических библиотек | `lua_bytecode.dynlib_loading`, `suspicious` |
| **Advanced Stego** | JPEG APP0–APP15/COM, PNG IDAT/tEXt/zTXt, порядок IAT (T1027.003) | `suspicious_media_metadata`, `steganography.advanced`; RISK_SUSPICIOUS_MEDIA_METADATA +40 |
| **Streaming Entropy & YARA** | Чтение по 1 МБ, карта энтропии, острова с энтропией > 6.0 → YARA по буферу; основной файл — по дескриптору | `streaming_scan.entropy_map_size`, `yara_island_matches`; для гигантских файлов |

- **Интеграция с политикой:** в `evaluate_policy()` вызываются `compute_risk_score(ev, profile=profile)` и **`get_risk_reason_strings(ev, profile)`** — человекочитаемые причины дополняют `reasons`. После обновления `total_score = max(total_score, risk_score)` решение **пересчитывается** по порогам: при `total_score >= thr["deny"]` → **deny**, при `total_score >= thr["warn"]` → **warn**. При decision=deny — `build_deny_justification(ev, result)`; при **любом risk_score > 0** выставляется **justification** = сводка по модулям + «Причины: …» (список reasons). В `ev["policy"]` — `risk_score`, `critical_risk_jump`, `justification`, `reasons`.
- **Environment Profiles:** `compute_risk_score(ev, profile="dev"|"prod")` учитывает более строгие веса в PROD (отсутствие подписи PE → +50).
- **Differential scoring:** при росте риска > 30% относительно `historical_risk_score` — `critical_risk_jump=True`, причина `[differential] ... Manual Review`, решение минимум `warn`.
- **Visual masquerading:** жёсткая проверка в **pe_hardening.py** и **run_one_file.py**: если расширение файла — документ (`.xlsx`, `.docx`, `.pdf`, `.txt` и др.), а фактический тип по заголовку — PE, выставляются `visual.masquerading_suspect = True`, `visual.icon_mismatch = True`. В reasons добавляется «Критическое несоответствие типа файла и расширения (маскировка под документ)».
- **Entropy trigger:** при энтропии > 7.2 в политике при allow принудительно **warn** с причиной «High Risk: Obfuscated — требуется ручная проверка (manual review)».
- **Justification:** **build_risk_summary(ev)** формирует строку «Вредоносное ПО в памяти: Да/Нет, Секреты: Да/Нет, Маскировка: Да/Нет, Уязвимости: Да/Нет.» (находки в памяти — первыми). **build_deny_justification** при наличии reasons строит текст из `policy_result["reasons"]`, причины про дамп памяти («КРИТИЧЕСКАЯ УГРОЗА: … в дампе памяти») выводятся первыми.
- **Human-отчёт:** уровень риска (0–100), шкала, блок «Обоснование вердикта», **«HVCI-совместимость: Да/Нет»** (из `pe.hardening.hvci_compatible`), **«Предупреждение об обходе WDAC/AppLocker»** при `pe.wdac_bypass.suspect` (LOLBins/эвристики загрузчика), «Визуальный аудит», hardening (в т.ч. Intel CET), CWE, «Архитектурные риски (поиск секретов)», матрица MITRE ATT&CK, блок **[MEMORY DUMP]** — YARA/CWE по дампу памяти.
- **False positive mitigation:** валидная цифровая подпись доверенного вендора снимает штраф RISK_NO_SIGNATURE.

### 2. Поиск техник и сигнатур: YARA + DIE (быстрый режим) и capa (глубокий)

**Архитектура (v0.0.5):** Для повышения скорости анализа техники ATT&CK извлекаются из **YARA метаданных** и **DIE детектов** по умолчанию. Тяжёлый `capa` отключён — используется только при флаге `--deep-capa` или `ENABLE_DEEP_CAPA=1`.

- **YARA (основной источник техник):** `yara_scan.py` — компиляция правил из директории (или встроенные минимальные правила для упаковщиков PE/ELF), сканирование файла с таймаутом, лимитом размера и ограничением числа совпадений.
  - **Извлечение техник из meta:** парсинг полей `meta.technique`, `meta.attack`, `meta.mitre`, `meta.tactic`, `meta.capability` из YARA-правил.
  - **Keyword-based detection:** автоматический маппинг имён правил в техники ATT&CK (например, `PACKER_*` → `defense-evasion`, `*persistence*` → `persistence`).
  - **Функция `extract_all_techniques(yara_hits)`:** агрегирует все техники и формирует `(techniques, rule_hits)` для `Evidence.capa`.
  - Результат: `ev.yara[].techniques`, `ev.capa.techniques` (merged from YARA+DIE).

- **Внешние базы YARA (полноценный сканер угроз):** директория **`src/bin_gate/rules/external/`** и модуль **`rules/updater.py`** обеспечивают подключение и обновление внешних баз сигнатур.
  - **Источники:** Yara-Rules/rules (общая база малвари), Neo23x0/signature-base (APT, хакерские утилиты, anti-analysis, packers). При необходимости можно добавить Malpedia или иные агрегаторы.
  - **Команда синхронизации:** `python -m bin_gate.rules.updater --sync` или после установки пакета — `bin-gate-rules-sync --sync`. Требуется `git` в PATH и доступ в интернет.
  - **Интеграция в сканирование:** при наличии правил в `rules/external/` модуль `yara_scan.py` загружает их через **`_load_external_rules()`**: рекурсивная компиляция всех `.yar*`; при ошибке компиляции всего каталога — компиляция по файлам с пропуском сломанных. Хиты из внешних баз попадают в `ev["yara"]` с полем **namespace** (например, Yara-Rules, Neo23x0); любая находка из категории malware или из внешней базы даёт **+70 к risk_score** (RISK_YARA_MALWARE) и причину «Обнаружена сигнатура вредоносного ПО (внешняя база YARA)».
  - **Кэширование:** скомпилированные внешние правила сохраняются в **.yarc** (файл `external_{fingerprint}.yarac` в каталоге кэша YARA — `~/.cache/bin-gate/yara` или `%LOCALAPPDATA%\bin-gate\yara-cache`); при неизменном содержимом `external/` пересборка не выполняется.
  - Документация: **`src/bin_gate/rules/README.md`**.

- **DIE (Detect It Easy) — второй источник техник:**
  - При обнаружении packer/protector/cryptor автоматически добавляется `defense-evasion`.
  - Функция `extract_techniques_from_die(die_result)` возвращает `(techniques, rule_hits)`.
  - Findings добавляются в `Evidence.capa.rule_hits` с префиксом `DIE:` (например, `DIE:packer:UPX`, `DIE:protector:VMProtect`).

- **capa (глубокий режим, отключён по умолчанию):**
  - `capa_analyzer.py` с флагом `ENABLE_DEEP_CAPA` (default: False).
  - При `--deep-capa` или `ENABLE_DEEP_CAPA=1` — вызов внешнего бинарника `capa -j --quiet`.
  - **Агрегация по meta.att&ck:** функция `_extract_attck_by_tactic(rule)` извлекает из правил пары (tactic, technique id); в результате capa возвращается **`attck_by_tactic`** — словарь { тактика: [id/названия техник] }. В режиме YARA/DIE тактики также группируются в `attck_by_tactic`.
  - При таймауте или отсутствии capa — fallback на YARA+DIE данные.
  - Результат мержится с предсобранными техниками из YARA/DIE; в Evidence сохраняется `capa.attck_by_tactic` для отчёта «Матрица техник (MITRE ATT&CK)».

**Результат в Evidence:**
```python
ev.capa = {
    "techniques": ["defense-evasion", "persistence", ...],  # merged YARA + DIE (+ capa при --deep-capa)
    "rule_hits": ["YARA:PACKER_UPX", "DIE:packer:upx", ...],
    "attck_by_tactic": {"defense-evasion": ["T1562", ...], "persistence": [...], ...},  # для матрицы MITRE в отчёте
    "source": "yara_die" | "capa" | "yara_die_fallback"
}
```

**Полная интеграция маппинга MITRE во все анализаторы (v0.1.9):**
- **YARA:** `meta.technique`, `meta.mitre`, `meta.attack` → `extract_all_techniques()`, единый формат (T1562), без дублей.
- **Эмуляция:** Speakeasy → `emulation.techniques` (T1055, T1548.002 и др.).
- **Скоринг:** `get_risk_mitre_techniques(ev)` по `pe.technique_hints`, `ev.technique_hints` (LNK/Office), `behavior_hints`; `REASON_TO_MITRE_MAP` — автоматическое добавление ID при появлении причин в `scoring_reasons`; итог пишется в `ev["highlights"]["mitre_techniques"]`.

**Hybrid Evidence Collection (v1.0):** Сбор доказательств объединяет три уровня в единый Evidence:
- **Статика:** YARA, DIE, pe_hardening (строки, импорты, hardening, technique_hints), signing_trust, obfuscation, LNK/Office/PDF парсинг (`office_pdf_lnk`), PowerShell/скрипты — без выполнения кода.
- **Эмуляция:** Speakeasy — выполнение в изолированной среде, api_calls, techniques, дамп памяти; результат в `emulation.techniques`, `emulation.memory_dump_path`; дамп используется для Deep Memory Scan (YARA/CWE) и для CVE/SBOM (Syft/Grype по распакованным библиотекам).
- **Docker-сканеры:** DIE (horsicq/detectiteasy), Syft/Grype (SBOM + CVE), CWE checker — контейнеризированный анализ без установки инструментов на хост. Итог мержится в `evidence.die`, `evidence.cve`, `evidence.cwe_analysis`.

Синергия: статика даёт быстрые technique_hints и risk; эмуляция подтверждает поведение и даёт дамп для памяти и CVE; Docker даёт воспроизводимые результаты по упаковщикам и уязвимостям.

**Cross-Analyzer Mapping (v1.0):** Объединение находок YARA, Speakeasy и статического анализа в единые MITRE-индикаторы:
- **Источники:** (1) YARA — `meta.technique` / `meta.mitre` / `meta.attack` → `extract_all_techniques()` → `ev.capa.techniques` и rule_hits; (2) Speakeasy — поведенческие техники (process hollowing, UAC bypass, registry и т.д.) → `emulation.techniques`; (3) статика — `pe_hardening` строковые паттерны → `pe.technique_hints`, LNK/Office → `ev.technique_hints` через `office_pdf_lnk`.
- **Объединение:** при оценке политики (`evaluate_policy`) вызывается `get_risk_mitre_techniques(ev)`: объединяются `pe.technique_hints` и `ev.technique_hints`, плюс `behavior_hints` и `emulation.techniques`; к результату добавляются ID из `REASON_TO_MITRE_MAP` по строкам в `scoring_reasons`. Итоговый список без дублей записывается в `ev["highlights"]["mitre_techniques"]`.
- **Использование:** матрица MITRE в human-отчёте, политики по `capa_tactics` / правилам, SARIF и обоснование вердикта строятся на едином наборе ID (T1562, T1546.012, T1204.001 и т.д.).

Эта архитектура даёт **секунды на файл** вместо минут, сохраняя информацию о техниках для политик (`capa_tactics`).

### 3. Проверка подписей и доверия

- **signing_trust.py:** лёгкая проверка наличия таблицы подписи Authenticode в PE (DIR_SECURITY, размер); на **не-Windows** — проверка цепочки через **osslsigncode verify** (поле `valid`); при наличии `cryptography` — **базовая проверка отзыва по OCSP** (поле `revoked`: True/False/None). Результат мержится в `pe.signature` в `run_one_file.py` (`revoked`, `valid`).
- **pe_hardening.py:** полная проверка подписи через PowerShell (Status, SignerCertificate, TimeStamperCertificate) на Windows; на не-Windows — данные из signing_trust (valid/revoked).
- **Скоринг:** при `pe.signature.revoked === true` добавляется **RISK_REVOKED_CERTIFICATE = 100**; в `get_risk_reason_strings` — причина «Обнаружен отозванный сертификат подписи (CRL/OCSP)»; при decision=deny — эта фраза в justification.

Используется в политиках для «packed and unsigned», отозванных сертификатов и общих правил по доверию.

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
  - **Speakeasy (эмуляция):** в `run_one_file.py` после эмуляции в `supply_chain.dependencies` дописываются: URL из `emulation.decoded_strings`, URL из `emulation.network`, пути из `emulation.files` (type `file_ref`). В **orchestrate.py** после завершения эмуляции и **до этапа CVE** вызывается `_extract_dll_names_from_emulation`: имена DLL (паттерн `.*\.dll`) из `api_summary` и `decoded_strings` сохраняются в `evidence.supply_chain.dependencies` с `type: "dynamic_lib"`, source: `emulation_speakeasy_strings`. Версии DLL из эмуляции (`emulation.module_details` / `detailed_modules`, LIEF в контейнере) подставляются в синтетический SBOM в **cve/collector.py** вместо UNKNOWN; в human-отчёте в колонке «Библиотека» выводится версия рядом с именем (напр. `zlib1.dll (v1.2.11)`). Эти зависимости до начала CVE-сканирования доступны для синтетического SBOM в коллекторе.
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
- **Секреты:** `secrets_scan.py` — **Gitleaks (Docker)** по умолчанию: образ `zricethezav/gitleaks`, отчёт в файл проекта **`.tmp_gitleaks_report.json`** (избегание Permission denied в Windows Temp), монтирование исходников `/scan:ro` и корня проекта `/out:rw`; при ошибке или пустом результате — **regex fallback**. Regex-сканер читает файл с учётом **PE-оверлея** (`_read_file_with_overlay`: первые N байт + хвост 256 KB), ищет AWS Key ID, AWS Secret, GitHub/Slack/Discord/Telegram токены, private keys. Результат — `evidence.secrets` (`hits`, `suspicious`, `score`). Находки учитываются в скоринге (**RISK_SECRETS_DETECTED = +15**) и в обосновании DENY; в human-отчёте — блок **«Архитектурные риски (поиск секретов)»** (`_append_secrets_arch_risks`). Сбои Gitleaks пишутся в **cli_debug.log** (`_log_gitleaks_failure`). Env: `BIN_GATE_GITLEAKS=0` отключает Gitleaks (только regex); `BIN_GATE_PROJECT_ROOT` — база для пути отчёта.
- **Репутация по ключевым словам:** `reputation_scan.py` — сканирование по YAML-правилам (термины/регулярки).

Все перечисленные методики направлены на **быстрый статический анализ** EXE, MSI, ELF, архивов и смежных артефактов без запуска кода, с возможностью офлайн-режима (--no-network) и кэширования VT.

---

## Tech Stack & Architecture

### Используемые технологии (из кода и pyproject.toml)

- **Язык:** Python 3.10+ (до 3.14).
- **Версия проекта:** 0.0.8+ (binary-intake-gate); расширения v2.0 — Elite Level (стеганография, padding, экзотические рантаймы, Tauri/WebView, Go Garble, custom cryptors).
- **Бинарники/зависимости:** YARA (yara-python), capa (CLI, опционально при `--deep-capa`), DIE (Docker: `horsicq/detectiteasy`), Syft/Grype (Docker: `anchore/syft`, `anchore/grype`), CWE checker (Docker: `fkiecad/cwe_checker:latest`), Bandit (опционально, SAST для Python-пакетов).
- **Библиотеки:** pathlib, dataclasses, argparse, subprocess, re, json, sqlite3; для PE/ELF/Mach-O — pefile, pyelftools (elftools), lief (по контексту); YAML (policy), requests (VT API); опционально: packaging (pythonpkg), py7zr, rarfile (архивы), Playwright (VT UI).
- **Сборка:** PyInstaller (`bin-gate.spec`), **`build.ps1`** — полная сборка всех компонентов: (1) Python-пакет — `pip wheel . --wheel-dir dist`, затем `pip install -e .` (bin-gate, bin-gate-rules-sync в PATH); (2) **bin-gate.exe** в корень проекта (`pyinstaller --distpath . --workpath build bin-gate.spec`); (3) Docker-образ эмуляции **bin-gate-emulation:latest** (`python -m bin_gate.cli emulation-build`, при отсутствии Docker — предупреждение). В конце скрипта — итог по каждому компоненту (package, exe, Docker). Spec-файл настроен на сборку из `src/` с правильным `pathex`.
- **Конфигурация:** YAML-политики (policy.example.yaml), профили dev/staging/prod, пороги deny/warn.
- **Секреты и переменные окружения:** файл `.env.example` содержит шаблон всех переменных. Скопировать в `.env` и заполнить (`.env` в `.gitignore`).

### Supported Tech Stack (v1.2)

Поддерживаемые языки программирования и упаковщики с указанием глубины анализа:

| Язык / среда | Глубина анализа | Детекция |
|--------------|-----------------|----------|
| **Rust** | Signature only | DIE/YARA, секция .rustc, строки рантайма |
| **Go** | Signature only | DIE/YARA, go.buildid, runtime.main, language_rules исключения |
| **Python (PyInstaller)** | Full Unpacking | MEI/PYZ magic, extract_pyinstaller_pyz() — извлечение PYZ для статики |
| **Nuitka** | Signature only | DIE/YARA |
| **Nim** | Signature only | DIE/YARA, строки рантайма (NimMain, raiseException), экзотический +15 риск |
| **AutoIt / AutoHotkey** | Signature only | DIE/YARA, AU3!, AutoIt3, экзотический +15 риск |
| **Delphi / FreePascal** | Signature only | DIE/YARA, VCL/TForm/Borland |
| **Zig** | Signature only | DIE/YARA, секции/LLVM артефакты, экзотический +15 риск |
| **Electron (Node.js)** | Signature only | ASAR-подобный заголовок, app.asar, DIE/YARA |
| **.NET (C# / F#)** | Full (metadata) | Assembly Version, GUID, Strong Name, ConfuserEx/обфускаторы (dotnet_intel); без обфускации −10 к риску |
| **C/C++ (MSVC, GCC, Clang)** | Signature only | DIE compiler |
| **Swift (Win/Lin)** | v2.0 Signature | swiftCore, $s…, swift_retain (language_detector) |
| **Ruby / Lua (embedded)** | v2.0 Signature | mri_embed, RString / lua_, lua_state (language_detector); RISK_EXOTIC_RUNTIME_SWIFT_RUBY +25 |
| **Java (JAR-in-EXE)** | v2.0 Route | Поиск PK\x03\x04 в PE (Launch4j) → route_jar_in_pe, анализ байт-кода |
| **Go (Garble)** | v2.0 YARA | GO_Garble_Heuristic: Go без main.main/runtime.main (packers_detect) |

| Упаковщик / протектор | Глубина анализа | Поведение |
|----------------------|-----------------|-----------|
| **UPX** | Full Unpacking | pre_analysis_dispatch: распаковка перед YARA (unpack_upx) |
| **VMProtect** | Emulation support | force_emulation, timeout 60s, max_api_calls 5000, CVE по дампу |
| **Themida / Enigma / Obsidium** | Emulation support | force_emulation, timeout **120s**, max_api_calls 5000 |
| **PyInstaller / Nuitka** | First-level unpacker | extract_pyinstaller_pyz() — извлечение PYZ/MEI блоков для анализа Python-слоя |
| **MSI Installers** | Deep parsing | get_msi_custom_actions() — разбор CustomAction для бинарных DLL (best-effort) |
| **SFX (WinRAR / 7z)** | Signature only | is_sfx_archive() — определение самораспаковывающихся архивов |

**Scoring (v1.2):** Nim/Zig/AutoIt в контексте Enterprise — +15 к риску; .NET без обфускации — −10; PDB-пути окружения разработчика (\Users\admin\Desktop, …) — +20.

### Supported Runtimes & Protectors (MITRE ATT&CK)

Таблица поддерживаемых рантаймов и протекторов с версиями и глубиной анализа (APT-style):

| Рантайм / протектор | Версия/тип | Глубина анализа | Модуль |
|---------------------|------------|-----------------|--------|
| **Nim** | — | Signature (language_detector, DIE/YARA) | language_detector.py, language_analyzer.py |
| **Delphi / FreePascal** | VCL, Borland | Signature | language_detector.py |
| **AutoIt / AutoHotkey** | AU3!, AutoIt3 | Signature + при обнаружении → поиск скрипта в ресурсах | language_detector.py (route_autoit_resources) |
| **Zig** | LLVM | Signature | language_analyzer.py |
| **.NET (C#/F#)** | 4.0.30319 | Metadata + ConfuserEx detection | dotnet_intel.py, scoring RISK_OBFUSCATED_DOTNET |
| **UPX** | — | Full Unpacking (статический распаковщик перед YARA) | unpackers.unpack_upx, unpacker_orchestrator |
| **MPRESS** | — | Static unpack (диспетчер направляет на распаковщик) | unpacker_orchestrator.py |
| **Themida** | — | Emulation (aggressive_emulation=True, timeout 120s) | unpacker_orchestrator, emulation.py |
| **Enigma** | — | Emulation (aggressive_emulation=True, timeout 120s) | unpacker_orchestrator, emulation.py |
| **VMProtect** | — | Emulation (timeout 60s, max_api_calls 5000) | emulation.py |
| **PyInstaller** | pyi-archive, MEI | First-level: извлечение имён упакованных файлов из оверлея | pyinstaller_extractor.py, unpackers.extract_pyinstaller_pyz |
| **Ruby (embedded)** | v2.0 | Signature (mri_embed, RString, rb_enc) | language_detector.py, artifact_factory.build_ruby_embedded_sample |
| **Lua (embedded)** | v2.0 | Signature (lua_, lua_state, luaopen_) | language_detector.py, artifact_factory.build_lua_embedded_sample |
| **Swift (Win/Lin)** | v2.0 | Signature (swiftCore, $s…, swift_retain) | language_detector.py, artifact_factory.build_swift_sample |
| **Java JAR-in-EXE (Launch4j)** | v2.0 | Поиск PK\x03\x04 в PE → маршрутизация на анализ байт-кода | language_detector.find_jar_in_pe, route_jar_in_pe, jar_in_pe_offset |
| **Go Garble** | v2.0 | YARA: GO-рантайм без main.main/runtime.main | go_rust_packers_advanced.yar (GO_Garble_Heuristic), packers_detect |

**Scoring (APT/MITRE):** RISK_UNCOMMON_RUNTIME (Nim, Zig, AutoIt) +20; RISK_COMMERCIAL_PROTECTOR (Themida, Enigma) +40; RISK_OBFUSCATED_DOTNET (ConfuserEx) +30; **v2.0:** RISK_STEGANOGRAPHY_DETECTED +50, RISK_EXOTIC_RUNTIME_SWIFT_RUBY +25, RISK_PADDING_DETECTED +30, RISK_TAURI_WEBVIEW_SMUGGLING +25, RISK_CUSTOM_CRYPTOR_T1027_013 +35.

### Elite Level Support (v2.0) — Exotic & Invisible Horizon

Защита от продвинутых техник маскировки и экзотических рантаймов:

| Механизм | Описание | Модуль / Evidence |
|----------|----------|-------------------|
| **Стеганография (T1027.003)** | LSB-анализ в иконках и BMP-ресурсах PE; высокая энтропия битов LSB — признак скрытых данных. Для файлов > 200 МБ разбор PE-ресурсов не выполняется (избежание OOM). | `steganography.py` → `evidence.steganography.{detected, lsb_high_entropy}`; **RISK_STEGANOGRAPHY_DETECTED +50** |
| **Бинарный padding (T1027.001)** | Файлы > 200 МБ обрабатываются в «ленивом» режиме: только заголовки, Entry Point, импорты и оверлей; мусорные данные не загружаются в память. | `streaming_reader.py`, `run_one_file.py` → `evidence.binary_padding.{detected, lazy_analyzed}`; **RISK_PADDING_DETECTED +30** |
| **Tauri/WebView smuggling (T1027.006)** | В архивах (ZIP/JAR/VSIX) проверяются пути `assets/`, `resources/`, `www/` на наличие .js с высокой энтропией (обфусцированный JS для сборки малвари). | `tauri_webview.py` → `evidence.tauri_webview_smuggling`, technique_hints T1027.006 |
| **Экзотические рантаймы (Swift, Ruby, Lua)** | Детекция по сигнатурам (swiftCore, $s…; Ruby/Lua embedded). JAR-in-EXE (Launch4j): поиск PK\\x03\\x04 в PE, маршрутизация на анализ байт-кода. | `language_detector.py`, `artifact_factory.py`; **RISK_EXOTIC_RUNTIME_SWIFT_RUBY +25** |
| **Go Garble** | YARA-эвристика: Go-рантайм без строк `main.main` / `runtime.main` (обфускация имён). | `go_rust_packers_advanced.yar` (GO_Garble_Heuristic), `packers_detect.py` |
| **Custom Cryptors (T1027.013)** | Цепочка API: GetVolumeInformation → XOR → VirtualAlloc (генерация ключа на основе железа). | `pe_hardening.py` → technique_hints T1027.013 |
| **.NET Boxed App / Eazfuscator** | Сигнатуры в статическом анализе .NET. | `dotnet_intel.py` (KNOWN_OBFUSCATORS) |

**Streaming reader:** модуль `streaming_reader.py` — безопасное чтение «раздутых» файлов (порог 200 МБ): `read_head`, `read_tail`, `read_pe_lazy`, `is_giant_file`, итератор по чанкам (`open_stream`) для предотвращения OOM. Используется в `run_one_file.py` при `binary_padding.detected` для language_detector (только head).

**Evidence (v2.0):** в объекте Evidence/evidence dict присутствуют: `steganography` (detected, lsb_high_entropy, details, mitre), `binary_padding` (detected, size_mb, lazy_analyzed, mitre), `tauri_webview_smuggling` (detected, assets_js_high_entropy, tauri_wry_hints), топ-уровень `technique_hints` (в т.ч. T1027.006 из архива), `meta.route_jar_in_pe`, `meta.jar_in_pe_offset`.

**Тесты методологии (v2.0):** в `tests/test_methodology.py`: `test_giant_file_handling` — генерация файла с полезной нагрузкой в конце (размер задаётся `BIN_GATE_GIANT_TEST_MB`, по умолчанию 201 МБ), проверка отсутствия OOM и установки `binary_padding.detected`; `test_stego_extraction` — проверка анализатора стеганографии (LSB-энтропия, T1027.003).

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
| `BIN_GATE_GITLEAKS` | Включить Gitleaks для поиска секретов (1 = да; 0 = только regex fallback) | 1 |
| `BIN_GATE_PROJECT_ROOT` | Корень проекта для отчёта Gitleaks (`.tmp_gitleaks_report.json`) и cli_debug.log | cwd |
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

2. **Автоматическая проверка контейнеров:** после валидации Docker в `validate_docker_at_startup()` выполняются:
   - Создание кэш-volumes (Grype, Syft, DIE).
   - Принудительный pull образа CWE checker (`fkiecad/cwe_checker:latest`); при неудаче — `DockerImageNotFoundError`.
   - Если CVE включен (не `--no-cve`): проверяются образы Syft и Grype.
   - Если DIE включен (не `--no-die`): проверяется образ DIE.
   - Недостающие образы автоматически загружаются (если не `--no-auto-pull`).
   - При ошибке загрузки — предупреждение, но scan продолжается с уменьшенной функциональностью.

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

7. **Цикл по файлам:** для каждого пути вызывается `sniff_magic` → определение типа (PE, ELF, MACHO, EXT, MANIFEST). Создаётся объект `Evidence` (`new_evidence`), заполняются `meta` (path, name, type, size). К evidence привязывается происхождение (MSI/архив) через `annotate_evidence`. **CWE (Binary SCA)** выполняется **только в конце** `run_parallel_scan` (FINAL MANDATORY CWE STAGE): для каждого evidence `target = Path(ev["meta"]["path"])`, вывод `[CWE_CHECK] Processing: <target.name>`, `ev["cwe_analysis"] = run_cwe_checker(target)`; вызовов run_cwe_checker внутри воркеров нет.

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

11. **Политика:** для каждого evidence вызывается `evaluate_policy(ev_dict, policy, profile, historical_risk_score=None)`. Движок в `policy/engine.py`: CEL-подобные выражения (when) с безопасным доступом к pe, elf, vt, die, yara_families, capa_tactics, cve, reputation, obfuscation, supply_chain (в т.ч. dependencies); правила с score или then: deny/warn. После применения правил выполняется **VMProtect lockdown:** при обнаружении «Protector: VMProtect» в DIE (detects) или в obfuscation.packer_families для профиля **prod** решение принудительно **deny** (при высоких детекциях VirusTotal — усиление); для **dev** — **warn**, если иначе было бы allow. Далее выполняется risk scoring `compute_risk_score(ev, profile=profile)` и (опционально) дифференциальный контроль скачка риска через `historical_risk_score` (см. 6.1). Итог: decision (allow/warn/deny), score, reasons, matched, `risk_score`, `critical_risk_jump`. Результат записывается в `ev_dict["policy"]`.

12. **Постобработка:** сверка MF-манифестов с хэшами, проверка OVF references (missing/size_mismatch).

13. **Выход:** `write_markdown_report` (report.md), опционально `write_human_report` (путь из `--human-out` или `BIN_GATE_HUMAN_OUT_DEFAULT`), `write_sarif_report`, GitHub Step Summary и аннотации. В **human-отчёте** (reporters/human.py): **сразу под заголовком «ПРОВЕРКА»** — уровень риска (0–100), визуальная шкала (progress bar), блок **«Обоснование вердикта»** (build_deny_justification при DENY). Далее: блок *«Обнаружено в памяти (Dynamic Load)»* — список DLL из `supply_chain.dependencies` (type `dynamic_lib`, из эмуляции), с версией из `emulation.module_details`/`detailed_modules`; раздел 4 — **«Анализ бинарного кода (CWE)»** (`_append_cwe_section`), подраздел **«Архитектурные риски»** (CWE-415, 416, 134); **«Архитектурные риски (поиск секретов)»** (`_append_secrets_arch_risks`) — критические замечания по результатам анализа секретов (AWS, токены и т.д.); таблица **«Матрица техник (MITRE ATT&CK)»** по тактикам (`_append_mitre_matrix`); блок **«[MEMORY DUMP] Анализ дампа памяти»** — YARA и CWE по дампу эмуляции (`_append_memory_dump_section`); в строке hardening для PE выводится **Intel CET (IBT)** при наличии Load Config с GuardFlags; при DENY — обоснование VMProtect/скрытые библиотеки. Код возврата — `--fail-on` (none/warn/deny).

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
- **`--analysis-profile {fast,balanced,deep}`** — интенсивность анализа (Enterprise): `fast` — CI/PR (&lt;15 с, без эмуляции/CVE/рекурсии), `balanced` (по умолчанию), `deep` — полная распаковка и эмуляция. Env: **`ANALYSIS_PROFILE`**.

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

### CLI-команды для CVE, эмуляции и правил YARA

- `bin-gate cve-check` — проверка готовности (Docker, образы Syft/Grype).
- `bin-gate cve-check --pull` — проверка + автоматический pull недостающих образов.
- `bin-gate cve-update` — обновление базы уязвимостей Grype. То же обновление выполняется автоматически перед каждым CVE-сканом (если не задано `--no-cve-update`).
- `bin-gate emulation-build` — сборка Docker-образа для эмуляции (Speakeasy в контейнере); используется при `BIN_GATE_EMULATION_DOCKER=1`.
- **`python -m bin_gate.rules.updater --sync`** или **`bin-gate-rules-sync --sync`** — первоначальная загрузка и синхронизация внешних баз YARA (Yara-Rules, Neo23x0) в `src/bin_gate/rules/external/`. Требуется git и сеть.

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
| **`emulation`** | dict | **Speakeasy эмуляция (v0.0.8)**; включает `module_details` / `detailed_modules` (LIEF: версия и хеши секций DLL) |
| **`cwe_analysis`** | dict | **Binary SCA (CWE checker):** `{findings, error, return_code, stderr}` — результат fkiecad/cwe_checker по бинарнику (монтирование родительской папки как /share) |
| **`memory_dump_analysis`** | dict | **Deep Memory Scan:** после эмуляции — повторный YARA + CWE по дампу: `{yara, cwe, dump_path}`; в отчёте — префикс [MEMORY DUMP] |
| **`threat_intel`** | dict | **Threat Intelligence данные (v0.0.8)** |
| **`visual`** | dict | **Icon и resource analysis (v0.0.8);** при маскировке (иконка документа + PE): `masquerading: True`, `icon_mismatch` |
| **`script_analysis`** | dict | **Deep script/office analysis (v0.0.8)** |
| **`persistence_analysis`** | dict | **Persistence Logic:** признаки закрепления по строкам (Run/RunOnce/Winlogon/Services/Task Scheduler) |
| **`network_profile`** | dict | **Network Profile:** DoH/скрытый сетевой профиль (sneaky_doh) по строкам и контексту браузера |
| **`secrets`** | dict | **Поиск секретов** (secrets_scan.py): `{hits, suspicious, score}` — AWS keys, токены, private keys; влияет на risk_score (RISK_SECRETS_DETECTED) и блок «Архитектурные риски (поиск секретов)» в отчёте |
| `errors` | list | Ошибки анализа |

В процессе скана в объект добавляются и другие атрибуты (например, manifest, python_pkg, docscripts); финальный отчёт строится по списку словарей evidence (ev.to_dict() + policy).

---

## Professional Context

- **DevSecOps:** шлюз встроен в пайплайн приёма артефактов: один запуск по директории или файлу, выход — отчёт и решение политики (allow/warn/deny). Поддержка профилей (dev/staging/prod) и порогов позволяет ужесточать требования к prod. Флаг `--fail-on` даёт возможность падать по CI при warn/deny. SARIF и GitHub Checks (step summary, annotations) позволяют интегрировать результаты в системы код-сканирования и PR-чеклисты.
- **Анализ LNK / Office / Scripts:** для форматов `.lnk`, `.doc`/`.docx`, `.xlsx`, `.pptx`, `.pdf`, `.ps1`, `.js`, `.vbs` выполняется **office_pdf_lnk** (парсинг LNK: command line, URL на .zip/.iso → T1204.001; Base64/hex payloads; Office/VBA — oletools при наличии). Результат в `evidence.docscripts` и `evidence.technique_hints`; при наличии подозрительных паттернов — риск и MITRE ID в `highlights.mitre_techniques`. Поддержка подтверждена тестами: `test_lnk_and_office_parsing`, `test_apt_techniques_coverage[t1204_001_malicious_link]`, артефакты `build_t1204_001_malicious_link`, `build_lnk_sample`.

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
  - **CWE:** монтирование родительской директории в `/share`; парсинг JSON через regex `\[\s*\{.*\}\s*\]` (re.DOTALL). При returncode≠0 в консоль — `[DOCKER_ERROR] cwe_checker failed: <stderr>`; в консоль также длина stdout `[DOCKER_CWE] Raw stdout length`. В конце `run_parallel_scan` — этап `!!! FINAL MANDATORY CWE STAGE START !!!`, для каждого evidence — `[CWE_CHECK] Processing: <name>`, затем `run_cwe_checker(target)`.
  - Сообщения в коде часто имеют доменный префикс (`pe_error:...`, `capa_error:...`, `vt_http_error:...`).

- **Внешние вызовы:** subprocess/Docker для capa, YARA, DIE, Syft, Grype, Bandit, PowerShell — с таймаутами и лимитами размера файла, чтобы тяжёлые файлы не блокировали скан. Сетевые запросы (VT) — с throttle (min_interval), таймаутами и повторными попытками. Работа с путями в архивах — через безопасную сборку (`_safe_join`), блокировка path traversal и симлинков в распаковщике.

- **Конфигурация:** пути к правилам и ключи задаются через CLI и переменные окружения (CAPA_RULES_DIR, YARA_RULES_DIR, VT_API_KEY, CVE_ECOSYSTEM и т.д.), что удобно для CI и разных сред без изменения кода.

- **Секреты:** VT API ключ и другие чувствительные данные **НЕ хранятся в коде**. Используется `.env` файл (шаблон: `.env.example`), который добавлен в `.gitignore`.

---

## QA / Automated Security Testing

Проект содержит автоматизированные QA-тесты, которые проверяют ключевые модули анализа: Hardening (в т.ч. CFG, HighEntropyVA, Intel CET), Masquerading, Scoring, Differential, Persistence, Network (DoH), Memory Dump (YARA в отчёте), поиск секретов (secrets_scan), парсинг LNK/Office и попадание URL в supply_chain.dependencies, детекцию Intel CET (Load Config GuardFlags), снижение риска при валидной подписи (false positive mitigation), обоснование DENY (justification), валидацию human_report (уровень риска, блоки ПРОВЕРКА и Архитектурные риски).

### Artifact Factory

- **`tests/artifact_factory.py`** генерирует минимальные PE артефакты и тестовые файлы (без внешних зависимостей от компилятора):
  - **Naked:** PE без ASLR/DEP/CFG (DllCharacteristics=0)
  - **Hardened:** PE с ASLR/DEP/CFG/HighEntropyVA (DllCharacteristics=0x4570)
  - **Masquerade:** PE, сохранённый под именем `report.xlsx` (триггер icon/name mismatch)
  - **Sneaky:** PE с оверлеем, содержащим DoH строки и пути автозагрузки Run/RunOnce
  - **Ordinal:** PE для проверки структуры полей ординальных импортов (см. `pe.ordinal_imports`)
  - **high_entropy:** PE с оверлеем из высокоэнтропийных данных (энтропия > 7.2) для проверки Entropy Trigger
  - **with_secrets:** PE с оверлеем, содержащим строки-имитаторы секретов (AWS Key ID, AWS Secret Access Key) для проверки `secrets_scan.py`
  - **cet_hardened:** PE с двумя секциями (.text, .rdata), в .rdata — структура **IMAGE_LOAD_CONFIG_DIRECTORY32** с GuardFlags (CET IBT: RF_INSTRUMENTED | RF_ENABLE) для детекта Intel CET в `pe_hardening.py`
  - **hvci_compliant:** PE с **IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY** (0x0080), секцией .reloc и без W^X — для проверки `pe.hardening.hvci_compatible === true`
  - **wdac_bypass_sample:** PE с оверлеем, содержащим строки certutil/mshta (LOLBins) — для проверки `pe.wdac_bypass.suspect` и `lolbins_detected`
  - **revoked_sig_mock:** минимальный PE без подписи; тесты отзыва используют мок evidence с `signature.revoked=true`
  - **lnk_sample:** минимально валидный .lnk файл с аргументами командной строки (PowerShell DownloadString, URL) для проверки парсинга LNK и попадания URL в `supply_chain.dependencies` (при `deep_script`)
  - **Поддержка форматов LNK / Office / Scripts (v1.0):** анализ артефактов охватывает `.lnk`, `.doc`/`.docx`, `.xlsx`, `.pptx`, `.pdf`, `.ps1`, `.js`, `.vbs`. Модуль `office_pdf_lnk` парсит LNK (command line, URL на .zip/.iso → T1204.001), Base64/hex payloads; при наличии oletools — Office/VBA. Результат в `evidence.docscripts` и `evidence.technique_hints`; тесты `test_lnk_and_office_parsing`, `test_apt_techniques_coverage[t1204_001_malicious_link]` и артефакты `build_t1204_001_malicious_link`, `build_lnk_sample` подтверждают поддержку.

### Pytest E2E

- **`tests/test_methodology.py`** прогоняет артефакты через `run_one_file_analysis` и проверяет:
  - **test_hardening_score:** базовый risk scoring в профилях **DEV/PROD** (Naked vs Hardened), включая проверку CFG и HighEntropyVA для Hardened.
  - **test_masquerading_alert:** алерты мимикрии и блок «Визуальный аудит» в human-отчёте (артефакт Masquerade).
  - **test_entropy_trigger:** артефакт high_entropy — энтропия > 7.2 и/или риск/флаг manual review.
  - **test_ordinal_resolution:** наличие полей `pe.ordinal_imports`, `pe.dangerous_ordinal_imports`, `pe.has_ordinal_imports`.
  - **test_persistence_detection:** строки автозагрузки (Run/RunOnce/Winlogon) в артефакте Sneaky распознаются `persistence_analysis`.
  - **test_sneaky_network_doh_detection:** DoH-индикаторы и `network_profile.sneaky_doh` для артефакта Sneaky.
  - **test_differential_scoring:** общий сценарий дифференциального риска и текст о скачке >30%.
  - **test_differential_jump:** симуляция роста риска с 10 до 50 для одного Identity → флаг `critical_risk_jump` и `evaluate_policy(..., historical_risk_score=10)`.
  - **test_justification_text:** при DENY в `policy.justification` присутствуют ключевые фразы (ASLR, DGA, маскировка/мимикрия).
  - **test_supply_chain_dynamic_lib_in_report:** evidence с `supply_chain.dependencies` (dynamic_lib) не ломает human-отчёт; проверка блока ПРОВЕРКА/уровень риска.
  - **test_memory_dump_scan:** YARA-находки из `memory_dump_analysis` попадают в human-отчёт (секция *[MEMORY DUMP]* и имена правил).
  - **test_profile_no_signature_penalty:** в PROD отсутствие подписи даёт +50, в DEV +20.
  - **test_human_report_crosscheck:** финальная валидация human_report — уровень риска, ПРОВЕРКА, при DENY обоснование вердикта, при masquerade — Визуальный аудит или имя артефакта.
  - **test_secret_scanning_logic:** артефакт with_secrets — модуль секретов фиксирует находки (hits/suspicious), risk_score увеличивается на RISK_SECRETS_DETECTED; в human-отчёте присутствует блок по секретам/архитектурным рискам.
  - **test_lnk_and_office_parsing:** .lnk артефакт (lnk_sample) прогоняется с `deep_script=True`; проверка извлечения метаданных (target_path, arguments, command_line), подозрительных аргументов и попадания извлечённых URL в `supply_chain.dependencies`.
  - **test_cet_detection:** артефакт cet_hardened — в отчёте флаг Intel CET (cet_ibt или cet_shstk) помечен как Enabled (Load Config с GuardFlags).
  - **test_false_positive_mitigation (Negative):** артефакт с сетевым поведением (sneaky_doh), но с валидной подписью доверенного вендора — итоговый риск существенно ниже, чем без подписи; проверка, что подпись снимает штраф и снижает risk_score.
  - **test_deep_memory_scan_eicar:** полный цикл эмуляции + дамп + Deep Memory Scan; проверяет наличие EICAR в дампе, попадание **EICAR_Test** в `ev["memory_dump_analysis"]["yara"]` (в т.ч. через fallback при отсутствии yara-python), **risk_score ≥ 100** (ограничено 100), **decision = deny**, justification с «Вредоносное ПО в памяти: Да» и причиной про критическую угрозу в дампе.
  - **test_external_rules_loading:** проверяет, что сканер успешно инициализируется с подключёнными внешними базами (загрузка основных правил, вызов `_load_external_rules()`, устойчивость `run_yara` на тестовом файле). При отсутствии yara-python тест пропускается.
  - **test_gitleaks_integration:** файл с секретами (with_secrets) прогоняется через Gitleaks (Docker); при доступном Docker проверяется заполнение `evidence.secrets.hits`; при недоступности Docker тест пропускается; при пустом/ошибочном результате Gitleaks используется regex fallback (в т.ч. по PE-оверлею).
  - **test_hvci_and_wdac_detection:** для артефакта hvci_compliant — `pe.hardening.hvci_compatible === true`; для wdac_bypass_sample — `pe.wdac_bypass.suspect` или `lolbins_detected` не пусты.
  - **test_signature_revocation_scoring:** симуляция отозванного сертификата (evidence с `signature.revoked=true`) — risk_score ≥ 100, decision=deny, в justification/reasons фраза «Обнаружен отозванный сертификат подписи (CRL/OCSP)».
  - **test_osslsigncode_fallback:** (только не-Windows) проверка, что при отсутствии PowerShell подпись проверяется через osslsigncode и данные издателя извлекаются.
  - **test_human_report_hvci_wdac_justification:** в блоке «Обоснование вердикта» human-отчёта присутствуют «HVCI-совместимость» и предупреждение WDAC/AppLocker.
  - **test_methodology_results_json:** сводный JSON по методологическим тестам (gitleaks, hvci_wdac, revocation, osslsigncode, human_report) записывается в `methodology_results.json` в каталог артефактов (при запуске с `-s`).

### Локальный запуск

```bash
pip install -e ".[test]"
pytest tests/test_methodology.py -v
```

### Makefile / CI

- `make test-security` — запускает security QA тесты (pytest).
- `.github/workflows/test-security.yml` — GitHub Actions workflow для PR/push.

---

## Project Structure

```
bin_intake_gateway/
├── .github/workflows/       # CI
│   └── test-security.yml    # GitHub Actions: make test-security
├── tests/                  # QA (artifact factory + pytest)
│   ├── artifact_factory.py
│   ├── test_methodology.py
│   └── conftest.py
├── src/bin_gate/           # Основной код
│   ├── analyzers/          # Анализаторы (PE, ELF, YARA, DIE, capa, etc.)
│   │   ├── pe_hardening.py     # PE hardening checks (Enterprise); masquerading по расширению документа + PE
│   │   ├── elf_checksec.py     # ELF checksec (Enterprise)
│   │   ├── dotnet_intel.py     # .NET assembly intelligence
│   │   ├── die_scanner.py      # Detect It Easy (Docker)
│   │   ├── yara_scan.py        # YARA scanning; внешние базы из rules/external/, кэш .yarc
│   │   ├── capa_analyzer.py    # capa (optional, deep mode)
│   │   ├── persistence_logic.py # Persistence Logic: Run/RunOnce/Winlogon/Services/Tasks (strings)
│   │   ├── network_profile.py   # Network Profile: DoH/sneaky network (strings)
│   │   ├── archive_dispatcher.py # Archive extraction (streaming)
│   │   ├── memory_stream.py    # In-memory file processing
│   │   └── ...                 # Остальные анализаторы
│   ├── rules/              # Внешние базы YARA и загрузчик
│   │   ├── __init__.py         # get_external_rules_dir()
│   │   ├── updater.py          # Синхронизация Yara-Rules, Neo23x0 (--sync)
│   │   ├── external/           # Каталог для скачанных правил (заполняется updater)
│   │   └── README.md           # Документация по загрузке и кэшу
│   ├── integrations/       # Внешние API (VirusTotal, Playwright)
│   ├── cve/                # CVE scanning (Syft + Grype)
│   │   └── collector.py        # ContainerVulnerabilityScanner, Supply Chain Risk
│   ├── cache/              # SQLite кэш
│   ├── policy/             # Движок политик (пересчёт decision после risk_score)
│   ├── reporters/          # Генераторы отчётов (MD, SARIF, GitHub)
│   ├── extractors/         # Распаковщики (MSI, архивы)
│   ├── docker_utils.py     # Docker (Hard Fail, volumes, run_cwe_checker /share mount, CWE JSON parse)
│   ├── orchestrate.py      # Parallel analysis; Deep Memory Scan (YARA+CWE по дампу, fallback EICAR); FINAL MANDATORY CWE STAGE
│   ├── scoring.py          # Risk 0–100 (memory dump +80, YARA malware +70, masquerading, secrets, …); get_risk_reason_strings; build_risk_summary; build_deny_justification
│   ├── evidence.py         # Evidence dataclass
│   └── cli.py              # Точка входа CLI
├── rules/                  # YARA правила (проектный каталог; в т.ч. anti_vm_debug.yar)
├── policy/                 # YAML политики
├── .env.example            # Шаблон переменных окружения
├── .gitignore              # Исключения из git
├── pyproject.toml          # Метаданные проекта
├── build.ps1               # Полная сборка: wheel, bin-gate.exe (PyInstaller), Docker-образ эмуляции; итог по компонентам
├── Makefile                # QA targets: test-security, artifacts, cleanup
└── CURSOR.md               # Эта документация
```

### .gitignore

Исключены из репозитория:
- **Логи:** `*.log`, `cli_debug.log`, `vt_debug.log`
- **Отчёты:** `report.md`, `report.json`, `human_report.md`, `*.sarif`
- **Сборка:** `build/`, `dist/`, `*.exe`, `*.spec`
- **Секреты:** `.env`, `.env.local` (но НЕ `.env.example`)
- **Временные:** `.tmp_bin_gate/`, `.tmp/`, `.tmp_gitleaks/`, `.tmp_gitleaks_report.json`, `__pycache__/`
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
- `validate_docker_at_startup()` — валидация при старте CLI (Hard Fail); принудительный pull `CWE_CHECKER_IMAGE` (fkiecad/cwe_checker:latest), при неудаче — `DockerImageNotFoundError`
- `ensure_cache_volumes()` — создание volumes для кэширования
- `pull_image()`, `image_exists()` — управление образами
- `run_cwe_checker(path)` — монтирование родительской папки как `/share:ro`, команда `cwe_checker /share/<name> --json`; парсинг JSON через regex `\[\s*\{.*\}\s*\]` (re.DOTALL); возврат `{findings, error, return_code, stderr}`; при returncode≠0 — вывод stderr в консоль `[DOCKER_ERROR]`
- `DockerNotAvailableError`, `DockerImageNotFoundError` — исключения для Hard Fail

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

Итог: проект описан по фактической реализации; акцент сделан на методиках безопасности (статический анализ, YARA/DIE/capa, подписи, VT, CVE через Syft/Grype, **Binary SCA через CWE checker**, политики, эмуляция, threat intelligence, visual analysis) и на том, как они обеспечивают комплексный анализ бинарников и артефактов в контуре intake/DevSecOps. Версия 0.0.8 расширяет возможности детекции вредоносного ПО: Speakeasy эмуляция (в т.ч. дамп памяти для CVE/SBOM); **Deep Memory Scan** — YARA+CWE по дампу, результат в `ev["memory_dump_analysis"]`; находки в дампе дают **+80 к риску** (RISK_MALWARE_IN_MEMORY) и при score ≥ порога deny — вердикт **deny**; fallback EICAR при отсутствии yara-python. **Внешние базы YARA:** `rules/updater.py` и `rules/external/` (Yara-Rules, Neo23x0), команда `python -m bin_gate.rules.updater --sync`; хиты из внешних баз учитываются в `ev["yara"]` и дают **+70 к риску** (RISK_YARA_MALWARE); кэш скомпилированных правил в .yarc. **Скоринг и обоснование:** пересчёт decision после учёта risk_score; при risk > 0 — justification со сводкой («Вредоносное ПО в памяти: Да/Нет», Секреты, Маскировка, Уязвимости) и списком reasons; маскировка по расширению документа при PE (report.xlsx и т.п.) — жёсткая проверка в pe_hardening и run_one_file. **FINAL MANDATORY CWE STAGE** в конце `run_parallel_scan`; интеграция с threat feeds (URLHaus, Abuse.ch), DGA detection, icon masquerading, oletools VBA, LNK parsing. Supply chain: URL и внешние ресурсы из LNK/Office/PDF и Speakeasy; DLL из эмуляции в `supply_chain.dependencies` (type `dynamic_lib`); версии из LIEF подставляются в SBOM и human-отчёт. **Memory-Injection CVE:** при 0 компонентов Syft — синтетический CycloneDX в Grype; для дампов — маскировка .dmp как .exe для Syft. Human-отчёт: «Обнаружено в памяти (Dynamic Load)», «Анализ бинарного кода (CWE)», **[MEMORY DUMP]** по дампу; при DENY — обоснование (в т.ч. причина про дамп памяти первой). Sequential: batch CVE после цикла (после эмуляции). Docker-эмуляция: `BIN_GATE_EMULATION_DOCKER=1`, `bin-gate emulation-build`.

---

## Malware Detection & MITRE ATT&CK Matrix

Раздел служит **картой покрытия (Coverage Map)** детекции вредоносного ПО: по нему можно объективно оценить готовность шлюза к работе в PROD. Таблица привязана к классам малвари, техникам MITRE ATT&CK и конкретным индикаторам (L — Local/статический анализ, E — Emulation, V — VirusTotal behaviour).

| Класс ПО | Подтип / Техника | MITRE ID | Индикаторы (L — Local, E — Emu, V — VT) | Статус (v1.0) | Chain Analysis Support |
|----------|------------------|----------|----------------------------------------|------------------|------------------------|
| **Ransomware** | File Encryption | T1486 | L: Crypto API (BCrypt/Advapi32), FindFirst/Next; E: File enumeration | ✅ Добавлено | — |
| **Ransomware** | Data Destruction | T1485 | E: DeleteFile / MoveFile patterns | ✅ Добавлено | — |
| **Spyware / Keyloggers** | Input Capture | T1056.001 | L: SetWindowsHookEx; E: Keyboard API access | ✅ Добавлено | — |
| **Spyware / Keyloggers** | Credential Stealing | T1555 | L: Браузерные пути (SQLITE/Profiles); E: Read sensitive files | ✅ Добавлено | — |
| **Stealers** | Registry Run Keys | T1547.001 | L: Run/RunOnce strings; E: RegSetValue; V: normalized_behavior.registry | ✅ Добавлено | — |
| **Stealers** | Data exfiltration | T1041 | L: DGA/DoH; E: Network connections; V: C2 verified (risk_level) | ✅ Добавлено | — |
| **Banking Trojans** | Man-in-the-Browser | T1185 | L: Браузерные строки; E: Process Search (chrome/firefox) | ✅ Добавлено | — |
| **Banking Trojans** | Web Injectors | T1105 | L: JS/HTML patterns в оверлее; E: Module injection | ✅ Добавлено | — |
| **Crypto Miners** | Resource Hijacking | T1496 | L: Stratum protocol; E: High CPU/GPU lib usage; High entropy overlay | ✅ Добавлено | — |
| **Rootkits / Drivers** | Boot/Logon Auto-start | T1547.006 | L: .sys headers; E: Kernel API imports; Driver signatures | ✅ Добавлено | — |
| **Evasion / Droppers** | Process Injection | T1055 | E: Process Hollowing chain (Alloc+Write+Execute); L: loader_process_hollowing_chain | ✅ Добавлено | — |
| **Evasion / Droppers** | Process Hollowing | T1055.012 | L: CreateProcessA+VirtualAllocEx+WriteProcessMemory+SetThreadContext+ResumeThread | ✅ Добавлено | — |
| **Anti-Analysis** | Debugger Evasion | T1497 | E: IsDebuggerPresent, cpuid, rdtsc; L: anti_analysis.debug_api_strings | ✅ Добавлено | — |
| **Obfuscation** | Software Packing | T1027 | L: Entropy > 7.2; DIE/YARA packer hits; overlay.suspicious | ✅ Добавлено | — |
| **Discovery** | Peripheral Device Discovery | T1120 | L: SetupDiGetClassDevs в строках; E: SetupDi* API | ✅ Добавлено | — |
| **Discovery** | Query Registry | T1012 | L: HKLM\\…\\CurrentVersion, RegQueryValueEx; E: RegOpenKey/RegQueryValue | ✅ Добавлено | — |
| **Discovery** | File and Directory Discovery | T1083 | L: FindFirst/Next + *.docx/*.pdf/*.key; E: FindFirstFile/FindNextFile | ✅ Добавлено | — |
| **Collection** | Screen Capture | T1113 | L: BitBlt, GetDC в строках; E: GDI32 BitBlt/GetDC | ✅ Добавлено | — |
| **Discovery** | Process Discovery | T1057 | L: CreateToolhelp32Snapshot, Process32First/Next; E: Toolhelp32 API | ✅ Добавлено | — |
| **Execution** | Native API | T1106 | L: NtCreateSection, ntdll в строках; E: ntdll API | ✅ Добавлено | — |
| **Discovery** | System Network Configuration Discovery | T1016 | L: GetAdaptersInfo в строках; E: GetAdaptersInfo/GetAdaptersAddresses | ✅ Добавлено | — |
| **Discovery** | System Network Connections Discovery | T1049 | L: GetTcpTable в строках; E: GetTcpTable/GetExtendedTcpTable | ✅ Добавлено | — |
| **Persistence** | Windows Service | T1543.003 | L: CreateServiceA в строках; E: CreateService/OpenSCManager | ✅ Добавлено | — |
| **Defense Evasion** | Deobfuscation/Decoding Files | T1140 | L: RtlDecompressBuffer, XOR/decode; E: CryptDecrypt, RtlDecompressBuffer | ✅ Добавлено | — |
| **Privilege Escalation** | Bypass User Account Control | T1548.002 | L: fodhelper/eventvwr + ms-settings в реестре; E: RegSetValueEx + RegCreateKeyEx | ✅ Добавлено | — |
| **Defense Evasion** | Modify Registry | T1112 | L: Policies\\Microsoft\\Windows Defender, DisableAntiSpyware; persistence_logic | ✅ Добавлено | — |
| **Defense Evasion** | File Deletion (Self-deletion) | T1070.004 | L: cmd /c del, MoveFileEx DELAY_UNTIL_REBOOT; E: DeleteFile/MoveFileEx | ✅ Добавлено | — |
| **Discovery** | System Time Discovery | T1124 | L: GetSystemTime/GetTickCount в строках; E: API; RISK_ANTI_SANDBOX_STALL | ✅ Добавлено | — |
| **Discovery** | System Information Discovery | T1082 | L: GetComputerName, GetVersionEx; E: GetComputerName/GetVersionEx | ✅ Добавлено | T1082+T1021 |
| **Command and Control** | Encrypted Channel | T1573 | L: AES/ChaCha20 + сетевые импорты; E: BCryptEncrypt + InternetOpen | ✅ Добавлено | — |
| **Collection** | Data from Local System | T1005 | L: %APPDATA%, %TEMP%, Telegram, Signal, tdata | ✅ Добавлено | — |
| **Discovery** | Security Software Discovery | T1518.001 | L: WMI/WbemClient, пути Windows Defender; E: перечисление AV | ✅ Добавлено | — |
| **Command and Control** | Proxy | T1090 | L: InternetSetOption + proxy; E: INTERNET_OPTION_PROXY | ✅ Добавлено | — |
| **Defense Evasion** | System Binary Proxy: Rundll32 | T1218.011 | L: rundll32.exe + CreateProcess/Control_RunDLL; LOLBins | ✅ Добавлено | — |
| **Collection** | Data from Local System (archives/VPN/KeePass) | T1005 | L: .zip, .7z, .ovpn, .kdbx; RISK_SENSITIVE_STORAGE_ACCESS | ✅ Добавлено | — |
| **Credential Access** | Steal Web Session Cookie | T1539 | L: Cookies, Login Data (Chrome/Edge/Firefox) | ✅ Добавлено | — |
| **Collection** | Input Capture: CLI | T1056.004 | L: NtQueryInformationProcess, Win32_Process CommandLine; E: WMI | ✅ Добавлено | — |
| **Collection** | Email: Local (Outlook/Thunderbird) | T1114.001 | L: .pst, .ost; пути Outlook/Thunderbird | ✅ Добавлено | — |
| **Collection** | Data Staged: Local | T1074.001 | L: %LOCALAPPDATA%, FILE_ATTRIBUTE_HIDDEN; RISK_DATA_STAGING | ✅ Добавлено | — |
| **Command and Control** | Application Layer Protocol: DNS | T1071.004 | L: DnsQuery, dnsapi; network_profile.dns_tunneling_suspect; **DENY** | ✅ Добавлено | — |
| **Exfiltration** | Over Web: Cloud Storage | T1567.002 | L: Mega.nz, Telegram Bot API, Discord Webhooks; RISK_CLOUD_EXFIL; **DENY** | ✅ Добавлено | — |
| **Command and Control** | Data Encoding: Standard | T1132.001 | L: Base64/Hex множественное кодирование | ✅ Добавлено | — |
| **Discovery** | Query Registry (Uninstall) | T1012 | L: Uninstall, RegEnumKey, DisplayName | ✅ Добавлено | — |
| **Persistence** | Winlogon Helper DLL | T1547.004 | L: Winlogon\\Shell, Userinit; persistence_logic | ✅ Добавлено | — |
| **Defense Evasion** | Impair Defenses: Disable/Modify Tools | T1562.001 | L: MsMpEng, TerminateProcess; E: TerminateProcess; RISK_DEFENSE_DISABLED; **DENY** | ✅ Добавлено | T1204+T1562 |
| **Defense Evasion** | Disable/Modify System Firewall | T1562.004 | L: netsh advfirewall, INetFwPolicy2; RISK_DEFENSE_DISABLED; **DENY** | ✅ Добавлено | T1204+T1562 |
| **Defense Evasion** | Clear Windows Event Logs | T1070.001 | L: ClearEventLogA, wevtutil cl; E: ClearEventLog; RISK_LOG_CLEAR_ATTEMPT | ✅ Добавлено | — |
| **Persistence** | IFEO Injection | T1546.012 | L: Image File Execution Options, Debugger; RISK_IFEO_INJECTION; **DENY** | ✅ Добавлено | — |
| **Defense Evasion** | Modify Registry (Security Center) | T1112 | L: Security Center, NotificationsDisabled, ZoneMap 1806 | ✅ Добавлено | — |
| **Defense Evasion** | Hidden Files and Directories | T1564.001 | L: SetFileAttributes FILE_ATTRIBUTE_HIDDEN; E: SetFileAttributes; sections.hidden_attributes_referenced | ✅ Добавлено | — |
| **Defense Evasion** | Hidden Window | T1564.003 | L: CREATE_NO_WINDOW, SW_HIDE; E: ShowWindow, CreateProcess flags | ✅ Добавлено | — |
| **Defense Evasion** | Indirect Command Execution | T1202 | L: pcalua.exe, conhost.exe | ✅ Добавлено | — |
| **Defense Evasion** | Install Root Certificate | T1553.004 | L: CertAddCertificateContextToStore, ROOT; E: CertAddCertificateContextToStore | ✅ Добавлено | — |
| **Credential Access** | GUI Input Capture (Phishing UI) | T1056.002 | L: CreateWindowEx, password, GetWindowText | ✅ Добавлено | — |
| **Discovery** | Remote System Discovery | T1018 | L: NetServerEnum, GetIpNetTable; E: NetAPI32; RISK_INTERNAL_NETWORK_SCAN; **DENY/WARN** | ✅ Добавлено | — |
| **Discovery** | Account Discovery: Local Account | T1087.001 | L: NetUserEnum, /etc/passwd; E: NetUserEnum | ✅ Добавлено | — |
| **Discovery** | Account Discovery: Domain Account | T1087.002 | L: ADSI, NetGetDisplayInformationIndex; RISK_DOMAIN_ENUMERATION; **DENY/WARN** | ✅ Добавлено | — |
| **Discovery** | Network Service Discovery | T1046 | L: порты 80/443/445/3389, RFC 1918; network_profile.internal_ip_scan_suspect; **DENY/WARN** | ✅ Добавлено | — |
| **Discovery** | Permission Groups: Local Groups | T1069.001 | L: NetLocalGroupEnum; E: NetLocalGroupEnum | ✅ Добавлено | — |
| **Lateral Movement** | Remote Services: RDP | T1021.001 | L: mstscax, 3389, RDP; E: WTSConnect | ✅ Добавлено | T1082+T1021 |
| **Lateral Movement** | Remote Services: SMB/Admin Shares | T1021.002 | L: NetUseAdd, C$, ADMIN$, Named Pipes; E: NetUseAdd | ✅ Добавлено | T1082+T1021 |
| **Lateral Movement** | Software Deployment Tools | T1072 | L: SCCM, PDQ Deploy, CCMSetup, реестр CCM | ✅ Добавлено | — |
| **Lateral Movement** | Lateral Tool Transfer | T1570 | L: CopyFileEx + UNC; E: CopyFileEx; RISK_LATERAL_TRANSFER_ATTEMPT; **DENY/WARN** | ✅ Добавлено | — |
| **Exfiltration** | Exfiltration Over Bluetooth | T1011.001 | L: BluetoothFindFirstDevice, Bthprops; E: BluetoothFind* | ✅ Добавлено | — |
| **Supply Chain** | Compromise Software Dependencies | T1195.002 | L: zlib/libssl + вредоносный экспорт; RISK_SUPPLY_CHAIN_TAMPERING; **DENY** | ✅ Добавлено | — |
| **Defense Evasion** | Subvert Trust: Code Signing | T1553.002 | L: expired/Authenticode; signing_trust; штрафы за подпись | ✅ Добавлено | — |
| **Initial Access** | Valid Accounts | T1078 | L: захардкоженные логин/пароль, WNetAddConnection2 | ✅ Добавлено | — |
| **Persistence** | Office Application Startup | T1137 | L: Add-ins, XLSTART, WLL; автозапуск Word/Excel | ✅ Добавлено | — |
| **Persistence** | Event Triggered: Screensaver | T1546.002 | L: SCRNSAVE.EXE, Control Panel\Desktop в реестре | ✅ Добавлено | — |
| **Exfiltration** | Over Alternative Protocol: Uncommon Port | T1048.003 | L: порты 1337, 666, 4444; RISK_UNCOMMON_PORT | ✅ Добавлено | — |
| **Defense Evasion** | Indicator Blocking | T1562.006 | L: модификация hosts; RISK_HOSTS_MODIFICATION; **DENY/WARN** | ✅ Добавлено | T1204+T1562 |
| **Command and Control** | Web Service | T1102 | L: Pastebin, GitHub Gist, Google Docs как C2 | ✅ Добавлено | — |
| **Defense Evasion** | Rootkit | T1014 | L: SSDT, KeServiceDescriptorTable, .sys; скрытие | ✅ Добавлено | — |
| **Execution** | User Execution: Malicious File | T1204.002 | L: .vbs внутри .zip; опасные типы в архивах/MSI | ✅ Добавлено | T1204+T1562 |
| **Impact** | Defacement | T1491 | L: SystemParametersInfo, SPI_SETDESKWALLPAPER; обои | ✅ Добавлено | — |
| **Persistence** | WMI Event Subscription | T1546.003 | L: __EventFilter, CommandLineEventConsumer; E: IWbemServices; RISK_WMI_SUBSCRIPTION +45 | ✅ Добавлено | — |
| **Persistence** | Shortcut Modification | T1547.009 | L: Start Menu, .lnk, IShellLink, SetPath; office_pdf_lnk | ✅ Добавлено | — |
| **Persistence** | Netsh Helper DLL | T1546.007 | L: netsh add helper, INetCfg | ✅ Добавлено | — |
| **Defense Evasion** | DLL Injection | T1055.002 | L: CreateRemoteThread + LoadLibrary; E: LoadLibrary + CreateRemoteThread | ✅ Добавлено | — |
| **Defense Evasion** | Thread Execution Hijacking | T1055.003 | L: SuspendThread + SetThreadContext; E: SuspendThread/GetThreadContext | ✅ Добавлено | — |
| **Defense Evasion** | Timestomp | T1070.006 | L: SetFileTime, $STANDARD_INFORMATION; E: SetFileTime | ✅ Добавлено | — |
| **Defense Evasion** | Downgrade Attack | T1562.010 | L: bcdedit testsigning, nointegritychecks | ✅ Добавлено | — |
| **Defense Evasion** | Mshta | T1218.005 | L: mshta.exe, vbscript:, .hta URL | ✅ Добавлено | — |
| **Defense Evasion** | Regsvr32 (Squiblydoo) | T1218.010 | L: regsvr32 /i:http, scrobj.dll | ✅ Добавлено | — |
| **Collection** | Archive via Library | T1560.001 | L: zlib, bzip2, compress2 перед экфильтрацией | ✅ Добавлено | — |
| **Collection** | Local Data Discovery | T1005.001 | L: .env, .config, .xml, FindFirstFile | ✅ Добавлено | — |
| **Collection** | Keyboard Logging | T1056.001 | L: GetAsyncKeyState, WH_KEYBOARD | ✅ Добавлено | — |
| **Execution** | PowerShell | T1059.001 | L: IEX, FromBase64String, -enc, IEX(New-Object Net.WebClient); docscripts/pe_hardening | ✅ Добавлено | — |
| **Execution** | Windows Command Shell | T1059.003 | L: cmd.exe, &&, \|\| | ✅ Добавлено | — |
| **Discovery** | System Info (wmic) | T1082 | L: wmic cpu get name; E: GetComputerName/GetVersionEx | ✅ Добавлено | — |
| **Discovery** | Network Config (routing) | T1016.001 | L: GetIpForwardTable, route print; E: GetIpForwardTable | ✅ Добавлено | — |
| **Discovery** | Domain Groups | T1069.002 | L: NetGroupEnum; E: NetGroupEnum | ✅ Добавлено | — |
| **Execution** | Malicious Link | T1204.001 | L: LNK с URL на .zip/.iso; docscripts.technique_hints | ✅ Добавлено | — |
| **Execution** | Native API (NtMapViewOfSection) | T1106 | L: NtMapViewOfSection, ntdll; E: NtMapViewOfSection | ✅ Добавлено | — |
| **Obfuscation** | Software Packing (custom) | T1027.002 | L: кастомный упаковщик, VMProtect, эвристика DIE | ✅ Добавлено | — |
| **Credential Access** | OS Credential Dumping: LSASS Memory | T1003.001 | L: lsass.exe, MiniDumpWriteDump, OpenProcess; E: MiniDumpWriteDump | ✅ Добавлено | — |
| **Credential Access** | Credentials in Files | T1552.001 | L: password=, login=, apikey=, .env, config.ini, credentials.json | ✅ Добавлено | — |
| **Credential Access** | OS Credential Dumping: SAM | T1003.002 | L: SAM, SYSTEM, SECURITY, RegSaveKey, reg.exe save HKLM\\SAM | ✅ Добавлено | — |
| **Impact** | Service Stop | T1489 | L: ControlService, OpenService, EventLog, WinDefend; E: ControlService STOP | ✅ Добавлено | — |
| **Impact** | Inhibit System Recovery | T1490 | L: vssadmin delete shadows, wbadmin, bcdedit | ✅ Добавлено | — |
| **Impact** | Data Encrypted for Impact | T1486 | L: .locked, .crypted, CryptEncrypt, FindFirstFile; E: массовое шифрование | ✅ Добавлено | — |
| **Impact** | Account Access Removal | T1531 | L: NetUserDel, net user /delete, NetUserSetInfo, USER_ACCOUNT_DISABLED | ✅ Добавлено | — |
| **Impact** | Endpoint Denial of Service | T1499 | L: CreateProcess в цикле, GetDiskFreeSpaceEx, SetEndOfFile; E: fork bomb / fill disk | ✅ Добавлено | — |
| **Exfiltration** | Automated Exfiltration | T1020 | L: zip + HttpSendRequest/WinHttpSendRequest POST на подозрительный URL | ✅ Добавлено | — |
| **Persistence** | Account Manipulation | T1098 | L: NetLocalGroupAddMembers, Administrators, net localgroup Administrators add | ✅ Добавлено | — |
| **Defense Evasion** | Process Injection: APC | T1055.004 | L: QueueUserAPC, NtQueueApcThread; E: API_TO_TECHNIQUE; RISK_APC_INJECTION | ✅ Добавлено | — |
| **Defense Evasion** | Process Injection: TLS | T1055.005 | L: TlsAlloc, TlsSetValue, __tls_used; E: TlsAlloc/TlsSetValue | ✅ Добавлено | — |
| **Defense Evasion** | Process Injection: EWMI | T1055.011 | L: SetWindowLongPtr, GWLP_WNDPROC; E: SetWindowLongPtr | ✅ Добавлено | — |
| **Persistence** | AppCert DLLs | T1546.009 | L: AppCertDlls, Session Manager (реестр) | ✅ Добавлено | — |
| **Persistence** | AppInit DLLs | T1546.010 | L: AppInit_DLLs, LoadAppInit_DLLs (реестр) | ✅ Добавлено | — |
| **Persistence** | Security Support Provider | T1547.005 | L: Security Packages, Lsa (реестр) | ✅ Добавлено | — |
| **Persistence** | Active Setup | T1547.014 | L: Active Setup\\Installed Components, StubPath | ✅ Добавлено | — |
| **Defense Evasion** | Safe Mode Boot | T1562.009 | L: safeboot, bcdedit /set safeboot minimal, boot.ini; RISK_SAFE_MODE_BOOT | ✅ Добавлено | — |
| **Defense Evasion** | Disable Windows Event Logging | T1562.002 | L: EtwEventWrite, ntdll (патчинг); E: EtwEventWrite; RISK_DISABLE_EVENT_LOGGING | ✅ Добавлено | — |
| **Defense Evasion** | Steganography | T1027.003 | L: steganography, LSB, embed in bitmap, RT_ICON; RISK_STEGANOGRAPHY | ✅ Добавлено | — |
| **Lateral Movement** | DCOM | T1021.003 | L: CoInitializeEx, CoCreateInstanceEx, MMC20.Application; E: CoInitializeEx; RISK_DCOM_LATERAL | ✅ Добавлено | — |

**Покрытие матрицы: 150+ техник и подтехник (v1.0, Deep Coverage).** Основная таблица выше — 96 строк ✅ Добавлено. Дополнительные ID поступают из YARA meta, emulation.techniques, pe.technique_hints и попадают в highlights.mitre_techniques (get_risk_mitre_techniques + все th_hints). Дифференцированный скоринг: APC/IFEO/Safe Mode — повышенный вес.

**Дополнительные подтехники (маппинг L/E, единый список без дублей):** T1055.001 (CreateRemoteThread), T1055.012 (Process Hollowing), T1070.002 (Clear Linux Logs), T1070.003 (Clear Command History), T1070.005 (Network Share Connection Removal), T1087.003 (Cloud Account), T1136.001 (Domain Account), T1136.002 (Domain Controller), T1136.003 (Cloud Account), T1190 (Exploit Public-Facing Application), T1197 (BITS Jobs), T1203 (Exploitation for Client Execution), T1213 (Data from Information Repositories), T1218.001 (Signed Binary Proxy: Compiled HTML), T1218.002 (Signed Binary Proxy: Control Panel), T1218.004 (Signed Binary Proxy: InstallUtil), T1218.007 (Signed Binary Proxy: Msiexec), T1218.008 (Signed Binary Proxy: Odbcconf), T1218.009 (Signed Binary Proxy: Regsvcs/Regasm), T1220 (XSL Script Processing), T1221 (Template Injection), T1222 (File Permissions Modification), T1482 (Domain Trust Modification), T1484 (Domain Policy Modification), T1491.001 (Internal Defacement), T1492 (Stored Data Manipulation), T1495 (Firmware Corruption), T1498 (Network Denial of Service), T1525 (Impersonation), T1537 (Transfer Data to Cloud Account), T1542 (Pre-OS Boot), T1546.001 (Change Default File Association), T1546.004 (Winlogon Helper DLL), T1546.005 (Terminal Services DLL), T1546.006 (LC_LOAD_DYLIB Addition), T1546.008 (Netsh Helper DLL — дубль .007), T1546.011 (Application Shimming), T1546.013 (PowerShell Profile), T1547.002 (Authentication Package), T1547.003 (Time Providers), T1547.007 (Re-opened Applications), T1547.008 (LSASS Driver), T1547.010 (Port Monitors), T1547.012 (Print Processors), T1547.013 (Windows Management Instrumentation Event Subscription), T1547.015 (Login Item), T1550.001 (Application Access Token), T1550.002 (Web Session Cookie), T1550.003 (Pass the Ticket), T1550.004 (Web Session Cookie), T1562.001 (Disable or Modify Tools), T1562.003 (Impair Command History Logging), T1562.004 (Disable or Modify System Firewall), T1562.005 (Indicator Blocking), T1562.007 (Disable or Modify Cloud Tools), T1562.008 (Disable Cloud Logs), T1564.002 (NTFS File Attributes), T1564.004 (NTFS File Attributes), T1564.005 (Hidden File System), T1564.007 (VBA Stomping), T1564.008 (Email Hiding Rules), T1566.001 (Phishing: Spearphishing Attachment), T1566.002 (Phishing: Spearphishing Link), T1566.003 (Phishing: Spearphishing via Service), T1574.001 (DLL Search Order Hijacking), T1574.002 (DLL Side-Loading), T1574.006 (Dynamic Linker Hijacking), T1583.001 (Domains), T1583.002 (DNS Server), T1583.003 (Virtual Private Server), T1583.004 (Server), T1583.006 (Web Services), T1584.001 (Domains), T1584.002 (DNS Server), T1584.003 (Virtual Private Server), T1584.004 (Server), T1584.006 (Web Services), T1585.001 (Domains), T1585.002 (DNS Server), T1585.003 (Virtual Private Server), T1587.001 (Malware), T1587.002 (Code Signing Certificates), T1587.003 (Digital Certificates), T1588.001 (Malware), T1588.002 (Code Signing Certificates), T1588.003 (Digital Certificates). Итого: **150+ уникальных ID** в матрице детекта.

### Легенда индикаторов

- **L (Local):** статический анализ (pe_hardening, persistence_logic, network_profile, behavior_hints, strings, DIE, YARA, capa).
- **E (Emulation):** Speakeasy — api_calls, techniques (T1055, process-hollowing), registry, network, files.
- **V (VT):** VirusTotal behaviour — normalized_behavior (registry_modified, network), verified_by_vt / verified_by_behavior.

### Артефакты для QA (artifact_factory)

| Артефакт | Класс | Проверяемые факторы |
|----------|--------|----------------------|
| `ransomware_sample` | Ransomware | behavior_hints.crypto_usage, RISK_CRYPTO_USAGE |
| `spyware_keylogger_sample` | Spyware/Keylogger | behavior_hints.sensitive_data_access, RISK_SENSITIVE_DATA_ACCESS |
| `crypto_miner_sample` | Crypto Miner | Stratum strings, crypto_usage, RISK_CRYPTO_USAGE |
| `injection_chain_sample` | Process Hollowing | loader_process_hollowing_chain, DENY + «Process Hollowing injection chain» |
| `stealer_persistence_sample` | Stealer | persistence + DGA/DoH, scoring_reasons (единый профиль угрозы) |
| `complex_masquerade_sample` | Phishing | document.pdf.exe, certutil/powershell -enc в оверлее |
| `evasive_malware` | Anti-Analysis | EICAR + IsDebuggerPresent, memory_dump_analysis, RISK_EVASION_TECHNIQUE |
| `obfuscated_dropper` | Packing | High entropy + VirtualAllocEx/WriteProcessMemory |
| `t1120_peripheral_discovery` | Discovery (T1120) | technique_hints/emulation.techniques T1120 |
| `t1012_query_registry` | Discovery (T1012) | technique_hints/emulation.techniques T1012 |
| `t1083_file_discovery` | Discovery (T1083) | technique_hints T1083, RISK_DISCOVERY_ACTIVITY |
| `t1113_screen_capture` | Collection (T1113) | technique_hints T1113, RISK_SCREEN_CAPTURE |
| `t1057_process_discovery` | Discovery (T1057) | technique_hints T1057, RISK_DISCOVERY_ACTIVITY |
| `t1106_native_api` | Native API (T1106) | technique_hints T1106, RISK_NATIVE_API_USAGE |
| `t1016_network_config_discovery` | Discovery (T1016) | technique_hints/emulation.techniques T1016 |
| `t1049_network_connections_discovery` | Discovery (T1049) | technique_hints/emulation.techniques T1049 |
| `t1543_003_windows_service` | Persistence (T1543.003) | technique_hints/emulation.techniques T1543.003 |
| `t1140_deobfuscation` | Defense Evasion (T1140) | technique_hints/emulation.techniques T1140 |
| `t1548_002_uac_bypass` | Privilege Escalation (T1548.002) | technique_hints T1548.002, RISK_UAC_BYPASS, **DENY** |
| `t1112_modify_registry` | Defense Evasion (T1112) | technique_hints T1112, persistence Policies, RISK_DEFENDER_DISABLE, **DENY** |
| `t1070_004_file_deletion` | Defense Evasion (T1070.004) | technique_hints T1070.004 |
| `t1124_system_time_discovery` | Discovery (T1124) | technique_hints T1124, RISK_ANTI_SANDBOX_STALL |
| `t1082_system_info_discovery` | Discovery (T1082) | technique_hints/emulation.techniques T1082 |
| `t1573_encrypted_channel` | C2 (T1573) | technique_hints T1573 |
| `t1005_data_local_system` | Collection (T1005) | technique_hints T1005 |
| `t1518_001_security_software_discovery` | Discovery (T1518.001) | technique_hints T1518.001 |
| `t1090_proxy` | C2 (T1090) | technique_hints/emulation.techniques T1090 |
| `t1218_011_rundll32` | Defense Evasion (T1218.011) | technique_hints T1218.011, LOLBins |
| `t1005_sensitive_storage` | Collection (T1005) | .zip/.7z/.ovpn/.kdbx, RISK_SENSITIVE_STORAGE_ACCESS |
| `t1539_steal_cookie` | Credential (T1539) | Cookies, Login Data, technique_hints T1539 |
| `t1056_004_cli_capture` | Collection (T1056.004) | NtQueryInformationProcess, CommandLine |
| `t1114_001_email_collection` | Collection (T1114.001) | .pst, .ost, RISK_SENSITIVE_STORAGE_ACCESS |
| `t1074_001_data_staging` | Collection (T1074.001) | %LOCALAPPDATA%, RISK_DATA_STAGING |
| `t1071_004_dns_tunneling` | C2 (T1071.004) | DnsQuery, dns_tunneling_suspect, **DENY** |
| `t1567_002_cloud_exfil` | Exfiltration (T1567.002) | Mega/Telegram/Discord, RISK_CLOUD_EXFIL, **DENY** |
| `t1132_001_encoding` | C2 (T1132.001) | technique_hints T1132.001 |
| `t1012_uninstall_enum` | Discovery (T1012) | Uninstall, RegEnumKey, DisplayName |
| `t1547_004_winlogon` | Persistence (T1547.004) | Winlogon/Shell/Userinit, persistence_logic |
| `t1562_001_impair_tools` | Defense Evasion (T1562.001) | MsMpEng, TerminateProcess, RISK_DEFENSE_DISABLED, **DENY** |
| `t1562_004_disable_firewall` | Defense Evasion (T1562.004) | netsh advfirewall, RISK_DEFENSE_DISABLED, **DENY** |
| `t1070_001_clear_event_logs` | Defense Evasion (T1070.001) | ClearEventLog, wevtutil, RISK_LOG_CLEAR_ATTEMPT |
| `t1546_012_ifeo_injection` | Persistence (T1546.012) | IFEO, Debugger, RISK_IFEO_INJECTION, **DENY** |
| `t1112_security_center` | Defense Evasion (T1112) | Security Center, NotificationsDisabled |
| `t1564_001_hidden_files` | Defense Evasion (T1564.001) | SetFileAttributes, FILE_ATTRIBUTE_HIDDEN |
| `t1564_003_hidden_window` | Defense Evasion (T1564.003) | CREATE_NO_WINDOW, SW_HIDE |
| `t1202_indirect_command` | Defense Evasion (T1202) | pcalua, conhost |
| `t1553_004_install_root_cert` | Defense Evasion (T1553.004) | CertAddCertificateContextToStore, ROOT |
| `t1056_002_phishing_ui` | Credential (T1056.002) | CreateWindowEx, password, GetWindowText |
| `t1018_remote_system_discovery` | Discovery (T1018) | NetServerEnum, GetIpNetTable, RISK_INTERNAL_NETWORK_SCAN, **DENY/WARN** |
| `t1087_001_local_account_discovery` | Discovery (T1087.001) | NetUserEnum, /etc/passwd |
| `t1087_002_domain_account_discovery` | Discovery (T1087.002) | ADSI, NetGetDisplayInformationIndex, RISK_DOMAIN_ENUMERATION, **DENY/WARN** |
| `t1046_network_service_discovery` | Discovery (T1046) | порты 80/443/445/3389, internal_ip_scan_suspect, **DENY/WARN** |
| `t1069_001_local_groups_discovery` | Discovery (T1069.001) | NetLocalGroupEnum |
| `t1021_001_rdp` | Lateral (T1021.001) | mstscax, 3389, RDP |
| `t1021_002_smb_admin_shares` | Lateral (T1021.002) | NetUseAdd, C$, ADMIN$, Named Pipes |
| `t1072_software_deployment_tools` | Lateral (T1072) | SCCM, PDQ Deploy, CCMSetup |
| `t1570_lateral_tool_transfer` | Lateral (T1570) | CopyFileEx + UNC, RISK_LATERAL_TRANSFER_ATTEMPT, **DENY/WARN** |
| `t1011_001_bluetooth_exfil` | Exfiltration (T1011.001) | BluetoothFindFirstDevice, Bthprops |
| `t1195_002_supply_chain_dll` | Supply Chain (T1195.002) | zlib/libssl + malicious export, RISK_SUPPLY_CHAIN_TAMPERING, **DENY** |
| `t1553_002_code_signing` | Defense Evasion (T1553.002) | expired/Authenticode, signing_trust |
| `t1078_valid_accounts` | Initial Access (T1078) | hardcoded credentials, WNetAddConnection2 |
| `t1137_office_startup` | Persistence (T1137) | Add-ins, XLSTART, WLL |
| `t1546_002_screensaver` | Persistence (T1546.002) | SCRNSAVE.EXE, Control Panel\Desktop |
| `t1048_003_uncommon_port` | Exfiltration (T1048.003) | ports 1337/666/4444, RISK_UNCOMMON_PORT |
| `t1562_006_hosts_blocking` | Defense Evasion (T1562.006) | hosts file, RISK_HOSTS_MODIFICATION, **DENY/WARN** |
| `t1102_web_service` | C2 (T1102) | Pastebin, Gist, Google Docs |
| `t1014_rootkit` | Defense Evasion (T1014) | SSDT, KeServiceDescriptorTable, .sys |
| `t1204_002_malicious_file` | Execution (T1204.002) | .vbs in .zip, dangerous types in archive |
| `t1491_defacement` | Impact (T1491) | SystemParametersInfo, wallpaper |
| `t1546_003_wmi_subscription` | Persistence (T1546.003) | __EventFilter, CommandLineEventConsumer, RISK_WMI_SUBSCRIPTION |
| `t1547_009_shortcut_modification` | Persistence (T1547.009) | Start Menu, .lnk, IShellLink |
| `t1546_007_netsh_helper` | Persistence (T1546.007) | netsh add helper |
| `t1055_002_dll_injection` | Defense Evasion (T1055.002) | CreateRemoteThread + LoadLibrary |
| `t1055_003_thread_hijacking` | Defense Evasion (T1055.003) | SuspendThread + SetThreadContext |
| `t1070_006_timestomp` | Defense Evasion (T1070.006) | SetFileTime |
| `t1562_010_downgrade_attack` | Defense Evasion (T1562.010) | bcdedit, testsigning |
| `t1218_005_mshta` | Defense Evasion (T1218.005) | mshta, .hta |
| `t1218_010_regsvr32` | Defense Evasion (T1218.010) | regsvr32, scrobj.dll |
| `t1560_001_archive_via_library` | Collection (T1560.001) | zlib, bzip2 |
| `t1005_001_local_data_discovery` | Collection (T1005.001) | .env, .config, .xml |
| `t1056_001_keyboard_logging` | Collection (T1056.001) | GetAsyncKeyState |
| `t1059_001_powershell` | Execution (T1059.001) | IEX, Base64 |
| `t1059_003_cmd_shell` | Execution (T1059.003) | cmd, &&, \|\| |
| `t1082_wmic_discovery` | Discovery (T1082) | wmic cpu get name |
| `t1016_001_ip_forward_table` | Discovery (T1016.001) | GetIpForwardTable |
| `t1069_002_domain_groups` | Discovery (T1069.002) | NetGroupEnum |
| `t1204_001_malicious_link` | Execution (T1204.001) | LNK URL .zip/.iso, docscripts |
| `t1106_nt_map_view` | Execution (T1106) | NtMapViewOfSection |
| `t1027_002_custom_packer` | Obfuscation (T1027.002) | custom packer heuristics |
| `t1055_004_apc_injection` | Injection (T1055.004) | QueueUserAPC, NtQueueApcThread |
| `t1055_005_tls_injection` | Injection (T1055.005) | TlsAlloc, TlsSetValue |
| `t1055_011_ewmi` | Injection (T1055.011) | SetWindowLongPtr, GWLP_WNDPROC |
| `t1546_009_appcert_dlls` | Persistence (T1546.009) | AppCertDlls |
| `t1546_010_appinit_dlls` | Persistence (T1546.010) | AppInit_DLLs |
| `t1547_005_ssp` | Persistence (T1547.005) | Security Support Provider |
| `t1547_014_active_setup` | Persistence (T1547.014) | Active Setup |
| `t1562_009_safe_mode_boot` | Defense Evasion (T1562.009) | safeboot, bcdedit |
| `t1027_003_steganography` | Obfuscation (T1027.003) | steganography, LSB |
| `t1562_002_disable_event_logging` | Defense Evasion (T1562.002) | EtwEventWrite |
| `t1021_003_dcom` | Lateral (T1021.003) | CoInitializeEx, DCOM |
| `t1003_001_lsass_memory` | Credential (T1003.001) | lsass, MiniDumpWriteDump |
| `t1552_001_credentials_in_files` | Credential (T1552.001) | password=, .env |
| `t1003_002_sam_dump` | Credential (T1003.002) | SAM, RegSaveKey |

### Инструкции по использованию для QA

- **Связь с артефакторием:** каждая строка таблицы «Malware Detection & MITRE ATT&CK Matrix» обязана иметь соответствующий метод генерации в `tests/artifact_factory.py` (например, `build_ransomware_sample`, `build_spyware_keylogger_sample`). Отсутствие билдера для строки считается пробелом покрытия.
- **Критерий успешного детекта:** детект считается успешным, если в Evidence попадает соответствующий MITRE ID (или эквивалентный индикатор из таблицы), а итоговый вердикт политики — **deny** (для критических классов) или **warn** (для подозрительных). Для строк со статусом «В разработке» допускается отсутствие вердикта при наличии индикатора в Evidence.
- **KPI проекта:** целевой показатель — **процент покрытия строк данной таблицы автоматическими тестами** (в `tests/test_methodology.py` или аналоге). Цель к релизу **v1.0** — **100%** покрытия: у каждой строки матрицы есть артефакт и тест, проверяющий попадание MITRE ID/индикатора в Evidence и ожидаемый вердикт (deny/warn).
