Binary Intake Gate

A single gateway to assess PE/ELF binaries in PRs and releases. Performs fast static due-diligence: hashes & entropy, hardening checks (PE/ELF), signature/chain (PE), YARA, capa, VirusTotal hash lookup (optional upload), CVE discovery via OSV, profile-based policy (dev/staging/prod), and clean, human-friendly reports (plus optional SARIF).

Stack: Python 3.10+ · yara-python, pefile, lief, pyelftools, capa (CLI), requests, sqlite3 (cache), a CEL-style safe policy engine, OSV API, and (optional) Playwright for VT UI uploads.

Features

🧾 Identity & Integrity: SHA-256, file/section entropy, basic magic/MIME.

🛡️ Hardening checks:

PE: ASLR / DEP / CFG, Authenticode (presence/chain/timestamp), sections (RWX/overlay).

ELF: PIE / NX / RELRO / Canary, RPATH/RUNPATH/TEXTREL.

🧬 Signatures & behavior: YARA (your rules + built-ins), capa (techniques/rules).

🧭 VirusTotal reputation: hash lookup (detections, reputation, sandbox refs). Upload is opt-in.

🐧/🪟 CVE for external libs: via OSV API.

ELF: NEEDED → distro package (Debian/Ubuntu/Alpine/RedHat) with summarised CRITICAL/HIGH/MEDIUM/LOW.

PE: best-effort from VersionInfo/DLL versions.

📜 Policies & profiles: allow/warn/deny with explainable reasons; CEL-style expressions; thresholds per profile.

🧑‍💻 Reports:

report.md — concise summary;

human_report.md — human-friendly narrative (RU locale);

optional SARIF for code-scanning platforms.

🧩 Cache & offline: SQLite by SHA-256; --no-network guarantees zero outbound requests.

Installation
git clone https://github.com/<you>/binary-intake-gate.git
cd binary-intake-gate

# Install the CLI
pip install -e .

# (optional) Playwright for VT UI uploads
# playwright install chromium


Optional resources

capa rules: provide via --capa-rules or CAPA_RULES_DIR.

YARA rules: provide via --yara-rules or YARA_RULES_DIR.

VT API key: set VT_API_KEY for hash lookups (and API upload).

Quick start (copy-paste)
1) Minimal (offline, no network)
bin-gate scan examples \
  --policy policy/policy.example.yaml \
  --no-network \
  --out report.md --human-out human_report.md

2) With capa + YARA
bin-gate scan examples \
  --capa-rules ./capa-rules --capa-timeout 120 \
  --yara-rules ./yara-rules \
  --policy policy/policy.example.yaml \
  --out report.md --human-out human_report.md

3) With VirusTotal (hash lookup only)
export VT_API_KEY=...   # (PowerShell: $env:VT_API_KEY="...")
bin-gate scan examples \
  --policy policy/policy.example.yaml \
  --out report.md --human-out human_report.md

4) Optional: VT upload (UI/API)
bin-gate scan examples \
  --vt-upload --vt-upload-mode auto \
  --policy policy/policy.example.yaml \
  --out report.md --human-out human_report.md


Upload happens only if the hash is unknown. Use with consent for non-public binaries.

5) CVE for dependencies (ELF/PE)
bin-gate scan examples \
  --cve-ecosystem Debian \
  --cve-inventory ./inventory.json \
  --policy policy/policy.example.yaml \
  --out report.md --human-out human_report.md


inventory.json is an array of {ecosystem,name,version} representing installed packages of your image/host.
ELF package resolution is tunable via --cve-resolve (auto|dpkg|rpm|apk|pacman|none).


**Common flags**

* Policy & profile: --policy policy/policy.example.yaml, --profile dev|staging|prod
* Offline/cache: --no-network, --cache-db path/to/cache.sqlite
* capa: --no-capa, --capa-rules DIR, --capa-timeout 120, --capa-max-mb N
YARA: --no-yara, --yara-rules DIR, --yara-timeout 7, --yara-max-hits 80
VirusTotal: --no-vt, --vt-upload, --vt-upload-mode auto|api|ui, --vt-ttl-hours 168
CVE/OSV: --no-cve, --cve-ecosystem Debian|Ubuntu|Alpine|RedHat, --cve-inventory FILE, --cve-resolve auto
Reports: --out report.md, --human-out human_report.md, --sarif-out artifacts/bin-gate.sarif.json
Fail level: --fail-on none|warn|deny (exit code 1 at/over the level)

**Policy format (CEL-style)**

Policies are YAML with profiles and rules. Expressions support and/or/not, comparisons, in, and safe dotted access to pe.*, elf.*, vt.*, yara_families, capa_tactics, cve.*, meta.profile.

version: 2

profiles:
  dev:     { thresholds: { deny: 80, warn: 40 } }
  staging: { thresholds: { deny: 80, warn: 40 } }
  prod:    { thresholds: { deny: 80, warn: 40 } }

rules:
  - id: vt-high-mal
    when: vt and vt.detections and vt.detections.stats.malicious >= 5
    then: deny
    reason: VT malicious detections ≥ 5

  - id: elf-weak
    when: elf and ((elf.hardening.pie == false) or (elf.hardening.nx == false))
    score: 40
    reason: ELF hardening weak (PIE/NX)

  - id: pe-no-cfg
    when: pe and pe.hardening and pe.hardening.cfg == false
    score: 30
    reason: PE: CFG disabled

  - id: cve-critical
    when: cve and cve.summary and cve.summary.critical > 0
    then: deny
    reason: Known critical CVEs in dependencies


The engine produces allow | warn | deny with human-readable reasons. The human report includes mitigation suggestions for warn/deny.

**Stack:** Python3.13|capa/yara-python/lief/pefile/pyelftools, VT SDK, checksec, scipy, cel-python, sqlite

**Contributing**

PRs and issues are welcome: bug fixes, new YARA/capa rules, ELF→package mappers, policy profiles.

**Troubleshooting**

* capa finds no rules: set --capa-rules to your local capa-rules clone.
* YARA shows no hits but you expect matches: verify --yara-rules path and rule compilation.
* capa hangs: raise/limit with --capa-timeout or disable with --no-capa to isolate.
* OSV/CVE returns nothing: provide --cve-inventory and a correct --cve-ecosystem.
* Playwright UI upload won’t start: run playwright install chromium and try --vt-ui-headed if captcha appears.

**Platform support**

Windows & Linux (x86_64).
capa/YARA require their respective binaries/bindings; VT UI upload requires Playwright browser to be installed.

**Privacy & safety**

By default the tool does not perform any network requests (--no-network enforces it strictly).

VirusTotal upload is opt-in (--vt-upload) and only triggered when the hash is unknown.
Ensure you have permission to upload non-public binaries.

SQLite cache stores aggregated results keyed by SHA-256 only.

**Configuration & env**

* BIN_GATE_PROFILE — default profile (dev)
* CAPA_RULES_DIR — path to capa rules
* YARA_RULES_DIR — path to YARA rules
* VT_API_KEY — VirusTotal key
* YARA_TIMEOUT_SEC, CAPA_TIMEOUT_SEC, CVE_ECOSYSTEM, CVE_INVENTORY, … — see --help

**Reports**

* report.md — per-file summary (hashes, hardening, YARA/capa, VT, CVE, policy decision).
* human_report.md — narrative report (currently RU locale) with bold markers: Outcome / Reasons / Recommended inside Verification blocks.
* *.sarif.json — optional SARIF v2.1.0 for code-scanning.
