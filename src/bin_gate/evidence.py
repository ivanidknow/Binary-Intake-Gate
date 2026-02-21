from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional
from pathlib import Path

@dataclass
class Evidence:
    # --- базовые метаданные/результаты ---
    meta: Dict[str, Any] = field(default_factory=dict)
    pe: Optional[Dict[str, Any]] = None
    elf: Optional[Dict[str, Any]] = None
    hashes: Dict[str, Optional[str]] = field(default_factory=dict)
    entropy: Dict[str, Any] = field(default_factory=dict)
    capa: Optional[Dict[str, Any]] = None
    yara: Optional[List[Dict[str, Any]]] = None
    vt: Optional[Dict[str, Any]] = None
    kes: Optional[Dict[str, Any]] = None
    libs: Optional[Dict[str, Any]] = None
    score: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    # --- строки и их сводка ---
    # ожидается политиками/репортёром: evidence.strings.{static, ...}
    strings: Dict[str, List[str]] = field(default_factory=dict)
    strings_summary: Dict[str, int] = field(default_factory=dict)

    # --- DIE (Detect It Easy) результаты ---
    # packer/compiler/protector detection, entropy
    die: Optional[Dict[str, Any]] = None

    # --- ДОБАВЛЕНО: блок «обфускация» под правила obf-* ---
    # держим dict даже когда анализатор не сработал, чтобы условия были null-safe
    obfuscation: Dict[str, Any] = field(default_factory=dict)

    # --- ДОБАВЛЕНО: вспомогательные поля под политики ---
    # политики часто делают `"packers" in yara_families` и `"defense-evasion" in capa_tactics`
    yara_families: List[str] = field(default_factory=list)
    capa_tactics: List[str] = field(default_factory=list)

    # --- ДОБАВЛЕНО: «репутация» под repu-правила (безопасный каркас по умолчанию) ---
    reputation: Dict[str, Any] = field(
        default_factory=lambda: {"findings": [], "counts": {}, "categories": []}
    )

    # --- Enterprise Hardening (v0.0.7+) ---
    # PE overlay analysis
    overlay: Optional[Dict[str, Any]] = None
    
    # .NET assembly intelligence
    dotnet: Optional[Dict[str, Any]] = None
    
    # Supply chain risk (outdated critical libraries + referenced URLs/external resources)
    supply_chain: Dict[str, Any] = field(
        default_factory=lambda: {
            "outdated_libraries": [],
            "policy_reasons": [],
            "risk_level": None,  # "critical", "high", "medium", "low", None
            "dependencies": [],  # [{type, value, source}] from LNK/Office/PDF URLs and external refs
        }
    )
    
    # Extended hardening summary (aggregated)
    hardening_summary: Dict[str, Any] = field(
        default_factory=lambda: {
            # PE checks
            "aslr": None, "dep": None, "cfg": None, "cet": None, "acg": None,
            "safeseh": None, "gs_cookie": None, "authenticode": None,
            # ELF checks
            "pie": None, "nx": None, "relro_full": None, "canary": None, "bti": None,
            # Common
            "signed": None, "hardening_score": None,
        }
    )
    
    # Policy decision reasons (for audit trail)
    policy_reasons: List[str] = field(default_factory=list)

    # --- Advanced Malware Detection (v0.0.8) ---
    
    # Emulation results (Speakeasy)
    emulation: Optional[Dict[str, Any]] = field(
        default_factory=lambda: {
            "enabled": False,
            "success": False,
            "api_calls": [],
            "api_summary": {},
            "mutexes": [],
            "files": {"created": [], "read": [], "written": []},
            "registry": [],
            "network": [],
            "techniques": [],
            "shellcode": {"detected": False},
        }
    )
    
    # Threat Intelligence results
    threat_intel: Optional[Dict[str, Any]] = field(
        default_factory=lambda: {
            "enabled": False,
            "iocs": {"domains": [], "ips": [], "urls": []},
            "ti_matches": {"urlhaus": [], "abusech": []},
            "dga": {"suspects": [], "score": 0.0, "count": 0},
            "findings": [],
            "risk_level": "low",
        }
    )
    
    # Visual Analysis (PE icons, resource entropy)
    visual: Optional[Dict[str, Any]] = field(
        default_factory=lambda: {
            "icon": {"present": False, "dhash": None, "mismatch_detected": False},
            "resource_entropy": {"suspicious": False},
        }
    )
    
    # Deep Script/Office Analysis
    script_analysis: Optional[Dict[str, Any]] = field(
        default_factory=lambda: {
            "type": None,
            "vba": None,
            "lnk": None,
            "pdf": None,
            "stagers": [],
            "obfuscation": {"score": 0, "techniques": []},
            "decoded_payloads": [],
            "risk_score": 0,
        }
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def new_evidence(path: Path, filetype: str) -> Evidence:
    ev = Evidence()
    ev.meta = {
        "path": str(path),
        "name": path.name,
        "type": filetype,  # 'PE', 'ELF', 'EXT', 'NONE'
        "size": path.stat().st_size if path.exists() else None,
        # удобно иметь профиль здесь, т.к. политики читают meta.profile
        # "profile": "dev",  # при желании заполняй сверху в пайплайне
    }
    # ИНИЦИАЛИЗИРУЕМ безопасные дефолты, чтобы политики не падали на сложении None:
    ev.strings = {}                 # будет заполнено DIE или fallback strings
    ev.strings_summary = {
        "total_cnt": 0, "decoded_cnt": 0, "stack_cnt": 0, "static_cnt": 0, "tight_cnt": 0,
        "url_cnt": 0, "ip_cnt": 0, "cmd_cnt": 0,
    }
    # Обфускация: если анализатор не заполнит — нули спасут от policy_unsafe_node:Add
    ev.obfuscation.setdefault("string_ratio_ascii", 0.0)
    ev.obfuscation.setdefault("string_ratio_utf16", 0.0)
    ev.obfuscation.setdefault("max_section_entropy", None)
    ev.obfuscation.setdefault("packed_suspect", False)
    ev.obfuscation.setdefault("has_dyn_api_resolve", False)
    
    # v0.0.8 Advanced Malware Detection defaults
    ev.emulation = {
        "enabled": False,
        "success": False,
        "error": None,
        "api_calls": [],
        "api_summary": {},
        "mutexes": [],
        "files": {"created": [], "read": [], "written": []},
        "registry": [],
        "network": [],
        "techniques": [],
        "shellcode": {"detected": False, "info": {}},
        "stats": {"elapsed_ms": 0, "instructions": 0},
    }
    ev.threat_intel = {
        "enabled": False,
        "success": False,
        "iocs": {"domains": [], "ips": [], "urls": [], "emails": []},
        "ti_matches": {"urlhaus": [], "abusech": []},
        "dga": {"suspects": [], "score": 0.0, "count": 0},
        "findings": [],
        "risk_level": "low",
    }
    ev.visual = {
        "icon": {"present": False, "dhash": None, "md5": None, "mismatch_detected": False, "mismatch_type": None},
        "resource_entropy": {"suspicious": False, "max_resource_entropy": 0.0},
    }
    ev.script_analysis = {
        "type": None,
        "basic": {},
        "vba": None,
        "lnk": None,
        "pdf": None,
        "stagers": [],
        "obfuscation": {"score": 0, "techniques": [], "entropy": 0.0},
        "decoded_payloads": [],
        "iocs": [],
        "risk_score": 0,
    }
    return ev
