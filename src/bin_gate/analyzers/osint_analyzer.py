# osint_analyzer.py — Deep OSINT: извлечение сетевых IoC и обогащение через внешние источники (v3.2)
"""
Сбор IP/доменов/URL из статики и эмуляции; проверка репутации (AbuseIPDB, Whois/ASN).
Результат в evidence["osint"] для скоринга: c2_detected (+60), suspicious_asn (+25).
"""
from __future__ import annotations
import os
from typing import Dict, Any, List, Optional, Set

from .threat_intel import extract_iocs_from_strings

# Ограничения для обогащения (чтобы не дергать API по сотням IP)
OSINT_MAX_IPS_ENRICH = int(os.getenv("BIN_GATE_OSINT_MAX_IPS", "20"))
OSINT_ABUSEIPDB = bool(os.getenv("BIN_GATE_ABUSEIPDB", "1")) and bool(os.getenv("ABUSEIPDB_API_KEY", ""))
OSINT_ASN = bool(os.getenv("BIN_GATE_OSINT_ASN", "1"))


def _collect_strings_from_evidence(ev: Dict[str, Any]) -> List[str]:
    """Собирает все строки из evidence для извлечения IoC."""
    strings: List[str] = []
    for key in ("strings", "decoded_strings"):
        val = ev.get(key)
        if isinstance(val, list):
            for s in val:
                if isinstance(s, str) and len(s) > 2:
                    strings.append(s)
        elif isinstance(val, dict):
            for v in val.values():
                if isinstance(v, list):
                    for s in v:
                        if isinstance(s, str):
                            strings.append(s)
    pe = ev.get("pe") or {}
    if isinstance(pe, dict):
        for s in (pe.get("strings_sample") or [])[:500]:
            if isinstance(s, str):
                strings.append(s)
    emu = ev.get("emulation") or {}
    if isinstance(emu, dict):
        for s in (emu.get("decoded_strings") or [])[:500]:
            if isinstance(s, str):
                strings.append(s)
        for conn in (emu.get("network") or []):
            if isinstance(conn, dict):
                for p in (conn.get("params") or []):
                    if isinstance(p, str):
                        strings.append(p)
    return strings


def _is_private_ip(ip: str) -> bool:
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return True
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        return False
    except Exception:
        return True


def analyze_osint(evidence: Dict[str, Any], options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Извлекает сетевые IoC из evidence (статики + эмуляции), обогащает через AbuseIPDB/Whois.
    Возвращает структуру для evidence["osint"] и скоринга.
    """
    opts = options or {}
    enable_abuseipdb = OSINT_ABUSEIPDB and not opts.get("no_ti", False)
    enable_asn = OSINT_ASN

    out: Dict[str, Any] = {
        "iocs": {"ips": [], "domains": [], "urls": []},
        "c2_detected": False,
        "c2_ips": [],
        "suspicious_asn": False,
        "suspicious_asn_ips": [],
        "ip_reputation": {},
        "risk_level": "low",
    }

    strings = _collect_strings_from_evidence(evidence)
    if not strings:
        return out

    iocs = extract_iocs_from_strings(strings)
    out["iocs"]["ips"] = sorted(iocs.get("ips", set()))[:100]
    out["iocs"]["domains"] = sorted(iocs.get("domains", set()))[:100]
    out["iocs"]["urls"] = sorted(iocs.get("urls", set()))[:100]

    public_ips = [ip for ip in out["iocs"]["ips"] if not _is_private_ip(ip)][:OSINT_MAX_IPS_ENRICH]
    if not public_ips:
        return out

    try:
        from bin_gate.external.abuseipdb import check_ip_abuseipdb
    except ImportError:
        try:
            from ..external.abuseipdb import check_ip_abuseipdb
        except ImportError:
            check_ip_abuseipdb = None
    try:
        from bin_gate.external.whois_asn import get_asn_info
    except ImportError:
        try:
            from ..external.whois_asn import get_asn_info
        except ImportError:
            get_asn_info = None

    for ip in public_ips:
        if enable_abuseipdb and check_ip_abuseipdb:
            rep = check_ip_abuseipdb(ip)
            out["ip_reputation"][ip] = rep
            if rep.get("c2_detected"):
                out["c2_detected"] = True
                out["c2_ips"].append(ip)
        if enable_asn and get_asn_info:
            asn_info = get_asn_info(ip)
            if asn_info.get("suspicious_asn"):
                out["suspicious_asn"] = True
                out["suspicious_asn_ips"].append(ip)

    if out["c2_detected"]:
        out["risk_level"] = "critical"
    elif out["suspicious_asn"]:
        out["risk_level"] = "high" if out["risk_level"] == "low" else out["risk_level"]
    return out
