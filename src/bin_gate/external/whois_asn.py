# whois_asn.py — Whois/ASN для определения владельца инфраструктуры (VPS/хостинг)
from __future__ import annotations
import os
import re
from typing import Dict, Any, Optional, Set

# Нетипичные для корпоративного ПО: хостинг-провайдеры, анонимные VPS
SUSPICIOUS_ASN_KEYWORDS: Set[str] = {
    "hosting", "vps", "cloud", "bulletproof", "offshore", "proxy",
    "tor", "vpn", "bulletproof", "ddos", "colocation", "noc",
    "asn", "network", "broadband", "isp",
}
# Известные легитимные (снижают подозрение)
BENIGN_ORG_KEYWORDS: Set[str] = {
    "microsoft", "google", "amazon", "apple", "cloudflare", "akamai",
    "digital ocean", "linode", "vultr", "ovh", "hetzner", "aws", "azure", "gcp",
}


def get_asn_info(ip: str, timeout_sec: int = 8) -> Dict[str, Any]:
    """
    Получение ASN/владельца для IP (через whois или внешний API).
    Возвращает: { "asn": str, "org": str, "suspicious_asn": bool, "error": str? }
    """
    out: Dict[str, Any] = {
        "asn": None,
        "org": None,
        "suspicious_asn": False,
        "error": None,
    }
    if not ip or not ip.strip():
        return out
    ip = ip.strip()
    try:
        import subprocess
        r = subprocess.run(
            ["whois", ip],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        text = (r.stdout or "") + (r.stderr or "")
        asn_match = re.search(r"(?:ASN|Origin|origin):\s*AS?(\d+)", text, re.I)
        org_match = re.search(r"(?:OrgName|Organization|org-name|descr):\s*(.+)", text, re.I)
        if asn_match:
            out["asn"] = "AS" + asn_match.group(1)
        if org_match:
            out["org"] = org_match.group(1).strip()[:200]
        org_lower = (out["org"] or "").lower()
        for kw in SUSPICIOUS_ASN_KEYWORDS:
            if kw in org_lower and not any(b in org_lower for b in BENIGN_ORG_KEYWORDS):
                out["suspicious_asn"] = True
                break
        return out
    except FileNotFoundError:
        out["error"] = "whois not available"
        return out
    except Exception as e:
        out["error"] = str(e)[:200]
        return out
