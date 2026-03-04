# external — обёртки для внешних API (Threat Intelligence, Whois/ASN)
from __future__ import annotations

from .abuseipdb import check_ip_abuseipdb
from .whois_asn import get_asn_info

__all__ = ["check_ip_abuseipdb", "get_asn_info"]
