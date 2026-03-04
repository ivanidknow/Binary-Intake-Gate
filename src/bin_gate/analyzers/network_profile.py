# src/bin_gate/analyzers/network_profile.py
# Анализ агрессивности сетевого стека: DoH (DNS-over-HTTPS), кастомные протоколы.
# Если файл содержит признаки DoH при отсутствии бизнес-логики браузера — RISK_SNEAKY_NETWORK.

from __future__ import annotations
import re
from typing import Dict, Any, List

# DoH-резолверы и характерные домены/URL
_DOH_DOMAINS_AND_URLS = [
    "cloudflare-dns.com",
    "dns.google",
    "dns10.quad9.net",
    "doh.opendns.com",
    "security.cloudflare-dns.com",
    "family.cloudflare-dns.com",
    "dns.quad9.net",
    "/dns-query",
    "application/dns-message",
]

# Библиотеки/константы сетевого стека с аномальными флагами (признаки кастомного использования)
_NETWORK_HINTS = [
    "libcurl",
    "wininet",
    "winhttp",
    "curl_easy_setopt",
    "CURLOPT_",
    "INTERNET_OPEN_",
    "DoH",
    "dns-over-https",
]


def analyze_network_profile(
    strings: List[str],
    ev: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    Проверяет строки на DoH/кастомные протоколы.
    ev: опционально evidence для проверки «бизнес-логики браузера» (ProductName и т.д.).
    Возвращает: { "sneaky_doh": bool, "doh_indicators": [...], "browser_context": bool }
    """
    result: Dict[str, Any] = {
        "sneaky_doh": False,
        "doh_indicators": [],
        "browser_context": False,
        "dns_tunneling_suspect": False,
        "internal_ip_scan_suspect": False,
    }
    if not strings:
        return result

    text = " ".join(s for s in strings if isinstance(s, str))[:50000]
    low = text.lower()

    for hint in _DOH_DOMAINS_AND_URLS:
        if hint.lower() in low:
            result["doh_indicators"].append(hint)

    has_doh = len(result["doh_indicators"]) > 0
    has_network_hints = any(h.lower() in low for h in _NETWORK_HINTS)

    # Бизнес-логика браузера: ProductName/InternalName содержат Chrome, Firefox, Edge, Opera, Brave
    if ev:
        pe = ev.get("pe") or {}
        res = (pe.get("resources") or {}) if isinstance(pe, dict) else {}
        ver = (res.get("version") or {}) if isinstance(res, dict) else {}
        if isinstance(ver, dict):
            for key in ("ProductName", "InternalName", "OriginalFilename", "FileDescription"):
                val = ver.get(key)
                if val and isinstance(val, str):
                    v = val.lower()
                    if any(b in v for b in ("chrome", "firefox", "edge", "opera", "brave", "browser", "msedge")):
                        result["browser_context"] = True
                        break

    # Sneaky: DoH присутствует, а контекста браузера нет
    result["sneaky_doh"] = bool(has_doh and not result["browser_context"])

    # DNS tunneling (T1071.004): DnsQuery/dnsapi + длинные или высокоэнтропийные субдомены
    has_dns_api = "dnsquery" in low or "dnsapi" in low
    if has_dns_api:
        for s in strings:
            if not isinstance(s, str) or len(s) < 20:
                continue
            s_low = s.lower()
            # Подозрительно: строка с несколькими точками (субдомен.субдомен.домен) и длина > 40
            if s.count(".") >= 2 and len(s) > 40 and s.isprintable():
                result["dns_tunneling_suspect"] = True
                break
            # Ключевые слова туннелирования
            if any(k in s_low for k in ("subdomain", "payload.", "dns.tunnel", "txt.")):
                result["dns_tunneling_suspect"] = True
                break
        # Длинные субдомен-подобные строки (много точек + много уникальных символов)
        if not result["dns_tunneling_suspect"] and has_dns_api:
            for part in re.split(r"[\s\x00/\\]+", text):
                if len(part) > 35 and part.count(".") >= 2 and part.isprintable():
                    if len(set(part)) >= 20:
                        result["dns_tunneling_suspect"] = True
                        break

    # Попытки соединения с внутренними IP (RFC 1918) в недоверенном коде — T1018/T1046
    rfc1918_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")
    has_internal_ip = any(p in low for p in rfc1918_prefixes)
    has_connect_or_port = any(k in low for k in ("connect", "3389", ":445", ":80", ":443", "socket", "winsock"))
    if has_internal_ip and has_connect_or_port and not result["browser_context"]:
        result["internal_ip_scan_suspect"] = True
    return result


def _normalize_ioc(s: str) -> str:
    """Нормализация домена/IP/URL для сопоставления (нижний регистр, без пробелов)."""
    if not s or not isinstance(s, str):
        return ""
    return s.lower().strip()


def merge_network_with_vt(
    network_result: Dict[str, Any],
    threat_intel: Dict[str, Any] | None,
    vt_normalized_behavior: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """
    Сопоставляет извлечённые IOC (домены/IP, doh_indicators) с сетевой активностью VT.
    При совпадении повышает threat_intel.risk_level и помечает network_result.vt_verified.
    network_result и threat_intel модифицируются на месте; возвращается network_result.
    """
    if not vt_normalized_behavior:
        return network_result
    net = vt_normalized_behavior.get("network") or {}
    vt_domains = {_normalize_ioc(d) for d in (net.get("domains") or []) if d}
    vt_ips = {_normalize_ioc(i) for i in (net.get("ips") or []) if i}
    vt_urls = {_normalize_ioc(u) for u in (net.get("urls") or []) if u}
    if not (vt_domains or vt_ips or vt_urls):
        return network_result

    # Собираем локальные IOC: doh_indicators + threat_intel.iocs
    local_domains: set = set()
    local_ips: set = set()
    local_urls: set = set()
    for ind in (network_result.get("doh_indicators") or []):
        if isinstance(ind, str):
            v = _normalize_ioc(ind)
            if v:
                if any(c in v for c in ".:/"):
                    if "/" in v or v.startswith("http"):
                        local_urls.add(v)
                    elif "." in v and not v.replace(".", "").isdigit():
                        local_domains.add(v)
                    else:
                        local_ips.add(v)
                else:
                    local_domains.add(v)
    ti = threat_intel or {}
    for d in (ti.get("iocs") or {}).get("domains") or []:
        if isinstance(d, str) and _normalize_ioc(d):
            local_domains.add(_normalize_ioc(d))
    for i in (ti.get("iocs") or {}).get("ips") or []:
        if isinstance(i, str) and _normalize_ioc(i):
            local_ips.add(_normalize_ioc(i))
    for u in (ti.get("iocs") or {}).get("urls") or []:
        if isinstance(u, str) and _normalize_ioc(u):
            local_urls.add(_normalize_ioc(u))

    matched = bool(
        (local_domains & vt_domains)
        or (local_ips & vt_ips)
        or (local_urls & vt_urls)
    )
    if not matched:
        # Проверка по подстрокам (домен в URL и т.д.)
        for d in local_domains:
            if any(d in vt for vt in vt_domains) or any(d in vt for vt in vt_urls):
                matched = True
                break
        for u in local_urls:
            if any(u in vt for vt in vt_urls) or any(u in vt for vt in vt_domains):
                matched = True
                break
    if matched:
        network_result["vt_verified"] = True
        network_result["verified_by_behavior"] = True
        network_result["vt_verified_indicators"] = list(
            (local_domains & vt_domains) | (local_ips & vt_ips) | (local_urls & vt_urls)
        )
        if isinstance(threat_intel, dict):
            current = (threat_intel.get("risk_level") or "low").lower()
            order = ("low", "medium", "high", "critical")
            idx = order.index(current) if current in order else 0
            threat_intel["risk_level"] = order[min(idx + 1, len(order) - 1)]
    return network_result


def merge_network_with_emulation(
    network_result: Dict[str, Any],
    emulation_data: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """
    Если локально найденные IOC (DoH/домены) подтверждаются сетевой активностью из emulation,
    помечаем verified_by_behavior: True.
    """
    if not network_result or not emulation_data:
        return network_result
    # Собираем домены/URL из emulation (network, decoded_strings с URL-подобными строками)
    emu_net = emulation_data.get("network") or []
    emu_domains: set = set()
    emu_urls: set = set()
    for n in emu_net if isinstance(emu_net, list) else []:
        if isinstance(n, str):
            v = _normalize_ioc(n)
            if v and ("." in v or "/" in v):
                if v.startswith("http") or "/" in v:
                    emu_urls.add(v)
                else:
                    emu_domains.add(v)
        elif isinstance(n, dict):
            for k in ("domain", "host", "url", "uri"):
                v = n.get(k)
                if isinstance(v, str) and _normalize_ioc(v):
                    vn = _normalize_ioc(v)
                    if "/" in vn or vn.startswith("http"):
                        emu_urls.add(vn)
                    else:
                        emu_domains.add(vn)
    for s in (emulation_data.get("decoded_strings") or [])[:200]:
        if not isinstance(s, str) or "http" not in s.lower():
            continue
        v = _normalize_ioc(s.strip()[:500])
        if v and ("http" in v or ".com" in v or ".net" in v):
            emu_urls.add(v)
            if "." in v and not v.replace(".", "").isdigit():
                emu_domains.add(v)
    if not (emu_domains or emu_urls):
        return network_result
    local_domains = {_normalize_ioc(d) for d in (network_result.get("doh_indicators") or []) if isinstance(d, str)}
    local_urls = {_normalize_ioc(u) for u in (network_result.get("doh_indicators") or []) if isinstance(u, str) and ("http" in u or "/" in u)}
    if (local_domains & emu_domains) or (local_urls & emu_urls):
        network_result["verified_by_behavior"] = True
    return network_result
