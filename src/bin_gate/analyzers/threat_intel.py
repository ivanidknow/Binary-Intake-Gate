"""
Network & Threat Intelligence Module.

Features:
- Extract domains/IPs from strings and emulation logs
- Check against URLHaus and Abuse.ch threat feeds
- DGA (Domain Generation Algorithm) detection via entropy and N-gram analysis
- Integrate with reputation system

Usage:
    result = analyze_threat_intel(strings, emulation_data, enable_ti=True)
"""
from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
import re
import os
import json
import time
import math
import hashlib
from collections import Counter


# TI Configuration
TI_TIMEOUT_SEC = int(os.getenv("BIN_GATE_TI_TIMEOUT", "30"))
TI_CACHE_TTL_HOURS = int(os.getenv("BIN_GATE_TI_CACHE_TTL", "24"))
TI_URLHAUS_FEED = os.getenv("BIN_GATE_TI_URLHAUS_FEED", "https://urlhaus.abuse.ch/downloads/csv_recent/")
TI_ABUSECH_FEED = os.getenv("BIN_GATE_TI_ABUSECH_FEED", "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv")

# Regex patterns for IOC extraction
RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)
RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)
RE_IPV6 = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
)
RE_URL = re.compile(
    r'https?://[^\s"\'<>\[\]{}|\\^`]+',
    re.IGNORECASE
)
RE_EMAIL = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)

# Common benign domains to filter
BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "msn.com",
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "facebook.com", "twitter.com", "github.com", "githubusercontent.com",
    "cloudflare.com", "cloudfront.net", "amazonaws.com", "azure.com",
    "apple.com", "icloud.com", "akamai.net", "akamaized.net",
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "localhost", "example.com", "test.com", "invalid",
}

# Known malicious TLDs (high risk)
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",  # Free TLDs often abused
    "xyz", "top", "wang", "win", "bid", "loan", "click", "link",
    "work", "date", "racing", "stream", "download", "cricket",
}

# DGA characteristics
DGA_CONSONANTS = set("bcdfghjklmnpqrstvwxyz")
DGA_VOWELS = set("aeiou")


@dataclass
class ThreatIntelResult:
    """Result of threat intelligence analysis."""
    success: bool = False
    error: str = ""
    
    # Extracted IOCs
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    
    # TI matches
    urlhaus_matches: List[Dict[str, Any]] = field(default_factory=list)
    abusech_matches: List[Dict[str, Any]] = field(default_factory=list)
    
    # DGA analysis
    dga_suspects: List[Dict[str, Any]] = field(default_factory=list)
    dga_score: float = 0.0
    
    # Summary
    findings: List[str] = field(default_factory=list)
    risk_level: str = "low"  # low, medium, high, critical


# ----- IOC Extraction -----

def extract_iocs_from_strings(strings: List[str]) -> Dict[str, Set[str]]:
    """Extract IOCs (domains, IPs, URLs) from a list of strings."""
    iocs: Dict[str, Set[str]] = {
        "domains": set(),
        "ips": set(),
        "urls": set(),
        "emails": set(),
    }
    
    text = " ".join(strings)
    
    # Extract URLs first (more specific)
    for url in RE_URL.findall(text):
        iocs["urls"].add(url[:500])
    
    # Extract domains
    for domain in RE_DOMAIN.findall(text):
        domain = domain.lower().strip(".")
        # Filter benign and extract only interesting domains
        base_domain = ".".join(domain.split(".")[-2:]) if "." in domain else domain
        if base_domain not in BENIGN_DOMAINS and len(domain) > 3:
            iocs["domains"].add(domain)
    
    # Extract IPs
    for ip in RE_IPV4.findall(text):
        # Filter private/reserved IPs
        if not _is_private_ip(ip):
            iocs["ips"].add(ip)
    
    for ip in RE_IPV6.findall(text):
        iocs["ips"].add(ip)
    
    # Extract emails
    for email in RE_EMAIL.findall(text):
        iocs["emails"].add(email.lower())
    
    return iocs


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private/reserved."""
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return True
        
        # Private ranges
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        if parts[0] == 0:
            return True
        if parts[0] >= 224:  # Multicast/reserved
            return True
        
        return False
    except Exception:
        return True


# ----- DGA Detection -----

def _calc_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = Counter(s.lower())
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _calc_consonant_ratio(s: str) -> float:
    """Calculate consonant to vowel ratio."""
    s = s.lower()
    consonants = sum(1 for c in s if c in DGA_CONSONANTS)
    vowels = sum(1 for c in s if c in DGA_VOWELS)
    if vowels == 0:
        return 10.0  # High ratio = suspicious
    return round(consonants / vowels, 2)


def _calc_ngram_score(s: str, n: int = 2) -> float:
    """
    Calculate N-gram unusualness score.
    DGA domains often have unusual character combinations.
    """
    s = s.lower()
    if len(s) < n:
        return 0.0
    
    # Common English bigrams
    common_bigrams = {
        "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
        "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
        "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
    }
    
    ngrams = [s[i:i+n] for i in range(len(s) - n + 1)]
    if not ngrams:
        return 0.0
    
    uncommon_count = sum(1 for ng in ngrams if ng not in common_bigrams)
    return round(uncommon_count / len(ngrams), 3)


def _has_digit_letter_mix(s: str) -> bool:
    """Check if string has mixed digits and letters (common in DGA)."""
    has_digit = any(c.isdigit() for c in s)
    has_letter = any(c.isalpha() for c in s)
    return has_digit and has_letter


def analyze_domain_for_dga(domain: str) -> Dict[str, Any]:
    """
    Analyze a domain for DGA characteristics.
    
    Returns:
        Dict with DGA analysis results
    """
    # Extract just the domain name part (before TLD)
    parts = domain.lower().split(".")
    if len(parts) < 2:
        return {"is_dga": False, "score": 0.0}
    
    # Get the main domain part
    domain_part = parts[-2] if len(parts) >= 2 else parts[0]
    tld = parts[-1]
    
    result = {
        "domain": domain,
        "domain_part": domain_part,
        "tld": tld,
        "is_dga": False,
        "score": 0.0,
        "reasons": [],
    }
    
    score = 0.0
    
    # Length analysis
    if len(domain_part) > 15:
        score += 0.15
        result["reasons"].append("long_domain")
    elif len(domain_part) < 4:
        score += 0.1
        result["reasons"].append("short_domain")
    
    # Entropy analysis
    entropy = _calc_entropy(domain_part)
    result["entropy"] = entropy
    if entropy > 3.5:
        score += 0.25
        result["reasons"].append(f"high_entropy:{entropy}")
    elif entropy > 3.0:
        score += 0.1
    
    # Consonant ratio
    cons_ratio = _calc_consonant_ratio(domain_part)
    result["consonant_ratio"] = cons_ratio
    if cons_ratio > 3.0:
        score += 0.2
        result["reasons"].append(f"high_consonant_ratio:{cons_ratio}")
    
    # N-gram analysis
    ngram_score = _calc_ngram_score(domain_part)
    result["ngram_score"] = ngram_score
    if ngram_score > 0.6:
        score += 0.2
        result["reasons"].append(f"unusual_ngrams:{ngram_score}")
    
    # Digit-letter mix
    if _has_digit_letter_mix(domain_part):
        score += 0.15
        result["reasons"].append("digit_letter_mix")
    
    # Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        score += 0.15
        result["reasons"].append(f"suspicious_tld:{tld}")
    
    # No vowels
    if not any(c in DGA_VOWELS for c in domain_part.lower()):
        score += 0.2
        result["reasons"].append("no_vowels")
    
    result["score"] = round(min(score, 1.0), 3)
    result["is_dga"] = score >= 0.5
    
    return result


# ----- Threat Feed Integration -----

# In-memory cache for threat feeds
_ti_cache: Dict[str, Any] = {
    "urlhaus": {"data": set(), "loaded_at": 0},
    "abusech": {"data": set(), "loaded_at": 0},
}


def _load_urlhaus_feed(timeout: int = TI_TIMEOUT_SEC) -> Set[str]:
    """Load URLHaus recent malware URLs feed."""
    global _ti_cache
    
    # Check cache
    now = time.time()
    if _ti_cache["urlhaus"]["data"] and (now - _ti_cache["urlhaus"]["loaded_at"]) < TI_CACHE_TTL_HOURS * 3600:
        return _ti_cache["urlhaus"]["data"]
    
    try:
        import requests
        response = requests.get(TI_URLHAUS_FEED, timeout=timeout)
        if response.status_code != 200:
            return _ti_cache["urlhaus"]["data"]
        
        # Parse CSV (skip comments)
        urls = set()
        for line in response.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                url = parts[2].strip('"') if len(parts) > 2 else parts[1].strip('"')
                urls.add(url.lower())
        
        _ti_cache["urlhaus"]["data"] = urls
        _ti_cache["urlhaus"]["loaded_at"] = now
        return urls
        
    except Exception:
        return _ti_cache["urlhaus"]["data"]


def _load_abusech_feed(timeout: int = TI_TIMEOUT_SEC) -> Set[str]:
    """Load Abuse.ch Feodo Tracker IP blocklist."""
    global _ti_cache
    
    now = time.time()
    if _ti_cache["abusech"]["data"] and (now - _ti_cache["abusech"]["loaded_at"]) < TI_CACHE_TTL_HOURS * 3600:
        return _ti_cache["abusech"]["data"]
    
    try:
        import requests
        response = requests.get(TI_ABUSECH_FEED, timeout=timeout)
        if response.status_code != 200:
            return _ti_cache["abusech"]["data"]
        
        ips = set()
        for line in response.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            ip = line.strip().split(",")[0].strip('"')
            if RE_IPV4.match(ip):
                ips.add(ip)
        
        _ti_cache["abusech"]["data"] = ips
        _ti_cache["abusech"]["loaded_at"] = now
        return ips
        
    except Exception:
        return _ti_cache["abusech"]["data"]


def check_iocs_against_feeds(
    domains: List[str],
    ips: List[str],
    urls: List[str],
    timeout: int = TI_TIMEOUT_SEC,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Check extracted IOCs against threat intelligence feeds.
    
    Returns:
        Tuple of (urlhaus_matches, abusech_matches)
    """
    urlhaus_matches = []
    abusech_matches = []
    
    # Load feeds
    urlhaus_data = _load_urlhaus_feed(timeout)
    abusech_data = _load_abusech_feed(timeout)
    
    # Check URLs against URLHaus
    for url in urls:
        url_lower = url.lower()
        if url_lower in urlhaus_data:
            urlhaus_matches.append({
                "type": "url",
                "value": url,
                "source": "urlhaus",
                "severity": "high",
            })
        # Also check domain part
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if any(domain in u for u in urlhaus_data):
                urlhaus_matches.append({
                    "type": "domain",
                    "value": domain,
                    "source": "urlhaus",
                    "severity": "medium",
                })
        except Exception:
            pass
    
    # Check IPs against Abuse.ch
    for ip in ips:
        if ip in abusech_data:
            abusech_matches.append({
                "type": "ip",
                "value": ip,
                "source": "feodotracker",
                "severity": "critical",
            })
    
    return urlhaus_matches, abusech_matches


# ----- Main Analysis Function -----

def analyze_threat_intel(
    strings: List[str],
    emulation_data: Optional[Dict[str, Any]] = None,
    enable_ti: bool = True,
    enable_dga: bool = True,
    timeout: int = TI_TIMEOUT_SEC,
) -> Dict[str, Any]:
    """
    Perform threat intelligence analysis on extracted data.
    
    Args:
        strings: List of strings from the binary
        emulation_data: Optional emulation results with network/file artifacts
        enable_ti: Enable threat feed lookups
        enable_dga: Enable DGA detection
        timeout: Timeout for TI API calls
        
    Returns:
        Dict with TI results for Evidence.threat_intel
    """
    result: Dict[str, Any] = {
        "enabled": enable_ti,
        "success": False,
        "error": None,
        "iocs": {
            "domains": [],
            "ips": [],
            "urls": [],
            "emails": [],
        },
        "ti_matches": {
            "urlhaus": [],
            "abusech": [],
        },
        "dga": {
            "suspects": [],
            "score": 0.0,
            "count": 0,
        },
        "findings": [],
        "risk_level": "low",
    }
    
    try:
        # Extract IOCs from strings
        iocs = extract_iocs_from_strings(strings)
        
        # Also extract from emulation data
        if emulation_data:
            # Network connections
            for conn in emulation_data.get("network", []):
                params = conn.get("params", [])
                for param in params:
                    if RE_IPV4.match(str(param)):
                        iocs["ips"].add(param)
            
            # Decoded strings
            emu_iocs = extract_iocs_from_strings(emulation_data.get("decoded_strings", []))
            for key in iocs:
                iocs[key].update(emu_iocs.get(key, set()))
        
        result["iocs"] = {
            "domains": sorted(iocs["domains"])[:100],
            "ips": sorted(iocs["ips"])[:100],
            "urls": sorted(iocs["urls"])[:100],
            "emails": sorted(iocs["emails"])[:50],
        }
        
        # DGA Analysis
        if enable_dga and iocs["domains"]:
            dga_suspects = []
            for domain in list(iocs["domains"])[:50]:  # Limit for performance
                dga_result = analyze_domain_for_dga(domain)
                if dga_result["is_dga"]:
                    dga_suspects.append(dga_result)
            
            result["dga"]["suspects"] = dga_suspects
            result["dga"]["count"] = len(dga_suspects)
            if dga_suspects:
                result["dga"]["score"] = round(
                    sum(d["score"] for d in dga_suspects) / len(dga_suspects), 3
                )
                result["findings"].append(f"dga_detected:{len(dga_suspects)}_domains")
        
        # TI Feed Checks
        if enable_ti:
            urlhaus_matches, abusech_matches = check_iocs_against_feeds(
                list(iocs["domains"]),
                list(iocs["ips"]),
                list(iocs["urls"]),
                timeout=timeout,
            )
            
            result["ti_matches"]["urlhaus"] = urlhaus_matches
            result["ti_matches"]["abusech"] = abusech_matches
            
            if urlhaus_matches:
                result["findings"].append(f"urlhaus_hit:{len(urlhaus_matches)}")
            if abusech_matches:
                result["findings"].append(f"feodotracker_hit:{len(abusech_matches)}")
        
        # Calculate risk level
        risk_score = 0
        if result["ti_matches"]["abusech"]:
            risk_score += 3  # C2 IPs are critical
        if result["ti_matches"]["urlhaus"]:
            risk_score += 2
        if result["dga"]["count"] >= 3:
            risk_score += 2
        elif result["dga"]["count"] >= 1:
            risk_score += 1
        
        if risk_score >= 4:
            result["risk_level"] = "critical"
        elif risk_score >= 3:
            result["risk_level"] = "high"
        elif risk_score >= 1:
            result["risk_level"] = "medium"
        else:
            result["risk_level"] = "low"
        
        result["success"] = True
        
    except Exception as e:
        result["error"] = f"ti_error:{str(e)[:200]}"
    
    return result


def merge_ti_to_reputation(
    ti_result: Dict[str, Any],
    reputation: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Merge threat intelligence findings into reputation data.
    
    Args:
        ti_result: Threat intel analysis result
        reputation: Existing reputation dict
        
    Returns:
        Updated reputation dict
    """
    if reputation is None:
        reputation = {"findings": [], "counts": {}, "categories": []}
    
    findings = list(reputation.get("findings", []))
    categories = set(reputation.get("categories", []))
    
    # Add TI findings
    for match in ti_result.get("ti_matches", {}).get("urlhaus", []):
        findings.append({
            "type": "urlhaus_match",
            "value": match.get("value", ""),
            "severity": match.get("severity", "high"),
            "source": "threat_intel",
        })
        categories.add("malware_url")
    
    for match in ti_result.get("ti_matches", {}).get("abusech", []):
        findings.append({
            "type": "c2_ip_match",
            "value": match.get("value", ""),
            "severity": "critical",
            "source": "threat_intel",
        })
        categories.add("c2_infrastructure")
    
    # Add DGA findings
    for dga in ti_result.get("dga", {}).get("suspects", []):
        findings.append({
            "type": "dga_domain",
            "value": dga.get("domain", ""),
            "score": dga.get("score", 0),
            "severity": "high" if dga.get("score", 0) > 0.7 else "medium",
            "source": "threat_intel",
        })
        categories.add("dga")
    
    reputation["findings"] = findings
    reputation["categories"] = sorted(categories)
    
    # Update counts
    counts = reputation.get("counts", {})
    counts["ti_urlhaus"] = len(ti_result.get("ti_matches", {}).get("urlhaus", []))
    counts["ti_abusech"] = len(ti_result.get("ti_matches", {}).get("abusech", []))
    counts["dga_domains"] = ti_result.get("dga", {}).get("count", 0)
    reputation["counts"] = counts
    
    return reputation
