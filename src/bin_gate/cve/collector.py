# collector.py
"""
CVE/Vulnerability scanning via Docker containers: Syft (SBOM) + Grype (vuln scan).

Flow:
  1. Syft generates CycloneDX SBOM from target file/directory
  2. Grype scans SBOM for known vulnerabilities
  3. Results are normalized to Evidence.cve format

Docker is MANDATORY. Uses volume caching for Grype DB and Syft cache.
"""
from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path
from dataclasses import dataclass, field
import subprocess
import shutil
import json
import os
import re
import tempfile
import time

# DLL name regex for emulation-based extraction (same logic as orchestrate, no circular import)
_DLL_NAME_PATTERN = re.compile(r"\b[\w\-. ]+\.[Dd][Ll][Ll]\b")


def _extract_dll_names_from_emulation(emu: Dict[str, Any]) -> List[str]:
    """Collect unique DLL names from emulation.api_summary keys and emulation.decoded_strings."""
    if not emu or not isinstance(emu, dict):
        return []
    results: Set[str] = set()
    strings_to_scan: List[str] = []
    api_summary = emu.get("api_summary") or {}
    if isinstance(api_summary, dict):
        strings_to_scan.extend(api_summary.keys())
    for s in emu.get("decoded_strings") or []:
        if isinstance(s, str):
            strings_to_scan.append(s)
    for text in strings_to_scan:
        for m in _DLL_NAME_PATTERN.finditer(text):
            name = m.group(0).strip()
            if len(name) <= 256:
                results.add(name)
    return list(results)

from ..docker_utils import (
    check_docker_available, image_exists, pull_image,
    get_grype_volume_mount, get_syft_volume_mount,
    SYFT_IMAGE, GRYPE_IMAGE, DockerNotAvailableError,
)

DOCKER_TIMEOUT_SEC = 300

import threading

_cve_log_lock = threading.Lock()


def _cve_log(msg: str) -> None:
    """Append a line to cli_debug.log for CVE/Syft/Grype diagnostics."""
    with _cve_log_lock:
        try:
            log_path = os.path.join(os.getcwd(), "cli_debug.log")
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[cve_collector] {msg}\n")
        except Exception:
            pass
SYFT_TIMEOUT_SEC = 300
GRYPE_TIMEOUT_SEC = 300


# ---------------------------------------------------------------------------
# Critical Library Versions - Enterprise Supply Chain Risk Detection
# ---------------------------------------------------------------------------
# Libraries with known critical vulnerabilities below these versions
# Format: {"library_name": {"min_safe_version": "x.y.z", "cve_examples": ["CVE-..."]}}
CRITICAL_LIBRARY_THRESHOLDS = {
    # C/C++ core libraries
    "openssl": {
        "min_safe_version": "3.0.0",
        "cve_examples": ["CVE-2022-3602", "CVE-2022-3786", "CVE-2014-0160"],
        "risk": "critical",
        "reason": "Heartbleed, buffer overflows, memory corruption",
    },
    "libssl": {
        "min_safe_version": "3.0.0",
        "cve_examples": ["CVE-2022-3602"],
        "risk": "critical",
        "reason": "OpenSSL vulnerability inheritance",
    },
    "zlib": {
        "min_safe_version": "1.2.12",
        "cve_examples": ["CVE-2022-37434", "CVE-2018-25032"],
        "risk": "high",
        "reason": "Heap buffer overflow in inflate",
    },
    "glibc": {
        "min_safe_version": "2.35",
        "cve_examples": ["CVE-2023-4911", "CVE-2021-3999"],
        "risk": "critical",
        "reason": "Looney Tunables, buffer overflows",
    },
    "libc6": {
        "min_safe_version": "2.35",
        "cve_examples": ["CVE-2023-4911"],
        "risk": "critical",
        "reason": "glibc vulnerability inheritance",
    },
    "libcurl": {
        "min_safe_version": "8.0.0",
        "cve_examples": ["CVE-2023-38545", "CVE-2023-38546"],
        "risk": "high",
        "reason": "SOCKS5 heap buffer overflow",
    },
    "curl": {
        "min_safe_version": "8.0.0",
        "cve_examples": ["CVE-2023-38545"],
        "risk": "high",
        "reason": "SOCKS5 heap buffer overflow",
    },
    "libexpat": {
        "min_safe_version": "2.5.0",
        "cve_examples": ["CVE-2022-40674", "CVE-2022-43680"],
        "risk": "high",
        "reason": "Use-after-free vulnerabilities",
    },
    "expat": {
        "min_safe_version": "2.5.0",
        "cve_examples": ["CVE-2022-40674"],
        "risk": "high",
        "reason": "Use-after-free vulnerabilities",
    },
    "libxml2": {
        "min_safe_version": "2.10.0",
        "cve_examples": ["CVE-2022-40303", "CVE-2022-40304"],
        "risk": "high",
        "reason": "Integer overflows, memory corruption",
    },
    "libpng": {
        "min_safe_version": "1.6.39",
        "cve_examples": ["CVE-2019-7317"],
        "risk": "medium",
        "reason": "Use-after-free in png_image_free",
    },
    "libjpeg": {
        "min_safe_version": "9e",
        "cve_examples": ["CVE-2021-46822"],
        "risk": "medium",
        "reason": "Denial of service",
    },
    "sqlite": {
        "min_safe_version": "3.40.0",
        "cve_examples": ["CVE-2022-46908", "CVE-2022-35737"],
        "risk": "high",
        "reason": "SQL injection, array bounds overflow",
    },
    "sqlite3": {
        "min_safe_version": "3.40.0",
        "cve_examples": ["CVE-2022-46908"],
        "risk": "high",
        "reason": "SQL injection, array bounds overflow",
    },
    
    # Java/JVM
    "log4j": {
        "min_safe_version": "2.17.1",
        "cve_examples": ["CVE-2021-44228", "CVE-2021-45046"],
        "risk": "critical",
        "reason": "Log4Shell RCE vulnerability",
    },
    "log4j-core": {
        "min_safe_version": "2.17.1",
        "cve_examples": ["CVE-2021-44228"],
        "risk": "critical",
        "reason": "Log4Shell RCE vulnerability",
    },
    "spring-core": {
        "min_safe_version": "5.3.18",
        "cve_examples": ["CVE-2022-22965"],
        "risk": "critical",
        "reason": "Spring4Shell RCE vulnerability",
    },
    "spring-framework": {
        "min_safe_version": "5.3.18",
        "cve_examples": ["CVE-2022-22965"],
        "risk": "critical",
        "reason": "Spring4Shell RCE vulnerability",
    },
    "jackson-databind": {
        "min_safe_version": "2.14.0",
        "cve_examples": ["CVE-2020-36518"],
        "risk": "high",
        "reason": "Deserialization vulnerabilities",
    },
    
    # Python
    "cryptography": {
        "min_safe_version": "41.0.0",
        "cve_examples": ["CVE-2023-38325"],
        "risk": "high",
        "reason": "NULL pointer dereference",
    },
    "urllib3": {
        "min_safe_version": "2.0.0",
        "cve_examples": ["CVE-2023-43804"],
        "risk": "medium",
        "reason": "Cookie leakage",
    },
    "requests": {
        "min_safe_version": "2.31.0",
        "cve_examples": ["CVE-2023-32681"],
        "risk": "medium",
        "reason": "Proxy credential leakage",
    },
    "pillow": {
        "min_safe_version": "10.0.0",
        "cve_examples": ["CVE-2023-44271"],
        "risk": "high",
        "reason": "Denial of service via large images",
    },
    
    # JavaScript/Node.js
    "lodash": {
        "min_safe_version": "4.17.21",
        "cve_examples": ["CVE-2021-23337", "CVE-2020-8203"],
        "risk": "high",
        "reason": "Prototype pollution",
    },
    "minimist": {
        "min_safe_version": "1.2.6",
        "cve_examples": ["CVE-2021-44906"],
        "risk": "high",
        "reason": "Prototype pollution",
    },
    "node-forge": {
        "min_safe_version": "1.3.0",
        "cve_examples": ["CVE-2022-24771"],
        "risk": "high",
        "reason": "Signature verification bypass",
    },
    
    # Go
    "golang.org/x/crypto": {
        "min_safe_version": "0.17.0",
        "cve_examples": ["CVE-2023-48795"],
        "risk": "high",
        "reason": "SSH prefix truncation (Terrapin)",
    },
    "golang.org/x/net": {
        "min_safe_version": "0.17.0",
        "cve_examples": ["CVE-2023-44487"],
        "risk": "high",
        "reason": "HTTP/2 Rapid Reset DoS",
    },
}


def _parse_version(version_str: str) -> tuple:
    """Parse version string to comparable tuple."""
    import re
    if not version_str:
        return (0,)
    
    # Remove common prefixes
    version_str = version_str.lstrip("v").lstrip("V")
    
    # Extract numeric parts
    parts = re.split(r'[.\-_+~]', version_str)
    result = []
    for part in parts:
        # Extract leading digits
        match = re.match(r'^(\d+)', part)
        if match:
            result.append(int(match.group(1)))
        else:
            break
    
    return tuple(result) if result else (0,)


def _version_below_threshold(version: str, min_safe: str) -> bool:
    """Check if version is below minimum safe threshold."""
    try:
        current = _parse_version(version)
        minimum = _parse_version(min_safe)
        
        # Compare tuple elements
        for c, m in zip(current, minimum):
            if c < m:
                return True
            elif c > m:
                return False
        
        # If all compared elements are equal, check lengths
        return len(current) < len(minimum)
    except Exception:
        return False


def check_outdated_critical_libraries(components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Check SBOM components against known critical library thresholds.
    
    Args:
        components: List of SBOM components with 'name' and 'version' keys
        
    Returns:
        List of outdated library findings with supply chain risk details
    """
    findings = []
    
    for comp in components:
        name = (comp.get("name") or "").lower()
        version = comp.get("version") or ""
        
        # Check against thresholds
        for lib_name, threshold in CRITICAL_LIBRARY_THRESHOLDS.items():
            if name == lib_name or name.endswith(f"/{lib_name}") or name.startswith(f"{lib_name}/"):
                min_safe = threshold["min_safe_version"]
                
                if _version_below_threshold(version, min_safe):
                    findings.append({
                        "library": name,
                        "current_version": version,
                        "min_safe_version": min_safe,
                        "risk": threshold["risk"],
                        "reason": threshold["reason"],
                        "cve_examples": threshold["cve_examples"],
                        "policy_reason": f"supply_chain_risk:{name}<{min_safe}",
                    })
                break
    
    return findings


@dataclass
class ScanConfig:
    """Configuration for container vulnerability scanning."""
    syft_image: str = SYFT_IMAGE
    grype_image: str = GRYPE_IMAGE
    docker_timeout: int = DOCKER_TIMEOUT_SEC
    syft_timeout: int = SYFT_TIMEOUT_SEC
    grype_timeout: int = GRYPE_TIMEOUT_SEC
    pull_if_missing: bool = True
    grype_network_none: bool = True  # --network none for Grype (offline after db update)
    cleanup_containers: bool = True  # --rm flag


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _sev_buckets() -> Dict[str, int]:
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0, "total": 0}


def _normalize_severity(sev: Optional[str]) -> str:
    """Normalize Grype severity to standard bucket."""
    if not sev:
        return "unknown"
    s = sev.lower().strip()
    if s in ("critical", "crit"):
        return "critical"
    if s in ("high",):
        return "high"
    if s in ("medium", "med", "moderate"):
        return "medium"
    if s in ("low",):
        return "low"
    if s in ("negligible", "none", "info", "informational"):
        return "negligible"
    return "unknown"


def _docker_available() -> bool:
    """Check if Docker daemon is available."""
    status = check_docker_available(raise_on_fail=False)
    return status.available


def _image_exists_local(image: str) -> bool:
    """Check if Docker image exists locally."""
    return image_exists(image)


def _pull_image_local(image: str, timeout: int = 300) -> Tuple[bool, str]:
    """Pull Docker image if not present."""
    return pull_image(image, timeout)


def __docker_available_old() -> bool:
    """Old implementation - kept for reference."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _image_exists(image: str) -> bool:
    """Check if Docker image exists locally."""
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            timeout=15,
        )
        return result.returncode == 0
    except Exception:
        return False


def _pull_image(image: str, timeout: int = 300, retries: int = 3) -> Tuple[bool, str]:
    """
    Pull Docker image with retry mechanism.
    
    Args:
        image: Docker image name
        timeout: Timeout per attempt in seconds
        retries: Number of retry attempts (default: 3)
    
    Returns:
        (success, error_message)
    """
    # Use centralized pull_image from docker_utils
    from ..docker_utils import pull_image
    return pull_image(image, timeout, retries)


# ---------------------------------------------------------------------------
# ContainerVulnerabilityScanner
# ---------------------------------------------------------------------------
class ContainerVulnerabilityScanner:
    """
    Vulnerability scanner using Docker containers:
    - anchore/syft for SBOM generation
    - anchore/grype for vulnerability scanning
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self._docker_ok: Optional[bool] = None
        self._images_pulled: Dict[str, bool] = {}

    def _check_docker(self) -> Tuple[bool, str]:
        """Check Docker availability (cached)."""
        if self._docker_ok is None:
            self._docker_ok = _docker_available()
        if not self._docker_ok:
            return False, "docker_unavailable"
        return True, ""

    def _ensure_image(self, image: str) -> Tuple[bool, str]:
        """Ensure Docker image is available, pull if needed."""
        if image in self._images_pulled:
            return self._images_pulled[image], "" if self._images_pulled[image] else f"image_pull_failed:{image}"

        if _image_exists(image):
            self._images_pulled[image] = True
            return True, ""

        if not self.config.pull_if_missing:
            self._images_pulled[image] = False
            return False, f"image_not_found:{image}"

        ok, err = _pull_image(image, timeout=self.config.docker_timeout)
        self._images_pulled[image] = ok
        if not ok:
            return False, err
        return True, ""

    def _run_syft(self, target_path: Path, force_pe_cataloger: bool = False) -> Tuple[Optional[dict], str]:
        """
        Run Syft to generate SBOM.
        Returns (sbom_dict, error_message).
        force_pe_cataloger: when True (e.g. memory dump masked as .exe), force PE binary package cataloger.
        """
        ok, err = self._ensure_image(self.config.syft_image)
        if not ok:
            return None, f"syft_{err}"

        # Determine mount path (file or directory)
        host_path = target_path.resolve()
        if not host_path.exists():
            return None, f"syft_target_not_found:{host_path}"

        # For Windows paths, convert to Docker-compatible format
        host_path_str = str(host_path)
        if os.name == "nt":
            # Convert C:\path to /c/path for Docker
            if len(host_path_str) >= 2 and host_path_str[1] == ":":
                drive = host_path_str[0].lower()
                host_path_str = f"/{drive}{host_path_str[2:].replace(os.sep, '/')}"

        # Mount as read-only
        mount_spec = f"{host_path_str}:/target:ro"

        cmd = [
            "docker", "run",
            "--rm" if self.config.cleanup_containers else "",
            "-v", mount_spec,
            self.config.syft_image,
            "/target",
            "-o", "cyclonedx-json",
        ]
        # Memory dump (.dmp / masked .exe): deep binary cataloging — PE imports + classifier (zlib, openssl, etc. in binary body)
        if force_pe_cataloger or target_path.suffix.lower() == ".dmp":
            cmd.extend(["--select-catalogers", "+pe-binary-package-cataloger"])
            cmd.extend(["--select-catalogers", "+binary-classifier-cataloger"])
            cmd.extend(["--exclude-binary-packages-with-file-ownership-overlap", "false"])
        if target_path.suffix.lower() == ".dmp":
            cmd.extend(["--scope", "all-layers"])
        # Remove empty strings from cmd
        cmd = [c for c in cmd if c]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.syft_timeout,
            )
            if result.returncode != 0:
                stderr_snip = (result.stderr or "")[:300]
                return None, f"syft_exit_{result.returncode}:{stderr_snip}"

            # Diagnostic: log raw SBOM output (first 500 chars)
            raw_stdout = (result.stdout or "").strip()
            _cve_log(f"Syft raw SBOM (first 500 chars): {raw_stdout[:500]!r}")

            # Parse SBOM JSON from stdout
            try:
                sbom = json.loads(result.stdout)
                return sbom, ""
            except json.JSONDecodeError as e:
                return None, f"syft_json_error:{e}"

        except subprocess.TimeoutExpired:
            return None, f"syft_timeout:{self.config.syft_timeout}s"
        except Exception as e:
            return None, f"syft_error:{e}"

    def _run_grype(self, sbom: dict) -> Tuple[Optional[dict], str]:
        """
        Run Grype to scan SBOM for vulnerabilities.
        Returns (grype_result_dict, error_message).
        """
        ok, err = self._ensure_image(self.config.grype_image)
        if not ok:
            return None, f"grype_{err}"

        # Write SBOM to temp file and mount it
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json",
                delete=False,
                encoding="utf-8"
            ) as f:
                json.dump(sbom, f)
                sbom_tmp_path = f.name
        except Exception as e:
            return None, f"grype_sbom_write_error:{e}"

        try:
            # Convert path for Docker on Windows
            sbom_path_docker = sbom_tmp_path
            if os.name == "nt":
                if len(sbom_tmp_path) >= 2 and sbom_tmp_path[1] == ":":
                    drive = sbom_tmp_path[0].lower()
                    sbom_path_docker = f"/{drive}{sbom_tmp_path[2:].replace(os.sep, '/')}"

            # Offline по умолчанию: контейнер без сети, без проверки версии/БД (иначе toolbox-data.anchore.io)
            grype_offline = os.getenv("BIN_GATE_GRYPE_OFFLINE", "1").strip().lower() in ("1", "true", "yes")
            grype_args = ["--offline", "sbom:/sbom.json", "-o", "json"] if grype_offline else ["sbom:/sbom.json", "-o", "json"]
            use_network_none = self.config.grype_network_none or grype_offline
            grype_db_mount = get_grype_volume_mount()
            cmd = [
                "docker", "run",
                "--rm" if self.config.cleanup_containers else "",
                "--network", "none" if use_network_none else "bridge",
                "-e", "GRYPE_CHECK_FOR_APP_UPDATE=false",
                "-e", "GRYPE_DB_AUTO_UPDATE=false",
                "-e", "GRYPE_DB_VALIDATE_AGE=false",
                "-v", grype_db_mount,
                "-v", f"{sbom_path_docker}:/sbom.json:ro",
                self.config.grype_image,
            ] + grype_args
            cmd = [c for c in cmd if c]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.grype_timeout,
            )

            if result.returncode != 0:
                stderr_snip = (result.stderr or "")[:300]
                return None, f"grype_exit_{result.returncode}:{stderr_snip}"

            try:
                grype_out = json.loads(result.stdout)
                matches = grype_out.get("matches") if isinstance(grype_out, dict) else None
                if not grype_out or (isinstance(matches, list) and len(matches) == 0):
                    _cve_log(
                        "Grype returned empty or no matches. "
                        "Check if vulnerability database is initialized: run 'bin-gate cve-update' or 'docker run --rm anchore/grype:latest db update'"
                    )
                return grype_out, ""
            except json.JSONDecodeError as e:
                return None, f"grype_json_error:{e}"

        except subprocess.TimeoutExpired:
            return None, f"grype_timeout:{self.config.grype_timeout}s"
        except Exception as e:
            return None, f"grype_error:{e}"
        finally:
            # Cleanup temp file
            try:
                os.unlink(sbom_tmp_path)
            except Exception:
                pass

    def _parse_grype_results(self, grype_out: dict) -> Tuple[Dict[str, int], List[Dict[str, Any]]]:
        """
        Parse Grype JSON output to Evidence.cve format.
        Returns (summary, items).
        """
        summary = _sev_buckets()
        items: List[Dict[str, Any]] = []

        # Grype output structure:
        # {
        #   "matches": [
        #     {
        #       "vulnerability": {"id": "CVE-...", "severity": "High", ...},
        #       "artifact": {"name": "pkg", "version": "1.0", "type": "deb", ...}
        #     }
        #   ],
        #   "source": {...},
        #   "descriptor": {...}
        # }
        matches = grype_out.get("matches") or []

        # Group by package
        pkg_vulns: Dict[str, Dict[str, Any]] = {}

        for match in matches:
            vuln = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}

            vuln_id = vuln.get("id") or vuln.get("cve") or "unknown"
            severity = _normalize_severity(vuln.get("severity"))
            fix_state = vuln.get("fix", {}).get("state") if isinstance(vuln.get("fix"), dict) else ""
            fix_versions = vuln.get("fix", {}).get("versions", []) if isinstance(vuln.get("fix"), dict) else []

            pkg_name = artifact.get("name") or "unknown"
            pkg_version = artifact.get("version") or ""
            pkg_type = artifact.get("type") or ""  # deb, rpm, apk, go-module, npm, etc.

            # Map artifact type to ecosystem
            ecosystem = self._map_type_to_ecosystem(pkg_type)

            # Create unique key for package
            pkg_key = f"{pkg_name}:{pkg_version}:{ecosystem}"

            if pkg_key not in pkg_vulns:
                pkg_vulns[pkg_key] = {
                    "package": pkg_name,
                    "ecosystem": ecosystem,
                    "version": pkg_version,
                    "arch": artifact.get("metadata", {}).get("architecture", "") if isinstance(artifact.get("metadata"), dict) else "",
                    "lib": [],
                    "vulns": [],
                }

            # Add vulnerability
            pkg_vulns[pkg_key]["vulns"].append({
                "id": vuln_id,
                "severity": severity,
                "description": vuln.get("description", "")[:500] if vuln.get("description") else "",
                "fix_state": fix_state,
                "fix_versions": fix_versions[:5] if fix_versions else [],
                "datasource": vuln.get("dataSource", ""),
                "urls": (vuln.get("urls") or [])[:3],
            })

            # Update summary
            summary[severity] += 1
            summary["total"] += 1

        items = list(pkg_vulns.values())
        return summary, items

    def _map_type_to_ecosystem(self, pkg_type: str) -> str:
        """Map Grype artifact type to ecosystem name."""
        type_map = {
            "deb": "Debian",
            "apk": "Alpine",
            "rpm": "RedHat",
            "go-module": "Go",
            "npm": "npm",
            "python": "PyPI",
            "pip": "PyPI",
            "gem": "RubyGems",
            "java-archive": "Maven",
            "nuget": "NuGet",
            "rust-crate": "crates.io",
            "binary": "Binary",
        }
        return type_map.get(pkg_type.lower(), pkg_type or "unknown")

    def scan(self, target_path: Path, force_pe_cataloger: bool = False, evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Main scan method. Returns Evidence.cve compatible dict:
        {
            "summary": {"total": int, "critical": int, "high": int, ...},
            "items": [...],
            "notes": [...],
            "sbom_components": int  # number of components in SBOM
        }
        force_pe_cataloger: when True, pass --select-catalogers +pe-binary-package-cataloger to Syft (e.g. for dumps masked as .exe).
        evidence: optional; if Syft returns 0 components, dynamic_lib from supply_chain.dependencies are injected as library components (version 1.0.0) and passed to Grype.
        """
        result: Dict[str, Any] = {
            "summary": _sev_buckets(),
            "items": [],
            "notes": [],
            "sbom_components": 0,
        }

        # Check Docker
        ok, err = self._check_docker()
        if not ok:
            result["notes"].append(f"cve_container:{err}")
            return result

        # Step 1: Generate SBOM with Syft
        sbom, err = self._run_syft(target_path, force_pe_cataloger=force_pe_cataloger)
        if err:
            result["notes"].append(f"cve_syft:{err}")
            return result
        if not sbom:
            result["notes"].append("cve_syft:empty_sbom")
            return result

        # Count SBOM components and keep list for logging (e.g. emulation dump)
        components = list(sbom.get("components") or [])
        if evidence is not None:
            _cve_log(f"DEBUG: current supply_chain deps count: {len(evidence.get('supply_chain', {}).get('dependencies', []))}")
        # Dump fix: if Syft returns 0 components, always take evidence["supply_chain"]["dependencies"] and feed to Grype with version 1.0.0
        deps_current = ((evidence or {}).get("supply_chain") or {}).get("dependencies") or []
        has_dynamic_lib = any(
            isinstance(d, dict) and d.get("type") == "dynamic_lib" and d.get("value")
            for d in deps_current
        )
        if evidence and has_dynamic_lib:
            deps = deps_current
            dynamic_libs = [
                (d.get("value") or "").strip() for d in deps
                if isinstance(d, dict) and d.get("type") == "dynamic_lib" and d.get("value")
            ]
            dynamic_libs = [n for n in dynamic_libs if n and len(n) <= 500]
            if dynamic_libs:
                injected = []
                seen_names: set = set()
                dump_ver = "1.0.0"
                for name in dynamic_libs:
                    safe_name = name[:200].replace("\\", "_").replace("/", "_")
                    if not safe_name:
                        continue
                    bom_ref = f"pkg:generic/{safe_name}@{dump_ver}"
                    if name not in seen_names:
                        seen_names.add(name)
                        injected.append({"bom-ref": bom_ref, "type": "library", "name": name, "version": dump_ver})
                    if name.lower().endswith(".dll"):
                        stem = name[:-4].strip()
                        if stem and stem not in seen_names and len(stem) <= 200:
                            seen_names.add(stem)
                            safe_stem = stem.replace("\\", "_").replace("/", "_")
                            bom_ref_stem = f"pkg:generic/{safe_stem}@{dump_ver}"
                            injected.append({"bom-ref": bom_ref_stem, "type": "library", "name": stem, "version": dump_ver})
                if not components:
                    sbom = {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.4",
                        "version": 1,
                        "components": injected,
                    }
                    components = injected
                    result["notes"].append("cve_sbom:injected_dynamic_lib_from_supply_chain")
                    _cve_log(f"Syft failed on dump, injecting {len(injected)} libraries from emulation directly to Grype.")
                else:
                    # Supplement: add injected libs so Grype guaranteed gets them
                    existing_names = {c.get("name") for c in components if c.get("name")}
                    added = [c for c in injected if c.get("name") not in existing_names]
                    if added:
                        components = components + added
                        sbom["components"] = components
                        result["notes"].append("cve_sbom:supplemented_with_supply_chain_deps")
                        _cve_log(f"Supplemented SBOM with {len(added)} libraries from supply_chain.")

        result["sbom_components"] = len(components)
        result["sbom_component_list"] = [
            f"{c.get('name', '')}@{c.get('version', '')}".strip("@") or c.get("bom-ref", "")
            for c in components
        ]

        if not components:
            # No components found, nothing to scan
            result["notes"].append("cve_syft:no_components_found")
            return result

        # Step 2: Scan SBOM with Grype
        grype_out, err = self._run_grype(sbom)
        if err:
            result["notes"].append(f"cve_grype:{err}")
            return result
        if not grype_out:
            result["notes"].append("cve_grype:empty_result")
            return result

        # Step 3: Parse results
        try:
            summary, items = self._parse_grype_results(grype_out)
            # Fix report map: ensure every component we sent to Grype appears in items (incl. forced/injected libs)
            seen_pkg = {it.get("package") for it in items if it.get("package")}
            for c in components:
                name = c.get("name") or ""
                if not name or name in seen_pkg:
                    continue
                seen_pkg.add(name)
                items.append({
                    "package": name,
                    "ecosystem": "Binary",
                    "version": c.get("version") or "",
                    "arch": "",
                    "lib": [],
                    "vulns": [],
                })
            result["summary"] = summary
            result["items"] = items
        except Exception as e:
            result["notes"].append(f"cve_parse_error:{e}")

        return result


# ---------------------------------------------------------------------------
# Global scanner instance (lazy initialization)
# ---------------------------------------------------------------------------
_scanner: Optional[ContainerVulnerabilityScanner] = None


def _get_scanner(config: Optional[ScanConfig] = None) -> ContainerVulnerabilityScanner:
    """Get or create global scanner instance."""
    global _scanner
    if _scanner is None:
        _scanner = ContainerVulnerabilityScanner(config)
    return _scanner


# ---------------------------------------------------------------------------
# BatchVulnerabilityMap — pакетный анализ CVE
# ---------------------------------------------------------------------------
@dataclass
class BatchScanResult:
    """Result of batch CVE scan for entire directory."""
    success: bool = False
    error: str = ""
    summary: Dict[str, int] = field(default_factory=_sev_buckets)
    items: List[Dict[str, Any]] = field(default_factory=list)
    sbom_components: int = 0
    grype_raw: Optional[dict] = None
    sbom_raw: Optional[dict] = None
    # Enterprise: Outdated critical libraries (supply chain risk)
    outdated_critical_libraries: List[Dict[str, Any]] = field(default_factory=list)
    policy_reasons: List[str] = field(default_factory=list)


class BatchVulnerabilityMap:
    """
    Batch vulnerability scanner — один запуск Syft + Grype для всей директории.
    
    Вместо N запусков контейнеров (один на файл) делает:
    1. Один вызов Syft для всей директории → общий SBOM
    2. Один вызов Grype для SBOM → все уязвимости
    3. Индексация результатов по путям файлов
    
    Использование:
        batch = BatchVulnerabilityMap(config)
        result = batch.scan_directory(Path("/path/to/targets"))
        if result.success:
            for path in target_paths:
                cve_data = batch.get_results_for_file(path)
                evidence.cve = cve_data
    """
    
    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.scanner = ContainerVulnerabilityScanner(self.config)
        
        # Результаты последнего скана
        self._scan_result: Optional[BatchScanResult] = None
        self._scanned_directory: Optional[Path] = None
        
        # Индекс: путь файла → список уязвимостей
        self._path_index: Dict[str, List[Dict[str, Any]]] = {}
        self._component_index: Dict[str, Dict[str, Any]] = {}
        
    def scan_directory(self, directory: Path) -> BatchScanResult:
        """
        Выполняет batch-скан всей директории.
        
        Args:
            directory: Корневая директория для скана
            
        Returns:
            BatchScanResult с общей статистикой и ошибками
        """
        result = BatchScanResult()
        self._scan_result = result
        self._scanned_directory = directory.resolve()
        self._path_index.clear()
        self._component_index.clear()
        
        # Проверка Docker
        ok, err = self.scanner._check_docker()
        if not ok:
            result.error = f"docker_unavailable:{err}"
            return result
        
        # Валидация директории
        if not directory.exists():
            result.error = f"directory_not_found:{directory}"
            return result
        if not directory.is_dir():
            result.error = f"not_a_directory:{directory}"
            return result
            
        # Шаг 1: Batch Syft SBOM
        sbom, err = self._run_batch_syft(directory)
        if err:
            result.error = f"syft_batch:{err}"
            return result
        if not sbom:
            result.error = "syft_batch:empty_sbom"
            return result
            
        result.sbom_raw = sbom
        components = sbom.get("components") or []
        result.sbom_components = len(components)
        
        if not components:
            result.success = True  # Нет компонентов — нет уязвимостей, это не ошибка
            return result
            
        # Шаг 2: Batch Grype scan
        grype_out, err = self.scanner._run_grype(sbom)
        if err:
            result.error = f"grype_batch:{err}"
            return result
        if not grype_out:
            result.error = "grype_batch:empty_result"
            return result
            
        result.grype_raw = grype_out
        
        # Шаг 3: Парсинг и индексация
        try:
            summary, items = self._parse_and_index(grype_out, sbom)
            result.summary = summary
            result.items = items
            result.success = True
        except Exception as e:
            result.error = f"parse_error:{e}"
        
        # Шаг 4: Enterprise — проверка устаревших критических библиотек
        try:
            outdated = check_outdated_critical_libraries(components)
            result.outdated_critical_libraries = outdated
            
            # Формируем policy_reasons для критических рисков
            for lib in outdated:
                if lib.get("risk") in ("critical", "high"):
                    result.policy_reasons.append(lib.get("policy_reason", ""))
                    
            # Добавляем policy_reasons для критических CVE
            if summary.get("critical", 0) > 0:
                result.policy_reasons.append(f"cve_critical_count:{summary['critical']}")
            if summary.get("high", 0) >= 5:
                result.policy_reasons.append(f"cve_high_count_excessive:{summary['high']}")
                
        except Exception as e:
            result.policy_reasons.append(f"outdated_check_error:{e}")
            
        return result
    
    def _run_batch_syft(self, directory: Path) -> Tuple[Optional[dict], str]:
        """
        Запуск Syft для всей директории.
        """
        ok, err = self.scanner._ensure_image(self.config.syft_image)
        if not ok:
            return None, f"syft_{err}"
            
        host_path = directory.resolve()
        host_path_str = str(host_path)
        
        # Конвертация пути для Windows/Docker
        if os.name == "nt":
            if len(host_path_str) >= 2 and host_path_str[1] == ":":
                drive = host_path_str[0].lower()
                host_path_str = f"/{drive}{host_path_str[2:].replace(os.sep, '/')}"
                
        # Монтируем директорию как /src
        mount_spec = f"{host_path_str}:/src:ro"
        
        cmd = [
            "docker", "run",
            "--rm" if self.config.cleanup_containers else "",
            "-v", mount_spec,
            self.config.syft_image,
            "dir:/src",  # Явно указываем, что это директория
            "-o", "cyclonedx-json",
        ]
        cmd = [c for c in cmd if c]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.syft_timeout * 2,  # Увеличенный таймаут для batch
            )
            if result.returncode != 0:
                stderr_snip = (result.stderr or "")[:300]
                return None, f"exit_{result.returncode}:{stderr_snip}"

            raw_stdout = (result.stdout or "").strip()
            _cve_log(f"Syft batch raw SBOM (first 500 chars): {raw_stdout[:500]!r}")

            try:
                sbom = json.loads(result.stdout)
                return sbom, ""
            except json.JSONDecodeError as e:
                return None, f"json_error:{e}"

        except subprocess.TimeoutExpired:
            return None, f"timeout:{self.config.syft_timeout * 2}s"
        except Exception as e:
            return None, f"error:{e}"
            
    def _parse_and_index(self, grype_out: dict, sbom: dict) -> Tuple[Dict[str, int], List[Dict[str, Any]]]:
        """
        Парсит результаты Grype и индексирует их по путям файлов.
        """
        summary = _sev_buckets()
        pkg_vulns: Dict[str, Dict[str, Any]] = {}
        
        # Строим индекс компонентов SBOM по имени
        for comp in sbom.get("components") or []:
            comp_name = comp.get("name", "")
            comp_version = comp.get("version", "")
            comp_key = f"{comp_name}:{comp_version}"
            
            # Извлекаем путь из properties или purl
            file_path = ""
            for prop in comp.get("properties") or []:
                if prop.get("name") in ("syft:location:0:path", "syft:location:path", "path"):
                    file_path = prop.get("value", "")
                    break
            if not file_path:
                purl = comp.get("purl", "")
                if "?" in purl:
                    # Пытаемся извлечь путь из query params
                    pass
                    
            self._component_index[comp_key] = {
                "name": comp_name,
                "version": comp_version,
                "path": file_path,
                "type": comp.get("type", ""),
            }
            
        # Парсим уязвимости
        matches = grype_out.get("matches") or []
        
        for match in matches:
            vuln = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}
            
            vuln_id = vuln.get("id") or vuln.get("cve") or "unknown"
            severity = _normalize_severity(vuln.get("severity"))
            fix_state = ""
            fix_versions = []
            if isinstance(vuln.get("fix"), dict):
                fix_state = vuln["fix"].get("state", "")
                fix_versions = vuln["fix"].get("versions", [])[:5]
                
            pkg_name = artifact.get("name") or "unknown"
            pkg_version = artifact.get("version") or ""
            pkg_type = artifact.get("type") or ""
            ecosystem = self.scanner._map_type_to_ecosystem(pkg_type)
            
            # Извлекаем путь файла из artifact.locations
            file_paths: List[str] = []
            for loc in artifact.get("locations") or []:
                if isinstance(loc, dict):
                    p = loc.get("path", "")
                    if p:
                        file_paths.append(p)
                        
            # Если путей нет, пробуем component index
            if not file_paths:
                comp_key = f"{pkg_name}:{pkg_version}"
                if comp_key in self._component_index:
                    p = self._component_index[comp_key].get("path", "")
                    if p:
                        file_paths.append(p)
                        
            # Дефолтный путь если ничего не нашли
            if not file_paths:
                file_paths = [""]
                
            # Записываем уязвимость
            pkg_key = f"{pkg_name}:{pkg_version}:{ecosystem}"
            
            if pkg_key not in pkg_vulns:
                pkg_vulns[pkg_key] = {
                    "package": pkg_name,
                    "ecosystem": ecosystem,
                    "version": pkg_version,
                    "arch": artifact.get("metadata", {}).get("architecture", "") if isinstance(artifact.get("metadata"), dict) else "",
                    "lib": [],
                    "vulns": [],
                    "file_paths": list(set(file_paths)),  # Уникальные пути
                }
            else:
                # Мержим пути
                existing_paths = set(pkg_vulns[pkg_key].get("file_paths", []))
                existing_paths.update(file_paths)
                pkg_vulns[pkg_key]["file_paths"] = list(existing_paths)
                
            vuln_entry = {
                "id": vuln_id,
                "severity": severity,
                "description": (vuln.get("description", "") or "")[:500],
                "fix_state": fix_state,
                "fix_versions": fix_versions,
                "datasource": vuln.get("dataSource", ""),
                "urls": (vuln.get("urls") or [])[:3],
            }
            pkg_vulns[pkg_key]["vulns"].append(vuln_entry)
            
            # Индексируем по путям
            for fp in file_paths:
                if fp:
                    if fp not in self._path_index:
                        self._path_index[fp] = []
                    self._path_index[fp].append({
                        "package": pkg_name,
                        "version": pkg_version,
                        "ecosystem": ecosystem,
                        "vuln": vuln_entry,
                    })
                    
            summary[severity] += 1
            summary["total"] += 1
            
        items = list(pkg_vulns.values())
        return summary, items
        
    def get_results_for_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Возвращает CVE данные для конкретного файла.
        
        Args:
            file_path: Абсолютный или относительный путь к файлу
            
        Returns:
            Словарь в формате Evidence.cve:
            {
                "summary": {...},
                "items": [...],
                "notes": [...],
                "batch_mode": True
            }
        """
        result: Dict[str, Any] = {
            "summary": _sev_buckets(),
            "items": [],
            "notes": [],
            "batch_mode": True,
        }
        
        if self._scan_result is None or not self._scan_result.success:
            if self._scan_result and self._scan_result.error:
                result["notes"].append(f"cve_batch_failed:{self._scan_result.error}")
            else:
                result["notes"].append("cve_batch_not_run")
            return result
            
        # Нормализуем путь относительно отсканированной директории
        if isinstance(file_path, str):
            file_path = Path(file_path)
            
        file_path_resolved = file_path.resolve()
        
        # Пробуем разные варианты пути
        search_paths = []
        
        # Относительно scanned directory
        if self._scanned_directory:
            try:
                rel_path = file_path_resolved.relative_to(self._scanned_directory)
                search_paths.append(str(rel_path).replace("\\", "/"))
                search_paths.append("/" + str(rel_path).replace("\\", "/"))
                search_paths.append("/src/" + str(rel_path).replace("\\", "/"))
            except ValueError:
                pass
                
        # Абсолютный путь
        search_paths.append(str(file_path_resolved).replace("\\", "/"))
        
        # Только имя файла
        search_paths.append(file_path.name)
        
        # Ищем совпадения
        matched_vulns: Dict[str, Dict[str, Any]] = {}
        
        for sp in search_paths:
            if sp in self._path_index:
                for vuln_info in self._path_index[sp]:
                    key = f"{vuln_info['package']}:{vuln_info['version']}"
                    if key not in matched_vulns:
                        matched_vulns[key] = {
                            "package": vuln_info["package"],
                            "ecosystem": vuln_info["ecosystem"],
                            "version": vuln_info["version"],
                            "vulns": [],
                        }
                    matched_vulns[key]["vulns"].append(vuln_info["vuln"])
                    
        # Считаем summary
        summary = _sev_buckets()
        for pkg in matched_vulns.values():
            for v in pkg.get("vulns", []):
                sev = v.get("severity", "unknown")
                summary[sev] += 1
                summary["total"] += 1
                
        result["summary"] = summary
        result["items"] = list(matched_vulns.values())
        
        # Если для этого файла нет уязвимостей, но batch успешен — это нормально
        if not matched_vulns and self._scan_result.success:
            result["notes"].append("cve_no_vulns_for_file")
            
        return result
        
    def get_all_results(self) -> Dict[str, Any]:
        """
        Возвращает все CVE данные из batch-скана.
        """
        if self._scan_result is None:
            return {
                "summary": _sev_buckets(),
                "items": [],
                "notes": ["cve_batch_not_run"],
            }
            
        if not self._scan_result.success:
            return {
                "summary": _sev_buckets(),
                "items": [],
                "notes": [f"cve_batch_failed:{self._scan_result.error}"],
            }
            
        return {
            "summary": self._scan_result.summary,
            "items": self._scan_result.items,
            "sbom_components": self._scan_result.sbom_components,
            "notes": [],
            "batch_mode": True,
        }
        
    @property
    def is_ready(self) -> bool:
        """Возвращает True если batch-скан был успешно выполнен."""
        return self._scan_result is not None and self._scan_result.success


# ---------------------------------------------------------------------------
# Pre-scan API для batch CVE
# ---------------------------------------------------------------------------
_batch_map: Optional[BatchVulnerabilityMap] = None


def pre_scan_vulnerabilities(
    directory: Path,
    *,
    config: Optional[ScanConfig] = None,
) -> Tuple[bool, str, Optional[BatchVulnerabilityMap]]:
    """
    Выполняет batch CVE-скан директории перед основным циклом анализа.
    
    Запускает один контейнер Syft + один контейнер Grype для всей директории,
    вместо N вызовов для каждого файла.
    
    Args:
        directory: Корневая директория с файлами для скана
        config: Конфигурация сканера
        
    Returns:
        (success, error_message, batch_map)
        - success: True если скан успешен
        - error_message: Описание ошибки или ""
        - batch_map: BatchVulnerabilityMap для получения результатов по файлам
        
    Example:
        success, err, batch = pre_scan_vulnerabilities(Path("./targets"))
        if success:
            for file_path in target_files:
                cve_data = batch.get_results_for_file(file_path)
                evidence.cve = cve_data
        else:
            # Все evidence.errors += ["cve_batch_failed"]
            log.error(f"CVE batch scan failed: {err}")
    """
    global _batch_map
    
    if isinstance(directory, str):
        directory = Path(directory)
        
    batch = BatchVulnerabilityMap(config)
    result = batch.scan_directory(directory)
    
    if result.success:
        _batch_map = batch
        return True, "", batch
    else:
        _batch_map = batch  # Сохраняем даже при ошибке для доступа к error
        return False, result.error, batch


def get_batch_results_for_file(file_path: Path) -> Dict[str, Any]:
    """
    Получает CVE результаты для файла из глобального batch-скана.

    Используется в цикле анализа вместо индивидуальных вызовов collect_cve_for_file.
    .dmp файлы никогда не берутся из batch — только индивидуальный collect_cve_for_file.

    Returns:
        Словарь в формате Evidence.cve
    """
    global _batch_map

    if _batch_map is None:
        return {
            "summary": _sev_buckets(),
            "items": [],
            "notes": ["cve_batch_not_initialized"],
        }
    # Dumps must never use batch; they go through individual collect_cve_for_file only
    if isinstance(file_path, Path) and file_path.suffix.lower() == ".dmp":
        return {"summary": _sev_buckets(), "items": [], "notes": ["cve_batch_skipped_dump"]}
    if isinstance(file_path, str) and file_path.lower().endswith(".dmp"):
        return {"summary": _sev_buckets(), "items": [], "notes": ["cve_batch_skipped_dump"]}

    return _batch_map.get_results_for_file(file_path)


def is_batch_scan_ready() -> bool:
    """Проверяет, был ли выполнен batch CVE-скан."""
    global _batch_map
    return _batch_map is not None and _batch_map.is_ready


def get_batch_vulnerability_map() -> Optional[BatchVulnerabilityMap]:
    """Возвращает текущий batch map (после pre_scan_vulnerabilities)."""
    global _batch_map
    return _batch_map


# ---------------------------------------------------------------------------
# Public API (backward compatible)
# ---------------------------------------------------------------------------
def collect_cve_for_file(
    file_path: Path,
    ev: Optional[Dict[str, Any]] = None,
    *,
    ecosystem: Optional[str] = None,
    inventory_path: Optional[Path] = None,
    libmap_path: Optional[Path] = None,
    osv_timeout_sec: int = 15,
    docker_config: Optional[ScanConfig] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Scan file for CVE/vulnerabilities using Syft + Grype containers.

    Returns:
        {
            "summary": {"total": int, "critical": int, "high": int, "medium": int, "low": int, ...},
            "items":   [{"package": str, "ecosystem": str, "version": str, "vulns": [...]}],
            "notes":   ["..."]
        }

    Guarantees: never raises exceptions, errors go to "notes".

    Note: ecosystem, inventory_path, libmap_path, osv_timeout_sec are kept
    for backward compatibility but are not used (Syft/Grype handle detection).
    """
    # Syft on dump returns 0 libs: use LOADED_MODULE / ev["emulation"]["modules"] and force into supply_chain
    if ev and (".dmp" in str(file_path) or "VMProtect" in str(ev)):
        real_libs = [
            d["value"] for d in ev.get("supply_chain", {}).get("dependencies", [])
            if d.get("type") == "dynamic_lib" and d.get("value")
        ]
        emu = ev.get("emulation") or {}
        if emu.get("modules"):
            existing_values = {d.get("value") for d in ev.get("supply_chain", {}).get("dependencies", []) if isinstance(d, dict)}
            deps = ev.setdefault("supply_chain", {}).get("dependencies", []) or []
            for name in emu["modules"]:
                if isinstance(name, str) and name.strip() and name.strip() not in existing_values:
                    deps.append({"type": "dynamic_lib", "value": name.strip(), "source": "emulation_modules"})
                    existing_values.add(name.strip())
            ev["supply_chain"]["dependencies"] = deps
            real_libs = [d["value"] for d in ev["supply_chain"]["dependencies"] if d.get("type") == "dynamic_lib" and d.get("value")]
        if not real_libs and ev.get("emulation"):
            extracted = _extract_dll_names_from_emulation(ev.get("emulation") or {})
            if extracted:
                existing_deps = ev.setdefault("supply_chain", {}).get("dependencies", []) or []
                for lib in extracted:
                    if lib not in [d.get("value") for d in existing_deps if isinstance(d, dict)]:
                        existing_deps.append({"type": "dynamic_lib", "value": lib, "source": "forced_fix_v0.0.8"})
                ev["supply_chain"]["dependencies"] = existing_deps
                real_libs = extracted
        if real_libs:
            n = len(real_libs)
            _cve_log(f"Injecting {n} real libraries from emulation into Grype.")
            print(f"[cve_collector] Injecting {n} real libraries from emulation into Grype.")

    # Initialize result early so manual Grype path can return it
    result: Dict[str, Any] = {
        "summary": _sev_buckets(),
        "items": [],
        "notes": [],
    }

    # Force CVE scan: if we have at least one DLL, force generate SBOM and run Grype; use real version from module_details when available.
    deps = ((ev or {}).get("supply_chain") or {}).get("dependencies") or []
    has_dynamic_lib = any(isinstance(d, dict) and d.get("type") == "dynamic_lib" and d.get("value") for d in deps)
    emu = (ev or {}).get("emulation") or {}
    module_details = emu.get("module_details") or emu.get("detailed_modules") or []
    version_by_name: Dict[str, str] = {}
    for md in module_details:
        if isinstance(md, dict) and md.get("name"):
            n = (md.get("name") or "").strip().lower()
            v = (md.get("version") or "").strip()
            if n and v and v != "—":
                version_by_name[n] = v
    if ev and has_dynamic_lib:
        forced_names = [
            (d.get("value") or "").strip() for d in deps
            if isinstance(d, dict) and d.get("type") == "dynamic_lib" and d.get("value")
        ]
        forced_names = [n for n in forced_names if n and len(n) <= 500]
        if forced_names:
            try:
                scanner = _get_scanner(docker_config)
            except Exception:
                scanner = None
            if scanner:
                injected: List[Dict[str, Any]] = []
                seen_names: set = set()
                for name in forced_names:
                    safe_name = name[:200].replace("\\", "_").replace("/", "_")
                    if not safe_name:
                        continue
                    emu_ver = version_by_name.get(name.lower()) or version_by_name.get(name[:-4].lower() if name.lower().endswith(".dll") else "") or "1.0.0"
                    bom_ref = f"pkg:generic/{safe_name}@{emu_ver}"
                    if name not in seen_names:
                        seen_names.add(name)
                        injected.append({"bom-ref": bom_ref, "type": "library", "name": name, "version": emu_ver})
                    if name.lower().endswith(".dll"):
                        stem = name[:-4].strip()
                        if stem and stem not in seen_names and len(stem) <= 200:
                            seen_names.add(stem)
                            stem_ver = version_by_name.get(stem.lower()) or version_by_name.get(name.lower()) or "1.0.0"
                            safe_stem = stem.replace("\\", "_").replace("/", "_")
                            bom_ref_stem = f"pkg:generic/{safe_stem}@{stem_ver}"
                            injected.append({"bom-ref": bom_ref_stem, "type": "library", "name": stem, "version": stem_ver})
                sbom = {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "version": 1,
                    "components": injected,
                }
                grype_out, err = scanner._run_grype(sbom)
                if not err and grype_out:
                    summary, items = scanner._parse_grype_results(grype_out)
                    seen_pkg = {it.get("package") for it in items if it.get("package")}
                    for c in injected:
                        n = c.get("name") or ""
                        if n and n not in seen_pkg:
                            seen_pkg.add(n)
                            items.append({
                                "package": n,
                                "ecosystem": "Binary",
                                "version": c.get("version") or "",
                                "arch": "",
                                "lib": [],
                                "vulns": [],
                            })
                    result["summary"] = summary
                    result["items"] = items
                    result["notes"].append("cve_individual_forced_grype")
                    result["sbom_components"] = len(injected)
                    result["sbom_component_list"] = [
                        f"{c.get('name', '')}@{c.get('version', '')}".strip("@") or c.get("bom-ref", "")
                        for c in injected
                    ]
                    return result
                if err:
                    result["notes"].append(f"cve_forced_grype:{err}")
                else:
                    result["notes"].append("cve_forced_grype:empty_result")

    # Nuclear debug: show full supply_chain and ev identity (compare id with orchestrate FORCE INJECTION)
    print(f"DEBUG_CVE_FLOW: File={file_path} | ev id={id(ev) if ev else 'no ev'} | Full Supply Chain={ev.get('supply_chain') if ev else 'no ev'}")

    # Normalize path
    if isinstance(file_path, str):
        file_path = Path(file_path)

    # Validate path
    if not file_path.exists():
        result["notes"].append(f"cve_file_not_found:{file_path}")
        return result

    # Get scanner
    try:
        scanner = _get_scanner(docker_config)
    except Exception as e:
        result["notes"].append(f"cve_scanner_init_error:{e}")
        return result

    # Mask .dmp as .exe for Syft: create temp copy with .exe so Syft treats it as PE and we can force PE cataloger
    path_for_scan = file_path
    temp_exe_path: Optional[Path] = None
    if file_path.suffix.lower() == ".dmp":
        try:
            fd, temp_exe_path_str = tempfile.mkstemp(suffix=".exe", prefix="temp_dump_for_syft_")
            os.close(fd)
            temp_exe_path = Path(temp_exe_path_str)
            shutil.copy2(file_path, temp_exe_path)
            path_for_scan = temp_exe_path
        except Exception as e:
            result["notes"].append(f"cve_dump_copy_error:{e}")
            return result

    try:
        # Scan (force_pe_cataloger when we masked a dump as .exe; evidence for dynamic_lib → SBOM fallback).
        # Synthetic SBOM: if Syft returns 0 components but ev["supply_chain"]["dependencies"] has data,
        # the scanner builds a synthetic CycloneDX SBOM from those deps and runs Grype on it.
        scan_result = scanner.scan(
            path_for_scan,
            force_pe_cataloger=(temp_exe_path is not None),
            evidence=ev,
        )
        result["summary"] = scan_result.get("summary", result["summary"])
        result["items"] = scan_result.get("items", [])
        result["notes"] = scan_result.get("notes", [])
        if "sbom_components" in scan_result:
            result["sbom_components"] = scan_result["sbom_components"]
        if "sbom_component_list" in scan_result:
            result["sbom_component_list"] = scan_result["sbom_component_list"]
        # If Syft on dump found nothing, force use extracted DLLs for SBOM with version 1.0.0
        if result.get("sbom_components") == 0 and ev and (ev.get("supply_chain") or {}).get("dependencies"):
            deps = ev["supply_chain"]["dependencies"]
            forced_names = [
                (d.get("value") or "").strip() for d in deps
                if isinstance(d, dict) and d.get("type") == "dynamic_lib" and d.get("value")
            ]
            forced_names = [n for n in forced_names if n and len(n) <= 500]
            if forced_names:
                try:
                    emu_ver = "1.0.0"
                    injected: List[Dict[str, Any]] = []
                    seen_names: set = set()
                    for name in forced_names:
                        safe_name = name[:200].replace("\\", "_").replace("/", "_")
                        if not safe_name:
                            continue
                        bom_ref = f"pkg:generic/{safe_name}@{emu_ver}"
                        if name not in seen_names:
                            seen_names.add(name)
                            injected.append({"bom-ref": bom_ref, "type": "library", "name": name, "version": emu_ver})
                        if name.lower().endswith(".dll"):
                            stem = name[:-4].strip()
                            if stem and stem not in seen_names and len(stem) <= 200:
                                seen_names.add(stem)
                                safe_stem = stem.replace("\\", "_").replace("/", "_")
                                injected.append({"bom-ref": f"pkg:generic/{safe_stem}@{emu_ver}", "type": "library", "name": stem, "version": emu_ver})
                    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1, "components": injected}
                    grype_out, err = scanner._run_grype(sbom)
                    if not err and grype_out:
                        summary, items = scanner._parse_grype_results(grype_out)
                        seen_pkg = {it.get("package") for it in items if it.get("package")}
                        for c in injected:
                            n = c.get("name") or ""
                            if n and n not in seen_pkg:
                                seen_pkg.add(n)
                                items.append({"package": n, "ecosystem": "Binary", "version": c.get("version") or "", "arch": "", "lib": [], "vulns": []})
                        result["summary"] = summary
                        result["items"] = items
                        result["notes"].append("cve_sbom_fallback_dynamic_lib_1.0.0")
                        result["sbom_components"] = len(injected)
                        result["sbom_component_list"] = [f"{c.get('name', '')}@{c.get('version', '')}".strip("@") or c.get("bom-ref", "") for c in injected]
                except Exception as e:
                    result["notes"].append(f"cve_sbom_fallback_error:{e}")
        # Log libraries extracted from emulation dump to cli_debug.log: [cve_collector] emulation dump: libraries extracted (N): {list}
        is_dump = file_path.suffix.lower() == ".dmp" or (
            ev and (ev.get("emulation") or {}).get("memory_dump_path")
            and str(Path((ev.get("emulation") or {}).get("memory_dump_path", "")).resolve()) == str(file_path.resolve())
        )
        if is_dump:
            libs = result.get("sbom_component_list") or []
            if libs:
                libs_list = ", ".join(libs[:50]) + (f" ... +{len(libs) - 50} more" if len(libs) > 50 else "")
                _cve_log(f"emulation dump: libraries extracted ({len(libs)}): {libs_list}")
            else:
                _cve_log("emulation dump: no libraries extracted (Syft ran on dump)")
    except Exception as e:
        result["notes"].append(f"cve_scan_error:{e}")
    finally:
        # Cleanup: remove temporary .exe copy of the dump
        if temp_exe_path is not None and temp_exe_path.exists():
            try:
                temp_exe_path.unlink()
            except Exception:
                pass

    return result


def collect_cve_for_directory(
    dir_path: Path,
    *,
    docker_config: Optional[ScanConfig] = None,
) -> Dict[str, Any]:
    """
    Scan entire directory (e.g., unpacked archive) for vulnerabilities.
    Syft can scan directories directly, making this efficient for archives.
    """
    if isinstance(dir_path, str):
        dir_path = Path(dir_path)

    result: Dict[str, Any] = {
        "summary": _sev_buckets(),
        "items": [],
        "notes": [],
    }

    if not dir_path.is_dir():
        result["notes"].append(f"cve_not_a_directory:{dir_path}")
        return result

    try:
        scanner = _get_scanner(docker_config)
        scan_result = scanner.scan(dir_path)
        result["summary"] = scan_result.get("summary", result["summary"])
        result["items"] = scan_result.get("items", [])
        result["notes"] = scan_result.get("notes", [])
        if "sbom_components" in scan_result:
            result["sbom_components"] = scan_result["sbom_components"]
    except Exception as e:
        result["notes"].append(f"cve_dir_scan_error:{e}")

    return result


def update_grype_db(timeout_sec: int = 600) -> Tuple[bool, str]:
    """
    Update Grype vulnerability database.
    Run this periodically or before scans to ensure fresh data.

    Returns (success, message).
    """
    if not _docker_available():
        return False, "docker_unavailable"

    ok, err = _pull_image(GRYPE_IMAGE, timeout=120)
    if not ok:
        return False, f"grype_pull_failed:{err}"

    try:
        grype_db_mount = get_grype_volume_mount()
        result = subprocess.run(
            ["docker", "run", "--rm", "-v", grype_db_mount, GRYPE_IMAGE, "db", "update"],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        if result.returncode == 0:
            return True, "grype_db_updated"
        stderr_snip = (result.stderr or "")[:200]
        # When update fails (e.g. network unreachable), force offline for subsequent Grype scan
        os.environ["BIN_GATE_GRYPE_OFFLINE"] = "1"
        return False, f"grype_db_update_failed:{stderr_snip}"
    except subprocess.TimeoutExpired:
        os.environ["BIN_GATE_GRYPE_OFFLINE"] = "1"
        return False, f"grype_db_update_timeout:{timeout_sec}s"
    except Exception as e:
        err_str = str(e).lower()
        if "network" in err_str or "unreachable" in err_str or "connection" in err_str:
            os.environ["BIN_GATE_GRYPE_OFFLINE"] = "1"
        return False, f"grype_db_update_error:{e}"


def check_container_prereqs() -> Dict[str, Any]:
    """
    Check if Docker and required images are available.
    Useful for health checks and diagnostics.

    Returns:
        {
            "docker_available": bool,
            "syft_image": {"exists": bool, "image": str},
            "grype_image": {"exists": bool, "image": str},
            "ready": bool  # True if all prerequisites met
        }
    """
    docker_ok = _docker_available()
    syft_ok = _image_exists(SYFT_IMAGE) if docker_ok else False
    grype_ok = _image_exists(GRYPE_IMAGE) if docker_ok else False

    return {
        "docker_available": docker_ok,
        "syft_image": {"exists": syft_ok, "image": SYFT_IMAGE},
        "grype_image": {"exists": grype_ok, "image": GRYPE_IMAGE},
        "ready": docker_ok and syft_ok and grype_ok,
    }
