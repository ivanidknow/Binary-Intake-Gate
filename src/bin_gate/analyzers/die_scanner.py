# die_scanner.py
"""
Detect It Easy (DIE) scanner via Docker container.

Provides fast packer/compiler/protector detection and entropy analysis
as a lightweight replacement for FLOSS.

Docker is MANDATORY. Uses volume caching for DIE signatures.
"""
from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path
from dataclasses import dataclass
import subprocess
import json
import os
import re
import string
import math
import threading

# Log to cli_debug.log for Docker/JSON debugging (no dependency on cli)
_die_log_lock = threading.Lock()
DIE_DEBUG_LOG_MAX_CHARS = 2000  # Max raw output to log per call


def _die_log(msg: str) -> None:
    """Append a line to cli_debug.log for DIE debugging."""
    with _die_log_lock:
        try:
            log_path = os.path.join(os.getcwd(), "cli_debug.log")
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[die_scanner] {msg}\n")
        except Exception:
            pass


from ..docker_utils import (
    check_docker_available, image_exists, pull_image,
    get_die_volume_mount, run_docker_container, DIE_IMAGE,
    DockerNotAvailableError,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DIE_TIMEOUT_SEC = 60
# Executable name/path inside the container (e.g. "diec" or "/usr/bin/diec")
# Set DIE_EXECUTABLE if your image uses a different path or ENTRYPOINT
# For horsicq:diec image we use /usr/bin/diec explicitly
DIE_EXECUTABLE = os.getenv("DIE_EXECUTABLE", "diec")


def _die_executable_for_image(image: str) -> str:
    """Return the diec executable path for the given image. horsicq:diec uses /usr/bin/diec."""
    if not image:
        return DIE_EXECUTABLE
    img = image.split(":")[0].lower()
    if "horsicq" in img or image.strip().startswith("horsicq"):
        return "/usr/bin/diec"
    return DIE_EXECUTABLE


def _extract_json_blocks(text: str) -> List[str]:
    """
    Extract one or more JSON object blocks from diec stdout.
    diec may prefix JSON with a filename line (e.g. '/target/file:\\n' or 'path:\\n').
    Returns list of JSON substrings (each starts with { and has balanced braces).
    """
    if not text or not text.strip():
        return []
    blocks: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        # Find next '{'
        start = text.find("{", i)
        if start == -1:
            break
        depth = 0
        j = start
        while j < n:
            ch = text[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(text[start : j + 1])
                    i = j + 1
                    break
            elif ch == '"' and j > 0 and text[j - 1] != "\\":
                # Skip string content so we don't count braces inside strings
                k = j + 1
                while k < n:
                    if text[k] == "\\":
                        k += 2
                        continue
                    if text[k] == '"':
                        j = k
                        break
                    k += 1
            j += 1
        else:
            # Unbalanced, skip this { and continue
            i = start + 1
    return blocks


def _parse_die_stdout_single(stdout: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """
    Parse single-file diec stdout: may contain 'path:\\n' then JSON.
    Returns (parsed_dict, error_message).
    """
    blocks = _extract_json_blocks(stdout)
    if not blocks:
        return None, "die_empty_output"
    try:
        return json.loads(blocks[0]), ""
    except json.JSONDecodeError as e:
        return None, f"die_json_error:{e}; raw_begin={blocks[0][:100]!r}"


def _path_line_before(json_start_pos: int, text: str) -> Optional[str]:
    """Find the last line before json_start_pos that looks like 'path:' (filename prefix from diec)."""
    before = text[:json_start_pos]
    lines = before.splitlines()
    for line in reversed(lines):
        s = line.strip()
        if s.endswith(":") and not s.startswith("{"):
            return s.rstrip(":").strip()
    return None


def _parse_die_stdout_batch(stdout: str) -> Tuple[Optional[Any], str]:
    """
    Parse batch diec stdout: multiple 'path:\\n' lines and JSON blocks per file.
    Returns (structure for _index_results, error_message).
    """
    blocks = _extract_json_blocks(stdout)
    if not blocks:
        return None, "die_empty_output"
    parsed: List[Dict[str, Any]] = []
    pos = 0
    for raw in blocks:
        start = stdout.find(raw, pos)
        if start == -1:
            start = pos
        path = _path_line_before(start, stdout)
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                if path and not (obj.get("filename") or obj.get("file") or obj.get("path")):
                    obj["file"] = path
                    obj["filename"] = path
                parsed.append(obj)
        except json.JSONDecodeError:
            pass
        pos = start + len(raw)
    if not parsed:
        return None, "die_json_error:no_valid_blocks"
    if len(parsed) == 1:
        return parsed[0], ""
    return parsed, ""

PRINTABLE = set(bytes(string.printable, "ascii"))
MIN_STR_LEN = 4


@dataclass
class DieConfig:
    """Configuration for DIE container scanning."""
    image: str = DIE_IMAGE
    timeout: int = DIE_TIMEOUT_SEC
    pull_if_missing: bool = True
    cleanup_containers: bool = True


# ---------------------------------------------------------------------------
# Known packer/protector families for scoring
# ---------------------------------------------------------------------------
KNOWN_PACKERS = {
    "upx", "aspack", "pecompact", "petite", "mpress", "fsg",
    "npack", "upack", "nspack", "kkrunchy", "telock",
    "yoda", "morphine", "armadillo", "execryptor", "themida",
    "vmprotect", "enigma", "obsidium", "asprotect", "pelock",
    "rlpack", "ezip", "wwpack", "packman", "pklite",
}

KNOWN_PROTECTORS = {
    "themida", "vmprotect", "enigma", "obsidium", "asprotect",
    "execryptor", "armadillo", "pelock", "softdefender",
    "starforce", "safenet", "wibu", "denuvo",
}

KNOWN_INSTALLERS = {
    "inno", "nsis", "installshield", "wise", "sfx", "7-zip sfx",
    "winrar sfx", "createinstall", "ghost installer",
}


# ---------------------------------------------------------------------------
# Docker helpers (using centralized docker_utils)
# ---------------------------------------------------------------------------
def _docker_available() -> bool:
    """Check if Docker daemon is available."""
    status = check_docker_available(raise_on_fail=False)
    return status.available


def _image_exists(image: str) -> bool:
    """Check if Docker image exists locally."""
    return image_exists(image)


def _pull_image(image: str, timeout: int = 300) -> Tuple[bool, str]:
    """Pull Docker image if not present."""
    return pull_image(image, timeout)


# ---------------------------------------------------------------------------
# Fallback: simple ASCII string extraction (when Docker unavailable)
# ---------------------------------------------------------------------------
def _extract_ascii_strings(path: Path, min_len: int = MIN_STR_LEN, max_bytes: int = 4 * 1024 * 1024) -> List[str]:
    """Extract ASCII strings from binary file (fallback when Docker unavailable)."""
    try:
        data = path.read_bytes()[:max_bytes]
    except Exception:
        return []

    strings = []
    current = []

    for byte in data:
        if byte in PRINTABLE and byte not in (0x0b, 0x0c):
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []

    if len(current) >= min_len:
        strings.append("".join(current))

    return strings[:2000]  # limit


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = float(len(data))
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _fallback_analysis(path: Path, min_len: int = MIN_STR_LEN) -> Dict[str, Any]:
    """
    Fallback analysis when Docker is unavailable.
    Extracts strings, calculates entropy, detects basic patterns.
    """
    result: Dict[str, Any] = {
        "strings": [],
        "strings_summary": {
            "total_cnt": 0,
            "url_cnt": 0,
            "ip_cnt": 0,
            "cmd_cnt": 0,
        },
        "detects": [],
        "entropy": {"file": 0.0, "sections": {}},
        "packer_families": [],
        "compiler": None,
        "score": 0,
        "reasons": [],
        "fallback_mode": True,
    }

    try:
        data = path.read_bytes()[:4 * 1024 * 1024]
        result["entropy"]["file"] = round(_calculate_entropy(data), 2)
    except Exception:
        return result

    # Extract strings
    strings = _extract_ascii_strings(path, min_len)
    result["strings"] = strings[:500]
    result["strings_summary"]["total_cnt"] = len(strings)

    # Count IOCs
    re_url = re.compile(r'(?i)\bhttps?://[^\s"\'<>]+')
    re_ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    cmd_markers = ("cmd.exe", "powershell", "rundll32", "regsvr32", "mshta")

    for s in strings:
        try:
            if re_url.search(s):
                result["strings_summary"]["url_cnt"] += 1
            if re_ip.search(s):
                result["strings_summary"]["ip_cnt"] += 1
            if any(m in s.lower() for m in cmd_markers):
                result["strings_summary"]["cmd_cnt"] += 1
        except Exception:
            continue

    # Basic packer detection by string patterns
    data_lower = data.lower()
    packer_hints = {
        b"upx": "UPX",
        b"aspack": "ASPack",
        b"mpress": "MPRESS",
        b"vmprotect": "VMProtect",
        b"themida": "Themida",
        b"enigma": "Enigma",
    }
    for pattern, name in packer_hints.items():
        if pattern in data_lower:
            result["detects"].append({"type": "packer", "name": name, "confidence": "low"})
            result["packer_families"].append(name.lower())
            result["score"] += 15

    # High entropy detection
    if result["entropy"]["file"] >= 7.0:
        result["reasons"].append("high_entropy")
        result["score"] += 20

    return result


# ---------------------------------------------------------------------------
# DIE Scanner class
# ---------------------------------------------------------------------------
class DieScanner:
    """
    Detect It Easy scanner using Docker container.
    Identifies packers, compilers, protectors, and calculates entropy.
    """

    def __init__(self, config: Optional[DieConfig] = None):
        self.config = config or DieConfig()
        self._docker_ok: Optional[bool] = None
        self._image_ready: Optional[bool] = None

    def _check_docker(self) -> Tuple[bool, str]:
        """Check Docker availability (cached)."""
        if self._docker_ok is None:
            self._docker_ok = _docker_available()
        if not self._docker_ok:
            return False, "docker_unavailable"
        return True, ""

    def _ensure_image(self) -> Tuple[bool, str]:
        """Ensure Docker image is available."""
        if self._image_ready is True:
            return True, ""

        if _image_exists(self.config.image):
            self._image_ready = True
            return True, ""

        if not self.config.pull_if_missing:
            self._image_ready = False
            return False, f"image_not_found:{self.config.image}"

        ok, err = _pull_image(self.config.image, timeout=300)
        self._image_ready = ok
        return ok, err if not ok else ""

    def _run_die(self, target_path: Path) -> Tuple[Optional[dict], str]:
        """
        Run DIE container to analyze file.
        Returns (die_result_dict, error_message).
        """
        ok, err = self._ensure_image()
        if not ok:
            return None, f"die_{err}"

        host_path = target_path.resolve()
        if not host_path.exists():
            return None, f"die_target_not_found:{host_path}"

        # Convert path for Docker on Windows
        host_path_str = str(host_path)
        if os.name == "nt":
            if len(host_path_str) >= 2 and host_path_str[1] == ":":
                drive = host_path_str[0].lower()
                host_path_str = f"/{drive}{host_path_str[2:].replace(os.sep, '/')}"

        # Run DIE with JSON output
        # -j / --json: JSON output. Volume: file mapped to /target inside container
        # horsicq:diec image: use /usr/bin/diec -j /target explicitly
        die_exe = _die_executable_for_image(self.config.image)
        cmd = [
            "docker", "run",
            "--rm" if self.config.cleanup_containers else "",
            "-v", f"{host_path_str}:/target:ro",
            self.config.image,
        ]
        if die_exe:
            cmd.append(die_exe)
        cmd.extend(["-j", "/target"])
        cmd = [c for c in cmd if c]
        _die_log(f"DEBUG: DIE command: {' '.join(cmd)}")
        _die_log(f"single-file cmd: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
            )

            stdout = (result.stdout or "").strip()
            stderr = (result.stderr or "").strip()

            _die_log(f"single-file path={host_path} returncode={result.returncode} stdout_len={len(stdout)} stderr_len={len(stderr)}")
            if stdout:
                _die_log(f"single-file raw_stdout (first {DIE_DEBUG_LOG_MAX_CHARS} chars): {stdout[:DIE_DEBUG_LOG_MAX_CHARS]!r}")
            if stderr:
                _die_log(f"single-file raw_stderr (first 500 chars): {stderr[:500]!r}")

            if not stdout:
                if result.returncode != 0:
                    stderr_snip = stderr[:200]
                    return None, f"die_exit_{result.returncode}:{stderr_snip}"
                _die_log("single-file: empty output -> die_empty_output")
                return None, "die_empty_output"

            die_out, err = _parse_die_stdout_single(stdout)
            if err:
                _die_log(f"single-file parse: {err}")
                if "die_json_error" in err:
                    _die_log("single-file FULL stdout on JSON error:")
                    for line in stdout.splitlines():
                        _die_log(f"  | {line[:500]}")
                    if stderr:
                        _die_log("single-file FULL stderr on JSON error:")
                        for line in stderr.splitlines():
                            _die_log(f"  | {line[:500]}")
                return None, err
            return die_out, ""

        except subprocess.TimeoutExpired:
            return None, f"die_timeout:{self.config.timeout}s"
        except Exception as e:
            return None, f"die_error:{e}"

    def _parse_die_results(self, die_out: dict, path: Path) -> Dict[str, Any]:
        """
        Parse DIE JSON output and normalize to our format.
        """
        result: Dict[str, Any] = {
            "detects": [],
            "entropy": {"file": 0.0, "sections": {}},
            "packer_families": [],
            "compiler": None,
            "linker": None,
            "protector": None,
            "installer": None,
            "score": 0,
            "reasons": [],
            "raw_die": die_out,
        }

        # DIE output can be array or object
        detects_list = []
        if isinstance(die_out, list):
            detects_list = die_out
        elif isinstance(die_out, dict):
            detects_list = die_out.get("detects") or die_out.get("records") or []
            # Some DIE versions have different structure
            if not detects_list and "values" in die_out:
                detects_list = die_out.get("values", [])

        packer_families: Set[str] = set()

        for item in detects_list:
            if not isinstance(item, dict):
                continue

            detect_type = (item.get("type") or item.get("sType") or "").lower()
            name = item.get("name") or item.get("sName") or item.get("string") or ""
            version = item.get("version") or item.get("sVersion") or ""

            detect_entry = {
                "type": detect_type,
                "name": name,
                "version": version,
            }
            result["detects"].append(detect_entry)

            name_lower = name.lower()

            # Categorize detections
            if detect_type in ("packer", "protector", "cryptor"):
                # Extract packer family
                for known in KNOWN_PACKERS | KNOWN_PROTECTORS:
                    if known in name_lower:
                        packer_families.add(known)
                        break
                else:
                    # Add first word as family
                    first_word = name_lower.split()[0] if name_lower else ""
                    if first_word and len(first_word) > 2:
                        packer_families.add(first_word)

                result["score"] += 25
                result["reasons"].append(f"packer_detected:{name}")

            elif detect_type == "protector":
                result["protector"] = name
                for known in KNOWN_PROTECTORS:
                    if known in name_lower:
                        packer_families.add(known)
                result["score"] += 30
                result["reasons"].append(f"protector_detected:{name}")

            elif detect_type == "compiler":
                result["compiler"] = name

            elif detect_type == "linker":
                result["linker"] = name

            elif detect_type == "installer":
                result["installer"] = name
                for known in KNOWN_INSTALLERS:
                    if known in name_lower:
                        result["reasons"].append(f"installer_detected:{name}")
                        break

        result["packer_families"] = sorted(packer_families)

        # Extract entropy if available in DIE output
        if isinstance(die_out, dict):
            entropy_info = die_out.get("entropy") or {}
            if isinstance(entropy_info, dict):
                result["entropy"]["file"] = float(entropy_info.get("total") or entropy_info.get("file") or 0.0)
                sections = entropy_info.get("sections") or entropy_info.get("regions") or {}
                if isinstance(sections, dict):
                    result["entropy"]["sections"] = {k: float(v) for k, v in sections.items() if isinstance(v, (int, float))}
                elif isinstance(sections, list):
                    for i, sec in enumerate(sections):
                        if isinstance(sec, dict):
                            name = sec.get("name") or f"section_{i}"
                            ent = sec.get("entropy") or sec.get("value") or 0
                            result["entropy"]["sections"][name] = float(ent)

        # High entropy detection
        file_entropy = result["entropy"].get("file", 0)
        if file_entropy >= 7.0:
            result["reasons"].append("high_file_entropy")
            result["score"] += 15

        # Check for high entropy sections
        high_entropy_sections = sum(1 for e in result["entropy"].get("sections", {}).values() if e >= 7.2)
        if high_entropy_sections > 0:
            result["reasons"].append(f"high_entropy_sections:{high_entropy_sections}")
            result["score"] += 10 * min(high_entropy_sections, 3)

        # Cap score
        if result["score"] > 100:
            result["score"] = 100

        return result

    def scan(self, path: Path, min_str_len: int = MIN_STR_LEN) -> Dict[str, Any]:
        """
        Main scan method.
        Returns analysis results compatible with Evidence format.
        """
        result: Dict[str, Any] = {
            "strings": [],
            "strings_summary": {
                "total_cnt": 0,
                "url_cnt": 0,
                "ip_cnt": 0,
                "cmd_cnt": 0,
            },
            "detects": [],
            "entropy": {"file": 0.0, "sections": {}},
            "packer_families": [],
            "compiler": None,
            "linker": None,
            "protector": None,
            "installer": None,
            "score": 0,
            "reasons": [],
            "errors": [],
            "fallback_mode": False,
        }

        # Check Docker
        ok, err = self._check_docker()
        if not ok:
            # Use fallback
            fallback = _fallback_analysis(path, min_str_len)
            fallback["errors"] = [f"die_{err}", "using_fallback_analysis"]
            return fallback

        # Run DIE
        die_out, err = self._run_die(path)
        if err:
            # Use fallback on DIE error
            fallback = _fallback_analysis(path, min_str_len)
            fallback["errors"] = [f"die_{err}", "using_fallback_analysis"]
            return fallback

        if not die_out:
            fallback = _fallback_analysis(path, min_str_len)
            fallback["errors"] = ["die_no_output", "using_fallback_analysis"]
            return fallback

        # Parse DIE results
        try:
            parsed = self._parse_die_results(die_out, path)
            result.update(parsed)
        except Exception as e:
            result["errors"].append(f"die_parse_error:{e}")

        # Also extract strings for compatibility (DIE doesn't do this)
        # Use simple extraction
        strings = _extract_ascii_strings(path, min_str_len)
        result["strings"] = strings[:500]
        result["strings_summary"]["total_cnt"] = len(strings)

        # Count IOCs in strings
        re_url = re.compile(r'(?i)\bhttps?://[^\s"\'<>]+')
        re_ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        cmd_markers = ("cmd.exe", "powershell", "rundll32", "regsvr32", "mshta")

        for s in strings:
            try:
                if re_url.search(s):
                    result["strings_summary"]["url_cnt"] += 1
                if re_ip.search(s):
                    result["strings_summary"]["ip_cnt"] += 1
                if any(m in s.lower() for m in cmd_markers):
                    result["strings_summary"]["cmd_cnt"] += 1
            except Exception:
                continue

        return result


# ---------------------------------------------------------------------------
# Global scanner instance (lazy initialization)
# ---------------------------------------------------------------------------
_scanner: Optional[DieScanner] = None


def _get_scanner(config: Optional[DieConfig] = None) -> DieScanner:
    """Get or create global scanner instance."""
    global _scanner
    if _scanner is None:
        _scanner = DieScanner(config)
    return _scanner


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def run_die(
    path: Path,
    *,
    timeout_sec: int = DIE_TIMEOUT_SEC,
    min_len: int = MIN_STR_LEN,
    max_mb: Optional[int] = 50,
    config: Optional[DieConfig] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Run DIE analysis on file.

    Returns (result_dict, errors_list) where result_dict contains:
    - strings: list of extracted strings
    - strings_summary: {total_cnt, url_cnt, ip_cnt, cmd_cnt}
    - detects: list of {type, name, version}
    - entropy: {file: float, sections: {name: float}}
    - packer_families: list of detected packer families
    - compiler: detected compiler or None
    - score: obfuscation score (0-100)
    - reasons: list of score reasons
    """
    errors: List[str] = []

    # Check file size
    if max_mb and max_mb > 0:
        try:
            size_mb = path.stat().st_size / (1024 * 1024)
            if size_mb > max_mb:
                return {
                    "strings": [],
                    "strings_summary": {"total_cnt": 0, "url_cnt": 0, "ip_cnt": 0, "cmd_cnt": 0},
                    "detects": [],
                    "entropy": {"file": 0.0, "sections": {}},
                    "packer_families": [],
                    "compiler": None,
                    "score": 0,
                    "reasons": [],
                    "errors": [f"die_file_too_large:{size_mb:.1f}MB>{max_mb}MB"],
                    "fallback_mode": False,
                }, [f"die_file_too_large:{size_mb:.1f}MB"]
        except Exception:
            pass

    # Create config with timeout
    if config is None:
        config = DieConfig(timeout=timeout_sec)
    else:
        config.timeout = timeout_sec

    try:
        scanner = _get_scanner(config)
        result = scanner.scan(path, min_len)
        errors.extend(result.get("errors", []))
        return result, errors
    except Exception as e:
        errors.append(f"die_error:{e}")
        # Return fallback
        fallback = _fallback_analysis(path, min_len)
        fallback["errors"] = errors
        return fallback, errors


def check_die_prereqs() -> Dict[str, Any]:
    """
    Check if Docker and DIE image are available.
    """
    docker_ok = _docker_available()
    die_ok = _image_exists(DIE_IMAGE) if docker_ok else False

    return {
        "docker_available": docker_ok,
        "die_image": {"exists": die_ok, "image": DIE_IMAGE},
        "ready": docker_ok and die_ok,
    }


# ---------------------------------------------------------------------------
# Техники ATT&CK из DIE результатов (для интеграции с capa)
# ---------------------------------------------------------------------------
DIE_TYPE_TO_TECHNIQUES = {
    "packer": ["defense-evasion"],
    "protector": ["defense-evasion"],
    "cryptor": ["defense-evasion"],
    "obfuscator": ["defense-evasion"],
    "sfx": [],
    "installer": [],
    "compiler": [],
    "linker": [],
}


def extract_techniques_from_die(die_result: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """
    Извлекает техники ATT&CK и findings из DIE результатов.
    Возвращает (techniques, rule_hits) для заполнения Evidence.capa.
    """
    techniques: Set[str] = set()
    rule_hits: List[str] = []

    if not die_result:
        return [], []

    # Извлекаем из detects
    detects = die_result.get("detects") or []
    for detect in detects:
        if not isinstance(detect, dict):
            continue

        detect_type = (detect.get("type") or "").lower()
        name = detect.get("name") or ""

        if name:
            rule_hits.append(f"DIE:{detect_type}:{name}")

        # Маппинг типа в техники
        type_techniques = DIE_TYPE_TO_TECHNIQUES.get(detect_type, [])
        for t in type_techniques:
            techniques.add(t)

        # Дополнительный анализ по имени
        name_lower = name.lower()
        if any(p in name_lower for p in ("vmprotect", "themida", "enigma", "obsidium")):
            techniques.add("defense-evasion")
        if "crypto" in name_lower or "crypt" in name_lower:
            techniques.add("defense-evasion")

    # Из packer_families
    packer_families = die_result.get("packer_families") or []
    if packer_families:
        techniques.add("defense-evasion")
        for pf in packer_families:
            rule_hits.append(f"DIE:packer_family:{pf}")

    # Из protector
    protector = die_result.get("protector")
    if protector:
        techniques.add("defense-evasion")
        rule_hits.append(f"DIE:protector:{protector}")

    # Высокая энтропия
    entropy = die_result.get("entropy") or {}
    file_entropy = entropy.get("file", 0)
    if file_entropy >= 7.0:
        techniques.add("defense-evasion")
        rule_hits.append(f"DIE:high_entropy:{file_entropy:.2f}")

    # Из reasons
    reasons = die_result.get("reasons") or []
    for reason in reasons:
        if "packer" in reason.lower() or "protector" in reason.lower():
            techniques.add("defense-evasion")

    return sorted(techniques), rule_hits[:30]


def get_die_findings_for_capa(die_result: Dict[str, Any]) -> List[str]:
    """
    Возвращает список findings из DIE для добавления в Evidence.capa.rule_hits
    с префиксом "DIE:".
    """
    findings: List[str] = []

    if not die_result:
        return findings

    # Compiler/Linker
    compiler = die_result.get("compiler")
    if compiler:
        findings.append(f"DIE:compiler:{compiler}")

    linker = die_result.get("linker")
    if linker:
        findings.append(f"DIE:linker:{linker}")

    # Protector/Packer
    protector = die_result.get("protector")
    if protector:
        findings.append(f"DIE:protector:{protector}")

    # Installer
    installer = die_result.get("installer")
    if installer:
        findings.append(f"DIE:installer:{installer}")

    # Packer families
    for pf in (die_result.get("packer_families") or []):
        findings.append(f"DIE:packer:{pf}")

    # Detects
    for detect in (die_result.get("detects") or []):
        if isinstance(detect, dict):
            dtype = detect.get("type", "unknown")
            dname = detect.get("name", "")
            if dname:
                findings.append(f"DIE:{dtype}:{dname}")

    return findings[:50]


# ---------------------------------------------------------------------------
# BATCH MODE: DIE для всей директории (один контейнер)
# ---------------------------------------------------------------------------
@dataclass
class DieBatchResult:
    """Result of batch DIE scan for entire directory."""
    success: bool = False
    error: str = ""
    total_files: int = 0
    scanned_files: int = 0
    raw_output: Optional[dict] = None


class DieBatchMap:
    """
    Batch DIE scanner — один запуск diec -r для всей директории.
    
    Вместо N запусков контейнеров (один на файл) делает:
    1. Один вызов `diec -j -r /target` для рекурсивного сканирования
    2. Парсинг JSON и индексация результатов по путям файлов
    
    Использование:
        batch = DieBatchMap(config)
        result = batch.scan_directory(Path("/path/to/targets"))
        if result.success:
            for path in target_paths:
                die_info = batch.get_die_info(path)
                evidence.die = die_info
    """
    
    def __init__(self, config: Optional[DieConfig] = None):
        self.config = config or DieConfig()
        self._docker_ok: Optional[bool] = None
        self._image_ready: Optional[bool] = None
        
        # Результаты последнего скана
        self._scan_result: Optional[DieBatchResult] = None
        self._scanned_directory: Optional[Path] = None
        
        # Индекс: путь файла → DIE результат
        self._path_index: Dict[str, Dict[str, Any]] = {}
        
    def _check_docker(self) -> Tuple[bool, str]:
        """Check Docker availability (cached)."""
        if self._docker_ok is None:
            self._docker_ok = _docker_available()
        if not self._docker_ok:
            return False, "docker_unavailable"
        return True, ""
        
    def _ensure_image(self) -> Tuple[bool, str]:
        """Ensure Docker image is available."""
        if self._image_ready is True:
            return True, ""
            
        if _image_exists(self.config.image):
            self._image_ready = True
            return True, ""
            
        if not self.config.pull_if_missing:
            self._image_ready = False
            return False, f"image_not_found:{self.config.image}"
            
        ok, err = _pull_image(self.config.image, timeout=300)
        self._image_ready = ok
        return ok, err if not ok else ""
        
    def scan_directory(self, directory: Path) -> DieBatchResult:
        """
        Выполняет batch-скан всей директории.
        
        Args:
            directory: Корневая директория для скана
            
        Returns:
            DieBatchResult с общей статистикой и ошибками
        """
        result = DieBatchResult()
        self._scan_result = result
        self._scanned_directory = directory.resolve()
        self._path_index.clear()
        
        # Проверка Docker
        ok, err = self._check_docker()
        if not ok:
            result.error = f"docker_unavailable:{err}"
            return result
            
        ok, err = self._ensure_image()
        if not ok:
            result.error = f"die_image:{err}"
            return result
            
        # Валидация директории
        if not directory.exists():
            result.error = f"directory_not_found:{directory}"
            return result
        if not directory.is_dir():
            result.error = f"not_a_directory:{directory}"
            return result
            
        # Конвертация пути для Docker
        host_path = directory.resolve()
        host_path_str = str(host_path)
        
        if os.name == "nt":
            if len(host_path_str) >= 2 and host_path_str[1] == ":":
                drive = host_path_str[0].lower()
                host_path_str = f"/{drive}{host_path_str[2:].replace(os.sep, '/')}"
                
        # Запуск DIE с рекурсивным сканированием
        # horsicq:diec: use /usr/bin/diec -j -r /target
        die_exe = _die_executable_for_image(self.config.image)
        cmd = [
            "docker", "run",
            "--rm" if self.config.cleanup_containers else "",
            "-v", f"{host_path_str}:/target:ro",
            self.config.image,
        ]
        if die_exe:
            cmd.append(die_exe)
        cmd.extend(["-j", "-r", "/target"])
        cmd = [c for c in cmd if c]
        _die_log(f"DEBUG: DIE command: {' '.join(cmd)}")
        _die_log(f"batch cmd: {' '.join(cmd)}")

        try:
            proc_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout * 3,  # Увеличенный таймаут для batch
            )

            stdout = (proc_result.stdout or "").strip()
            stderr = (proc_result.stderr or "").strip()

            _die_log(f"batch dir={directory} returncode={proc_result.returncode} stdout_len={len(stdout)} stderr_len={len(stderr)}")
            if stdout:
                _die_log(f"batch raw_stdout (first {DIE_DEBUG_LOG_MAX_CHARS} chars): {stdout[:DIE_DEBUG_LOG_MAX_CHARS]!r}")
            if stderr:
                _die_log(f"batch raw_stderr (first 500 chars): {stderr[:500]!r}")

            if not stdout:
                if proc_result.returncode != 0:
                    stderr_snip = stderr[:300]
                    result.error = f"die_exit_{proc_result.returncode}:{stderr_snip}"
                else:
                    result.error = "die_empty_output"
                    _die_log("batch: empty output -> die_empty_output")
                return result

            # Extract only JSON blocks (diec prints path: then {...} per file)
            die_output, parse_err = _parse_die_stdout_batch(stdout)
            if parse_err:
                result.error = f"die_{parse_err}"
                _die_log(f"batch parse: {result.error}")
                _die_log("batch FULL stdout on parse error:")
                for line in (stdout or "").splitlines():
                    _die_log(f"  | {line[:500]}")
                if stderr:
                    _die_log("batch FULL stderr:")
                    for line in stderr.splitlines():
                        _die_log(f"  | {line[:500]}")
                return result

            result.raw_output = die_output
            
            # Индексируем результаты
            self._index_results(die_output, directory)
            
            result.success = True
            result.total_files = len(self._path_index)
            result.scanned_files = len(self._path_index)
            
        except subprocess.TimeoutExpired:
            result.error = f"die_timeout:{self.config.timeout * 3}s"
        except Exception as e:
            result.error = f"die_error:{e}"
            
        return result
        
    def _index_results(self, die_output: Any, base_dir: Path) -> None:
        """
        Индексирует DIE результаты по путям файлов.
        
        DIE recursive output может быть:
        1. Массив объектов с полем "filename" или "file"
        2. Объект с ключами-путями
        """
        if isinstance(die_output, list):
            # Массив результатов
            for item in die_output:
                if not isinstance(item, dict):
                    continue
                    
                # Ищем путь к файлу
                file_path = (
                    item.get("filename") or 
                    item.get("file") or 
                    item.get("path") or 
                    item.get("name") or
                    ""
                )
                
                if not file_path:
                    continue
                    
                # Нормализуем путь
                parsed = self._parse_single_result(item)
                self._add_to_index(file_path, parsed, base_dir)
                
        elif isinstance(die_output, dict):
            # Может быть объект с результатом для одного файла
            # или объект с ключами-путями
            if "detects" in die_output or "records" in die_output:
                # Один результат (не batch)
                file_path = die_output.get("filename") or die_output.get("file") or ""
                if file_path:
                    parsed = self._parse_single_result(die_output)
                    self._add_to_index(file_path, parsed, base_dir)
            else:
                # Объект с ключами-путями
                for key, value in die_output.items():
                    if isinstance(value, dict):
                        parsed = self._parse_single_result(value)
                        self._add_to_index(key, parsed, base_dir)
                        
    def _add_to_index(self, file_path: str, parsed: Dict[str, Any], base_dir: Path) -> None:
        """Добавляет результат в индекс с несколькими вариантами пути."""
        # Убираем /target/ prefix из Docker
        clean_path = file_path
        if clean_path.startswith("/target/"):
            clean_path = clean_path[8:]
        elif clean_path.startswith("/target"):
            clean_path = clean_path[7:]
            
        # Добавляем под разными вариантами пути
        variants = [
            clean_path,
            clean_path.replace("/", os.sep),
            clean_path.replace("\\", "/"),
        ]
        
        # Абсолютный путь
        try:
            abs_path = (base_dir / clean_path).resolve()
            variants.append(str(abs_path))
            variants.append(str(abs_path).replace("\\", "/"))
        except Exception:
            pass
            
        # Только имя файла
        if "/" in clean_path or "\\" in clean_path:
            name = Path(clean_path).name
            variants.append(name)
            
        for v in variants:
            if v:
                self._path_index[v] = parsed
                
    def _parse_single_result(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Парсит один DIE результат в наш формат.
        Аналогично _parse_die_results в DieScanner.
        """
        result: Dict[str, Any] = {
            "detects": [],
            "entropy": {"file": 0.0, "sections": {}},
            "packer_families": [],
            "compiler": None,
            "linker": None,
            "protector": None,
            "installer": None,
            "score": 0,
            "reasons": [],
            "batch_mode": True,
        }
        
        # Извлекаем detects
        detects_list = item.get("detects") or item.get("records") or []
        if isinstance(item.get("values"), list):
            detects_list = item.get("values", [])
            
        packer_families: Set[str] = set()
        
        for det in detects_list:
            if not isinstance(det, dict):
                continue
                
            detect_type = (det.get("type") or det.get("sType") or "").lower()
            name = det.get("name") or det.get("sName") or det.get("string") or ""
            version = det.get("version") or det.get("sVersion") or ""
            
            detect_entry = {
                "type": detect_type,
                "name": name,
                "version": version,
            }
            result["detects"].append(detect_entry)
            
            name_lower = name.lower()
            
            # Categorize
            if detect_type in ("packer", "protector", "cryptor"):
                for known in KNOWN_PACKERS | KNOWN_PROTECTORS:
                    if known in name_lower:
                        packer_families.add(known)
                        break
                else:
                    first_word = name_lower.split()[0] if name_lower else ""
                    if first_word and len(first_word) > 2:
                        packer_families.add(first_word)
                        
                result["score"] += 25
                result["reasons"].append(f"packer_detected:{name}")
                
            elif detect_type == "compiler":
                result["compiler"] = name
                
            elif detect_type == "linker":
                result["linker"] = name
                
            elif detect_type == "installer":
                result["installer"] = name
                
        result["packer_families"] = sorted(packer_families)
        
        # Entropy
        entropy_info = item.get("entropy") or {}
        if isinstance(entropy_info, dict):
            result["entropy"]["file"] = float(entropy_info.get("total") or entropy_info.get("file") or 0.0)
            sections = entropy_info.get("sections") or entropy_info.get("regions") or {}
            if isinstance(sections, dict):
                result["entropy"]["sections"] = {k: float(v) for k, v in sections.items() if isinstance(v, (int, float))}
                
        # Высокая энтропия
        if result["entropy"]["file"] >= 7.0:
            result["reasons"].append("high_entropy")
            result["score"] += 20
            
        return result
        
    def get_die_info(self, file_path: Path) -> Dict[str, Any]:
        """
        Возвращает DIE данные для конкретного файла.
        
        Args:
            file_path: Абсолютный или относительный путь к файлу
            
        Returns:
            Словарь с DIE результатами или пустой результат
        """
        empty_result: Dict[str, Any] = {
            "detects": [],
            "entropy": {"file": 0.0, "sections": {}},
            "packer_families": [],
            "compiler": None,
            "score": 0,
            "reasons": [],
            "batch_mode": True,
            "batch_lookup": "not_found",
        }
        
        if self._scan_result is None or not self._scan_result.success:
            empty_result["batch_lookup"] = "batch_not_ready"
            if self._scan_result and self._scan_result.error:
                empty_result["error"] = self._scan_result.error
            return empty_result
            
        # Нормализуем путь
        if isinstance(file_path, str):
            file_path = Path(file_path)
            
        file_path_resolved = file_path.resolve()
        
        # Пробуем разные варианты пути
        search_paths = [
            str(file_path_resolved),
            str(file_path_resolved).replace("\\", "/"),
            str(file_path),
            str(file_path).replace("\\", "/"),
            file_path.name,
        ]
        
        # Относительно scanned directory
        if self._scanned_directory:
            try:
                rel_path = file_path_resolved.relative_to(self._scanned_directory)
                search_paths.append(str(rel_path))
                search_paths.append(str(rel_path).replace("\\", "/"))
            except ValueError:
                pass
                
        # Ищем совпадение
        for sp in search_paths:
            if sp in self._path_index:
                result = self._path_index[sp].copy()
                result["batch_lookup"] = "found"
                return result
                
        return empty_result
        
    @property
    def is_ready(self) -> bool:
        """Возвращает True если batch-скан был успешно выполнен."""
        return self._scan_result is not None and self._scan_result.success
        
    @property
    def files_count(self) -> int:
        """Количество файлов в индексе."""
        return len(self._path_index)


# ---------------------------------------------------------------------------
# Pre-scan API для batch DIE
# ---------------------------------------------------------------------------
_die_batch_map: Optional[DieBatchMap] = None


def pre_scan_die(
    directory: Path,
    *,
    config: Optional[DieConfig] = None,
) -> Tuple[bool, str, Optional[DieBatchMap]]:
    """
    Выполняет batch DIE-скан директории перед основным циклом анализа.
    
    Запускает один контейнер DIE для всей директории (diec -j -r),
    вместо N вызовов для каждого файла.
    
    Args:
        directory: Корневая директория с файлами для скана
        config: Конфигурация сканера
        
    Returns:
        (success, error_message, batch_map)
        - success: True если скан успешен
        - error_message: Описание ошибки или ""
        - batch_map: DieBatchMap для получения результатов по файлам
        
    Example:
        success, err, batch = pre_scan_die(Path("./targets"))
        if success:
            for file_path in target_files:
                die_info = batch.get_die_info(file_path)
                evidence.die = die_info
    """
    global _die_batch_map
    
    if isinstance(directory, str):
        directory = Path(directory)
        
    batch = DieBatchMap(config)
    result = batch.scan_directory(directory)
    
    if result.success:
        _die_batch_map = batch
        return True, "", batch
    else:
        _die_batch_map = batch
        return False, result.error, batch


def get_batch_die_info(file_path: Path) -> Dict[str, Any]:
    """
    Получает DIE результаты для файла из глобального batch-скана.
    
    Используется в цикле анализа вместо индивидуальных вызовов run_die.
    """
    global _die_batch_map
    
    if _die_batch_map is None:
        return {
            "detects": [],
            "entropy": {"file": 0.0, "sections": {}},
            "packer_families": [],
            "score": 0,
            "reasons": [],
            "batch_mode": True,
            "batch_lookup": "batch_not_initialized",
        }
        
    return _die_batch_map.get_die_info(file_path)


def is_die_batch_ready() -> bool:
    """Проверяет, был ли выполнен batch DIE-скан."""
    global _die_batch_map
    return _die_batch_map is not None and _die_batch_map.is_ready
