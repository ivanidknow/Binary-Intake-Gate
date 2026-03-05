# docker_utils.py
"""
Docker utilities with hard-fail requirement and volume caching.

Docker is a MANDATORY dependency. If unavailable, scan fails with critical error.
Provides volume caching for Grype DB and DIE signatures to avoid update checks.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any
import subprocess
import os
import re as _re
import sys

# Volume names for caching
GRYPE_DB_VOLUME = "bin-gate-grype-db"
SYFT_CACHE_VOLUME = "bin-gate-syft-cache"
DIE_CACHE_VOLUME = "bin-gate-die-cache"

# Docker images
SYFT_IMAGE = "anchore/syft:latest"
GRYPE_IMAGE = "anchore/grype:latest"
DIE_IMAGE = "horsicq:diec"  # Custom local DIE image
EMULATION_IMAGE = "bin-gate-emulation:latest"  # Local build from docker/emulation/
CWE_CHECKER_IMAGE = "fkiecad/cwe_checker:latest"


class DockerNotAvailableError(Exception):
    """Raised when Docker is not available (HARD FAIL)."""
    pass


class DockerImageNotFoundError(Exception):
    """Raised when required Docker image is not found."""
    pass


@dataclass
class DockerStatus:
    """Docker daemon status."""
    available: bool
    version: str = ""
    error: str = ""


def check_docker_available(raise_on_fail: bool = True) -> DockerStatus:
    """
    Check if Docker daemon is available.
    
    Args:
        raise_on_fail: If True, raises DockerNotAvailableError (HARD FAIL)
        
    Returns:
        DockerStatus with availability info
        
    Raises:
        DockerNotAvailableError if docker is unavailable and raise_on_fail=True
    """
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return DockerStatus(
                available=True,
                version=result.stdout.strip(),
            )
        else:
            error = f"docker version failed: {result.stderr.strip()}"
            if raise_on_fail:
                raise DockerNotAvailableError(error)
            return DockerStatus(available=False, error=error)
    except FileNotFoundError:
        error = "docker command not found"
        if raise_on_fail:
            raise DockerNotAvailableError(error)
        return DockerStatus(available=False, error=error)
    except subprocess.TimeoutExpired:
        error = "docker daemon timeout"
        if raise_on_fail:
            raise DockerNotAvailableError(error)
        return DockerStatus(available=False, error=error)
    except Exception as e:
        error = f"docker check error: {e}"
        if raise_on_fail:
            raise DockerNotAvailableError(error)
        return DockerStatus(available=False, error=error)


def ensure_docker_or_fail() -> DockerStatus:
    """
    Ensure Docker is available or fail with critical error.
    
    This is the HARD FAIL function - call at scan startup.
    """
    status = check_docker_available(raise_on_fail=True)
    return status


def create_volume_if_not_exists(volume_name: str) -> bool:
    """Create Docker volume if it doesn't exist."""
    try:
        # Check if exists
        result = subprocess.run(
            ["docker", "volume", "inspect", volume_name],
            capture_output=True,
            timeout=10,
        )
        if result.returncode == 0:
            return True
        
        # Create
        result = subprocess.run(
            ["docker", "volume", "create", volume_name],
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0
    except Exception:
        return False


def ensure_cache_volumes() -> dict[str, bool]:
    """
    Create cache volumes for all tools.
    
    Returns dict of volume_name -> success status.
    """
    volumes = [GRYPE_DB_VOLUME, SYFT_CACHE_VOLUME, DIE_CACHE_VOLUME]
    results = {}
    for vol in volumes:
        results[vol] = create_volume_if_not_exists(vol)
    return results


def image_exists(image: str) -> bool:
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


def pull_image(image: str, timeout: int = 300, retries: int = 3) -> Tuple[bool, str]:
    """
    Pull Docker image with retry mechanism.
    
    Args:
        image: Docker image name (e.g., 'anchore/syft:latest')
        timeout: Timeout per attempt in seconds
        retries: Number of retry attempts (default: 3)
    
    Returns:
        (success, error_message)
    """
    import time
    
    last_error = ""
    for attempt in range(1, retries + 1):
        try:
            result = subprocess.run(
                ["docker", "pull", image],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode == 0:
                return True, ""
            
            last_error = result.stderr[:500].strip()
            
            # Check for specific error conditions
            if "pull access denied" in last_error.lower():
                return False, f"Image not found or access denied: {image}. Check the image name is correct."
            if "not found" in last_error.lower():
                return False, f"Image not found: {image}. Verify the image exists on Docker Hub."
            if "unauthorized" in last_error.lower():
                return False, f"Unauthorized access to {image}. Check Docker Hub credentials if private."
            
            # Retry on transient errors
            if attempt < retries:
                time.sleep(2 ** attempt)  # Exponential backoff: 2s, 4s, 8s
                continue
                
        except subprocess.TimeoutExpired:
            last_error = f"pull timeout ({timeout}s)"
            if attempt < retries:
                continue
        except Exception as e:
            last_error = str(e)
            if attempt < retries:
                time.sleep(2)
                continue
    
    return False, f"{last_error}. Check internet connection and image name: {image}"


def ensure_images(images: Optional[List[str]] = None) -> dict[str, bool]:
    """
    Ensure all required images are available, pulling if needed.
    
    Returns dict of image -> success status.
    """
    if images is None:
        images = [SYFT_IMAGE, GRYPE_IMAGE, DIE_IMAGE]
    
    results = {}
    for img in images:
        if image_exists(img):
            results[img] = True
        else:
            ok, _ = pull_image(img)
            results[img] = ok
    return results


def get_grype_volume_mount() -> str:
    """Get volume mount string for Grype DB (path must match grype db status: /.cache/grype/db)."""
    create_volume_if_not_exists(GRYPE_DB_VOLUME)
    return f"{GRYPE_DB_VOLUME}:/.cache/grype/db"


def get_syft_volume_mount() -> str:
    """Get volume mount string for Syft caching."""
    create_volume_if_not_exists(SYFT_CACHE_VOLUME)
    return f"{SYFT_CACHE_VOLUME}:/root/.cache/syft"


def get_die_volume_mount() -> str:
    """Get volume mount string for DIE caching."""
    create_volume_if_not_exists(DIE_CACHE_VOLUME)
    return f"{DIE_CACHE_VOLUME}:/root/.config/die"


def build_docker_run_cmd(
    image: str,
    args: List[str],
    *,
    mounts: Optional[List[str]] = None,
    volumes: Optional[List[str]] = None,
    network: str = "none",
    rm: bool = True,
    read_only_root: bool = False,
    timeout_sec: Optional[int] = None,
) -> List[str]:
    """
    Build docker run command with standard security flags.
    
    Args:
        image: Docker image name
        args: Command arguments
        mounts: Bind mounts (host:container:ro)
        volumes: Named volumes (volume:container)
        network: Network mode (default: none for security)
        rm: Remove container after exit
        read_only_root: Make root filesystem read-only
        timeout_sec: Add timeout (not a docker flag, for reference)
    
    Returns:
        List of command arguments for subprocess
    """
    cmd = ["docker", "run"]
    
    if rm:
        cmd.append("--rm")
    
    if network:
        cmd.extend(["--network", network])
    
    if read_only_root:
        cmd.append("--read-only")
    
    for mount in (mounts or []):
        cmd.extend(["-v", mount])
    
    for vol in (volumes or []):
        cmd.extend(["-v", vol])
    
    cmd.append(image)
    cmd.extend(args)
    
    return cmd


def run_docker_container(
    image: str,
    args: List[str],
    *,
    mounts: Optional[List[str]] = None,
    volumes: Optional[List[str]] = None,
    network: str = "none",
    timeout: int = 120,
    capture_output: bool = True,
    stdin_data: Optional[bytes] = None,
) -> Tuple[int, str, str]:
    """
    Run Docker container with standard options.

    Returns:
        (return_code, stdout, stderr)
    """
    cmd = build_docker_run_cmd(
        image, args,
        mounts=mounts,
        volumes=volumes,
        network=network,
    )

    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            timeout=timeout,
            input=stdin_data,
        )
        return (
            result.returncode,
            result.stdout.decode("utf-8", errors="replace") if result.stdout else "",
            result.stderr.decode("utf-8", errors="replace") if result.stderr else "",
        )
    except subprocess.TimeoutExpired:
        return -1, "", f"container timeout ({timeout}s)"
    except Exception as e:
        return -1, "", str(e)


def _emulation_docker_context() -> Path:
    """Path to docker/emulation (project root = parent of src)."""
    # docker_utils is in src/bin_gate/
    project_root = Path(__file__).resolve().parents[2]
    return project_root / "docker" / "emulation"


def build_emulation_image() -> Tuple[bool, str]:
    """
    Build bin-gate-emulation Docker image from docker/emulation/Dockerfile.
    Returns (success, error_message).
    """
    ctx = _emulation_docker_context()
    dockerfile = ctx / "Dockerfile"
    if not dockerfile.exists():
        return False, f"Dockerfile not found: {dockerfile}"
    try:
        result = subprocess.run(
            ["docker", "build", "-t", EMULATION_IMAGE, "."],
            cwd=ctx,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or result.stdout.strip() or "docker build failed"
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "docker build timeout (600s)"
    except Exception as e:
        return False, str(e)


def _host_path_for_docker_mount(path: Path) -> str:
    """Convert host path to form Docker accepts (Windows: /c/Users/...)."""
    s = str(path.resolve())
    if len(s) >= 2 and s[1] == ":":
        drive = s[0].lower()
        return f"/{drive}{s[2:].replace(os.sep, '/')}"
    return s.replace(os.sep, "/")


def run_emulation_container(
    host_file_path: Path,
    timeout: int = 60,
    max_api_calls: Optional[int] = None,
) -> Tuple[int, str, str, Optional[Dict[str, Any]]]:
    """
    Run Speakeasy emulation in Docker. Mounts host_file_path parent as /input and a temp dir as /output.
    Container outputs structured JSON between !!!JSON_REPORT_START!!! and !!!JSON_REPORT_END!!! (no Base64).
    !!!MODULE_LOADED:<name> lines are parsed into report_dict["modules"]. Returns (return_code, stdout, stderr, report_dict).
    max_api_calls: при VMProtect передать 5000 (контейнер читает MAX_API_CALLS).
    """
    import tempfile
    import json as _json
    host_file_path = Path(host_file_path)
    if not host_file_path.exists():
        return -1, "", f"file not found: {host_file_path}", None

    input_mount = f"{_host_path_for_docker_mount(host_file_path.parent)}:/input:ro"
    container_input_file = f"/input/{host_file_path.name}"

    report_dict: Optional[Dict[str, Any]] = None
    with tempfile.TemporaryDirectory(prefix="bin_gate_emu_out_") as out_dir:
        out_path = Path(out_dir)
        report_file_host = out_path / "emu_report.json"
        output_mount = f"{_host_path_for_docker_mount(out_path)}:/output"
        report_path_container = "/output/emu_report.json"

        cmd = [
            "docker", "run", "--rm", "--network", "none",
            "-v", input_mount,
            "-v", output_mount,
            "-e", f"INPUT_FILE={container_input_file}",
            "-e", f"TIMEOUT={timeout}",
            "-e", f"WRITE_REPORT={report_path_container}",
            EMULATION_IMAGE,
        ]
        if max_api_calls is not None:
            cmd.insert(-1, "-e")
            cmd.insert(-1, f"MAX_API_CALLS={max_api_calls}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30,
            )
        except subprocess.TimeoutExpired:
            return -1, "", f"container timeout ({timeout + 30}s)", None
        except Exception as e:
            return -1, "", str(e), None

        import re as _re
        stdout_str = result.stdout or ""
        if report_file_host.exists():
            try:
                with open(report_file_host, "r", encoding="utf-8") as f:
                    report_dict = _json.load(f)
            except Exception:
                report_dict = None
        # Prefer new markers, then legacy
        if report_dict is None and "!!!JSON_REPORT_START!!!" in stdout_str and "!!!JSON_REPORT_END!!!" in stdout_str:
            try:
                i = stdout_str.index("!!!JSON_REPORT_START!!!") + len("!!!JSON_REPORT_START!!!")
                j = stdout_str.index("!!!JSON_REPORT_END!!!")
                json_str = stdout_str[i:j].strip()
                if json_str:
                    report_dict = _json.loads(json_str)
            except Exception:
                report_dict = None
        if report_dict is None and "EMU_JSON_START" in stdout_str and "EMU_JSON_END" in stdout_str:
            try:
                i = stdout_str.index("EMU_JSON_START") + len("EMU_JSON_START")
                j = stdout_str.index("EMU_JSON_END")
                json_str = stdout_str[i:j].strip()
                if json_str:
                    report_dict = _json.loads(json_str)
            except Exception:
                report_dict = None
        if report_dict is None and "{" in stdout_str and "}" in stdout_str:
            try:
                start = stdout_str.rfind("{")
                end = stdout_str.rfind("}") + 1
                if start >= 0 and end > start:
                    report_dict = _json.loads(stdout_str[start:end])
            except Exception:
                pass
        if report_dict is None and "{" in stdout_str:
            try:
                match = _re.search(r"\{.*\}", stdout_str, _re.DOTALL)
                if match:
                    report_dict = _json.loads(match.group(0))
            except Exception:
                pass
        # Collect DLL names from !!!MODULE_LOADED!!!: / !!!MODULE_LOADED: (grab DLL even if separated by weird chars)
        loaded_from_stdout = []
        for m in _re.finditer(r"!!!MODULE_LOADED!!!:.*?([\w\-. ]+\.dll)", stdout_str, _re.IGNORECASE):
            name = m.group(1).strip()
            if name and name not in loaded_from_stdout and len(name) <= 256:
                loaded_from_stdout.append(name)
        for m in _re.finditer(r"!!!MODULE_LOADED:\s*(.+?)(?:\r?\n|$)", stdout_str):
            name = m.group(1).strip()
            if name and name not in loaded_from_stdout and len(name) <= 256:
                loaded_from_stdout.append(name)
        for m in _re.finditer(r"!!!DLL_LOADED:\s*(.+?)(?:\r?\n|$)", stdout_str):
            name = m.group(1).strip()
            if name and name not in loaded_from_stdout and len(name) <= 256:
                loaded_from_stdout.append(name)
        for m in _re.finditer(r"LOADED_MODULE:\s*(.+?\.dll)", stdout_str, _re.IGNORECASE):
            name = m.group(1).strip()
            if name and name not in loaded_from_stdout and len(name) <= 256:
                loaded_from_stdout.append(name)
        # Parse !!!MODULE_INFO!!!: new format name=...|ver=...|hash=... then fallback to old name|version|hash
        module_details: list = []
        for m in _re.finditer(r"!!!MODULE_INFO!!!:name=([^|]+)\|ver=([^|]*)\|hash=(.+?)(?:\r?\n|$)", stdout_str):
            name = (m.group(1) or "").strip()
            version = (m.group(2) or "").strip()
            hash_part = (m.group(3) or "").strip()
            if name and len(name) <= 256:
                module_details.append({"name": name, "version": version or "", "hash": hash_part or ""})
        if not module_details:
            for m in _re.finditer(r"!!!MODULE_INFO!!!:([^|]+)\|([^|]*)\|(.+?)(?:\r?\n|$)", stdout_str):
                name = (m.group(1) or "").strip()
                version = (m.group(2) or "").strip()
                hash_part = (m.group(3) or "").strip()
                if name and len(name) <= 256:
                    module_details.append({"name": name, "version": version or "", "hash": hash_part or ""})
        if module_details:
            if report_dict is None:
                report_dict = {"modules": [], "api_summary": {}, "decoded_strings": [], "module_details": [], "detailed_modules": []}
            report_dict["module_details"] = module_details
            report_dict["detailed_modules"] = list(module_details)
        elif report_dict is not None:
            report_dict.setdefault("module_details", [])
            report_dict.setdefault("detailed_modules", [])
        if loaded_from_stdout:
            if report_dict is None:
                report_dict = {"modules": [], "api_summary": {}, "decoded_strings": []}
            existing = set(report_dict.get("modules") or [])
            for n in loaded_from_stdout:
                if n not in existing:
                    existing.add(n)
                    report_dict.setdefault("modules", []).append(n)

        return (
            result.returncode,
            stdout_str,
            result.stderr or "",
            report_dict,
        )


def run_cwe_checker(file_path: Path, debug: bool = False) -> Dict[str, Any]:
    """
    Run cwe_checker (fkiecad/cwe_checker) in Docker on the given binary/dump file.
    Mounts parent folder as /share:ro; command: cwe_checker /share/<name> --json.
    Returns dict with keys: findings (list), error (str or None), return_code (int), stderr (str).
    When debug=True (или BIN_GATE_CWE_DEBUG=1), логирует stdout/stderr контейнера в консоль.
    """
    import json as _json
    debug = debug or (os.environ.get("BIN_GATE_CWE_DEBUG", "").strip().lower() in ("1", "true", "yes"))
    host_path = Path(file_path).resolve()
    if not host_path.exists():
        return {"findings": [], "error": "file_not_found", "return_code": -1, "stderr": ""}
    # Принудительные права на файл, чтобы контейнер мог прочитать бинарник (Permission Denied в CI)
    try:
        os.chmod(host_path, 0o644)
    except OSError:
        pass
    host_dir = host_path.parent
    # Монтируем родительский каталог в /share:ro; --user root избегает конфликтов UID с томами
    container_file = f"/share/{host_path.name}"
    mount_arg = f"{host_dir}:/share:ro"
    cmd = ["docker", "run", "--rm", "--user", "root", "-v", mount_arg, CWE_CHECKER_IMAGE, container_file, "--json"]
    if debug:
        print(f"[DOCKER_CWE_DEBUG] cmd: {cmd}", flush=True)
        print(f"[DOCKER_CWE_DEBUG] host_path={host_path!r} mount={mount_arg!r} container_file={container_file!r}", flush=True)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"findings": [], "error": "timeout_300s", "return_code": -1, "stderr": ""}
    except Exception as e:
        return {"findings": [], "error": str(e), "return_code": -1, "stderr": ""}
    stdout_str = (result.stdout or "").strip()
    stderr_str = (result.stderr or "").strip()
    if debug or result.returncode != 0:
        print(f"[DOCKER_CWE] returncode={result.returncode} stdout_len={len(stdout_str)} stderr_len={len(stderr_str)}", flush=True)
        if debug:
            print(f"[DOCKER_CWE_DEBUG] stdout:\n{stdout_str[:4000] or '(empty)'}", flush=True)
            print(f"[DOCKER_CWE_DEBUG] stderr:\n{stderr_str[:2000] or '(empty)'}", flush=True)
        elif result.returncode != 0 and stderr_str:
            print(f"[DOCKER_CWE] stderr: {stderr_str[:800]}", flush=True)
    if result.returncode != 0:
        print(f"[DOCKER_ERROR] cwe_checker failed: {stderr_str[:500]}", flush=True)
    findings: List[Dict[str, Any]] = []
    if stdout_str:
        match = _re.search(r"\[\s*\{.*\}\s*\]", stdout_str, _re.DOTALL)
        if match:
            try:
                data = _json.loads(match.group(0))
                if isinstance(data, list):
                    findings = data
            except Exception:
                pass
    error = None if result.returncode == 0 else (stderr_str[:500] if stderr_str else f"exit_{result.returncode}")
    return {
        "findings": findings,
        "error": error,
        "return_code": result.returncode,
        "stderr": stderr_str,
    }


# Startup validation
_docker_validated = False
_docker_status: Optional[DockerStatus] = None


def validate_docker_at_startup() -> DockerStatus:
    """
    Validate Docker availability at scan startup.
    
    Called once at CLI startup. Raises DockerNotAvailableError if unavailable.
    """
    global _docker_validated, _docker_status
    
    if _docker_validated:
        return _docker_status
    
    _docker_status = ensure_docker_or_fail()

    # Create cache volumes
    ensure_cache_volumes()

    # Force pull CWE checker image and fail if unavailable
    ok, err = pull_image(CWE_CHECKER_IMAGE, timeout=300)
    if not ok:
        raise DockerImageNotFoundError(
            f"Failed to pull {CWE_CHECKER_IMAGE}. {err or 'Unknown error'}. CWE analysis will be unavailable."
        )
    if not image_exists(CWE_CHECKER_IMAGE):
        raise DockerImageNotFoundError(
            f"Image {CWE_CHECKER_IMAGE} is not present after pull. CWE analysis will be unavailable."
        )

    _docker_validated = True
    return _docker_status


def is_docker_validated() -> bool:
    """Check if Docker has been validated."""
    return _docker_validated
