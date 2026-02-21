# docker_utils.py
"""
Docker utilities with hard-fail requirement and volume caching.

Docker is a MANDATORY dependency. If unavailable, scan fails with critical error.
Provides volume caching for Grype DB and DIE signatures to avoid update checks.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, List
import subprocess
import os
import sys

# Volume names for caching
GRYPE_DB_VOLUME = "bin-gate-grype-db"
SYFT_CACHE_VOLUME = "bin-gate-syft-cache"
DIE_CACHE_VOLUME = "bin-gate-die-cache"

# Docker images
SYFT_IMAGE = "anchore/syft:latest"
GRYPE_IMAGE = "anchore/grype:latest"
DIE_IMAGE = "horsicq:diec"  # Custom local DIE image


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
    """Get volume mount string for Grype DB caching."""
    create_volume_if_not_exists(GRYPE_DB_VOLUME)
    return f"{GRYPE_DB_VOLUME}:/root/.cache/grype"


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
    
    _docker_validated = True
    return _docker_status


def is_docker_validated() -> bool:
    """Check if Docker has been validated."""
    return _docker_validated
