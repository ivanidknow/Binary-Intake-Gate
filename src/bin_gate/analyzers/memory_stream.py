# memory_stream.py
"""
In-memory processing support for archive extraction and analysis.

Provides BytesIO-based processing for files < 50MB to avoid disk I/O.
Larger files use temp files on TMPDIR (ideally tmpfs/RAM disk).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union, BinaryIO, Iterator, Callable, Any
import io
import os
import tempfile
import hashlib

# Threshold for in-memory processing (50 MB)
MEMORY_THRESHOLD_BYTES = int(os.getenv("BIN_GATE_MEMORY_THRESHOLD_MB", "50")) * 1024 * 1024

# Check if TMPDIR is on tmpfs (RAM disk)
def _is_tmpfs(path: str) -> bool:
    """Check if path is on tmpfs (Linux only)."""
    if os.name != "posix":
        return False
    try:
        import subprocess
        result = subprocess.run(
            ["df", "-T", path],
            capture_output=True,
            text=True,
            timeout=5
        )
        return "tmpfs" in result.stdout.lower()
    except Exception:
        return False

# Detect optimal temp directory
def get_optimal_tmpdir() -> Path:
    """
    Returns optimal temp directory:
    1. BIN_GATE_TMPDIR env if set
    2. /dev/shm if available (Linux tmpfs)
    3. Standard tempdir
    """
    custom = os.getenv("BIN_GATE_TMPDIR")
    if custom and Path(custom).is_dir():
        return Path(custom)
    
    # Linux: prefer /dev/shm (shared memory, usually tmpfs)
    if os.name == "posix":
        shm = Path("/dev/shm")
        if shm.is_dir() and os.access(shm, os.W_OK):
            return shm
    
    return Path(tempfile.gettempdir())


@dataclass
class MemoryFile:
    """
    Represents a file that can be either in-memory (BytesIO) or on disk.
    
    Provides unified interface for analysis pipeline:
    - .data: raw bytes (reads from disk if file-backed)
    - .stream: BinaryIO for streaming reads
    - .path: Path (may be None for memory-only files)
    - .size: file size in bytes
    """
    name: str
    size: int
    _data: Optional[bytes] = field(default=None, repr=False)
    _path: Optional[Path] = field(default=None, repr=False)
    origin_chain: tuple = field(default_factory=tuple)
    depth: int = 0
    mime_hint: str = ""
    
    @property
    def is_memory(self) -> bool:
        """True if file is stored in memory."""
        return self._data is not None
    
    @property
    def data(self) -> bytes:
        """Get raw bytes (loads from disk if needed)."""
        if self._data is not None:
            return self._data
        if self._path and self._path.exists():
            return self._path.read_bytes()
        return b""
    
    @property
    def stream(self) -> BinaryIO:
        """Get readable stream."""
        if self._data is not None:
            return io.BytesIO(self._data)
        if self._path and self._path.exists():
            return open(self._path, "rb")
        return io.BytesIO(b"")
    
    @property
    def path(self) -> Optional[Path]:
        """Get file path (None if memory-only)."""
        return self._path
    
    def ensure_on_disk(self, base_dir: Optional[Path] = None) -> Path:
        """
        Ensure file exists on disk (for tools that require file path).
        Creates temp file if memory-only.
        """
        if self._path and self._path.exists():
            return self._path
        
        if base_dir is None:
            base_dir = get_optimal_tmpdir()
        
        # Create temp file
        suffix = Path(self.name).suffix or ""
        fd, tmp_path = tempfile.mkstemp(suffix=suffix, dir=base_dir)
        try:
            os.write(fd, self._data or b"")
        finally:
            os.close(fd)
        
        self._path = Path(tmp_path)
        return self._path
    
    def sha256(self) -> str:
        """Compute SHA-256 hash."""
        return hashlib.sha256(self.data).hexdigest()
    
    def cleanup(self) -> None:
        """Remove temp file if created."""
        if self._path and self._path.exists():
            try:
                self._path.unlink()
            except Exception:
                pass
            self._path = None


def create_memory_file(
    name: str,
    data: bytes,
    origin_chain: tuple = (),
    depth: int = 0,
    force_disk: bool = False,
    base_dir: Optional[Path] = None,
) -> MemoryFile:
    """
    Create MemoryFile, choosing storage based on size.
    
    Args:
        name: Original filename
        data: File content
        origin_chain: Archive chain for provenance
        depth: Nesting depth
        force_disk: Always write to disk
        base_dir: Directory for temp files (default: optimal tmpdir)
    
    Returns:
        MemoryFile with data in memory or on disk
    """
    size = len(data)
    
    # Small files: keep in memory
    if not force_disk and size <= MEMORY_THRESHOLD_BYTES:
        return MemoryFile(
            name=name,
            size=size,
            _data=data,
            origin_chain=origin_chain,
            depth=depth,
        )
    
    # Large files: write to disk
    if base_dir is None:
        base_dir = get_optimal_tmpdir()
    
    suffix = Path(name).suffix or ""
    fd, tmp_path = tempfile.mkstemp(suffix=suffix, dir=base_dir)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    
    return MemoryFile(
        name=name,
        size=size,
        _path=Path(tmp_path),
        origin_chain=origin_chain,
        depth=depth,
    )


class StreamingBuffer:
    """
    Buffered reader for streaming large files without loading entirely into memory.
    
    Usage:
        with StreamingBuffer(path, chunk_size=1024*1024) as buf:
            for chunk in buf:
                process(chunk)
    """
    
    def __init__(self, source: Union[Path, BinaryIO], chunk_size: int = 1024 * 1024):
        self.source = source
        self.chunk_size = chunk_size
        self._handle: Optional[BinaryIO] = None
        self._owned = False
    
    def __enter__(self) -> "StreamingBuffer":
        if isinstance(self.source, Path):
            self._handle = open(self.source, "rb")
            self._owned = True
        else:
            self._handle = self.source
            self._owned = False
        return self
    
    def __exit__(self, *args):
        if self._owned and self._handle:
            self._handle.close()
    
    def __iter__(self) -> Iterator[bytes]:
        if not self._handle:
            return
        while True:
            chunk = self._handle.read(self.chunk_size)
            if not chunk:
                break
            yield chunk
    
    def read_all(self) -> bytes:
        """Read entire content (use with caution for large files)."""
        if not self._handle:
            return b""
        return self._handle.read()


# Type alias for functions that can accept either path or bytes
FileInput = Union[Path, bytes, MemoryFile, BinaryIO]


def normalize_input(inp: FileInput) -> tuple[bytes, Optional[Path]]:
    """
    Normalize various input types to (bytes, optional_path).
    
    Allows analyzers to accept multiple input formats.
    """
    if isinstance(inp, bytes):
        return inp, None
    elif isinstance(inp, MemoryFile):
        return inp.data, inp.path
    elif isinstance(inp, Path):
        return inp.read_bytes(), inp
    elif hasattr(inp, "read"):
        data = inp.read()
        if hasattr(inp, "seek"):
            inp.seek(0)
        return data, None
    else:
        raise TypeError(f"Unsupported input type: {type(inp)}")


def with_file_input(func: Callable) -> Callable:
    """
    Decorator that allows a function expecting Path to also accept bytes/MemoryFile.
    
    The decorated function's first argument can be Path, bytes, or MemoryFile.
    If bytes/MemoryFile is provided, creates a temp file if the original function needs path.
    """
    import functools
    
    @functools.wraps(func)
    def wrapper(inp: FileInput, *args, **kwargs) -> Any:
        if isinstance(inp, Path):
            return func(inp, *args, **kwargs)
        
        if isinstance(inp, MemoryFile):
            # Try memory first, create temp file if needed
            try:
                return func(inp.data, *args, **kwargs)
            except TypeError:
                path = inp.ensure_on_disk()
                return func(path, *args, **kwargs)
        
        if isinstance(inp, bytes):
            # Try bytes first
            try:
                return func(inp, *args, **kwargs)
            except TypeError:
                # Function needs Path - create temp file
                mf = create_memory_file("temp", inp, force_disk=True)
                try:
                    return func(mf.path, *args, **kwargs)
                finally:
                    mf.cleanup()
        
        raise TypeError(f"Unsupported input type: {type(inp)}")
    
    return wrapper
