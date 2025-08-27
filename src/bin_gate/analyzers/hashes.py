from __future__ import annotations
from pathlib import Path
from typing import Dict, Optional
import hashlib

def compute_hashes(path: Path) -> Dict[str, Optional[str]]:
    """sha256 всегда; ssdeep/TLSH — если библиотеки установлены."""
    h_sha256 = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h_sha256.update(chunk)
    out: Dict[str, Optional[str]] = {"sha256": h_sha256.hexdigest()}

    # ssdeep (optional)
    try:
        import ssdeep  # type: ignore
        out["ssdeep"] = ssdeep.hash_from_file(str(path))
    except Exception:
        out["ssdeep"] = None

    # TLSH (optional)
    try:
        import tlsh  # type: ignore
        tl = tlsh.hash(open(path, "rb").read())
        out["tlsh"] = tl.decode() if isinstance(tl, bytes) else tl
    except Exception:
        out["tlsh"] = None

    return out
