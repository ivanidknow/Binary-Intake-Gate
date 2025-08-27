from __future__ import annotations
from pathlib import Path
from typing import Optional, Dict, Any
import json, sqlite3, time, os

def _default_cache_path() -> Path:
    # %LOCALAPPDATA%\bin-gate\cache.sqlite на Windows; ~/.cache/bin-gate/cache.sqlite иначе
    if os.name == "nt":
        base = os.getenv("LOCALAPPDATA") or os.path.expanduser(r"~\AppData\Local")
        return Path(base) / "bin-gate" / "cache.sqlite"
    return Path(os.path.expanduser("~/.cache")) / "bin-gate" / "cache.sqlite"

class Cache:
    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or _default_cache_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self.path))
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS kv (
               source   TEXT NOT NULL,
               sha256   TEXT NOT NULL,
               created  INTEGER NOT NULL,
               data     TEXT NOT NULL,
               PRIMARY KEY (source, sha256)
            )
        """)
        self._db.commit()

    def get(self, source: str, sha256: str, max_age_sec: Optional[int]) -> Optional[Dict[str, Any]]:
        cur = self._db.execute("SELECT created, data FROM kv WHERE source=? AND sha256=?", (source, sha256))
        row = cur.fetchone()
        if not row:
            return None
        created, data = row
        if max_age_sec is not None and max_age_sec > 0:
            if int(time.time()) - int(created) > max_age_sec:
                return None
        try:
            return json.loads(data)
        except Exception:
            return None

    def put(self, source: str, sha256: str, data: Dict[str, Any]) -> None:
        blob = json.dumps(data, ensure_ascii=False)
        self._db.execute(
            "REPLACE INTO kv(source, sha256, created, data) VALUES(?,?,?,?)",
            (source, sha256, int(time.time()), blob)
        )
        self._db.commit()
