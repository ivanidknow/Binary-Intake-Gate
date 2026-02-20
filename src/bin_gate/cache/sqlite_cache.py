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

    # --- Evidence cache: full Evidence dict by SHA-256 ---
    SOURCE_EVIDENCE = "evidence"

    def get_evidence(self, sha256: str, max_age_sec: Optional[int]) -> Optional[Dict[str, Any]]:
        """Return full cached Evidence dict if present and not expired."""
        return self.get(self.SOURCE_EVIDENCE, sha256, max_age_sec)

    def put_evidence(self, sha256: str, data: Dict[str, Any]) -> None:
        """Store full Evidence dict for instant reuse on next scan."""
        self.put(self.SOURCE_EVIDENCE, sha256, data)

    # --- VT negative cache: NOT_FOUND (404) / 429 (rate limit) — не дергать API повторно ---
    SOURCE_VT_NEGATIVE = "vt_negative"
    NOT_FOUND = "NOT_FOUND"   # 404 «не найдено», TTL 24 часа
    VT_NEGATIVE_TTL_404 = 24 * 3600   # 24 часа для NOT_FOUND
    VT_NEGATIVE_TTL_429 = 3600        # 1 час для 429

    def get_vt_negative(self, sha256: str, max_age_sec: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Вернуть закэшированный статус NOT_FOUND (404) / 429 для sha256 или None."""
        if max_age_sec is None:
            max_age_sec = self.VT_NEGATIVE_TTL_404
        return self.get(self.SOURCE_VT_NEGATIVE, sha256, max_age_sec)

    def put_vt_negative(self, sha256: str, status: str, ttl_sec: Optional[int] = None) -> None:
        """Записать статус NOT_FOUND (404) или 429. NOT_FOUND хранится 24 часа."""
        data = {"status": status, "sha256": sha256}
        self.put(self.SOURCE_VT_NEGATIVE, sha256, data)
