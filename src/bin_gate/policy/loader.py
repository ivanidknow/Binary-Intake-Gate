
from __future__ import annotations
import pathlib
try:
    import yaml
except Exception:
    yaml = None

def load_policy(path: str | None) -> dict:
    if not path:
        return {"profile":"dev","rules":[]}
    p = pathlib.Path(path)
    if not p.exists():
        return {"profile":"dev","rules":[]}
    if yaml is None:
        return {"profile":"dev","_raw": p.read_text(encoding="utf-8")}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {"profile":"dev","rules":[]}
