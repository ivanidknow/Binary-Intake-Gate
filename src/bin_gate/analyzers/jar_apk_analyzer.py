from __future__ import annotations
from pathlib import Path
import zipfile

def analyze(path: Path) -> dict:
    info = {"type": None, "classes_dex": 0, "has_manifest": False, "has_meta_inf": False, "entries": 0}
    p = Path(path)
    try:
        with zipfile.ZipFile(p) as z:
            names = [i.filename for i in z.infolist()]
            info["entries"] = len(names)
    except Exception as e:
        return {"error": str(e)}
    sfx = p.suffix.lower()
    if sfx in (".jar",".war",".ear"): info["type"]="jar"
    elif sfx in (".apk",".aab"): info["type"]="apk"
    elif sfx==".whl": info["type"]="wheel"
    else: info["type"]="zip"
    info["has_manifest"] = ("AndroidManifest.xml" in names) or ("META-INF/MANIFEST.MF" in names)
    info["has_meta_inf"] = any(n.startswith("META-INF/") for n in names)
    info["classes_dex"] = sum(1 for n in names if n.lower().startswith("classes") and n.lower().endswith(".dex"))
    return info
