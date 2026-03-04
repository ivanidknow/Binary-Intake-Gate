# tauri_webview.py — T1027.006: детекция упакованных ресурсов (assets) с обфусцированным JS (Tauri/WebView smuggling)

from __future__ import annotations
import math
from pathlib import Path
from typing import Dict, Any, List

# Порог энтропии для «обфусцированный JS»
OBFUSCATED_JS_ENTROPY = 6.5
# Пути, типичные для Tauri/WebView (assets с JS)
ASSETS_JS_PATTERNS = ("assets/", "resources/", "www/", "app/", "dist/")
TAURI_WRY_HINTS = (b"tauri", b"wry", b"__TAURI__", b"window.__TAURI__")


def _shannon_entropy(data: bytes) -> float:
    if not data or len(data) < 32:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    ent = 0.0
    for c in freq:
        if c == 0:
            continue
        p = c / total
        ent -= p * math.log2(p)
    return round(ent, 3)


def analyze_archive_for_tauri_webview(
    path: Path,
    max_entries: int = 500,
    max_js_size: int = 512 * 1024,
) -> Dict[str, Any]:
    """
    Проверяет архив (ZIP/JAR/…) на наличие путей assets/*.js или resources/*.js
    с высокой энтропией (признак обфусцированного JS для сборки малвари). T1027.006.
    """
    result: Dict[str, Any] = {
        "detected": False,
        "mitre": "T1027.006",
        "assets_js_high_entropy": [],
        "tauri_wry_hints": False,
    }
    try:
        import zipfile
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()[:max_entries]
            for name in names:
                if not name.lower().endswith(".js"):
                    continue
                low = name.lower().replace("\\", "/")
                if not any(p in low for p in ASSETS_JS_PATTERNS):
                    continue
                try:
                    raw = zf.read(name)
                except Exception:
                    continue
                if len(raw) > max_js_size:
                    raw = raw[:max_js_size]
                ent = _shannon_entropy(raw)
                if ent >= OBFUSCATED_JS_ENTROPY:
                    result["assets_js_high_entropy"].append({"path": name, "entropy": ent, "size": len(raw)})
            # Проверка на строки Tauri/Wry в любом файле архива
            for name in names[:100]:
                try:
                    raw = zf.read(name)
                    if any(h in raw for h in TAURI_WRY_HINTS):
                        result["tauri_wry_hints"] = True
                        break
                except Exception:
                    continue
        if result["assets_js_high_entropy"] or result["tauri_wry_hints"]:
            result["detected"] = True
    except Exception:
        pass
    return result
