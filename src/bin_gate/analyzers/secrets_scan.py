"""
Сканирование секретов: Gitleaks (Docker) с fallback на встроенные regex.
Результат в формате evidence.secrets: hits, suspicious, score (обратная совместимость со Scoring Engine).
"""
from __future__ import annotations
from pathlib import Path
import base64
import json
import os
import re
import subprocess
from typing import Dict, Any, List

# Максимальный размер декодированного Base64 для сканирования (байт)
_BASE64_DECODE_MAX = 65536

REGEXES = {
    "aws_access_key_id": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "aws_secret_access_key": re.compile(rb"(?i)aws_secret_access_key\s*[:=]\s*([A-Za-z0-9/+=]{32,})"),
    "github_token": re.compile(rb"ghp_[A-Za-z0-9]{36}"),
    "slack_token": re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,48}"),
    "discord_webhook": re.compile(rb"https?://(?:canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{6,}/[A-Za-z0-9_\-]{20,}"),
    "telegram_token": re.compile(rb"https?://api\.telegram\.org/bot[0-9]{8,10}:[A-Za-z0-9_\-]{35,}"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"),
}

GITLEAKS_IMAGE = "zricethezav/gitleaks:latest"


def _gitleaks_report_path() -> Path:
    """Путь к файлу отчёта Gitleaks: BIN_GATE_GITLEAKS_OUT или .gitleaks_out в cwd (права 0777 для контейнера)."""
    out_env = os.environ.get("BIN_GATE_GITLEAKS_OUT", "").strip()
    if out_env:
        base = Path(out_env)
    else:
        base = Path(os.environ.get("BIN_GATE_PROJECT_ROOT", os.getcwd())) / ".gitleaks_out"
    base.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(base, 0o777)
    except Exception:
        pass
    return base / "report.json"


def _log_gitleaks_failure(message: str, stdout: str = "", stderr: str = "") -> None:
    """Пишет в cli_debug.log причину сбоя Gitleaks (в т.ч. вывод контейнера)."""
    try:
        log_path = Path(os.environ.get("BIN_GATE_PROJECT_ROOT", os.getcwd())) / "cli_debug.log"
        with open(log_path, "a", encoding="utf-8", errors="replace") as f:
            f.write(f"\n[gitleaks] {message}\n")
            if stdout:
                f.write(f"[gitleaks stdout]\n{stdout[:2000]}\n")
            if stderr:
                f.write(f"[gitleaks stderr]\n{stderr[:2000]}\n")
    except Exception:
        pass


def run_gitleaks_scan(target_path: Path, timeout_sec: int = 60) -> Dict[str, Any]:
    """
    Запуск Gitleaks в Docker: сканирование директории (файла) и парсинг JSON-отчёта.
    Отчёт пишется в один файл в корне проекта (.tmp_gitleaks_report.json), чтобы избежать
    Permission denied при монтировании Windows Temp в контейнер.
    Возвращает {"hits": {rule_id: [match_str, ...]}, "suspicious": bool, "score": int} или {"error": str}.
    """
    path = Path(target_path)
    if not path.exists():
        return {"error": "path_not_found"}
    if path.is_file():
        scan_dir = path.parent
    else:
        scan_dir = path
    report_path = _gitleaks_report_path()
    base = report_path.parent
    try:
        report_path.touch(exist_ok=True)
        os.chmod(report_path, 0o666)
    except Exception:
        pass
    report_name = report_path.name
    try:
        # Исходники только для чтения; отчёт в /out (base с правами 0777) — избегаем Permission denied в контейнере
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{scan_dir.resolve()}:/scan:ro",
            "-v", f"{base.resolve()}:/out:rw",
            GITLEAKS_IMAGE,
            "detect", "--source", "/scan", "--no-git",
            "--report-format", "json", "--report-path", f"/out/{report_name}",
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        if not report_path.exists():
            stderr = (result.stderr or "") if hasattr(result, "stderr") else ""
            stdout = (result.stdout or "") if hasattr(result, "stdout") else ""
            _log_gitleaks_failure(
                "report file not created (Permission denied or container error)",
                stdout=stdout,
                stderr=stderr,
            )
            return {"hits": {}, "suspicious": False, "score": 0}
        try:
            if report_path.stat().st_size == 0:
                return {"hits": {}, "suspicious": False, "score": 0}
            raw = report_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError) as e:
            _log_gitleaks_failure(f"report file not readable: {e}")
            return {"hits": {}, "suspicious": False, "score": 0}
        try:
            report_path.unlink(missing_ok=True)
        except Exception:
            pass
        raw_stripped = raw.strip()
        if not raw_stripped or (not raw_stripped.startswith("[") and not raw_stripped.startswith("{")):
            return {"hits": {}, "suspicious": False, "score": 0}
        try:
            data = json.loads(raw_stripped)
        except json.JSONDecodeError:
            return {"hits": {}, "suspicious": False, "score": 0}
        if not isinstance(data, list):
            data = data.get("findings", data) if isinstance(data, dict) else []
        if not isinstance(data, list):
            return {"hits": {}, "suspicious": False, "score": 0}
        hits: Dict[str, List[str]] = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            rule_id = (item.get("RuleID") or item.get("ruleID") or "secret").strip()
            if not rule_id:
                rule_id = "secret"
            match_val = (item.get("Match") or item.get("Secret") or item.get("Finding") or "")
            if isinstance(match_val, str) and match_val:
                match_val = match_val[:120]
            else:
                match_val = str(match_val)[:120]
            if rule_id not in hits:
                hits[rule_id] = []
            if match_val and match_val not in hits[rule_id]:
                hits[rule_id].append(match_val)
        for k in hits:
            hits[k] = hits[k][:5]
        score = 5 * len(hits)
        return {"hits": hits, "suspicious": bool(hits), "score": min(100, score)}
    except subprocess.TimeoutExpired:
        _log_gitleaks_failure("gitleaks_timeout")
        return {"error": "gitleaks_timeout"}
    except FileNotFoundError:
        return {"error": "docker_not_found"}
    except json.JSONDecodeError as e:
        _log_gitleaks_failure(f"gitleaks_json_error: {e}")
        return {"error": f"gitleaks_json_error:{e}"}
    except Exception as e:
        err_msg = str(e)
        _log_gitleaks_failure(err_msg)
        if hasattr(e, "result") and getattr(e.result, "stderr", None):
            _log_gitleaks_failure("(container stderr)", stderr=e.result.stderr)
        return {"error": err_msg}


def _read_file_with_overlay(path: Path, max_bytes: int = 5 * 1024 * 1024, overlay_tail: int = 256 * 1024) -> bytes:
    """
    Читает файл так, чтобы обязательно захватить оверлей (секреты часто в конце PE).
    Для PE: первые max_bytes и хвост overlay_tail; иначе — целиком до max_bytes.
    """
    try:
        size = path.stat().st_size
    except Exception:
        return path.read_bytes()[:max_bytes]
    if size <= max_bytes:
        return path.read_bytes()
    data_head = path.read_bytes()[:max_bytes]
    if size <= max_bytes + overlay_tail:
        return data_head + path.read_bytes()[max_bytes:]
    with path.open("rb") as f:
        f.seek(-overlay_tail, 2)
        data_tail = f.read()
    return data_head + data_tail


def _decode_base64_chunks(data: bytes, max_decoded: int = _BASE64_DECODE_MAX) -> bytes:
    """Извлекает Base64-подобные последовательности и возвращает декодированные байты (ограничено max_decoded)."""
    # Паттерн: последовательности из A-Za-z0-9+/= длиной от 20
    b64_pat = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")
    out: List[bytes] = []
    total = 0
    for m in b64_pat.finditer(data):
        if total >= max_decoded:
            break
        try:
            decoded = base64.b64decode(m.group(0), validate=True)
            if 4 <= len(decoded) <= 4096:
                out.append(decoded)
                total += len(decoded)
        except Exception:
            pass
    return b"".join(out)[:max_decoded]


def _analyze_regex(path: Path, max_bytes: int = 5 * 1024 * 1024) -> dict:
    """Встроенный regex-скан (fallback). Сканирует весь файл, PE-оверлей и декодированный Base64."""
    out = {"hits": {}, "suspicious": False, "score": 0}
    try:
        data = _read_file_with_overlay(path, max_bytes=max_bytes)
    except Exception as e:
        return {"error": str(e)}
    for name, rx in REGEXES.items():
        hits = [m.group(0).decode(errors="ignore")[:120] for m in rx.finditer(data)]
        if hits:
            out["hits"].setdefault(name, []).extend(hits[:5])
    # Сканирование декодированного Base64 (секреты часто кодируют)
    try:
        b64_decoded = _decode_base64_chunks(data)
        if b64_decoded:
            for name, rx in REGEXES.items():
                for m in rx.finditer(b64_decoded):
                    val = m.group(0).decode(errors="ignore")[:120]
                    if name not in out["hits"] or val not in out["hits"][name]:
                        out["hits"].setdefault(name, []).append(val)
                        if len(out["hits"][name]) > 5:
                            out["hits"][name] = out["hits"][name][:5]
    except Exception:
        pass
    for k in list(out["hits"]):
        out["hits"][k] = out["hits"][k][:5]
    out["suspicious"] = bool(out["hits"])
    out["score"] = min(100, 5 * len(out["hits"]))
    return out


def analyze(path: Path, max_bytes: int = 5 * 1024 * 1024, use_gitleaks: bool = True) -> dict:
    """
    Единая точка входа: при use_gitleaks=True вызывается run_gitleaks_scan; при ошибке или
    пустом результате — встроенный regex (в т.ч. по PE-оверлею). Результат всегда в формате
    evidence.secrets: hits, suspicious, score.
    """
    p = Path(path)
    if use_gitleaks and os.getenv("BIN_GATE_GITLEAKS", "1") == "1":
        gitleaks_result = run_gitleaks_scan(p)
        if "error" not in gitleaks_result and gitleaks_result.get("hits"):
            return gitleaks_result
    return _analyze_regex(p, max_bytes)
