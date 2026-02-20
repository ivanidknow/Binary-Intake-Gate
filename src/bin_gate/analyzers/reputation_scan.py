from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import json, unicodedata

# Попытка использовать улучшенный модуль 'regex' (Unicode-границы слов, \p{...}, лучшее поведение).
# Если недоступен — падать не будем, используем стандартный re.
try:
    import regex as RE  # type: ignore
except Exception:  # pragma: no cover
    import re as RE  # type: ignore

# NOTE: старый ASCII-экстрактор больше не используется, но оставлен на случай отката.
# PRINTABLE = set(bytes(range(32, 127))).union({9, 10, 13})  # ASCII printable + \t\r\n


def _norm(s: str) -> str:
    """
    Unicode NFKC → снятие диакритик → lower → схлопывание пробелов.
    ВАЖНО: нормализация применяется и к строкам из файлов, и к имени файла (для filename_norm).
    """
    s = unicodedata.normalize("NFKC", s)
    s = "".join(ch for ch in s if not unicodedata.category(ch).startswith("M"))
    s = s.lower()
    s = RE.sub(r"\s+", " ", s).strip()
    return s


# Валидные UTF-8 codepoint'ы в байтах (без суррогатов, без overlong).
_UTF8_PRINTABLE = (
    rb"[\x09\x0a\x0d\x20-\x7e]"                              # ASCII ws + printable
    rb"|(?:[\xc2-\xdf][\x80-\xbf])"                          # 2-byte UTF-8
    rb"|(?:\xe0[\xa0-\xbf][\x80-\xbf])"                      # 3-byte (no overlong)
    rb"|(?:[\xe1-\xec\xee\xef][\x80-\xbf]{2})"
    rb"|(?:\xed[\x80-\x9f][\x80-\xbf])"                      # no surrogates
    rb"|(?:\xf0[\x90-\xbf][\x80-\xbf]{2})"                   # 4-byte planes
    rb"|(?:[\xf1-\xf3][\x80-\xbf]{3})"
    rb"|(?:\xf4[\x80-\x8f][\x80-\xbf]{2})"
)
_UTF8_SEGMENT_RE = RE.compile(rb"(?:%s){4,}" % _UTF8_PRINTABLE, RE.DOTALL)  # min_len=4 по умолчанию


def _extract_strings_utf8_lines(b: bytes, min_len: int = 4) -> List[Tuple[int, str]]:
    """
    Возвращает список (byte_offset, line_str) по валидным UTF-8 "печатным" подпоследовательностям,
    дополнительно режет их по переводам строки, чтобы не получать гигантские сегменты.

    byte_offset — точное смещение начала ПОДстроки в исходном файле.
    """
    out: List[Tuple[int, str]] = []
    if min_len < 1:
        min_len = 1

    # Найдём крупные UTF-8-последовательности, затем порежем их по CR/LF
    for m in _UTF8_SEGMENT_RE.finditer(b):
        seg_b = m.group(0)
        seg_off = m.start()

        i = 0
        line_start = 0
        n = len(seg_b)

        while i < n:
            by = seg_b[i]
            if by in (10, 13):  # \n or \r
                # Вырезаем строку до переводника
                if i - line_start >= min_len:
                    line_b = seg_b[line_start:i]
                    try:
                        line = line_b.decode("utf-8")
                    except UnicodeDecodeError:
                        line = line_b.decode("utf-8", errors="ignore")
                    if line:
                        out.append((seg_off + line_start, line))
                # Обработка CRLF как одного разделителя
                if by == 13 and i + 1 < n and seg_b[i + 1] == 10:
                    i += 2
                else:
                    i += 1
                line_start = i
            else:
                i += 1

        # Хвост
        if n - line_start >= min_len:
            line_b = seg_b[line_start:n]
            try:
                line = line_b.decode("utf-8")
            except UnicodeDecodeError:
                line = line_b.decode("utf-8", errors="ignore")
            if line:
                out.append((seg_off + line_start, line))

    return out


class _Rule:
    __slots__ = ("id", "category", "severity", "rx", "notes")

    def __init__(self, rid: str, cat: str, sev: str, rx: "RE.Pattern", notes: Optional[str]):
        self.id = rid
        self.category = cat
        self.severity = sev
        self.rx = rx
        self.notes = notes


def _compile_rules(doc: Dict[str, Any]) -> Tuple[List[_Rule], List[str], Dict[str, Any]]:
    errs: List[str] = []
    meta = {"version": int(doc.get("version", 1))}
    rules: List[_Rule] = []

    for i, r in enumerate(doc.get("rules") or []):
        rid = str(r.get("id") or f"rule_{i}")
        cat = str(r.get("category") or "generic")
        sev = str(r.get("severity") or "info").lower()

        flags = 0
        if not r.get("case_sensitive", False):
            flags |= RE.IGNORECASE

        word_boundary = bool(r.get("word_boundary", True))
        patterns: List[str] = []

        # terms → экранируем + опционально оборачиваем в границы слов
        for t in (r.get("terms") or []):
            t = str(t).strip()
            if not t:
                continue
            if word_boundary:
                patterns.append(rf"\b{RE.escape(t)}\b")
            else:
                patterns.append(RE.escape(t))

        # regex → берём как есть
        for rx_src in (r.get("regex") or []):
            patterns.append(str(rx_src))

        if not patterns:
            errs.append(f"reputation_rule_empty:{rid}")
            continue

        try:
            rx = RE.compile("|".join(f"(?:{p})" for p in patterns), flags)
        except Exception as e:
            errs.append(f"reputation_rule_bad_regex:{rid}:{e}")
            continue

        rules.append(_Rule(rid, cat, sev, rx, r.get("notes")))

    return rules, errs, meta


def run_reputation_scan(
    path: Path,
    *,
    rules_doc: Optional[Dict[str, Any]] = None,
    rules_path: Optional[Path] = None,
    max_bytes: int = 20 * 1024 * 1024,
    min_str_len: int = 4,
    context_chars: int = 32,
) -> Dict[str, Any]:
    """
    Возвращает:
    {
      "hits":[
        {
          "rule":"id",
          "category":"cat",
          "severity":"low|med|high|info",
          "where":"filename|filename_norm|strings",
          "offset":123,           # для strings: байтовый оффсет начала строки в файле; для filename* — 0
          "inner":45,             # смещение матча внутри нормализованной строки/имени
          "term":"...match...",   # фактическая подстрока матча
          "context":"...norm..."  # контекст из нормализованной строки (±context_chars)
        }
      ],
      "counts":{"cat":N,...},
      "errors":[...],
      "rules_meta":{"version": ...}
    }
    """
    res: Dict[str, Any] = {"hits": [], "counts": {}, "errors": [], "rules_meta": {}}

    # 1) загрузка правил
    doc = rules_doc
    if doc is None and rules_path:
        try:
            import yaml  # опционально
            doc = (rules_path.read_text(encoding="utf-8"))
            # yaml.safe_load может быть не установлен — fallback на JSON/YAML автодетект
            try:
                import yaml as _yaml  # type: ignore
                doc = _yaml.safe_load(doc) or {}
            except Exception:
                # Попробуем JSON, если это не YAML
                try:
                    doc = json.loads(doc) or {}
                except Exception as e2:
                    res["errors"].append(f"reputation_yaml_error:{e2}")
                    doc = {}
        except Exception as e:
            res["errors"].append(f"reputation_yaml_error:{e}")
            doc = {}

    rules, errs, meta = _compile_rules(doc or {})
    res["errors"].extend(errs)
    res["rules_meta"] = meta

    if not rules:
        return res

    # 2) скан имени файла (сырое и нормализованное)
    fname = path.name
    for rule in rules:
        # Сырое имя (без нормализации)
        for m in rule.rx.finditer(fname):
            span = m.span()
            snippet = fname[max(0, span[0] - context_chars): span[1] + context_chars]
            res["hits"].append({
                "rule": rule.id,
                "category": rule.category,
                "severity": rule.severity,
                "where": "filename",
                "offset": 0,
                "inner": span[0],
                "term": m.group(0),
                "context": snippet
            })
            res["counts"][rule.category] = int(res["counts"].get(rule.category, 0)) + 1

        # Нормализованное имя
        fname_norm = _norm(fname)
        for m in rule.rx.finditer(fname_norm):
            span = m.span()
            snippet = fname_norm[max(0, span[0] - context_chars): span[1] + context_chars]
            res["hits"].append({
                "rule": rule.id,
                "category": rule.category,
                "severity": rule.severity,
                "where": "filename_norm",
                "offset": 0,
                "inner": span[0],
                "term": m.group(0),
                "context": snippet
            })
            res["counts"][rule.category] = int(res["counts"].get(rule.category, 0)) + 1

    # 3) скан строк из бинаря (ограничение по размеру) — UTF-8, построчно, с точным байтовым оффсетом
    try:
        size = path.stat().st_size
        if size <= max_bytes:
            data = path.read_bytes()
            for off, line in _extract_strings_utf8_lines(data, min_len=min_str_len):
                ns = _norm(line)
                if not ns:
                    continue
                for rule in rules:
                    for m in rule.rx.finditer(ns):
                        span = m.span()
                        ctx = ns[max(0, span[0] - context_chars): span[1] + context_chars]
                        res["hits"].append({
                            "rule": rule.id,
                            "category": rule.category,
                            "severity": rule.severity,
                            "where": "strings",
                            "offset": off,     # байтовое смещение начала ЭТОЙ строки в файле
                            "inner": span[0],  # позиция совпадения внутри ns (нормализованной строки)
                            "term": m.group(0),
                            "context": ctx
                        })
                        res["counts"][rule.category] = int(res["counts"].get(rule.category, 0)) + 1
        else:
            res["errors"].append(f"reputation_skipped_large_file:{size}")
    except Exception as e:
        res["errors"].append(f"reputation_read_error:{e}")

    return res
