# src/bin_gate/analyzers/floss_runner.py
from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import os, shutil, subprocess, json, re, math, unicodedata

def _which(expl: Optional[str]) -> Optional[str]:
    if expl and Path(expl).exists():
        return expl
    env = os.getenv("FLOSS_EXE") or os.getenv("FLOSS_BIN")
    if env and Path(env).exists():
        return env
    return shutil.which("floss") or shutil.which("floss.exe")

def _cap_ok(p: Path, max_mb: Optional[int]) -> bool:
    if not max_mb or max_mb <= 0:
        return True
    try:
        return p.stat().st_size <= max_mb * 1024 * 1024
    except Exception:
        return True

# ---------------- IOC (базовые счётчики) ----------------

RE_URL = re.compile(r'(?i)\bhttps?://[^\s"\'<>]+')
RE_IPv4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
CMD_MARKERS = (
    "cmd.exe","powershell","pwsh","wscript","cscript","rundll32","regsvr32",
    "wget ","curl ","bitsadmin","mshta","schtasks","bcdedit","vssadmin"
)

def _count_iocs(strings: List[str]) -> Tuple[int,int,int]:
    urls = ips = cmds = 0
    for s in strings:
        try:
            if RE_URL.search(s): urls += 1
            if RE_IPv4.search(s): ips  += 1
            ls = s.lower()
            if any(m in ls for m in CMD_MARKERS): cmds += 1
        except Exception:
            continue
    return urls, ips, cmds

# ---------------- Парсинг вывода FLOSS ----------------

def _extract_json_from_stdout(out: str) -> Dict[str, Any]:
    """
    FLOSS v3 может писать INFO в stdout перед JSON.
    Пытаемся аккуратно выделить ровно JSON-объект.
    """
    s = out.strip()
    try:
        return json.loads(s)
    except Exception:
        pass
    start = s.find("{")
    if start == -1:
        raise ValueError("no JSON object found in stdout")
    tail = s[start:]
    end = tail.rfind("}")
    if end == -1:
        raise ValueError("unterminated JSON in stdout")
    j = tail[:end+1]
    return json.loads(j)

def _pull_list(arr) -> List[str]:
    if not isinstance(arr, list):
        return []
    res = []
    for x in arr:
        if isinstance(x, dict):
            for k in ("string", "value", "s", "str"):
                if k in x:
                    res.append(str(x.get(k, "")))
                    break
        elif isinstance(x, str):
            res.append(x)
    return res

def _parse_json(doc: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Унифицированный вытягиватель для разных схем FLOSS (v2/v3).
    Возвращает {"decoded": [...], "stack": [...], "static": [...], "tight": [...]}
    """
    out = {"decoded": [], "stack": [], "static": [], "tight": []}
    srcs: List[Dict[str, Any]] = []
    if isinstance(doc.get("strings"), dict):
        srcs.append(doc["strings"])
    srcs.append(doc)  # на случай, если ключи на верхнем уровне

    for src in srcs:
        got = False
        if any(k in src for k in ("decoded_strings","stack_strings","static_strings","tight_strings")):
            out["decoded"] = _pull_list(src.get("decoded_strings", [])) or out["decoded"]
            out["stack"]   = _pull_list(src.get("stack_strings", []))   or out["stack"]
            out["static"]  = _pull_list(src.get("static_strings", []))  or out["static"]
            out["tight"]   = _pull_list(src.get("tight_strings", []))   or out["tight"]
            got = True
        if any(k in src for k in ("decoded","stack","static","tight")):
            out["decoded"] = _pull_list(src.get("decoded", [])) or out["decoded"]
            out["stack"]   = _pull_list(src.get("stack", []))   or out["stack"]
            out["static"]  = _pull_list(src.get("static", []))  or out["static"]
            out["tight"]   = _pull_list(src.get("tight", []))   or out["tight"]
            got = True
        if got and (out["decoded"] or out["stack"] or out["static"] or out["tight"]):
            break
    return out

def _parse_plain(txt: str) -> Dict[str, List[str]]:
    """
    Plain-режим: отбрасываем лог-строки и прогресс, собираем секции.
    """
    out = {"decoded": [], "stack": [], "static": [], "tight": []}
    sec: Optional[str] = None
    for raw in txt.splitlines():
        line = raw.strip()
        low = line.lower()
        if not line:
            continue
        # выкинем шум FLOSS/rich/progress
        if low.startswith("info:") or "functions/s" in low or "100%" in low or "extracting " in low or "emulating function" in low:
            continue
        if line.startswith("---") or line.startswith("===") or low.startswith("floss "):
            continue
        # заголовки секций
        if "decoded strings" in low:
            sec = "decoded"; continue
        if "stack strings" in low:
            sec = "stack"; continue
        if "static strings" in low:
            sec = "static"; continue
        if "tight strings"  in low or "tightstrings" in low:
            sec = "tight"; continue
        bucket = sec if sec in out else "static"
        out[bucket].append(line)
    return out

# ---------------- Поиск секретов ----------------

# Общие шаблоны
RE_EMAIL  = re.compile(r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b')
RE_DOMAIN = re.compile(r'(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b')
RE_IPv6   = re.compile(r'\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b', re.I)

# Токены / ключи / креды
RE_JWT        = re.compile(r'\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}\b')
RE_AWS_AK     = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
RE_AWS_SECRET = re.compile(r'(?i)\baws[_-]?secret[_-]?access[_-]?key\b.{0,40}?[\'":=]\s*([A-Za-z0-9/+=]{30,})')
RE_GCP_API    = re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')
RE_STRIPE_SK  = re.compile(r'\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b')
RE_STRIPE_PK  = re.compile(r'\bpk_(?:live|test)_[A-Za-z0-9]{20,}\b')
RE_GITHUB_PAT = re.compile(r'\bgh[pousr]_[A-Za-z0-9]{30,}\b')      # ghp_/gho_/...
RE_GITLAB_PAT = re.compile(r'\bglpat-[A-Za-z0-9_-]{20,}\b')
RE_DISCORD    = re.compile(r'\b[mM][A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}\b')  # грубо
RE_SLACK      = re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b')
RE_TELEGRAM   = re.compile(r'\b\d{6,}:[A-Za-z0-9_-]{30,}\b')
RE_BEARER     = re.compile(r'(?i)\bAuthorization:\s*Bearer\s+[A-Za-z0-9._\-]{20,}\b')
RE_BASIC      = re.compile(r'(?i)\bAuthorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}\b')
RE_RSA_PRIV   = re.compile(r'-----BEGIN (?:RSA|EC|DSA)? ?PRIVATE KEY-----')
RE_SSH_PRIV   = re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----')

# «base64-подобная» и высокая энтропия — кандидаты на секреты
RE_BASE64ISH  = re.compile(r'^[A-Za-z0-9+/=]{20,}$')

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    ln = float(len(s))
    for c in freq.values():
        p = c / ln
        ent -= p * (math.log(p, 2))
    return ent

def _mask(s: str, left: int = 4, right: int = 4) -> str:
    try:
        if len(s) <= left + right + 2:
            return s
        return f"{s[:left]}…{s[-right:]}"
    except Exception:
        return s

def _find_secrets(strings: List[str]) -> Dict[str, Any]:
    """
    Находит и маскирует чувствительные шаблоны.
    """
    kinds = {
        "email": RE_EMAIL,
        "domain": RE_DOMAIN,
        "ipv6": RE_IPv6,
        "jwt": RE_JWT,
        "aws_access_key": RE_AWS_AK,
        "aws_secret_key": RE_AWS_SECRET,   # group(1)
        "gcp_api_key": RE_GCP_API,
        "stripe_sk": RE_STRIPE_SK,
        "stripe_pk": RE_STRIPE_PK,
        "github_pat": RE_GITHUB_PAT,
        "gitlab_pat": RE_GITLAB_PAT,
        "discord_token": RE_DISCORD,
        "slack_token": RE_SLACK,
        "telegram_bot_token": RE_TELEGRAM,
        "auth_bearer": RE_BEARER,
        "auth_basic": RE_BASIC,
        "rsa_private_key": RE_RSA_PRIV,
        "ssh_private_key": RE_SSH_PRIV,
    }

    counts: Dict[str, int] = {k: 0 for k in kinds.keys()}
    samples: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    seen: set = set()

    for s in strings:
        ls = s if isinstance(s, str) else str(s)

        for kind, rx in kinds.items():
            try:
                for m in rx.finditer(ls):
                    raw = m.group(1) if (kind == "aws_secret_key" and m.groups()) else m.group(0)
                    key = (kind, raw)
                    if key in seen:
                        continue
                    seen.add(key)
                    counts[kind] += 1
                    if kind in ("rsa_private_key", "ssh_private_key"):
                        masked = raw.splitlines()[0].strip()
                    else:
                        masked = _mask(raw, 4, 4)
                    samples.append({"kind": kind, "match": masked, "raw_len": len(raw)})
            except Exception:
                continue

        # high-entropy кандидаты: base64ish и H>=3.5 (грубо)
        try:
            st = ls.strip().strip('"').strip("'")
            if 20 <= len(st) <= 256 and RE_BASE64ISH.match(st):
                H = _shannon_entropy(st)
                if H >= 3.5:
                    masked = _mask(st, 6, 6)
                    key = ("high_entropy", masked)
                    if key not in seen:
                        seen.add(key)
                        candidates.append({"kind": "high_entropy", "match": masked, "entropy": round(H, 2), "raw_len": len(st)})
        except Exception:
            pass

    samples = samples[:50]
    candidates = candidates[:30]
    return {"counts": counts, "samples": samples, "candidates": candidates}

# ---------------- Репутационные правила (встроено) ----------------

def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKC", s)
    s = "".join(ch for ch in s if not unicodedata.category(ch).startswith("M"))
    s = s.lower()
    s = re.sub(r"\s+", " ", s).strip()
    return s

class _RepRule:
    __slots__ = ("id","category","severity","rx","notes")
    def __init__(self, rid: str, cat: str, sev: str, rx: re.Pattern, notes: Optional[str]):
        self.id = rid; self.category = cat; self.severity = sev; self.rx = rx; self.notes = notes

def _compile_rep_rules(doc: Dict[str, Any]) -> Tuple[List[_RepRule], List[str], Dict[str, Any]]:
    errs: List[str] = []
    meta = {"version": int(doc.get("version", 1))}
    rules: List[_RepRule] = []
    for i, r in enumerate(doc.get("rules") or []):
        rid = str(r.get("id") or f"rule_{i}")
        cat = str(r.get("category") or "generic")
        sev = str(r.get("severity") or "info").lower()
        flags = 0
        if not r.get("case_sensitive", False):
            flags |= re.IGNORECASE
        patterns: List[str] = []
        for t in (r.get("terms") or []):
            t = str(t).strip()
            if not t:
                continue
            if r.get("word_boundary", True):
                patterns.append(rf"\b{re.escape(t)}\b")
            else:
                patterns.append(re.escape(t))
        for rx in (r.get("regex") or []):
            patterns.append(str(rx))
        if not patterns:
            errs.append(f"reputation_rule_empty:{rid}")
            continue
        try:
            rx = re.compile("|".join(f"(?:{p})" for p in patterns), flags)
        except Exception as e:
            errs.append(f"reputation_rule_bad_regex:{rid}:{e}")
            continue
        rules.append(_RepRule(rid, cat, sev, rx, r.get("notes")))
    return rules, errs, meta

def _apply_rep_to_sources(
    rules: List[_RepRule],
    sources: Dict[str, List[str]],
    *,
    context_chars: int = 32
) -> Dict[str, Any]:
    res: Dict[str, Any] = {"hits": [], "counts": {}}
    for src_name, arr in sources.items():
        seen: set = set()
        for idx, s in enumerate(arr or []):
            ns = _norm(str(s))
            if not ns:
                continue
            # немного застрахуемся от дубликатов
            if (src_name, ns) in seen:
                continue
            seen.add((src_name, ns))
            for rule in rules:
                for m in rule.rx.finditer(ns):
                    span = m.span()
                    snippet = ns[max(0, span[0]-context_chars): span[1]+context_chars]
                    res["hits"].append({
                        "rule": rule.id,
                        "category": rule.category,
                        "severity": rule.severity,
                        "where": src_name,       # floss.decoded | floss.stack | ...
                        "offset": idx,           # индекс строки в ведре
                        "term": m.group(0),
                        "context": snippet
                    })
                    res["counts"][rule.category] = int(res["counts"].get(rule.category, 0)) + 1
    # агрегаты
    try:
        findings = sorted(set(h["rule"] for h in res["hits"]))
        categories = sorted(k for k, v in res["counts"].items() if int(v or 0) > 0)
    except Exception:
        findings, categories = [], []
    res["findings"] = findings
    res["categories"] = categories
    return res

# ---------------- Основная функция ----------------

def run_floss(
    path: Path,
    *,
    floss_bin: Optional[str] = None,
    timeout_sec: int = 120,   # было 60 — увеличено: твои прогоны ~52s
    min_len: int = 4,
    max_mb: Optional[int] = 16,
    # Новое: репутационные правила, применяемые к FLOSS-строкам
    reputation_rules_doc: Optional[Dict[str, Any]] = None,
    reputation_rules_path: Optional[Path] = None,
    rep_context_chars: int = 32,
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Возвращает (doc, errs), где doc =
    {
      "strings": {"decoded":[...], "stack":[...], "static":[...], "tight":[...]},
      "summary": {
        "total_cnt": N, "decoded_cnt": d, "stack_cnt": s, "static_cnt": st, "tight_cnt": tt,
        "url_cnt": u, "ip_cnt": i, "cmd_cnt": c,
        "email_cnt": e, "domain_cnt": dmn, "ipv6_cnt": v6,
        "secrets_total": S
      },
      "secrets": {"counts":{...}, "samples":[...], "candidates":[...]},
      "reputation": {                # ← НОВОЕ: проверка FLOSS-строк по политике
         "hits":[{rule,category,severity,where,offset,term,context}],
         "counts":{"cat":N,...},
         "findings":[rule_id,...],
         "categories":[cat1,cat2,...],
         "rules_meta":{"version":...},
         "errors":[...]
      }
    }
    """
    errs: List[str] = []
    empty_doc = {
        "strings":{"decoded":[],"stack":[],"static":[],"tight":[]},
        "summary":{
            "total_cnt":0,"decoded_cnt":0,"stack_cnt":0,"static_cnt":0,"tight_cnt":0,
            "url_cnt":0,"ip_cnt":0,"cmd_cnt":0,
            "email_cnt":0,"domain_cnt":0,"ipv6_cnt":0,
            "secrets_total":0
        },
        "secrets":{"counts":{}, "samples":[], "candidates":[]},
        "reputation":{"hits":[], "counts":{}, "findings":[], "categories":[], "rules_meta":{}, "errors":[]}
    }

    if not _cap_ok(path, max_mb):
        return empty_doc, errs

    exe = _which(floss_bin)
    if not exe:
        return empty_doc, ["floss_not_found"]

    tries = [
        [exe, "-q", "-j", "-n", str(min_len), str(path)],
        [exe, "-q", "-j", str(path)],
        [exe,      "-j", "-n", str(min_len), str(path)],
        [exe,      "-j", str(path)],
        [exe, "-n", str(min_len), str(path)],               # plain (с заголовками секций)
        [exe, str(path)],
        [exe, "-q", "-n", str(min_len), str(path)],         # quiet plain
        [exe, "-q", str(path)],
    ]

    decoded: List[str] = []
    stack:   List[str] = []
    static:  List[str] = []
    tight:   List[str] = []

    for cmd in tries:
        is_json_mode = ("-j" in cmd)
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout_sec, encoding="utf-8", errors="ignore")
        except subprocess.TimeoutExpired:
            errs.append("floss_timeout"); continue
        except Exception as e:
            errs.append(f"floss_spawn_error:{e}"); continue

        out, err, rc = (p.stdout or ""), (p.stderr or ""), int(p.returncode or 0)

        if os.getenv("BIN_GATE_FLOSS_DEBUG"):
            dbg_dir = Path(os.getenv("BIN_GATE_DEBUG_DIR", ".bin_gate_debug"))
            try:
                dbg_dir.mkdir(parents=True, exist_ok=True)
                suffix = "json" if is_json_mode else "txt"
                (dbg_dir / f"{path.name}.floss.{suffix}").write_text(out, encoding="utf-8", errors="ignore")
                if err.strip():
                    (dbg_dir / f"{path.name}.floss.stderr.txt").write_text(err, encoding="utf-8", errors="ignore")
            except Exception:
                pass

        if rc != 0 and not is_json_mode:
            if err.strip():
                errs.append(f"floss_rc={rc}:{err.strip()[:200]}")
            else:
                errs.append(f"floss_rc={rc}:no_stderr")
            continue

        if is_json_mode:
            try:
                doc = _extract_json_from_stdout(out)
                bags = _parse_json(doc)
                decoded, stack, static, tight = bags["decoded"], bags["stack"], bags["static"], bags["tight"]
                if decoded or stack or static or tight:
                    break
                continue
            except Exception as e:
                errs.append(f"floss_json_error:{e} | stderr={err.strip()[:200]}")
                continue
        else:
            bags = _parse_plain(out)
            decoded, stack, static, tight = bags["decoded"], bags["stack"], bags["static"], bags["tight"]
            if decoded or stack or static or tight:
                break
            if err.strip():
                errs.append(f"floss_stderr:{err.strip()[:200]}")

    # подрежем размер, чтобы не раздувать evidence
    def _trim(a: List[str], cap=500) -> List[str]:
        return a[:cap] if len(a) > cap else a

    decoded = _trim(decoded)
    stack   = _trim(stack)
    static  = _trim(static)
    tight   = _trim(tight)

    total = len(decoded) + len(stack) + len(static) + len(tight)
    urls_d, ips_d, cmds_d = _count_iocs(decoded)
    urls_s, ips_s, cmds_s = _count_iocs(stack)
    urls_t, ips_t, cmds_t = _count_iocs(static)
    urls_tt, ips_tt, cmds_tt = _count_iocs(tight)

    # ---- Расширенный поиск секретов по всем строкам ----
    all_strings = decoded + stack + static + tight
    secrets = _find_secrets(all_strings)

    # агрегируем дополнительные счётчики (email/domain/ipv6)
    email_cnt = secrets["counts"].get("email", 0)
    domain_cnt = secrets["counts"].get("domain", 0)
    ipv6_cnt = secrets["counts"].get("ipv6", 0)
    secrets_total = sum(secrets["counts"].values())

    doc_out: Dict[str, Any] = {
        "strings": {
            "decoded": decoded,
            "stack": stack,
            "static": static,
            "tight": tight,
        },
        "summary": {
            "total_cnt": total,
            "decoded_cnt": len(decoded),
            "stack_cnt": len(stack),
            "static_cnt": len(static),
            "tight_cnt": len(tight),
            "url_cnt": urls_d + urls_s + urls_t + urls_tt,
            "ip_cnt":  ips_d  + ips_s  + ips_t  + ips_tt,
            "cmd_cnt": cmds_d + cmds_s + cmds_t + cmds_tt,
            "email_cnt": email_cnt,
            "domain_cnt": domain_cnt,
            "ipv6_cnt": ipv6_cnt,
            "secrets_total": secrets_total,
        },
        "secrets": secrets,
        "reputation": {"hits":[], "counts":{}, "findings":[], "categories":[], "rules_meta":{}, "errors":[]}
    }

    # ---- Репутационные проверки по политике на FLOSS-строках (опционально) ----
    rep_errors: List[str] = []
    if reputation_rules_doc is not None or reputation_rules_path is not None:
        # загрузка YAML при необходимости
        rules_doc: Dict[str, Any] = {}
        if reputation_rules_doc is not None:
            rules_doc = reputation_rules_doc or {}
        elif reputation_rules_path is not None:
            try:
                import yaml
                rules_doc = yaml.safe_load(Path(reputation_rules_path).read_text(encoding="utf-8")) or {}
            except Exception as e:
                rep_errors.append(f"reputation_yaml_error:{e}")
                rules_doc = {}

        rules, comp_errs, meta = _compile_rep_rules(rules_doc or {})
        rep_errors.extend(comp_errs)

        if rules:
            sources = {
                "floss.decoded": decoded,
                "floss.stack":   stack,
                "floss.static":  static,
                "floss.tight":   tight,
            }
            rep_res = _apply_rep_to_sources(rules, sources, context_chars=rep_context_chars)
            rep_res["rules_meta"] = meta
            rep_res["errors"] = rep_errors
            doc_out["reputation"] = rep_res
        else:
            doc_out["reputation"]["errors"] = rep_errors

    return doc_out, errs
