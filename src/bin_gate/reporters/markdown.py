from __future__ import annotations
import pathlib, datetime, json
from collections import Counter, defaultdict
from pathlib import Path as _Path
from pathlib import Path
from typing import List, Dict, Any
from collections import Counter, defaultdict
HEADER = "# Binary Intake Gate — Report (Stage 4)\n\n_Base analyzers: hashes, entropy, PE/ELF hardening, capa, YARA. Integrations: VT (lookup/upload), SQLite cache. Policy engine with profiles._"


def _msi_source_line(meta: dict) -> str | None:
    c = (meta or {}).get("container") or {}
    if c.get("type") != "msi":
        return None
    from pathlib import Path as _P
    msi_name = _P(c.get("path", "")).name
    pn = c.get("ProductName") or "—"
    pv = c.get("ProductVersion") or ""
    pc = c.get("ProductCode") or "—"
    mf = c.get("Manufacturer") or "—"
    return f"- Source: MSI `{msi_name}` — {pn} {pv}; ProductCode={pc}; Manufacturer={mf}"

# src/bin_gate/reporters/markdown.py


def write_markdown_report(
    out_path: Path,
    files: List[Path],
    summary: Dict[str, Any],
    policy: Dict[str, Any],
    *,
    evidences: List[Dict[str, Any]],
    merge_msis: bool = False,
    merge_top: int = 12,
    compact: bool = False,
) -> None:
    """
    Короткий Markdown-отчёт.
    Поддерживает:
      - merge_msis=True — агрегировать содержимое MSI в один блок;
      - compact=True    — без перечислений файлов, только сводные итоги.
    Совместим с вызовом из cli.py.
    """

    def _get(d: Dict[str, Any], path: str, default=None):
        cur = d
        for p in path.split("."):
            if not isinstance(cur, dict):
                return default
            cur = cur.get(p)
        return cur if cur is not None else default

    def _container(ev: Dict[str, Any]) -> Dict[str, Any] | None:
        return (ev.get("meta") or {}).get("container") or None

    def _kind(ev: Dict[str, Any]) -> str:
        if ev.get("pe"):  return "PE"
        if ev.get("elf"): return "ELF"
        return "EXT"

    def _basename(p: str | None) -> str:
        try:
            return Path(p).name
        except Exception:
            return str(p or "")

    def _vt_stats(vt: Dict[str, Any] | None) -> Dict[str, int]:
        vt = vt or {}
        # ищем агрегат где угодно
        for p in ("stats",
                  "detections.stats",
                  "summary.stats",
                  "data.attributes.last_analysis_stats",
                  "attributes.last_analysis_stats",
                  "last_analysis_stats"):
            st = _get(vt, p, None)
            if isinstance(st, dict) and ("malicious" in st or "suspicious" in st):
                return {
                    "m": int(st.get("malicious") or 0),
                    "s": int(st.get("suspicious") or 0),
                    "h": int(st.get("harmless") or 0),
                    "u": int(st.get("undetected") or 0),
                }
        # посчитать из last_analysis_results, если нужно
        results = _get(vt, "data.attributes.last_analysis_results", {}) or \
                  _get(vt, "attributes.last_analysis_results", {}) or \
                  _get(vt, "last_analysis_results", {}) or {}
        agg = {"malicious":0, "suspicious":0, "harmless":0, "undetected":0}
        if isinstance(results, dict) and results:
            for obj in results.values():
                cat = str((obj or {}).get("category") or "").lower()
                if cat in agg: agg[cat] += 1
        return {
            "m": agg["malicious"], "s": agg["suspicious"],
            "h": agg["harmless"],  "u": agg["undetected"],
        }

    def _worst_decision(evs: List[Dict[str, Any]]):
        rank = {"allow":0, "warn":1, "deny":2}
        worst, max_sc = "allow", 0
        cnt = Counter()
        reasons: list[str] = []
        for ev in evs:
            pol = ev.get("policy") or {}
            dec = (pol.get("decision") or "allow").lower()
            sc  = int(pol.get("score") or 0)
            if rank.get(dec,0) > rank.get(worst,0): worst = dec
            if sc > max_sc: max_sc = sc
            cnt[dec] += 1
            for r in (pol.get("reasons") or []):
                s = str(r)
                if "policy_eval_error:" not in s:
                    reasons.append(s)
        # уникализировать причины, но в compact мы их не печатаем
        reasons = list(dict.fromkeys(reasons))
        return worst, max_sc, cnt, reasons

    # --- заголовок
    stage = summary.get("stage", "5")
    gen   = summary.get("generated") or ""
    prof  = policy.get("profile") or summary.get("profile") or "dev"

    # ===== ВАРИАНТ 1: merge_msis + compact =====
    if merge_msis and compact:
        groups: dict[str, list[Dict[str, Any]]] = defaultdict(list)
        singles: list[Dict[str, Any]] = []
        meta_map: dict[str, dict] = {}

        for ev in evidences:
            cont = _container(ev)
            if cont and cont.get("type") == "msi":
                key = cont.get("path") or cont.get("name") or "MSI"
                meta_map[key] = cont
                groups[key].append(ev)
            else:
                singles.append(ev)

        lines: list[str] = []
        lines.append(f"# Binary Intake Gate — Report (Stage {stage})")
        lines.append("")
        lines.append(f"- Generated: **{gen}**")
        lines.append(f"- Profile: **{prof}**")
        lines.append(f"- Containers (MSI): **{len(groups)}**, Singles: **{len(singles)}**, Files scanned: **{len(evidences)}**")
        lines.append("")
        lines.append("## Итог по MSI контейнерам")

        for msi_path, kids in groups.items():
            title = (meta_map.get(msi_path, {}).get("ProductName") or "") + \
                    (" " + meta_map[msi_path].get("ProductVersion") if meta_map.get(msi_path, {}).get("ProductVersion") else "")
            title = title.strip() or _basename(msi_path)
            kinds = Counter(_kind(ev) for ev in kids)
            worst, max_sc, cnt, _ = _worst_decision(kids)
            vt_sum = Counter()
            for ev in kids:
                st = _vt_stats(ev.get("vt"))
                vt_sum.update({"m":st["m"], "s":st["s"], "h":st["h"], "u":st["u"]})
            lines.append(
                f"- **{title}** ({_basename(msi_path)}): "
                f"policy={worst} (max score={max_sc}, deny={cnt['deny']}, warn={cnt['warn']}), "
                f"VT m/s/h/u={vt_sum['m']}/{vt_sum['s']}/{vt_sum['h']}/{vt_sum['u']}, "
                f"files={len(kids)} (PE={kinds['PE']}, ELF={kinds['ELF']}, EXT={kinds['EXT']})"
            )

        # общий итог по контейнерам
        overall = "deny" if any((ev.get("policy") or {}).get("decision") == "deny"
                                for kids in groups.values() for ev in kids) \
                  else ("warn" if any((ev.get("policy") or {}).get("decision") == "warn"
                                      for kids in groups.values() for ev in kids) else "allow")
        lines.append("")
        lines.append("## Вывод")
        lines.append(f"Итог по контейнеру(ам) MSI: **{overall}**. Детальные списки скрыты (compact).")

        out_path.write_text("\n".join(lines), encoding="utf-8")
        return

    # ===== ВАРИАНТ 2: merge_msis без compact (сжатые, но информативные блоки) =====
    if merge_msis and not compact:
        groups: dict[str, list[Dict[str, Any]]] = defaultdict(list)
        singles: list[Dict[str, Any]] = []
        meta_map: dict[str, dict] = {}

        for ev in evidences:
            cont = _container(ev)
            if cont and cont.get("type") == "msi":
                key = cont.get("path") or cont.get("name") or "MSI"
                meta_map[key] = cont
                groups[key].append(ev)
            else:
                singles.append(ev)

        lines: list[str] = []
        lines.append(f"# Binary Intake Gate — Report (Stage {stage})")
        lines.append("")
        lines.append(f"- Generated: **{gen}**")
        lines.append(f"- Profile: **{prof}**")
        lines.append(f"- Files scanned: **{len(groups) + len(singles)}** (MSI агрегированы)")
        lines.append("\n## Files\n")

        for msi_path, kids in groups.items():
            title = (meta_map.get(msi_path, {}).get("ProductName") or "") + \
                    (" " + meta_map[msi_path].get("ProductVersion") if meta_map.get(msi_path, {}).get("ProductVersion") else "")
            title = title.strip() or _basename(msi_path)
            kinds = Counter(_kind(ev) for ev in kids)
            worst, max_sc, cnt, reasons = _worst_decision(kids)
            vt_sum = Counter()
            for ev in kids:
                st = _vt_stats(ev.get("vt"))
                vt_sum.update({"m":st["m"], "s":st["s"], "h":st["h"], "u":st["u"]})

            lines.append(f"### {title} ({_basename(msi_path)})")
            lines.append(f"- Kind: MSI (files={len(kids)}; PE={kinds['PE']}, ELF={kinds['ELF']}, EXT={kinds['EXT']})")
            lines.append(f"- Policy (aggregate): decision={worst} max_score={max_sc} deny={cnt['deny']} warn={cnt['warn']}")
            if reasons:
                lines.append(f"- Reasons (unique top): " + "; ".join(reasons[:10]))
            # Примеры «шумных» файлов (только имена/скор)
            examples = sorted(
                [((ev.get("policy") or {}).get("decision","allow"),
                  int((ev.get("policy") or {}).get("score") or 0),
                  _basename(ev.get("path") or ev.get("file") or (ev.get('meta') or {}).get('name') or ""))
                 for ev in kids],
                key=lambda t: ({"allow":0,"warn":1,"deny":2}[t[0]], t[1]),
                reverse=True
            )[:max(0, int(merge_top))]
            if examples:
                lines.append("- Examples:")
                for dec, sc, nm in examples:
                    lines.append(f"  - {nm}: {dec}, score={sc}")
            lines.append("")

        # одиночные файлы как короткие карточки
        for ev in singles:
            name = (ev.get("meta") or {}).get("name") or _basename(ev.get("path") or ev.get("file") or "")
            pol  = ev.get("policy") or {}
            lines.append(f"### {name}")
            lines.append(f"- Kind: {_kind(ev)}")
            lines.append(f"- Policy: decision={pol.get('decision','allow')} score={pol.get('score',0)}")
            rs = "; ".join([str(r) for r in (pol.get("reasons") or []) if "policy_eval_error:" not in str(r)])
            if rs: lines.append(f"- Reasons: {rs}")
            lines.append("")

        out_path.write_text("\n".join(lines), encoding="utf-8")
        return

    # ===== ВАРИАНТ 3: классический отчёт (без merge_msis), но поддерживает compact =====
    if compact:
        # Только общий итог по всем файлам, без перечислений
        rank = {"allow":0,"warn":1,"deny":2}
        worst, max_sc = "allow", 0
        cnt = Counter()
        for ev in evidences:
            pol = ev.get("policy") or {}
            dec = (pol.get("decision") or "allow").lower()
            sc  = int(pol.get("score") or 0)
            if rank.get(dec,0) > rank.get(worst,0): worst = dec
            if sc > max_sc: max_sc = sc
            cnt[dec] += 1

        lines = [
            f"# Binary Intake Gate — Report (Stage {stage})",
            "",
            f"- Generated: **{gen}**",
            f"- Profile: **{prof}**",
            f"- Files scanned: **{len(evidences)}**",
            "",
            "## Итог",
            f"Policy={worst} (max score={max_sc}, deny={cnt['deny']}, warn={cnt['warn']}).",
        ]
        out_path.write_text("\n".join(lines), encoding="utf-8")
        return

    # ===== ВАРИАНТ 4: старое поведение — краткие карточки по каждому файлу =====
    lines: list[str] = []
    lines.append(f"# Binary Intake Gate — Report (Stage {stage})")
    lines.append("")
    lines.append(f"- Generated: **{gen}**")
    lines.append(f"- Profile: **{prof}**")
    lines.append(f"- Files scanned: **{len(evidences)}**")
    lines.append("\n## Files\n")

    for idx, ev in enumerate(evidences):
        name = (ev.get("meta") or {}).get("name") or _basename(ev.get("path") or ev.get("file") or "")
        pol  = ev.get("policy") or {}
        lines.append(f"### {name}")
        lines.append(f"- Kind: {_kind(ev)}")
        lines.append(f"- Policy: decision={pol.get('decision','allow')} score={pol.get('score',0)}")
        rs = "; ".join([str(r) for r in (pol.get("reasons") or []) if "policy_eval_error:" not in str(r)])
        if rs: lines.append(f"- Reasons: {rs}")
        lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")

