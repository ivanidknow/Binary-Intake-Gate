from __future__ import annotations
from typing import List, Dict, Any, Tuple
from pathlib import Path
import os

def _rel(p: str) -> str:
    ws = os.getenv("GITHUB_WORKSPACE")
    try:
        base = Path(ws) if ws else Path.cwd()
        rel = Path(p).resolve().relative_to(base.resolve())
    except Exception:
        rel = Path(p).name
    return str(rel).replace("\\", "/")

def write_step_summary(evidences: List[Dict[str, Any]], summary: Dict[str, Any], profile: str, out_path: str | None = None) -> None:
    md = []
    md.append(f"### Binary Intake Gate — {summary.get('stage','5')}  \n")
    md.append(f"**Profile:** `{profile}`  \n")
    # counters
    c_allow = c_warn = c_deny = 0
    for ev in evidences:
        dec = (ev.get("policy") or {}).get("decision")
        if dec == "deny": c_deny += 1
        elif dec == "warn": c_warn += 1
        else: c_allow += 1
    md.append(f"**Files:** {summary.get('scanned', len(evidences))}  —  ✅ {c_allow}  |  ⚠️ {c_warn}  |  ❌ {c_deny}\n\n")
    # per-file short rows
    for ev in evidences:
        pol = ev.get("policy") or {}
        dec = pol.get("decision", "allow")
        score = pol.get("score", 0)
        emoji = "✅" if dec=="allow" else ("⚠️" if dec=="warn" else "❌")
        path = _rel(ev.get("path") or ev.get("file") or "")
        reasons = "; ".join((pol.get("reasons") or [])[:3])
        md.append(f"{emoji} **{path}** — {dec} (score={score})  \n")
        if reasons:
            md.append(f"• {reasons}  \n")
    text = "".join(md)

    # куда писать
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
        return
    step = os.getenv("GITHUB_STEP_SUMMARY")
    if step:
        with open(step, "a", encoding="utf-8") as f:
            f.write(text)

def emit_workflow_commands(evidences: List[Dict[str, Any]]) -> None:
    # Выведем ::warning/::error для GitHub Actions
    for ev in evidences:
        pol = ev.get("policy") or {}
        dec = pol.get("decision", "allow")
        if dec not in ("warn","deny"):
            continue
        path = _rel(ev.get("path") or ev.get("file") or "")
        title = f"Policy {dec} (score={pol.get('score',0)})"
        msg = "; ".join(pol.get("reasons") or [])
        if dec == "deny":
            print(f"::error file={path},title={title}::{msg}")
        else:
            print(f"::warning file={path},title={title}::{msg}")
