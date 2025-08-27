from __future__ import annotations
from typing import List, Dict, Any, Tuple
from pathlib import Path
import os, json

def _rel_uri(p: str) -> str:
    ws = os.getenv("GITHUB_WORKSPACE")
    try:
        base = Path(ws) if ws else Path.cwd()
        rel = Path(p).resolve().relative_to(base.resolve())
    except Exception:
        rel = Path(p).name
    # SARIF хочет forward slashes
    return str(rel).replace("\\", "/")

def _collect_rules(evidences: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    # Берём id и текст из Reasons: "[id] reason"
    rules: Dict[str, Dict[str, Any]] = {}
    for ev in evidences:
        pol = ev.get("policy") or {}
        for r in pol.get("reasons") or []:
            if not isinstance(r, str) or not r.startswith("["):
                continue
            try:
                rid = r[1:r.index("]")]
                msg = r[r.index("]")+1:].strip() or rid
                rules.setdefault(rid, {
                    "id": rid,
                    "name": rid,
                    "shortDescription": {"text": msg},
                    "fullDescription": {"text": msg},
                })
            except Exception:
                continue
    return rules

def _level_for_decision(dec: str) -> str:
    return {"deny": "error", "warn": "warning"}.get(dec, "note")

def write_sarif_report(out_path: Path, evidences: List[Dict[str, Any]], tool_name: str = "bin-gate", tool_version: str | None = None) -> None:
    rules_map = _collect_rules(evidences)
    results: List[Dict[str, Any]] = []

    for ev in evidences:
        pol = ev.get("policy") or {}
        dec = pol.get("decision") or "allow"
        lvl = _level_for_decision(dec)
        reasons = pol.get("reasons") or []
        matched = pol.get("matched") or []
        # путь
        uri = _rel_uri(ev.get("path") or ev.get("file") or "")
        # делаем результат на каждое сработавшее правило
        if matched:
            for rid in matched:
                msg_txt = next((r for r in reasons if r.startswith(f"[{rid}]")), f"[{rid}]")
                results.append({
                    "ruleId": rid,
                    "level": lvl,
                    "message": {"text": f"{msg_txt} (decision={dec}, score={pol.get('score',0)})"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri}
                        }
                    }]
                })
        else:
            # нет явных совпадений — создадим общий результат only if warn/deny
            if dec in ("warn","deny"):
                results.append({
                    "ruleId": "policy-summary",
                    "level": lvl,
                    "message": {"text": f"Policy {dec} (score={pol.get('score',0)}): " + "; ".join(reasons[:3])},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri}
                        }
                    }]
                })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    **({"version": tool_version} if tool_version else {}),
                    "rules": list(rules_map.values()) + [{
                        "id": "policy-summary",
                        "name": "policy-summary",
                        "shortDescription": {"text": "Aggregated policy decision"},
                        "fullDescription": {"text": "Aggregated policy decision when no specific rule was matched"}
                    }]
                }
            },
            "results": results
        }]
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
