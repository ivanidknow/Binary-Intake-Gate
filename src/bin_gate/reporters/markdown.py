from __future__ import annotations
import pathlib, datetime, json

HEADER = "# Binary Intake Gate — Report (Stage 4)\n\n_Base analyzers: hashes, entropy, PE/ELF hardening, capa, YARA. Integrations: VT (lookup/upload), SQLite cache. Policy engine with profiles._"



def write_markdown_report(out_path: pathlib.Path, files: list[pathlib.Path], summary: dict, policy: dict, evidences: list[dict] | None = None) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    lines = [HEADER, "", f"- Generated: **{ts}**", f"- Profile: **{summary.get('profile','dev')}**",
             f"- Files scanned: **{summary.get('scanned',0)}**", "", "## Files", ""]
    if not files:
        lines.append("_No PE/ELF-like files found._")
    else:
        for p in sorted(files):
            lines.append(f"- `{p}`")

    lines.append("\n## Summary")
    if evidences:
        for ev in evidences:
            meta = ev.get("meta", {})
            h = ev.get("hashes", {}) or {}
            pe = ev.get("pe") or {}
            elf = ev.get("elf") or {}
            capa = ev.get("capa") or {}
            yara = ev.get("yara")
            errs = ev.get("errors") or []
            if errs:
                lines.append(f"- Analyzer errors: {', '.join(errs[:4])}{' …' if len(errs) > 4 else ''}")
            lines.append(f"\n### {meta.get('name')} ({meta.get('type')})")
            if h:
                lines.append(f"- sha256: `{h.get('sha256')}`")
            if pe:
                hard = pe.get("hardening", {})
                sig = pe.get("signature", {})
                sec = pe.get("sections", {})
                imports = pe.get("imports", [])
                lines.append("- PE hardening: "
                    f"ASLR={hard.get('aslr')} DEP={hard.get('dep')} CFG={hard.get('cfg')} "
                    f"SafeSEH={hard.get('safeseh')} HE-VA={hard.get('high_entropy_va')} LAA={hard.get('large_address_aware')}")
                if sig:
                    lines.append("- PE signature: "
                        f"present={sig.get('present')} valid={sig.get('valid')} chain_ok={sig.get('chain_ok')} "
                        f"publisher=`{sig.get('publisher')}` issuer=`{sig.get('issuer')}` thumbprint=`{sig.get('thumbprint')}` "
                        f"timestamp_present={sig.get('timestamp_present')} raw_status=`{sig.get('raw_status')}`")
                if sec:
                    lines.append(f"- PE sections: RWX={sec.get('has_rwx')} overlay%={sec.get('overlay_pct')}")
                if imports:
                    lines.append(f"- PE imports (high-risk): {', '.join(imports)}")
            if elf:
                hard = elf.get("hardening", {})
                lines.append("- ELF hardening: "
                    f"PIE={hard.get('pie')} NX={hard.get('nx')} RELRO={hard.get('relro')} Canary={hard.get('canary')} "
                    f"RPATH={hard.get('rpath')} RUNPATH={hard.get('runpath')} TEXTREL={hard.get('textrel')}")
            if capa:
                tacts = capa.get("techniques") or []
                hits = capa.get("rule_hits") or []
                lines.append(f"- capa tactics: {', '.join(tacts) if tacts else '—'}")
                if hits:
                    lines.append(f"- capa rules: {', '.join(hits[:10])}{' …' if len(hits)>10 else ''}")
            if yara is not None:
                # YARA запускалась (даже если 0 хитов)
                rule_names = [x.get('rule') for x in yara if isinstance(x, dict) and x.get('rule')]
                count = len(rule_names)
                if count > 0:
                    lines.append(f"- YARA hits: {count} — {', '.join(rule_names[:10])}{' …' if count>10 else ''}")
                else:
                    lines.append(f"- YARA hits: 0")
            vt = ev.get("vt") or {}
            if vt:
                det = vt.get("detections") or {}
                stats = (det.get("stats") or {}) if det else (vt.get("stats") or {})
                rep = det.get("reputation") if det else vt.get("reputation")
                threat = det.get("threat_label") if det else vt.get("threat_label")
                if stats:
                    lines.append(f"- VT: stats m/s/h/u = {stats.get('malicious',0)}/{stats.get('suspicious',0)}/{stats.get('harmless',0)}/{stats.get('undetected',0)}"
                                f"{' rep='+str(rep) if rep is not None else ''}{' threat='+str(threat) if threat else ''}")
                if vt.get("permalink"):
                    lines.append(f"- VT link: {vt.get('permalink')}")
                # behaviours / relations / comments (кратко)
                if vt.get("behaviours"):
                    lines.append(f"- VT behaviours: {len(vt['behaviours'])} sandbox(es)")
                rel = vt.get("relations") or {}
                if rel:
                    rc = []
                    for k in ("contacted_urls","contacted_domains","contacted_ips","bundled_files"):
                        if rel.get(k): rc.append(f"{k.split('_')[1]}={len(rel[k])}")
                    if rc:
                        lines.append(f"- VT relations: {', '.join(rc)}")
                if vt.get("_cached"):
                    lines[-1] = lines[-1] + " (cache)"
            pol = ev.get("policy") or {}
            if pol:
                dec = pol.get("decision")
                sc  = pol.get("score")
                rs  = pol.get("reasons") or []
                if dec is not None:
                    lines.append(f"- Policy: decision={dec} score={sc}")
                if rs:
                    lines.append(f"- Reasons: " + "; ".join(rs[:5]) + (" …" if len(rs) > 5 else ""))
            cve = ev.get("cve") or {}
            if cve:
                summ = cve.get("summary") or {}
                if summ:
                    lines.append(f"- CVE: total={summ.get('total',0)} (CRIT={summ.get('critical',0)}, HIGH={summ.get('high',0)}, MED={summ.get('medium',0)})")
                fnds = cve.get("findings") or []
                # короткий список первых 3 советов (package: CVE …)
                shown = 0
                for f in fnds:
                    pkg = f.get("package"); ver = f.get("version")
                    for adv in (f.get("advisories") or [])[:2]:
                        lines.append(f"  • {pkg} {ver}: {adv.get('id')} [{adv.get('severity')}] — {adv.get('summary')[:80]}")
                        shown += 1
                        if shown >= 3: break
                    if shown >= 3: break

    lines.append("\n---\n")
    lines.append("_Policies loaded:_")
    lines.append("```yaml\n" + (policy and str(policy) or "{}") + "\n```")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    if evidences is not None:
        json_path = out_path.with_suffix(".json")
        json_path.write_text(json.dumps(evidences, indent=2), encoding="utf-8")
