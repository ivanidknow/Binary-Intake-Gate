#!/usr/bin/env python3
"""
Run Speakeasy emulation inside Docker. Reads INPUT_FILE, outputs structured JSON report to stdout.
No Base64 dump. Full report between !!!JSON_REPORT_START!!! and !!!JSON_REPORT_END!!!.
Module list via !!!MODULE_LOADED:<name>; version/hash via !!!MODULE_INFO!!!:name=<dll>|ver=<version>|hash=<hash>
Env: INPUT_FILE, TIMEOUT, WRITE_REPORT.
"""
import hashlib
import json
import os
import re
import sys

try:
    import lief
except ImportError:
    lief = None


def extract_metadata(file_path: str) -> tuple:
    """Extract version (from resources_manager.version) and MD5 hashes for all executable sections. Returns (version_str, hash_str)."""
    if not lief or not os.path.isfile(file_path):
        return ("", "")
    try:
        binary = lief.parse(file_path)
        if binary is None:
            return ("", "")
        version_str = ""
        if hasattr(binary, "resources") and binary.resources:
            r = binary.resources
            if hasattr(r, "version") and r.version:
                v = r.version
                if hasattr(v, "file_version") and v.file_version and len(v.file_version) >= 4:
                    version_str = ".".join(str(x) for x in v.file_version[:4])
                elif hasattr(v, "product_version") and v.product_version and len(v.product_version) >= 4:
                    version_str = ".".join(str(x) for x in v.product_version[:4])
        if not version_str and hasattr(binary, "optional_header") and binary.optional_header:
            oh = binary.optional_header
            if hasattr(oh, "major_operating_system_version") and hasattr(oh, "minor_operating_system_version"):
                version_str = f"{oh.major_operating_system_version}.{oh.minor_operating_system_version}.0.0"
        hash_parts = []
        if hasattr(binary, "sections"):
            for sec in binary.sections:
                content = getattr(sec, "content", None)
                if content is None:
                    continue
                raw = bytes(content) if isinstance(content, (list, tuple)) else content
                if not raw:
                    continue
                exec_sec = (getattr(sec, "characteristics", 0) & 0x20000000) != 0
                name = (getattr(sec, "name", None) or "").strip() or "sec"
                if exec_sec or name in (".text", ".code", ".init"):
                    hash_parts.append(f"{name}:md5={hashlib.md5(raw).hexdigest()}")
        hash_str = ";".join(hash_parts[:10]) if hash_parts else ""
        return (version_str, hash_str)
    except Exception:
        pass
    return ("", "")


def main():
    input_file = os.environ.get("INPUT_FILE") or (sys.argv[1] if len(sys.argv) > 1 else None)
    if input_file and isinstance(input_file, str):
        input_file = input_file.strip()
    timeout = int(os.environ.get("TIMEOUT", "60"))
    report_path = os.environ.get("WRITE_REPORT", "/tmp/report.json")

    if not input_file or not os.path.isfile(input_file):
        print(f"ERROR: INPUT_FILE not set or not a file: {input_file!r}", file=sys.stderr)
        sys.exit(1)

    try:
        from speakeasy import Speakeasy
    except ImportError as e:
        print(f"ERROR: speakeasy import failed: {e}", file=sys.stderr)
        sys.exit(1)

    loaded_modules = []
    api_summary = {}
    decoded_strings = []
    report = {"modules": [], "api_summary": {}, "decoded_strings": []}

    try:
        try:
            se = Speakeasy(debug=False)
        except TypeError:
            se = Speakeasy()
            if hasattr(se, "set_debug"):
                try:
                    se.set_debug(False)
                except Exception:
                    pass
            elif hasattr(se, "debug"):
                try:
                    se.debug = False
                except Exception:
                    pass
        try:
            se.set_max_instructions(1000000)
        except Exception:
            pass
        # Aggressive analysis: scavenge strings and high API count (VMProtect etc.)
        try:
            cfg = getattr(se, "config", None) or getattr(se, "cfg", None)
            if cfg is not None:
                if hasattr(cfg, "set"):
                    cfg.set("analysis", "strings", True)
                    cfg.set("analysis", "max_api_count", 5000)
                    # Увеличение лимита памяти и стека для распаковщиков (MPRESS/UPX) — снижает UC_ERR_WRITE_UNMAPPED
                    try:
                        cfg.set("memory", "limit_memory", 256 * 1024 * 1024)
                    except Exception:
                        pass
                    try:
                        cfg.set("memory", "stack_size", 2 * 1024 * 1024)
                    except Exception:
                        pass
                elif isinstance(cfg, dict):
                    cfg["analysis"] = cfg.get("analysis") or {}
                    cfg["analysis"]["strings"] = True
                    cfg["analysis"]["max_api_count"] = 5000
                    cfg.setdefault("memory", {})["limit_memory"] = 256 * 1024 * 1024
                    cfg.setdefault("memory", {})["stack_size"] = 2 * 1024 * 1024
        except Exception:
            pass
        module = se.load_module(input_file)
        # Collect initial module name
        if hasattr(module, "get_name"):
            name = module.get_name()
            if name and name not in loaded_modules:
                loaded_modules.append(name)
        elif hasattr(module, "name"):
            n = getattr(module, "name", None)
            if n and n not in loaded_modules:
                loaded_modules.append(n)

        # Pre-run dump: снимаем дамп памяти сразу после успешного load_module и передаём в stdout
        # (для Deep Memory Scan на хосте; при падении run_module дамп всё равно уходит в except ниже)
        _pre_run_dump = None
        if hasattr(se, "get_mem_maps") and hasattr(se, "mem_read"):
            get_maps = getattr(se, "get_mem_maps", None)
            mem_read = getattr(se, "mem_read", None)
            if callable(get_maps) and callable(mem_read):
                try:
                    total = bytearray()
                    for entry in get_maps():
                        try:
                            base = entry.get_base() if hasattr(entry, "get_base") else getattr(entry, "base", None)
                            size = entry.get_size() if hasattr(entry, "get_size") else getattr(entry, "size", None)
                            if base is None or size is None or size <= 0:
                                continue
                            data = mem_read(base, size)
                            if not data:
                                continue
                            total.extend(data)
                            found = re.findall(rb"[A-Za-z0-9_\\.\-]+\.[Dd][Ll][Ll]", data)
                            for dll_bytes in found:
                                try:
                                    dll_name = dll_bytes.decode("ascii", errors="ignore").strip()
                                    if dll_name and len(dll_name) <= 256 and dll_name not in loaded_modules:
                                        loaded_modules.append(dll_name)
                                        print(f"!!!MODULE_LOADED!!!:{dll_name}", flush=True)
                                except Exception:
                                    continue
                        except Exception:
                            continue
                    if total:
                        _pre_run_dump = bytes(total)
                except Exception as e:
                    print(f"WARN: get_mem_maps scavenge: {e}", file=sys.stderr)

        try:
            se.debug = False
        except Exception:
            pass
        try:
            se.run_module(module, timeout=timeout, max_ins=1000000)
        except TypeError:
            try:
                se.run_module(module, max_instructions=1000000)
            except TypeError:
                se.run_module(module)
    except Exception as e:
        print(f"ERROR: emulation failed: {e}", file=sys.stderr)
        report["error"] = str(e)[:500]
        _write_report(report_path, report)
        # Pre-run dump (loaded image with EICAR) if we have it; else try get_mem_maps again
        import base64
        to_dump = _pre_run_dump
        if not to_dump and hasattr(se, "get_mem_maps") and hasattr(se, "mem_read"):
            get_maps = getattr(se, "get_mem_maps", None)
            mem_read = getattr(se, "mem_read", None)
            if callable(get_maps) and callable(mem_read):
                try:
                    total = bytearray()
                    for entry in get_maps():
                        try:
                            base = entry.get_base() if hasattr(entry, "get_base") else getattr(entry, "base", None)
                            size = entry.get_size() if hasattr(entry, "get_size") else getattr(entry, "size", None)
                            if base is None or size is None or size <= 0:
                                continue
                            data = mem_read(base, size)
                            if data:
                                total.extend(data)
                        except Exception:
                            continue
                    if total:
                        to_dump = bytes(total)
                except Exception as dump_err:
                    print(f"WARN: dump on failure: {dump_err}", file=sys.stderr)
        if to_dump:
            b64 = base64.b64encode(to_dump).decode("ascii")
            print("DUMP_BASE64_START", flush=True)
            sys.stdout.write(b64)
            print("\nDUMP_BASE64_END", flush=True)
        sys.exit(1)

    # Collect all loaded module names
    if hasattr(se, "get_modules"):
        try:
            for m in se.get_modules():
                name = None
                if hasattr(m, "get_name"):
                    name = m.get_name()
                elif hasattr(m, "name"):
                    name = getattr(m, "name", None)
                if name and isinstance(name, str) and len(name) <= 256 and name not in loaded_modules:
                    loaded_modules.append(name)
        except Exception as e:
            print(f"WARN: get_modules: {e}", file=sys.stderr)
    if hasattr(se, "get_loaded_modules"):
        try:
            for name in se.get_loaded_modules():
                if name and len(str(name)) <= 256:
                    s = str(name)
                    if s not in loaded_modules:
                        loaded_modules.append(s)
        except Exception as e:
            print(f"WARN: get_loaded_modules: {e}", file=sys.stderr)

    # Explicit memory strings scan: any string ending with .dll -> !!!MODULE_LOADED!!!:
    if hasattr(se, "get_strings"):
        try:
            for s in se.get_strings() or []:
                if isinstance(s, str) and s.strip().lower().endswith(".dll") and len(s.strip()) <= 256:
                    name = s.strip()
                    if name not in loaded_modules:
                        loaded_modules.append(name)
                    print(f"!!!MODULE_LOADED!!!:{name}", flush=True)
        except Exception as e:
            print(f"WARN: get_strings: {e}", file=sys.stderr)

    report["modules"] = loaded_modules
    report["api_summary"] = api_summary
    report["decoded_strings"] = decoded_strings

    # Output pre-run memory dump (loaded image) for host Deep Memory Scan
    if _pre_run_dump:
        try:
            import base64
            b64 = base64.b64encode(_pre_run_dump).decode("ascii")
            print("DUMP_BASE64_START", flush=True)
            sys.stdout.write(b64)
            print("\nDUMP_BASE64_END", flush=True)
        except Exception as dump_err:
            print(f"WARN: pre-run dump output: {dump_err}", file=sys.stderr)

    # Dump memory before script exits (for host-side CVE/dump analysis)
    if hasattr(se, "dump_memory") and callable(getattr(se, "dump_memory")):
        try:
            se.dump_memory()
        except Exception as e:
            print(f"WARN: dump_memory: {e}", file=sys.stderr)

    # Critical fallback: if module list is still empty, manual DLL search in memory strings
    if not report.get("modules") and hasattr(se, "get_strings"):
        try:
            for s in se.get_strings() or []:
                if isinstance(s, str) and s.strip().lower().endswith(".dll") and len(s.strip()) <= 256:
                    name = s.strip()
                    if name not in loaded_modules:
                        loaded_modules.append(name)
                    print(f"!!!MODULE_LOADED!!!:{name}", flush=True)
            report["modules"] = loaded_modules
        except Exception as e:
            print(f"WARN: get_strings fallback: {e}", file=sys.stderr)

    _write_report(report_path, report)

    # LIEF fingerprinting: for each DLL try to find file, extract_metadata, output !!!MODULE_INFO!!!:name=...|ver=...|hash=...
    input_dir = os.path.dirname(input_file) or "/input"
    search_dirs = [input_dir, os.path.join(input_dir, "System32"), os.path.join(input_dir, "Windows", "System32"), "/input", "/input/System32"]
    for mod_name in loaded_modules:
        if not mod_name or not isinstance(mod_name, str) or len(mod_name) > 256:
            continue
        base = mod_name.strip()
        found_path = None
        for d in search_dirs:
            if not d or not os.path.isdir(d):
                continue
            cand = os.path.join(d, base)
            if os.path.isfile(cand):
                found_path = cand
                break
        if found_path:
            ver_str, hash_str = extract_metadata(found_path)
            ver_out = ver_str or "—"
            hash_out = hash_str or "—"
            print(f"!!!MODULE_INFO!!!:name={base}|ver={ver_out}|hash={hash_out}", flush=True)

    # Extract modules: explicit lines for host parser
    for mod_name in loaded_modules:
        print(f"!!!MODULE_LOADED:{mod_name}", flush=True)
    # Full report to stdout with markers (no Base64 dump)
    try:
        raw = json.dumps(report, ensure_ascii=False)
        print("!!!JSON_REPORT_START!!!", flush=True)
        sys.stdout.write(raw)
        print("\n!!!JSON_REPORT_END!!!", flush=True)
    except Exception as e:
        print(f"WARN: could not output report: {e}", file=sys.stderr)
    sys.exit(0)


def _write_report(path: str, report: dict) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=0)
    except Exception as e:
        print(f"WARN: could not write report to {path}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
