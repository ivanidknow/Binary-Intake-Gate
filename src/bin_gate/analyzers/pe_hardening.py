from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, Optional
import platform, json, subprocess

# DllCharacteristics flags
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020  # HighEntropyVA
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE    = 0x0040  # ASLR
IMAGE_DLLCHARACTERISTICS_NX_COMPAT       = 0x0100  # DEP
IMAGE_DLLCHARACTERISTICS_GUARD_CF        = 0x4000  # CFG

# FileHeader.Characteristics
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020

IMAGE_FILE_MACHINE_I386 = 0x014c

def _extract_cn(subject_str: str | None) -> Optional[str]:
    if not subject_str:
        return None
    parts = [p.strip() for p in subject_str.split(",")]
    for it in parts:
        if it.upper().startswith("CN="):
            return it[3:].strip()
    return subject_str

def _ps_quote_single(s: str) -> str:
    # PowerShell single-quoted string: escape ' as ''
    return s.replace("'", "''")

def _get_authenticode_via_powershell(path: Path) -> Optional[dict]:
    """Windows-only: возвращает объект с полями:
       Status (string), StatusCode (int), StatusMessage (string),
       SignerCertificate, TimeStamperCertificate.
    """
    if platform.system().lower() != "windows":
        return None
    cmd = [
        "powershell", "-NoProfile", "-NonInteractive",
        "-Command",
        (
            f"$p='{_ps_quote_single(str(path))}'; "
            "$sig = Get-AuthenticodeSignature -FilePath $p; "
            # Принудительно делаем Status строкой, но сохраняем и код
            "$out = [PSCustomObject]@{ "
            "  Status = $sig.Status.ToString(); "
            "  StatusCode = [int]$sig.Status; "
            "  StatusMessage = $sig.StatusMessage; "
            "  SignerCertificate = $sig.SignerCertificate; "
            "  TimeStamperCertificate = $sig.TimeStamperCertificate "
            "}; "
            "$out | ConvertTo-Json -Depth 10"
        )
    ]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if cp.returncode != 0:
            return None
        data = cp.stdout.strip()
        if not data:
            return None
        return json.loads(data)
    except Exception:
        return None

def analyze_pe_hardening(path: Path) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "signature": {
            "present": None, "valid": None, "chain_ok": None,
            "publisher": None, "issuer": None, "thumbprint": None,
            "timestamp_present": None, "timestamp_time": None,
            "raw_status": None, "raw_status_code": None
        },
        "hardening": {
            "aslr": None, "dep": None, "cfg": None,
            "safeseh": None, "high_entropy_va": None, "large_address_aware": None
        },
        "imports": [],
        "sections": {"has_rwx": None, "overlay_pct": None},
        "pdb_path": None,
        "incremental": None,
        "errors": []
    }
    try:
        import pefile  # type: ignore
    except Exception as e:
        info["errors"].append(f"pefile_import_error:{e}")
        return info

    try:
        pe = pefile.PE(str(path), fast_load=False)

        # --- наличие таблицы подписи (Certificate Table / SECURITY)
        present_by_dir = False
        try:
            wcd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
            present_by_dir = bool(getattr(wcd, "Size", 0))
        except Exception:
            present_by_dir = False

        # --- PowerShell: издатель/валидность/цепочка (строковый Status + код)
        ps_sig = _get_authenticode_via_powershell(path)
        signer = {}
        timestamper = {}
        status_str = None
        if isinstance(ps_sig, dict):
            status_str = (ps_sig.get("Status") or "") or (ps_sig.get("StatusMessage") or "")
            info["signature"]["raw_status"] = status_str
            info["signature"]["raw_status_code"] = ps_sig.get("StatusCode")
            signer = ps_sig.get("SignerCertificate") or {}
            timestamper = ps_sig.get("TimeStamperCertificate") or {}

        # --- publisher/issuer/thumbprint
        subj = signer.get("Subject")
        issuer = signer.get("Issuer")
        thumb = signer.get("Thumbprint")
        if subj:   info["signature"]["publisher"] = _extract_cn(subj)
        if issuer: info["signature"]["issuer"]    = _extract_cn(issuer)
        if thumb:  info["signature"]["thumbprint"]= thumb
        info["signature"]["timestamp_present"] = bool(timestamper) or None

        # --- финальная логика present/valid/chain_ok
        present_ps = bool(signer)                 # есть ли сам сертификат подписанта
        info["signature"]["present"] = bool(present_by_dir or present_ps)
        if status_str:
            s = status_str.lower()
            if s == "valid":
                info["signature"]["valid"] = True
                info["signature"]["chain_ok"] = True
            elif s == "notsigned":
                info["signature"]["valid"] = False
                info["signature"]["chain_ok"] = False
                # если и таблицы подписи нет — явно нет подписи
                if not present_by_dir:
                    info["signature"]["present"] = False
            else:
                # NotTrusted/HashMismatch/UnknownError/etc
                info["signature"]["valid"] = False
                info["signature"]["chain_ok"] = False
        else:
            # нет статуса — оставим валидность неизвестной,
            # но present скажет, есть ли таблица подписи
            info["signature"]["valid"] = None
            info["signature"]["chain_ok"] = None

        # --- DllCharacteristics → ASLR/DEP/CFG/HighEntropyVA
        dc = pe.OPTIONAL_HEADER.DllCharacteristics
        info["hardening"]["aslr"] = bool(dc & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        info["hardening"]["dep"]  = bool(dc & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        info["hardening"]["cfg"]  = bool(dc & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
        info["hardening"]["high_entropy_va"] = bool(dc & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)

        # --- LargeAddressAware
        fhc = pe.FILE_HEADER.Characteristics
        info["hardening"]["large_address_aware"] = bool(fhc & IMAGE_FILE_LARGE_ADDRESS_AWARE)

        # --- SafeSEH (только x86)
        try:
            if pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_I386:
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]])
                lc = getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
                info["hardening"]["safeseh"] = bool(lc and getattr(lc.struct, "SEHandlerTable", 0))
            else:
                info["hardening"]["safeseh"] = None
        except Exception:
            info["hardening"]["safeseh"] = None

        # --- Импорты (краткий набор "red flags")
        red = {"CreateRemoteThread","WriteProcessMemory","VirtualAllocEx",
               "NtQueryInformationProcess","RegSetValueExA","RegSetValueExW"}
        imps = set()
        try:
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                for imp in getattr(entry, "imports", []) or []:
                    nm = None
                    if getattr(imp, "name", None):
                        try:
                            nm = imp.name.decode() if isinstance(imp.name, (bytes, bytearray)) else str(imp.name)
                        except Exception:
                            nm = str(imp.name)
                    if nm and nm in red:
                        imps.add(nm)
        except Exception:
            pass
        info["imports"] = sorted(imps)

        # --- Секции: RWX и overlay%
        try:
            has_rwx = False
            for s in getattr(pe, "sections", []) or []:
                ch = s.Characteristics
                is_r = bool(ch & 0x40000000)
                is_w = bool(ch & 0x80000000)
                is_x = bool(ch & 0x20000000)
                if is_r and is_w and is_x:
                    has_rwx = True
            info["sections"]["has_rwx"] = has_rwx
        except Exception:
            info["sections"]["has_rwx"] = None

        try:
            last_end = max([(s.PointerToRawData + s.SizeOfRawData) for s in pe.sections]) if pe.sections else 0
            file_size = Path(path).stat().st_size
            overlay = max(0, file_size - last_end)
            info["sections"]["overlay_pct"] = round(100.0 * overlay / file_size, 3) if file_size else 0.0
        except Exception:
            info["sections"]["overlay_pct"] = None

        # --- PDB path
        try:
            pdb = None
            for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
                data = pe.parse_debug_directory(entry.struct)
                for dbg in data:
                    if hasattr(dbg, "PdbFileName") and dbg.PdbFileName:
                        pdb = dbg.PdbFileName.decode(errors="ignore") if isinstance(dbg.PdbFileName, (bytes, bytearray)) else str(dbg.PdbFileName)
            info["pdb_path"] = pdb
        except Exception:
            info["pdb_path"] = None

        # --- Инкрементальная линковка (эвристика)
        try:
            info["incremental"] = bool(pe.OPTIONAL_HEADER.LoaderFlags)
        except Exception:
            info["incremental"] = None

    except Exception as e:
        info["errors"].append(f"pe_parse_error:{e}")
    return info
