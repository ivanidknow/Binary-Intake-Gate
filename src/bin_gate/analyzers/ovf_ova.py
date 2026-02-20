# analyzers/ovf_ova.py
from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List
import re
import xml.etree.ElementTree as ET

# --- базовый разбор OVF (уже был у тебя) ---
def analyze_ovf(p: Path) -> Dict[str, Any]:
    """
    Разбор OVF (XML): VirtualSystem/Product/Vendor/OS/CPU/RAM/Files.
    Возвращает краткую сводку для human-отчёта.
    """
    doc: Dict[str, Any] = {"path": str(p), "ok": False}
    try:
        tree = ET.parse(p)
        root = tree.getroot()
        ns = {
            "ovf": "http://schemas.dmtf.org/ovf/envelope/1",
            "vssd": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData",
            "rasd": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData",
        }
        env = root
        vs = env.find(".//ovf:VirtualSystem", ns)
        vs_id = (vs.get("{http://schemas.dmtf.org/ovf/envelope/1}id") if vs is not None else None) or (vs.get("id") if vs is not None else None)
        prod_sec = env.find(".//ovf:ProductSection", ns)
        product = (prod_sec.findtext("ovf:Product", default="", namespaces=ns) if prod_sec is not None else "")
        vendor  = (prod_sec.findtext("ovf:Vendor",  default="", namespaces=ns) if prod_sec is not None else "")
        os_sec = env.find(".//ovf:OperatingSystemSection", ns)
        os_id  = os_sec.get("{http://schemas.dmtf.org/ovf/envelope/1}id") if os_sec is not None else None
        os_desc = (os_sec.findtext("ovf:Description", default="", namespaces=ns) if os_sec is not None else "")
        vhs = env.find(".//ovf:VirtualHardwareSection", ns)
        cpu, mem_mb = None, None
        if vhs is not None:
            for item in vhs.findall("ovf:Item", ns):
                rtype = item.findtext("rasd:ResourceType", default="", namespaces=ns)
                if rtype == "3":  # CPU
                    cpu = item.findtext("rasd:VirtualQuantity", default="", namespaces=ns)
                if rtype == "4":  # Memory
                    mem_mb = item.findtext("rasd:VirtualQuantity", default="", namespaces=ns)
        refs = env.findall(".//ovf:File", ns)
        files = [{
            "id": r.get("{http://schemas.dmtf.org/ovf/envelope/1}id") or r.get("id"),
            "href": r.get("{http://schemas.dmtf.org/ovf/envelope/1}href") or r.get("href"),
            "size": r.get("{http://schemas.dmtf.org/ovf/envelope/1}size") or r.get("size"),
        } for r in refs]
        doc.update({
            "ok": True,
            "virtual_system_id": vs_id,
            "product": product,
            "vendor": vendor,
            "guest_os_id": os_id,
            "guest_os_desc": os_desc,
            "cpu": cpu, "mem_mb": mem_mb,
            "files": files,
        })
    except Exception as e:
        doc["error"] = str(e)
    return doc

# --- MF parsing & verification ---
_MF_RE = re.compile(r"^(?P<algo>SHA(?:1|256|512))\((?P<name>.+)\)=\s*(?P<hex>[0-9a-fA-F]{40,128})\s*$")

def parse_mf(p: Path) -> Dict[str, str]:
    """
    Разбор *.mf (OVF Manifest). Возвращает map: name -> HEX (SHA1/256/512).
    """
    out: Dict[str, str] = {}
    try:
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = _MF_RE.match(line.strip())
            if not m:
                continue
            name = m.group("name").strip()
            out[name] = m.group("hex").lower()
    except Exception:
        pass
    return out

def verify_mf_against_hashes(mf_map: Dict[str, str], hashes_index: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    """
    Сопоставляет ожидания из .mf с реальными хэшами.
    mf_map: name -> hex (как в .mf)
    hashes_index: basename -> {"sha1","sha256","sha512"}
    Возвращает: {"ok": bool, "items":[{name,expected,got,verdict}, ...]}
    """
    result = {"ok": True, "items": []}
    for name, hexv in mf_map.items():
        base = Path(name).name
        got = hashes_index.get(base) or {}
        if len(hexv) == 64:
            verdict = "match" if got.get("sha256") == hexv else "mismatch"
        elif len(hexv) == 40:
            verdict = "match" if got.get("sha1") == hexv else "mismatch"
        elif len(hexv) == 128:
            verdict = "match" if got.get("sha512") == hexv else "mismatch"
        else:
            verdict = "unknown"
        result["ok"] = result["ok"] and (verdict == "match")
        result["items"].append({
            "name": base,
            "expected": hexv,
            "got": (got.get("sha256") or got.get("sha1") or got.get("sha512")),
            "verdict": verdict
        })
    return result

def fold_manifest_algorithms(mf_map: Dict[str, str]) -> Dict[str, Any]:
    """Определяет алгоритмы, используемые в манифесте."""
    algos = set()
    for hexv in mf_map.values():
        ln = len(hexv)
        if ln == 40: algos.add("SHA1")
        elif ln == 64: algos.add("SHA256")
        elif ln == 128: algos.add("SHA512")
    ok = not (algos == {"SHA1"}) and len(algos) > 0
    reason = "" if ok else "manifest_uses_SHA1_only" if algos else "no_manifest_algos"
    return {"algos": sorted(algos), "ok": ok, "reason": reason}

# --- STRICT analyze: расширенный чек-лист требований ---
def analyze_ovf_strict(p: Path) -> Dict[str, Any]:
    """
    Расширенный разбор OVF с формированием чек-листа требований.
    Возвращает: {"ovf": <analyze_ovf() результат>, "checks": {...}}
    """
    base = analyze_ovf(p)
    checks: Dict[str, Any] = {}

    try:
        tree = ET.parse(p)
        root = tree.getroot()
        ns = {
            "ovf": "http://schemas.dmtf.org/ovf/envelope/1",
            "vssd": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData",
            "rasd": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData",
        }

        # VirtualSystemType / VirtualHardware type
        vtype_el = root.find(".//ovf:VirtualHardwareSection/ovf:System/vssd:VirtualSystemType", ns)
        vtype_val = (vtype_el.text or "").strip() if vtype_el is not None else ""
        checks["virtual_hw"] = {"value": vtype_val or "—", "ok": True, "reason": ""}

        # Disks: DiskSection -> ovf:Disk
        disk_items: List[Dict[str, Any]] = []
        disk_ok = True
        for d in root.findall(".//ovf:DiskSection/ovf:Disk", ns):
            did = d.get("{http://schemas.dmtf.org/ovf/envelope/1}diskId") or d.get("diskId")
            cap = d.get("{http://schemas.dmtf.org/ovf/envelope/1}capacity") or d.get("capacity") or None
            cau = d.get("{http://schemas.dmtf.org/ovf/envelope/1}capacityAllocationUnits") or d.get("capacityAllocationUnits") or ""
            fref= d.get("{http://schemas.dmtf.org/ovf/envelope/1}fileRef") or d.get("fileRef")
            it = {"id": did, "capacity": cap, "units": cau, "fileRef": fref, "controller": "?"}
            if not cap or cap in ("0",):
                it["ok"] = False
                disk_ok = False
            else:
                it["ok"] = True
            disk_items.append(it)
        checks["disks"] = {"items": disk_items, "ok": disk_ok, "reason": ""}

        # NICs: VirtualHardwareSection -> Item (ResourceType=10)
        nic_items: List[Dict[str, Any]] = []
        nic_ok = True
        for it in root.findall(".//ovf:VirtualHardwareSection/ovf:Item", ns):
            rtype = (it.findtext("rasd:ResourceType", default="", namespaces=ns) or "").strip()
            if rtype == "10":
                model = (it.findtext("rasd:ResourceSubType", default="", namespaces=ns) or "").strip().lower()
                aut  = (it.findtext("rasd:AutomaticAllocation", default="", namespaces=ns) or "").strip().lower()
                model_ok = (model in ("vmxnet3", "e1000e"))
                if not model_ok:
                    # e1000 acceptable (warn) but others -> warn/fail
                    nic_ok = False
                nic_items.append({"model": model or "?", "auto": aut or "true", "ok": model_ok})
        if not nic_items:
            nic_ok = False
        checks["nics"] = {"items": nic_items, "ok": nic_ok, "reason": "" if nic_ok else "no_nics_or_bad_model"}

        # Removable / extra devices: CD/USB/Serial/Parallel/Sound
        removable = {"cd_autoconnect": False, "usb": False, "serial": False, "parallel": False, "sound": False}
        for it in root.findall(".//ovf:VirtualHardwareSection/ovf:Item", ns):
            rtype = (it.findtext("rasd:ResourceType", default="", namespaces=ns) or "").strip()
            if rtype in ("15", "16", "17"):  # CD/DVD family
                aut = (it.findtext("rasd:AutomaticAllocation", default="true", namespaces=ns) or "").strip().lower()
                if aut in ("true", "1", "yes"):
                    removable["cd_autoconnect"] = True
            if rtype == "23":
                removable["serial"] = True
            if rtype == "21":
                removable["parallel"] = True
            if rtype == "35":
                removable["usb"] = True
            if rtype == "24":
                removable["sound"] = True
        rem_ok = not any(removable.values())
        checks["removable"] = {**removable, "ok": rem_ok, "reason": "" if rem_ok else "unwanted_devices_or_cd_autoconnect"}

        # References placeholder (проверка позже, в CLI, когда есть список реальных файлов)
        checks["references"] = {"missing": [], "orphan": [], "size_mismatch": [], "ok": True, "reason": ""}

        # Manifest algorithms placeholder (заполняется в CLI после чтения .mf)
        checks["manifest_algo"] = {"algos": [], "ok": True, "reason": ""}

        # PropertySection: найти подозрительные ключи
        suspicious: List[Dict[str, str]] = []
        for psec in root.findall(".//ovf:PropertySection", ns):
            for prop in psec.findall(".//ovf:Property", ns):
                key = prop.get("{http://schemas.dmtf.org/ovf/envelope/1}key") or prop.get("key") or ""
                val = prop.get("{http://schemas.dmtf.org/ovf/envelope/1}value") or prop.get("value") or ""
                if any(s in key.lower() for s in ("password", "secret", "token", "key")) or \
                   any(s in (val or "").lower() for s in ("http://", "https://", "token", "passwd", "secret")):
                    suspicious.append({"key": key, "value": (val[:120] + "…") if val and len(val) > 120 else val})
        checks["properties"] = {"suspicious": suspicious, "ok": (len(suspicious) == 0),
                                "reason": "" if len(suspicious) == 0 else "suspicious_properties_present"}

    except Exception as e:
        # В случае парс-ошибки — вернём частичный base + ошибку в checks
        checks["parse_error"] = str(e)

    return {"ovf": base, "checks": checks}
