# signing_trust.py — проверка Authenticode и отзыва сертификата (кроссплатформенно)
# v3.2: Chain of Trust, Stolen Cert Detection, Publisher Reputation
from __future__ import annotations
from pathlib import Path
import struct
import subprocess
import platform
import os
from typing import Dict, Any, Optional, Set

# Известные издатели (белый список); не в списке → uncertain_publisher (+15 к риску)
KNOWN_PUBLISHERS: Set[str] = {
    "microsoft", "microsoft corporation", "google", "google llc", "apple", "apple inc",
    "adobe", "oracle", "ibm", "vmware", "symantec", "mcafee", "kaspersky",
    "canonical", "red hat", "the open group", "mozilla", "mozilla foundation",
    "jetbrains", "gitlab", "github", "atlassian", "slack", "zoom",
    "crowdstrike", "palo alto", "cisco", "fortinet", "qualys",
}
_STOLEN_THUMBPRINTS: Optional[Set[str]] = None

def _u32le(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _light_check(p: Path) -> Dict[str, Any]:
    """Проверка наличия таблицы подписи (Authenticode) в PE."""
    try:
        with p.open("rb") as f:
            if f.read(2) != b"MZ":
                return {"error": "not_pe"}
            f.seek(0x3C)
            peoff = _u32le(f.read(4), 0)
            f.seek(peoff)
            if f.read(4) != b"PE\x00\x00":
                return {"error": "bad_pe_sig"}
            f.seek(peoff + 4 + 20)
            hdr = f.read(240)
            is_plus = hdr[:2] == b"\x0b\x02"
            dd_off = 96 if not is_plus else 112
            sec_va = _u32le(hdr, dd_off + 4 * 8)
            sec_sz = _u32le(hdr, dd_off + 4 * 8 + 4)
            return {
                "signed": bool(sec_va and sec_sz),
                "cert_table_size": int(sec_sz),
                "valid": None,
                "revoked": None,
            }
    except Exception as e:
        return {"error": str(e)}


def _osslsigncode_verify(path: Path, timeout_sec: int = 30) -> Dict[str, Any]:
    """Проверка цепочки Authenticode через osslsigncode (Linux/кроссплатформенно)."""
    try:
        r = subprocess.run(
            ["osslsigncode", "verify", "-in", str(path)],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        # exit 0 = success; non-zero or "Signature verification failed" in stderr = invalid
        out = (r.stdout or "") + (r.stderr or "")
        valid = r.returncode == 0 and "Signature verification failed" not in out
        return {"valid": valid, "revoked": None, "verify_output": out[:500]}
    except FileNotFoundError:
        return {"valid": None, "revoked": None}
    except subprocess.TimeoutExpired:
        return {"valid": None, "revoked": None}
    except Exception:
        return {"valid": None, "revoked": None}


def _check_revocation_ocsp(path: Path, timeout_sec: int = 10) -> Optional[bool]:
    """
    Базовая проверка отзыва через OCSP (при наличии сети и библиотеки cryptography).
    Возвращает True если сертификат отозван, False если не отозван, None если проверка недоступна.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        import urllib.request
    except ImportError:
        return None

    def _read_pe_cert_blob(p: Path) -> Optional[bytes]:
        try:
            data = p.read_bytes()
            if len(data) < 0x40 or data[:2] != b"MZ":
                return None
            peoff = _u32le(data, 0x3C)
            if peoff + 4 + 24 > len(data):
                return None
            if data[peoff:peoff + 4] != b"PE\x00\x00":
                return None
            is_plus = data[peoff + 4 + 20:peoff + 4 + 22] == b"\x0b\x02"
            dd_off = peoff + 4 + 20 + (96 if not is_plus else 112)
            if dd_off + 8 > len(data):
                return None
            rva = _u32le(data, dd_off + 4 * 8)
            cert_len = _u32le(data, dd_off + 4 * 8 + 4)
            if not cert_len or rva + 8 >= len(data):
                return None
            # WIN_CERTIFICATE: DWORD dwLength, WORD wRevision, WORD wCertificateType, then bCertificate
            blob_len = _u32le(data, rva)
            if blob_len > 8 and rva + blob_len <= len(data):
                return bytes(data[rva + 8 : rva + blob_len])
            return None
        except Exception:
            return None

    cert_der = _read_pe_cert_blob(path)
    if not cert_der:
        return None
    # PKCS#7 SignedData: certificate is inside; parse with cryptography
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
        # Load PKCS#7 (Authenticode is PKCS#7 SignedData)
        certs = pkcs7.load_der_pkcs7_certificates(cert_der)
        if not certs:
            return None
        leaf = certs[0]
    except Exception:
        try:
            # Alternative: cert_der might be raw cert in some cases
            leaf = x509.load_der_x509_certificate(cert_der, default_backend())
        except Exception:
            return None

    # OCSP URL from AIA
    try:
        aia = leaf.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        ocsp_url = None
        for desc in aia.value:
            if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                    ocsp_url = desc.access_location.value
                    break
        if not ocsp_url:
            return None
    except x509.ExtensionNotFound:
        return None

    # Build OCSP request and parse response (minimal: check status)
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(leaf, certs[1] if len(certs) > 1 else leaf, hashes.SHA256())
        req = builder.build()
        import ssl
        data = urllib.request.urlopen(
            ocsp_url,
            data=req.public_bytes(serialization.Encoding.DER),
            timeout=timeout_sec,
            context=ssl.create_default_context(),
        ).read()
        ocsp_resp = load_der_ocsp_response(data)
        if ocsp_resp.response_status == 0:  # successful
            single = ocsp_resp.responses[0]
            if single.certificate_status.name == "REVOKED":
                return True
            return False
    except Exception:
        pass
    return None


def analyze(path: Path, check_revocation: bool = True) -> dict:
    """
    Проверка подписи Authenticode и при возможности — отзыва сертификата.
    - Всегда: наличие таблицы подписи (signed, cert_table_size).
    - На не-Windows: проверка цепочки через osslsigncode verify (valid).
    - При наличии сети и cryptography: базовая проверка OCSP (revoked: True/False/None).
    """
    p = Path(path)
    out = _light_check(p)
    if out.get("error"):
        return out

    out.setdefault("valid", None)
    out.setdefault("revoked", None)

    # На Linux/не-Windows — полная проверка цепочки до Root CA (osslsigncode verify)
    if platform.system().lower() != "windows":
        verify_result = _osslsigncode_verify(p)
        if verify_result.get("valid") is not None:
            out["valid"] = verify_result["valid"]
            out["chain_valid"] = verify_result["valid"]  # Chain of Trust = result of verify
    else:
        out["chain_valid"] = None  # На Windows заполняется в pe_hardening (chain_ok)

    # Проверка отзыва (OCSP / CRL) — Stolen Cert Detection через отзыв
    if out.get("signed") and check_revocation and out.get("revoked") is None:
        revoked = _check_revocation_ocsp(p)
        if revoked is not None:
            out["revoked"] = revoked

    return out


def is_publisher_known(publisher: Optional[str]) -> bool:
    """True если издатель в белом списке (Publisher Reputation)."""
    if not publisher or not isinstance(publisher, str):
        return False
    low = publisher.strip().lower()
    return low in KNOWN_PUBLISHERS or any(low.startswith(p) for p in KNOWN_PUBLISHERS)


def check_stolen_thumbprint(thumbprint: Optional[str]) -> bool:
    """Сравнение отпечатка с базой известных украденных/скомпрометированных (env: BIN_GATE_STOLEN_CERT_LIST)."""
    global _STOLEN_THUMBPRINTS
    if not thumbprint or not isinstance(thumbprint, str):
        return False
    thumb = thumbprint.strip().replace(" ", "").upper()
    if not thumb:
        return False
    if _STOLEN_THUMBPRINTS is None:
        path = os.getenv("BIN_GATE_STOLEN_CERT_LIST")
        _STOLEN_THUMBPRINTS = set()
        if path and Path(path).exists():
            try:
                text = Path(path).read_text(encoding="utf-8", errors="ignore")
                for line in text.splitlines():
                    t = line.strip().replace(" ", "").upper()
                    if t and not t.startswith("#"):
                        _STOLEN_THUMBPRINTS.add(t)
            except Exception:
                pass
    return thumb in _STOLEN_THUMBPRINTS
