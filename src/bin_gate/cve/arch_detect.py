# arch_detect.py
from dataclasses import dataclass

@dataclass
class BinArch:
    fmt: str           # "ELF"|"PE"|"MachO"|"BIN"
    arch: str          # "x86_64","aarch64","armv7","i386",...
    bits: int          # 32|64
    abi: str|None      # "glibc"|"musl"|"windows"|"darwin"|None
    interp: str|None   # ELF PT_INTERP
    notes: list[str]

def detect_arch(fp: str) -> BinArch:
    with open(fp, "rb") as f:
        head = f.read(4)
    # ELF
    if head == b"\x7fELF":
        from elftools.elf.elffile import ELFFile
        with open(fp, "rb") as f:
            elf = ELFFile(f)
            bits = 64 if elf.elfclass == 64 else 32
            arch_map = {"EM_X86_64":"x86_64","EM_386":"i386","EM_AARCH64":"aarch64","EM_ARM":"arm",
                        "EM_PPC64":"ppc64","EM_PPC":"ppc","EM_RISCV":"riscv64"}
            arch = arch_map.get(elf["e_machine"], elf["e_machine"])
            interp = None
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_INTERP":
                    interp = seg.get_data().decode("ascii","ignore").strip("\x00")
                    break
            abi = "musl" if (interp and "ld-musl" in interp) else ("glibc" if interp else None)
            # armhf эвристика
            if arch == "arm":
                try:
                    dyn = elf.get_section_by_name(".dynamic")
                    need = [t.needed.decode() for t in dyn.iter_tags() if t.entry.d_tag == "DT_NEEDED"]
                    if any("gnueabihf" in n or "ld-linux-armhf" in n for n in need):
                        arch = "armv7"
                except Exception:
                    pass
            return BinArch("ELF", arch, bits, abi, interp, [])
    # PE
    if head[:2] == b"MZ":
        import pefile
        pe = pefile.PE(fp, fast_load=True)
        mm = {0x014c:"i386", 0x8664:"x86_64", 0x01c0:"arm", 0xaa64:"aarch64"}
        arch = mm.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
        return BinArch("PE", arch, 64 if arch in ("x86_64","aarch64") else 32, "windows", None, [])
    # Mach-O (минимально)
    try:
        from macholib.MachO import MachO
        m = MachO(fp)
        cm = {7:"i386", 12:"arm", 18:"ppc", 16777223:"x86_64", 16777228:"arm64"}
        arch = cm.get(m.headers[0].header.cputype, "unknown")
        return BinArch("MachO", arch, 64 if arch in ("x86_64","arm64") else 32, "darwin", None, [])
    except Exception:
        pass
    return BinArch("BIN", "unknown", 0, None, None, [])
