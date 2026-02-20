# platform_guess.py
def guess_platform(fmt: str, arch: str, abi: str|None):
    if fmt == "ELF":
        eco = "Alpine" if abi == "musl" else "Debian"
        arch_map = {
            "Debian": {"x86_64":"amd64","i386":"i386","aarch64":"arm64","armv7":"armhf","ppc64":"ppc64el","riscv64":"riscv64"},
            "RedHat": {"x86_64":"x86_64","i386":"i686","aarch64":"aarch64","armv7":"armv7hl","ppc64":"ppc64le"},
            "Alpine": {"x86_64":"x86_64","i386":"x86","aarch64":"aarch64","armv7":"armv7","ppc64":"ppc64le"},
        }
        return {"ecosystem": eco, "arch": arch_map.get(eco, {}).get(arch, arch)}
    if fmt == "PE":     return {"ecosystem":"Windows","arch":arch}
    if fmt == "MachO":  return {"ecosystem":"Darwin","arch":arch}
    return {"ecosystem":None,"arch":arch}
