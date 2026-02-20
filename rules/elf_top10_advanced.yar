/* elf_top10_advanced.yar
 * Unified ruleset for top-10 risky patterns in Linux ELF binaries.
 * Focus: fast triage, low FP, practical heuristics using elf module.
 * Author: ivan-gate
 */
import "elf"

/* ================= Helpers ================= */

private rule __is_elf { condition: uint32(0) == 0x7F454C46 and elf }

private rule __smallish_bin { condition: filesize > 10KB and filesize < 200MB }

private rule __has_rwX_section
{
  // SHF_WRITE=0x1, SHF_EXECINSTR=0x4
  condition:
    for any i in (0 .. elf.number_of_sections - 1):
      ( (elf.sections[i].flags & 0x1) == 0x1 and (elf.sections[i].flags & 0x4) == 0x4 )
}

/* ================= H1: Weak hardening (PIE/NX/RELRO/Canary/Fortify) ================= */

rule ELF_Weak_Hardening_PIE_NX_RELRO_Canary
{
  meta:
    category = "hardening"
    severity = "high"
    rationale = "Missing PIE/NX/RELRO/canary/FORTIFY increases exploitability"
  condition:
    __is_elf and __smallish_bin and
    (
      /* PIE: ET_DYN (3) обычно => PIE; ET_EXEC (2) => без PIE */
      elf.type == elf.ET_EXEC or
      /* NX: GNU_STACK (0x6474E551) не должен быть исполняемым */
      for any i in (0 .. elf.number_of_segments - 1):
        ( elf.segments[i].type == 0x6474E551 and (elf.segments[i].flags & elf.PF_X) == elf.PF_X ) or
      /* RELRO: отсутствует PT_GNU_RELRO (0x6474E552) */
      not for any i in (0 .. elf.number_of_segments - 1):
        ( elf.segments[i].type == 0x6474E552 ) or
      /* Canary: нет импорта __stack_chk_fail */
      not elf.imports("__stack_chk_fail") or
      /* Fortify: нет *_chk импортов вообще */
      not for any s in (0 .. elf.imports_count - 1):
        ( /__.*_chk/ matches elf.imports[s].name )
    )
}

/* ================= H2: RWX sections ================= */

rule ELF_Risky_RWX_Sections
{
  meta:
    category = "memory"
    severity = "high"
  condition:
    __is_elf and __smallish_bin and __has_rwX_section
}

/* ================= H3: Runtime injection / shellcode ================= */

rule ELF_Runtime_Injection_Mmap_Mprotect_Dlsym
{
  meta:
    category = "injection"
    severity = "critical"
  strings:
    $m1 = "mmap" ascii
    $m2 = "mprotect" ascii
    $dl = "dlsym" ascii
    $dl2 = "dlopen" ascii
    $wr = "memcpy" ascii
    $th = "clone" ascii
  condition:
    __is_elf and __smallish_bin and
    ( elf.imports("mmap") or $m1 ) and
    ( elf.imports("mprotect") or $m2 ) and
    ( elf.imports("dlsym") or elf.imports("dlopen") or $dl or $dl2 ) and
    ( $wr or elf.imports("memcpy") )
}

/* ================= H4: Packers / runtime unpack (UPX/SHC) ================= */

rule ELF_Packer_UPX_or_SHC
{
  meta:
    category = "packer/obfuscation"
    severity = "medium"
  strings:
    $upx = "UPX!" ascii
    $u0  = ".upx0" ascii nocase
    $u1  = ".upx1" ascii nocase
    $shc = "shc_version" ascii
    $sh2 = "__SHC_KEY" ascii
  condition:
    __is_elf and __smallish_bin and
    ( $upx or $u0 or $u1 or $shc or $sh2 or __has_rwX_section )
}

/* ================= H5: Backconnect / interactive shell ================= */

rule ELF_Backconnect_Shell
{
  meta:
    category = "c2"
    severity = "high"
  strings:
    $sh = "/bin/sh" ascii
    $nc = "nc -e /bin/sh" ascii
    $rb = "bash -i >& /dev/tcp/" ascii
    $so = "socket(" ascii
    $cn = "connect(" ascii
  condition:
    __is_elf and __smallish_bin and
    ( $sh or $nc or $rb ) and ( $so or $cn or elf.imports("connect") )
}

/* ================= H6: LD_PRELOAD / LD_AUDIT persistence & hijack ================= */

rule ELF_LD_PRELOAD_AUDIT_Persistence
{
  meta:
    category = "persistence/hijack"
    severity = "high"
  strings:
    $ldp = "LD_PRELOAD" ascii
    $lda = "LD_AUDIT" ascii
    $con = "__attribute__((constructor))" ascii
    $ini = "/etc/ld.so.preload" ascii
  condition:
    __is_elf and __smallish_bin and
    ( $ldp or $lda or $ini or $con )
}

/* ================= H7: Setuid + networking (priv abuse) ================= */

rule ELF_Setuid_Priv_Networking
{
  meta:
    category = "privilege"
    severity = "high"
  strings:
    $su1 = "setuid" ascii
    $su2 = "seteuid" ascii
    $sg1 = "setgid" ascii
    $sg2 = "setegid" ascii
    $so  = "socket(" ascii
    $cn  = "connect(" ascii
  condition:
    __is_elf and __smallish_bin and
    ( $su1 or $su2 or elf.imports("setuid") or elf.imports("seteuid") ) and
    ( $so or $cn or elf.imports("socket") or elf.imports("connect") )
}

/* ================= H8: Miners (stratum/xmrig/etc.) ================= */

rule ELF_CryptoMiner_Stratum_Family
{
  meta:
    category = "mining"
    severity = "high"
  strings:
    $st  = /stratum\+((tcp|ssl))/ nocase
    $p1  = ":3333" ascii
    $p2  = ":4444" ascii
    $p3  = ":5555" ascii
    $xm  = "xmrig" ascii nocase
    $cm  = "cpuminer" ascii
    $eth = "ethminer" ascii
  condition:
    __is_elf and __smallish_bin and
    ( $xm or $cm or $eth or ( $st and ( $p1 or $p2 or $p3 ) ) )
}

/* ================= H9: Persistence via cron/systemd ================= */

rule ELF_Persistence_Cron_Systemd
{
  meta:
    category = "persistence"
    severity = "medium"
  strings:
    $cr1 = "crontab -l" ascii
    $cr2 = "/etc/cron." ascii
    $sd1 = "/etc/systemd/system/" ascii
    $sd2 = "systemctl enable" ascii
  condition:
    __is_elf and __smallish_bin and ( any of ($cr*) or any of ($sd*) )
}

/* ================= H10: Suspicious exec chain (execve & ptrace/process_vm_writev) ================= */

rule ELF_Suspicious_Exec_Ptrace_Writev
{
  meta:
    category = "injection/evasion"
    severity = "high"
  strings:
    $ex = "execve" ascii
    $pt = "ptrace" ascii
    $vw = "process_vm_writev" ascii
  condition:
    __is_elf and __smallish_bin and
    ( elf.imports("execve") or $ex ) and
    ( elf.imports("ptrace") or $pt or elf.imports("process_vm_writev") or $vw )
}

/* ================= High-confidence combo: weak hardening + RWX + mmap/mprotect ================= */

rule ELF_HC_Combo_WeakHardening_RWX_AllocExec
{
  meta:
    category = "combo"
    severity = "critical"
  condition:
    __is_elf and __smallish_bin and
    ( ELF_Weak_Hardening_PIE_NX_RELRO_Canary ) and
    ( __has_rwX_section or ELF_Runtime_Injection_Mmap_Mprotect_Dlsym )
}
