/* rootkits_kernel_advanced.yar
 * Advanced detection for Windows kernel drivers (.sys) and Linux LKMs (.ko)
 * Author: ivan-gate
 */

import "pe"
import "elf"

/* ==================== Generic helpers ==================== */

private rule __smallish_bin { condition: filesize > 10KB and filesize < 50MB }

/* =========================================================
 *                  WINDOWS KERNEL DRIVERS
 * ========================================================= */

private rule __is_win_driver
{
  meta: note="PE, Subsystem=NATIVE (.sys), or imports to ntoskrnl"
  condition:
    uint16(0) == 0x5A4D and pe and
    (
      pe.optional_header.subsystem == pe.IMAGE_SUBSYSTEM_NATIVE or
      pe.imports("ntoskrnl.exe") or
      pe.imports("ntoskrnl")     or
      pe.imports("wdm")          or
      pe.imports("wdfldr.sys")
    )
}

/* H1: слабый харденинг / отсутствие подписи / RWX секции */
rule WIN_Kernel_Weak_Hardening_Unsigned_RWX
{
  meta: category="kernel-hardening" severity="high"
  condition:
    __is_win_driver and __smallish_bin and
    (
      // RWX section
      for any i in (0 .. pe.number_of_sections - 1):
        ( (pe.sections[i].characteristics & 0xA0000000) == 0xA0000000 )
      or
      // no Authenticode signature (IMAGE_DIRECTORY_ENTRY_SECURITY == 0)
      pe.data_directory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size == 0
      or
      // NX/ASLR likely absent for kernel driver (dll_characteristics flags)
      ( (pe.optional_header.dll_characteristics & 0x0040) == 0 ) or
      ( (pe.optional_header.dll_characteristics & 0x0100) == 0 )
    )
}

/* H2: ядро-примитивы R/W/инжект + IRP dispatch */
rule WIN_Kernel_RW_Primitives_And_Dispatch
{
  meta: category="kernel-primitives" severity="critical"
  strings:
    $mm1 = "MmMapIoSpace" ascii
    $mm2 = "MmCopyVirtualMemory" ascii
    $mm3 = "MmGetSystemRoutineAddress" ascii
    $zw1 = "ZwOpenProcess" ascii
    $zw2 = "ZwQuerySystemInformation" ascii
    $ps1 = "PsLookupProcessByProcessId" ascii
    $ir1 = "IRP_MJ_DEVICE_CONTROL" ascii
    $io1 = "IoCreateDevice" ascii
    $io2 = "IoCreateSymbolicLink" ascii
    $wd1 = "WdfDeviceCreate" ascii
  condition:
    __is_win_driver and __smallish_bin and
    ( 2 of ($mm1,$mm2,$mm3,$zw1,$ps1) ) and
    ( $ir1 or $io1 or $io2 or $wd1 )
}

/* H3: SSDT/inline hooks и callback’и */
rule WIN_Kernel_SSDT_Inline_Hooks_Callbacks
{
  meta: category="kernel-hook" severity="high"
  strings:
    $sd1 = "KeServiceDescriptorTable" ascii
    $sd2 = "KeServiceDescriptorTableShadow" ascii
    $ob1 = "ObRegisterCallbacks" ascii
    $ps2 = "PsSetCreateProcessNotifyRoutine" ascii
    $ps3 = "PsSetCreateThreadNotifyRoutine" ascii
    $cm1 = "CmRegisterCallbackEx" ascii
    $hk1 = "memcpy" ascii
  condition:
    __is_win_driver and __smallish_bin and
    ( 2 of ($sd1,$sd2,$ob1,$ps2,$ps3,$cm1) ) and $hk1
}

/* H4: EDR/ETW тамперинг */
rule WIN_Kernel_EDR_ETW_Tamper
{
  meta: category="defense-evasion" severity="high"
  strings:
    $et1 = "EtwEventWrite" ascii
    $et2 = "EtwNotificationRegister" ascii
    $ci1 = "Ci!g_CiOptions" ascii
    $ci2 = "CiOptions" ascii
    $pi1 = "PsSetLoadImageNotifyRoutine" ascii
    $pi2 = "PsRemoveLoadImageNotifyRoutine" ascii
  condition:
    __is_win_driver and __smallish_bin and ( 2 of ($et1,$et2,$pi1,$pi2,$ci1,$ci2) )
}

/* H5: обход DSE / тест-сигнинг / bcdedit */
rule WIN_Kernel_DSE_Bypass_Artifacts
{
  meta: category="boot-policy" severity="medium"
  strings:
    $bd1 = /bcdedit(\.exe)?\s+\/set\s+tests?igning\s+on/i ascii
    $bd2 = /bcdedit(\.exe)?\s+\/set\s+nointegritychecks\s+on/i ascii
    $ts1 = "testsigning" ascii
    $ci0 = "ci.dll" ascii
  condition:
    __is_win_driver and ( $bd1 or $bd2 or $ts1 or $ci0 )
}

/* H6: уязвимые драйверы (vuln-driver) поведение: IOCTL + произвольный R/W */
rule WIN_Kernel_VulnDriver_IOCTL_RW
{
  meta: category="vuln-driver" severity="high"
  strings:
    $dc1 = "DeviceIoControl" ascii
    $dc2 = "IRP_MJ_DEVICE_CONTROL" ascii
    $rw1 = "memmove" ascii
    $rw2 = "RtlCopyMemory" ascii
    $rw3 = "memcpy" ascii
  condition:
    __is_win_driver and __smallish_bin and
    ( $dc1 or $dc2 ) and ( 2 of ($rw1,$rw2,$rw3,$mm2,$mm3) )
}

/* =========================================================
 *                         LINUX LKM
 * ========================================================= */

private rule __is_lkm_rel
{
  meta: note="ELF relocatable (ET_REL) with .modinfo (typical .ko)"
  condition:
    uint32(0) == 0x7F454C46 and elf and
    elf.type == elf.ET_REL and
    for any i in (0 .. elf.number_of_sections - 1):
      ( elf.sections[i].name == ".modinfo" )
}

/* H7: базовые маркеры LKM + vermagic/license */
rule LKM_Generic_Modinfo
{
  meta: category="lkm" severity="info"
  strings:
    $mi1 = "vermagic=" ascii
    $mi2 = "license=" ascii
    $mi3 = "depends=" ascii
  condition:
    __is_lkm_rel and ( 1 of ($mi*) )
}

/* H8: ядро-хуки/символы: kallsyms/kprobe/ftrace/sys_call_table */
rule LKM_Kallsyms_Kprobe_Ftrace_Syscall
{
  meta: category="kernel-hook" severity="high"
  strings:
    $ks1 = "kallsyms_lookup_name" ascii
    $kp1 = "register_kprobe" ascii
    $kp2 = "register_kretprobe" ascii
    $ft1 = "register_ftrace_function" ascii
    $sc1 = "sys_call_table" ascii
    $wr0 = "write_cr0" ascii
    $mrw = "make_rw" ascii
  condition:
    __is_lkm_rel and __smallish_bin and
    ( $ks1 and ( $kp1 or $kp2 or $ft1 or $sc1 ) ) and ( $wr0 or $mrw or $sc1 )
}

/* H9: перехват файловой системы/скрытие: getdents64/iterate_shared */
rule LKM_Hide_Process_File_Getdents
{
  meta: category="stealth" severity="high"
  strings:
    $gd1 = "getdents64" ascii
    $gd2 = "iterate_shared" ascii
    $re1 = "readdir" ascii
    $hd1 = "hide_pid" ascii
    $hd2 = "module_hide" ascii
  condition:
    __is_lkm_rel and __smallish_bin and
    ( $gd1 or $gd2 or $re1 ) and ( $hd1 or $hd2 )
}

/* H10: сетевой бэкдор через netfilter/packet hooks */
rule LKM_Netfilter_Backdoor
{
  meta: category="c2" severity="medium"
  strings:
    $nf1 = "nf_register_net_hook" ascii
    $nf2 = "nf_register_hook" ascii
    $sk1 = "proto_ops" ascii
    $bk1 = "backdoor" ascii
    $mg1 = "magic" ascii
  condition:
    __is_lkm_rel and __smallish_bin and ( ( $nf1 or $nf2 ) and ( $bk1 or $mg1 or $sk1 ) )
}

/* H11: ftrace trampolines / text_poke (inline-хуки) */
rule LKM_Ftrace_TextPoke_Inline
{
  meta: category="kernel-hook" severity="medium"
  strings:
    $ft2 = "ftrace_ops" ascii
    $tp1 = "text_poke" ascii
    $tp2 = "stop_machine" ascii
  condition:
    __is_lkm_rel and ( $ft2 or ( $tp1 and $tp2 ) )
}

/* H12: персистентность LKM в системе */
rule LKM_Persistence_Install
{
  meta: category="persistence" severity="medium"
  strings:
    $lm1 = "/lib/modules/" ascii
    $dp1 = "depmod -a" ascii
    $in1 = "/etc/modules" ascii
    $md1 = "/sbin/modprobe" ascii
  condition:
    __is_lkm_rel and ( $lm1 or $dp1 or $in1 or $md1 )
}

/* H13: известные семейства (индикаторы строк) */
rule LKM_Family_Indicators
{
  meta: category="family-hints" severity="medium"
  strings:
    $r1 = "Diamorphine" ascii
    $r2 = "Suterusu" ascii
    $r3 = "Reptile" ascii
    $r4 = "HideProc" ascii
  condition:
    __is_lkm_rel and 1 of ($r*)
}

/* ==================== HIGH-CONFIDENCE COMBOS ==================== */

/* Windows: хуки + ядро-примитивы + ETW/EDR */
rule WIN_Kernel_HC_Hooks_Primitives_Tamper
{
  meta: category="combo" severity="critical" note="низкий FP: независимые сигналы"
  condition:
    WIN_Kernel_SSDT_Inline_Hooks_Callbacks and WIN_Kernel_RW_Primitives_And_Dispatch and WIN_Kernel_EDR_ETW_Tamper
}

/* Windows: vuln-driver стиль (IOCTL + R/W + unsigned) */
rule WIN_Kernel_HC_VulnDriver_Unsigned
{
  meta: category="combo" severity="high"
  condition:
    WIN_Kernel_VulnDriver_IOCTL_RW and WIN_Kernel_Weak_Hardening_Unsigned_RWX
}

/* Linux: kallsyms+kprobe/ftrace + getdents скрытие */
rule LKM_HC_Kallsyms_Getdents_Hide
{
  meta: category="combo" severity="critical"
  condition:
    LKM_Kallsyms_Kprobe_Ftrace_Syscall and LKM_Hide_Process_File_Getdents
}

/* Linux: netfilter-бэкдор + модульная персист */
rule LKM_HC_Netfilter_Persist
{
  meta: category="combo" severity="high"
  condition:
    LKM_Netfilter_Backdoor and LKM_Persistence_Install
}
