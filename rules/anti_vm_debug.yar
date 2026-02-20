/* anti_debug_vm_advanced.yar
 * Expanded anti-debug / anti-VM for PE & ELF
 * Author: ivan-gate
 */

import "pe"
import "elf"

/* ============ Helpers ============ */
private rule __is_pe { condition: uint16(0) == 0x5A4D and pe }
private rule __is_elf { condition: uint32(0) == 0x7F454C46 and elf }
private rule __smallish { condition: filesize > 10KB and filesize < 200MB }

/* ===================== PE: Anti-Debug ===================== */

rule PE_AntiDebug_APIs_And_PEB
{
  meta:
    category = "anti-debug"
    severity = "medium"
  strings:
    // WinAPI
    $ad1 = "IsDebuggerPresent" ascii wide
    $ad2 = "CheckRemoteDebuggerPresent" ascii wide
    $ad3 = "OutputDebugStringA" ascii wide
    $ad4 = "OutputDebugStringW" ascii wide
    $ad5 = "DbgUiConnectToDbg" ascii wide
    $ad6 = "DbgBreakPoint" ascii wide
    $ad7 = "DbgPrint" ascii wide
    $ad8 = "NtQueryInformationProcess" ascii wide
    $ad9 = "ZwQueryInformationProcess" ascii wide
    $qob = "NtQueryObject" ascii wide
    $ctc = "GetThreadContext" ascii wide
    $stc = "SetThreadContext" ascii wide
    $veh = "AddVectoredExceptionHandler" ascii wide
    $seh = "__except" ascii
    $seh2 = "__try" ascii
    $seh3 = "SetUnhandledExceptionFilter" ascii wide
    $seh4 = "UnhandledExceptionFilter" ascii wide
    $seh5 = "RaiseException" ascii wide
    $exs = "ContinueDebugEvent" ascii wide
    $clh = "CloseHandle" ascii wide
    // PEB/NtGlobalFlag checks
    $peb1 = "BeingDebugged" ascii wide
    $peb2 = "NtGlobalFlag" ascii wide
    $flg1 = "\x00\x30\x00\x00" /* FLG_HEAP_ENABLE_TAIL_CHECK */ 
    $flg2 = "\x00\x40\x00\x00" /* FLG_HEAP_ENABLE_FREE_CHECK */
    $flg3 = "\x00\x20\x00\x00" /* FLG_HEAP_VALIDATE_PARAMETERS */
    // Privilege
    $prv = "SeDebugPrivilege" ascii wide
  condition:
    __is_pe and __smallish and
    (
      // Imports
      pe.imports("kernel32.dll","IsDebuggerPresent") or
      pe.imports("kernel32.dll","CheckRemoteDebuggerPresent") or
      pe.imports("kernel32.dll","GetThreadContext") or
      pe.imports("kernel32.dll","SetThreadContext") or
      pe.imports("kernel32.dll","OutputDebugStringA") or
      pe.imports("kernel32.dll","OutputDebugStringW") or
      pe.imports("ntdll.dll","NtQueryInformationProcess") or
      pe.imports("ntdll.dll","NtQueryObject") or
      pe.imports("kernel32.dll","AddVectoredExceptionHandler") or
      pe.imports("kernel32.dll","SetUnhandledExceptionFilter") or
      // Strings fallback (statically linked / obfuscated imports)
      3 of ($ad*,$qob,$ctc,$stc,$veh,$seh,$seh2,$seh3,$seh4,$exs,$clh,$peb*,$prv) or
      // Magic NtGlobalFlag constants seen in binaries that probe heap flags
      any of ($flg*)
    )
}

rule PE_AntiDebug_Timing_CPU_Tricks
{
  meta:
    category = "anti-debug"
    severity = "medium"
  strings:
    $qpc = "QueryPerformanceCounter" ascii wide
    $qpf = "QueryPerformanceFrequency" ascii wide
    $slp = "Sleep" ascii wide
    $sks = "SleepConditionVariableCS" ascii wide
    $rdt = "RDTSC" ascii
    $tic = "GetTickCount" ascii wide
    $ti6 = "GetTickCount64" ascii wide
    $etr = "timeGetTime" ascii wide
  condition:
    __is_pe and __smallish and
    (
      pe.imports("kernel32.dll","QueryPerformanceCounter") or
      pe.imports("kernel32.dll","GetTickCount") or
      pe.imports("kernel32.dll","GetTickCount64") or
      // strings fallback
      2 of ($qpc,$qpf,$slp,$sks,$rdt,$tic,$ti6,$etr)
    )
}

rule PE_AntiDebug_DebugObjects_Handles
{
  meta:
    category = "anti-debug"
    severity = "medium"
  strings:
    $dbg = "\\Device\\NamedPipe\\ntsvcs" ascii
    $do1 = "DebugObject" ascii
    $obq = "NtQueryObject" ascii wide
    $ob2 = "ObjectTypes" ascii
    $ob3 = "SystemHandleInformation" ascii
  condition:
    __is_pe and __smallish and
    (
      pe.imports("ntdll.dll","NtQueryObject") or
      2 of ($do1,$obq,$ob2,$ob3) or
      $dbg
    )
}

/* ===================== PE: Anti-VM (useful side-by-side) ===================== */

rule PE_AntiVM_Artifacts_CPUID_Parent
{
  meta:
    category = "anti-vm"
    severity = "medium"
  strings:
    $vm1 = "VBox" ascii
    $vm2 = "VMware" ascii
    $vm3 = "KVMKVMKVM" ascii
    $vm4 = "prl_tg" ascii
    $vm5 = "QEMU" ascii
    $wmi = "SELECT * FROM Win32_ComputerSystem" ascii
    $pp  = "ParentProcessId" ascii
    $cp  = "CPUID" ascii
    $hv  = "HYPERVISOR" ascii nocase
  condition:
    __is_pe and __smallish and
    ( 2 of ($vm*) or $wmi or $pp or $cp or $hv )
}

/* ===================== High-Confidence PE combo ===================== */

rule PE_HC_AntiDebug_Combo
{
  meta:
    category = "anti-debug"
    severity = "high"
    note     = "Multiple independent anti-debug signals"
  condition:
    __is_pe and __smallish and
    ( PE_AntiDebug_APIs_And_PEB ) and
    ( PE_AntiDebug_Timing_CPU_Tricks or PE_AntiDebug_DebugObjects_Handles )
}

/* ===================== ELF: Anti-Debug ===================== */

rule ELF_AntiDebug_Ptrace_Prctl_Status
{
  meta:
    category = "anti-debug"
    severity = "medium"
  strings:
    $pt1 = "ptrace" ascii
    $pt2 = "PTRACE_TRACEME" ascii
    $pc1 = "prctl" ascii
    $pc2 = "PR_SET_DUMPABLE" ascii
    $pc3 = "PR_SET_PTRACER" ascii
    $gb1 = "getppid" ascii
    $st1 = "/proc/self/status" ascii
    $trc = "TracerPid:" ascii
    $rt1 = "raise(SIGTRAP)" ascii
    $si1 = "sigaction" ascii
    $se1 = "__attribute__((constructor))" ascii
  condition:
    __is_elf and __smallish and
    (
      elf.imports("ptrace") or $pt1 or $pt2 or
      elf.imports("prctl") or 1 of ($pc2,$pc3) or
      ( $st1 and $trc ) or
      ( elf.imports("getppid") and ( $rt1 or $si1 ) ) or
      $se1
    )
}

rule ELF_AntiDebug_Timing_rdtsc_clock
{
  meta:
    category = "anti-debug"
    severity = "medium"
  strings:
    $rd = "rdtsc" ascii
    $cl = "clock_gettime" ascii
    $sl = "nanosleep" ascii
    $al = "alarm" ascii
  condition:
    __is_elf and __smallish and
    ( elf.imports("clock_gettime") or elf.imports("nanosleep") or 2 of ($rd,$cl,$sl,$al) )
}

/* ===================== High-Confidence ELF combo ===================== */

rule ELF_HC_AntiDebug_Combo
{
  meta:
    category = "anti-debug"
    severity = "high"
  condition:
    __is_elf and __smallish and
    ELF_AntiDebug_Ptrace_Prctl_Status and
    ( ELF_AntiDebug_Timing_rdtsc_clock )
}
