/* mach_o_macos_advanced.yar
 * Advanced detection for macOS: Mach-O binaries and persistence artifacts.
 * Author: ivan-gate
 */

import "macho"

/* ================= Helpers ================= */

private rule __is_macho
{
  condition:
    // thin (32/64) or FAT (universal)
    uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or uint32(0) == 0xBEBAFECA
}

private rule __smallish { condition: filesize > 10KB and filesize < 200MB }

private rule __rwx_segment
{
  // VM_PROT: READ=1, WRITE=2, EXEC=4
  condition:
    for any i in (0 .. macho.nsegments - 1):
      ( (macho.segments[i].initprot & 0x2) == 0x2 and (macho.segments[i].initprot & 0x4) == 0x4 )
}

/* ================= H1: Weak hardening (PIE/NX/RWX/unsigned) ================= */

rule MACHO_Weak_Hardening_PIE_NX_RWX_Unsigned
{
  meta:
    category = "hardening"
    severity = "high"
    rationale = "No PIE/NX or RWX segment; missing code signature"
  condition:
    __is_macho and __smallish and
    (
      // No PIE: MH_PIE (0x00200000) not set
      ( (macho.flags & 0x00200000) == 0 ) or
      // Allow stack exec: MH_ALLOW_STACK_EXECUTION (0x00020000)
      ( (macho.flags & 0x00020000) == 0x00020000 ) or
      // RWX mem
      __rwx_segment or
      // No code signature command (LC_CODE_SIGNATURE = 0x1d)
      not for any c in (0 .. macho.ncmds - 1): ( macho.commands[c].cmd == 0x1d )
    )
}

/* ================= H2: Injection / debug-evasion primitives ================= */

rule MACHO_Process_Injection_Primitives
{
  meta:
    category = "injection"
    severity = "critical"
  strings:
    $tfp  = "task_for_pid" ascii
    $mww  = "mach_vm_write" ascii
    $mpp  = "mach_vm_protect" ascii
    $thr  = "thread_create" ascii
    $dl1  = "dlopen" ascii
    $dl2  = "dlsym" ascii
  condition:
    __is_macho and __smallish and
    ( $tfp or $mww or $mpp or $thr ) and ( $dl1 or $dl2 )
}

rule MACHO_AntiDebug_DenyAttach_and_Sysctl
{
  meta:
    category = "anti-debug"
    severity = "medium"
  strings:
    $pt   = "ptrace" ascii
    $den  = "PT_DENY_ATTACH" ascii
    $sys  = "sysctl" ascii
    $kp   = "KERN_PROC" ascii
    $spwn = "posix_spawn" ascii
  condition:
    __is_macho and __smallish and
    ( ($pt and $den) or ($sys and $kp) or ($pt and $spwn) )
}

/* ================= H3: Reverse shells / backconnect ================= */

rule MACHO_Backconnect_Shells
{
  meta:
    category = "c2"
    severity = "high"
  strings:
    $sh1 = "/bin/sh" ascii
    $sh2 = "bash -i >& /dev/tcp/" ascii
    $nc1 = "nc -e /bin/sh" ascii
    $py1 = "python -c" ascii
    $rb1 = "ruby -rsocket" ascii
    $hk  = "connect(" ascii
  condition:
    __is_macho and __smallish and
    ( ($sh1 and $hk) or $sh2 or $nc1 or $py1 or $rb1 )
}

/* ================= H4: Persistence (LaunchAgents/Daemons, LoginHook, shells) ================= */

rule PLIST_LaunchAgents_Daemons_Suspicious
{
  meta:
    category = "persistence"
    severity = "high"
  strings:
    $ka = "<key>Label</key>" ascii
    $kb = "<key>ProgramArguments</key>" ascii
    $kc = "<key>RunAtLoad</key>" ascii
    $kd = "<key>KeepAlive</key>" ascii
    $p1 = "/Library/LaunchAgents/" ascii
    $p2 = "/Library/LaunchDaemons/" ascii
    $p3 = "/Users/" ascii
  condition:
    __smallish and ( uint32(0) == 0x3C3F786D /* '<?xm' XML */ or uint32(0) == 0x62706C69 /* 'bpli' binplist */ ) and
    ( 2 of ($ka,$kb,$kc,$kd) ) and ( $p1 or $p2 or $p3 )
}

rule MACHO_Persistence_LoginHook_Shells
{
  meta:
    category = "persistence"
    severity = "medium"
  strings:
    $lh1 = "defaults write com.apple.loginwindow LoginHook" ascii
    $lh2 = "/etc/zshrc" ascii
    $lh3 = "/etc/profile" ascii
    $lh4 = "~/.zprofile" ascii
  condition:
    __is_macho and ( $lh1 or $lh2 or $lh3 or $lh4 )
}

/* ================= H5: Gatekeeper / quarantine / TCC & AppleScript ================= */

rule MACHO_Gatekeeper_Quarantine_Bypass
{
  meta:
    category = "evasion"
    severity = "high"
  strings:
    $xa = "xattr -d com.apple.quarantine" ascii
    $sp = "spctl --master-disable" ascii
    $sp2= "spctl --add" ascii
  condition:
    __is_macho and __smallish and ( $xa or $sp or $sp2 )
}

rule MACHO_AppleScript_TCC_Abuse
{
  meta:
    category = "evasion/automation"
    severity = "medium"
  strings:
    $osas = "osascript -e" ascii
    $dos  = "do shell script" ascii
    $evt  = "NSAppleScript" ascii
  condition:
    __is_macho and ( $osas or $dos or $evt )
}

/* ================= H6: Keychain & browser secrets ================= */

rule MACHO_Keychain_Steal_APIs
{
  meta:
    category = "credential-access"
    severity = "high"
  strings:
    $kc1 = "SecKeychainCopyMatching" ascii
    $kc2 = "SecItemCopyMatching" ascii
    $kc3 = "kSecClassGenericPassword" ascii
    $kc4 = "kSecAttrAccount" ascii
  condition:
    __is_macho and __smallish and ( 2 of ($kc*) )
}

rule MACHO_Browser_Sensitive_Paths
{
  meta:
    category = "credential-access"
    severity = "medium"
  strings:
    $ch1 = "Library/Application Support/Google/Chrome/Default/Login Data" ascii
    $ch2 = "Library/Application Support/Google/Chrome/Default/Cookies" ascii
    $ff1 = "Library/Application Support/Firefox/Profiles" ascii
    $sf1 = "Keychains/login.keychain-db" ascii
  condition:
    __is_macho and ( 1 of ($ch1,$ch2,$ff1,$sf1) )
}

/* ================= H7: DYLD injection & env abuse ================= */

rule MACHO_DYLD_Env_Abuse
{
  meta:
    category = "injection"
    severity = "high"
  strings:
    $d1 = "DYLD_INSERT_LIBRARIES" ascii
    $d2 = "DYLD_PRINT_TO_FILE" ascii
    $d3 = "DYLD_LIBRARY_PATH" ascii
  condition:
    __is_macho and ( $d1 or $d2 or $d3 )
}

/* ================= H8: Network downloader / curl / URLSession ================= */

rule MACHO_Downloader_URLSession_Curl
{
  meta:
    category = "loader"
    severity = "medium"
  strings:
    $cu = "curl -fsSL" ascii
    $cf = "CFNetwork" ascii
    $ns = "NSURLSession" ascii
    $dl = "downloadTaskWithURL" ascii
  condition:
    __is_macho and __smallish and ( $cu or ( $cf and ( $ns or $dl ) ) )
}

/* ================= HIGH-CONFIDENCE COMBOS (low FP) ================= */

rule MACHO_HC_Keychain_Exfil_Combo
{
  meta:
    category = "combo"
    severity = "critical"
    note     = "Keychain APIs + network downloader"
  condition:
    MACHO_Keychain_Steal_APIs and MACHO_Downloader_URLSession_Curl
}

rule MACHO_HC_Injection_Persist_Combo
{
  meta:
    category = "combo"
    severity = "critical"
    note     = "Injection primitives + LaunchAgents/Daemons/plist"
  condition:
    MACHO_Process_Injection_Primitives and ( PLIST_LaunchAgents_Daemons_Suspicious or MACHO_Persistence_LoginHook_Shells )
}

rule MACHO_HC_Quarantine_Bypass_Backconnect
{
  meta:
    category = "combo"
    severity = "high"
    note     = "Gatekeeper/quarantine bypass + reverse shell/C2"
  condition:
    MACHO_Gatekeeper_Quarantine_Bypass and MACHO_Backconnect_Shells
}
