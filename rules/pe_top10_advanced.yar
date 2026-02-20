/* pe_top10_advanced.yar
 * Unified ruleset for top-10 risky patterns in Windows PE binaries.
 * Focus: low-FP triage, speed, clear signals; safe to run at scale.
 * Author: ivan-gate (consolidated & improved)
 */

private rule __is_pe {
  condition: uint16(0) == 0x5A4D and pe
}

private rule __smallish {
  condition: filesize > 10KB and filesize < 50MB
}

/* ---------- H1: WEAK HARDENING (no ASLR/NX/CFG, RWX sections) ---------- */

rule PE_Weak_Hardening_ASLR_NX_CFG
{
  meta:
    category = "hardening"
    severity = "high"
    rationale = "Missing ASLR/NX/CFG and/or RWX sections increases exploitability"
  condition:
    __is_pe and __smallish and
    (
      /* ASLR: DYNAMIC_BASE (0x40), NX: NX_COMPAT (0x0100), CFG: GUARD (0x4000).
         YARA pe module commonly exposes lowercased dll_characteristics. */
      ( (pe.optional_header.dll_characteristics & 0x0040) == 0 ) or
      ( (pe.optional_header.dll_characteristics & 0x0100) == 0 ) or
      ( (pe.optional_header.dll_characteristics & 0x4000) == 0 )
    ) or
    for any i in (0 .. pe.number_of_sections - 1):
      (
        /* RWX: WRITE (0x80000000) + EXECUTE (0x20000000) */
        (pe.sections[i].characteristics & 0xA0000000) == 0xA0000000
      )
}

/* ---------- H2: MEMORY INJECTION / SHELLCODE (VirtualAlloc + write + thread) ---------- */

rule PE_ProcessInjection_MemAlloc_Write_Thread
{
  meta:
    category = "injection"
    severity = "critical"
  condition:
    __is_pe and __smallish and
    (
      pe.imports("kernel32.dll", "VirtualAlloc") or
      pe.imports("kernel32.dll", "VirtualAllocEx") or
      pe.imports("kernel32.dll", "VirtualProtect")
    ) and
    (
      pe.imports("kernel32.dll", "WriteProcessMemory") or
      pe.imports("ntdll.dll",    "NtWriteVirtualMemory")
    ) and
    (
      pe.imports("kernel32.dll", "CreateRemoteThread") or
      pe.imports("kernel32.dll", "QueueUserAPC") or
      pe.imports("ntdll.dll",    "NtCreateThreadEx")
    )
}

/* ---------- H3: PACKERS / RUNTIME UNPACK (UPX + GetProcAddress/LoadLibrary + RWX) ---------- */

rule PE_Packer_UPX_or_RuntimeUnpack
{
  meta:
    category = "packer/obfuscation"
    severity = "medium"
  strings:
    $upx1 = "UPX!" ascii
    $s0 = ".UPX0" ascii
    $s1 = ".UPX1" ascii
  condition:
    __is_pe and
    (
      $upx1 or $s0 or $s1 or
      (
        pe.imports("kernel32.dll","GetProcAddress") and
        pe.imports("kernel32.dll","LoadLibraryA") and
        for any i in (0 .. pe.number_of_sections - 1):
          ( (pe.sections[i].characteristics & 0xA0000000) == 0xA0000000 )
      )
    )
}

/* ---------- H4: NETWORK EXFIL / C2 (WinHTTP/WinInet + multipart/gate.php) ---------- */

rule PE_Exfil_Net_Multipart_Gate
{
  meta:
    category = "exfiltration"
    severity = "high"
  strings:
    $m1 = "multipart/form-data; boundary=" ascii
    $g1 = "/gate.php" ascii
    $g2 = "/upload.php" ascii
    $ua = "User-Agent:" ascii
  condition:
    __is_pe and __smallish and
    (
      pe.imports("winhttp.dll","WinHttpSendRequest") or
      pe.imports("wininet.dll","InternetOpenA") or
      pe.imports("wininet.dll","InternetOpenW")
    ) and
    ( $m1 or $g1 or $g2 or $ua )
}

/* ---------- H5: CREDENTIAL ACCESS (DPAPI/Vault + Chromium/Firefox artifacts) ---------- */

rule PE_CredSteal_DPAPI_BrowserArtifacts
{
  meta:
    category = "credential-access"
    severity = "high"
  strings:
    $ch1 = "Login Data" ascii wide
    $ch2 = "Cookies" ascii wide
    $ch3 = "Web Data" ascii wide
    $ch4 = "Local State" ascii wide
    $ff1 = "key4.db" ascii wide
    $ff2 = "logins.json" ascii wide
  condition:
    __is_pe and __smallish and
    (
      pe.imports("crypt32.dll","CryptUnprotectData") or
      pe.imports("vaultcli.dll","VaultEnumerateItems") or
      pe.imports("vaultcli.dll","VaultGetItem")
    ) and
    ( 2 of ($ch*) or 2 of ($ff*) )
}

/* ---------- H6: KEYLOGGER / HOOKS ---------- */

rule PE_Keylogger_Hooks_Keyboard
{
  meta:
    category = "collection"
    severity = "high"
  condition:
    __is_pe and __smallish and
    (
      pe.imports("user32.dll","SetWindowsHookExA") or
      pe.imports("user32.dll","SetWindowsHookExW") or
      pe.imports("user32.dll","GetAsyncKeyState")
    ) and
    (
      pe.imports("user32.dll","CallNextHookEx") or
      pe.imports("user32.dll","UnhookWindowsHookEx")
    )
}

/* ---------- H7: PERSISTENCE (Run/RunOnce + SchTasks + Startup) ---------- */

rule PE_Persistence_Run_Schtasks_Startup
{
  meta:
    category = "persistence"
    severity = "medium"
  strings:
    $rk1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
    $rk2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
    $st1 = /SCHTASKS\.EXE\s+\/Create\s+\/SC\s+(ONLOGON|ONSTART|MINUTE)/ nocase ascii
    $sp1 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii wide
  condition:
    __is_pe and __smallish and
    ( $rk1 or $rk2 or $sp1 or $st1 )
}

/* ---------- H8: RANSOMWARE MARKERS (vssadmin/bcdedit/wbadmin + mass ext changes) ---------- */

rule PE_Ransomware_TTPs_VSS_BootCfg
{
  meta:
    category = "ransomware"
    severity = "critical"
  strings:
    $vss = /vssadmin(\.exe)?\s+delete\s+shadows/i ascii
    $wba = /wbadmin(\.exe)?\s+delete\s+catalog/i ascii
    $bcd = /bcdedit(\.exe)?\s+\/set\s+{default}\s+recoveryenabled\s+no/i ascii
    $sr  = /bcdedit(\.exe)?\s+\/set\s+{default}\s+bootstatuspolicy\s+ignoreallfailures/i ascii
    $enc = /AES-(GCM|CBC)|ChaCha20|Salsa20|RSA-2048|Curve25519/i ascii
  condition:
    __is_pe and __smallish and
    ( $vss or $wba or $bcd or $sr ) and
    ( $enc or pe.imports("advapi32.dll","CryptAcquireContextA") or pe.imports("bcrypt.dll","BCryptGenRandom") )
}

/* ---------- H9: ANTI-VM / ANTI-DEBUG ---------- */

rule PE_AntiVM_AntiDebug_Heur
{
  meta:
    category = "evasion"
    severity = "medium"
  strings:
    $v1 = "VBox" ascii
    $v2 = "VMware" ascii
    $v3 = "QEMU" ascii
  condition:
    __is_pe and __smallish and
    (
      pe.imports("kernel32.dll","IsDebuggerPresent") or
      pe.imports("kernel32.dll","CheckRemoteDebuggerPresent") or
      pe.imports("ntdll.dll","NtQueryInformationProcess")
    ) or
    1 of ($v*)
}

/* ---------- H10: LOLBINS ABUSE (powershell -enc, mshta/http, rundll32 js/zipfldr) ---------- */

rule PE_LOLBins_Abuse
{
  meta:
    category = "lateral/execution"
    severity = "medium"
  strings:
    $ps1 = /powershell(\.exe)?\s+(-enc|--encodedcommand)\s+[A-Za-z0-9+/=]{20,}/ nocase ascii
    $hta = /mshta(\.exe)?\s+https?:\/\// nocase ascii
    $rdl = /rundll32(\.exe)?\s+(javascript:|zipfldr\.dll)/ nocase ascii
    $reg = /regsvr32(\.exe)?\s+\/s\s+\/i\s+https?:\/\// nocase ascii
    $wsc = /wscript(\.exe)?\s+\/\/E:jscript/ nocase ascii
  condition:
    __is_pe and __smallish and ( $ps1 or $hta or $rdl or $reg or $wsc )
}

/* ---------- HIGH-CONFIDENCE COMBO (few FPs): DPAPI + Browser + Net ---------- */

rule PE_HC_Stealer_DPAPI_Browser_Net
{
  meta:
    category = "combo"
    severity = "critical"
    note     = "Multiple independent signals combined"
  strings:
    $c1 = "Login Data" ascii wide
    $c2 = "Cookies" ascii wide
    $c3 = "Web Data" ascii wide
  condition:
    __is_pe and __smallish and
    ( pe.imports("crypt32.dll","CryptUnprotectData") or pe.imports("vaultcli.dll","VaultGetItem") ) and
    ( 2 of ($c*) ) and
    (
      pe.imports("winhttp.dll","WinHttpSendRequest") or
      pe.imports("wininet.dll","InternetOpenA") or
      pe.imports("wininet.dll","InternetOpenW")
    )
}
