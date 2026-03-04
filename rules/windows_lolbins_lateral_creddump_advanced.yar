/* windows_lolbins_lateral_creddump_advanced.yar
 * Windows LOLBins, Lateral Movement, and Credential Dumping (PE & script-like text)
 * Author: ivan-gate
 */

import "pe"

/* ================= Helpers ================= */
private rule __is_pe      { condition: uint16(0) == 0x5A4D and pe }
private rule __smallish   { condition: filesize > 20KB and filesize < 200MB }
private rule __is_text    { condition: filesize > 200 and filesize < 5MB and !__is_pe }

/* ================= 1) Cred dumping: LSASS (MiniDump, comsvcs, ProcDump) ================= */

rule PE_CredDump_LSASS_MiniDump_APIs
{
  meta: category="cred-dump" technique="T1003.001" severity="critical" rationale="MiniDumpWriteDump + lsass + SeDebugPrivilege"
  strings:
    $mdw  = "MiniDumpWriteDump" ascii
    $dbg  = "SeDebugPrivilege" ascii
    $ls   = /lsass\.exe/i ascii
    $op   = "OpenProcess" ascii
  condition:
    __is_pe and __smallish and $mdw and ($ls or $op) and $dbg
}

rule PE_CredDump_Comsvcs_Rundll32
{
  meta: category="cred-dump" severity="high" rationale="comsvcs.dll MiniDump via rundll32"
  strings:
    $cs = /comsvcs\.dll/i ascii
    $md = /MiniDump/i ascii
    $rd = /rundll32(\.exe)?\s+[^\r\n]*comsvcs\.dll/i ascii
  condition:
    (__is_pe and __smallish and ( $cs and $md )) or ( __is_text and $rd )
}

rule PE_CredDump_ProcDump_LSASS
{
  meta: category="cred-dump" severity="high" rationale="procdump -ma lsass.exe / AcceptEula"
  strings:
    $pd1 = /procdump(\.exe)?/i ascii
    $pd2 = /-ma\s+lsass\.exe/i ascii
    $pd3 = /-accepteula/i ascii
  condition:
    __is_text and ( $pd1 and ( $pd2 or $pd3 ) )
}

/* ================= 2) Cred dumping: SAM/SYSTEM/SECURITY (registry save) ================= */

rule Win_RegSave_SAM_System_Security
{
  meta: category="cred-dump" technique="T1003.002" severity="high" rationale="reg save HKLM\\SAM/SYSTEM/SECURITY"
  strings:
    $rg = /reg(\.exe)?\s+save\s+HKLM\\(SAM|SYSTEM|SECURITY)\s+[A-Za-z0-9_:\\\.]+/i ascii
    $rv = /reg(\.exe)?\s+save\s+HKEY_LOCAL_MACHINE\\(SAM|SYSTEM|SECURITY)/i ascii
  condition:
    __is_text and ( $rg or $rv )
}

/* ================= 2b) Defense Evasion: Firewall disable / IFEO ================= */

rule PE_Defense_Disable_Firewall
{
  meta: category="defense-evasion" technique="T1562" severity="high" rationale="netsh advfirewall / INetFwPolicy2"
  strings:
    $f1 = /advfirewall\s+set\s+allprofiles\s+state\s+off/i ascii
    $f2 = "INetFwPolicy2" ascii
    $f3 = "netsh advfirewall" ascii nocase
  condition:
    (__is_pe and __smallish and ($f1 or $f2 or $f3)) or (__is_text and ($f1 or $f2 or $f3))
}

rule PE_IFEO_Injection
{
  meta: category="persistence" technique="T1546.012" severity="high" rationale="Image File Execution Options + Debugger"
  strings:
    $i1 = "Image File Execution Options" ascii nocase
    $i2 = "Debugger" ascii
    $i3 = /Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options/i ascii
  condition:
    (__is_pe and __smallish and $i1 and $i2) or (__is_text and $i1 and $i2) or (__is_pe and $i3 and $i2)
}

/* ================= 3) Mimikatz-like артефакты ================= */

rule PE_Mimikatz_Strings_Core
{
  meta: category="cred-dump/family-hints" severity="high" rationale="sekurlsa/privilege::debug/lsadump"
  strings:
    $s1 = "sekurlsa::logonpasswords" ascii nocase
    $s2 = "privilege::debug" ascii nocase
    $s3 = "lsadump::sam" ascii nocase
    $s4 = "wdigest" ascii nocase
    $s5 = "kerberos" ascii nocase
    $s6 = "mimidrv" ascii nocase
  condition:
    __is_pe and __smallish and 2 of ($s*)
}

/* ================= 4) Lateral: SCM/Service create + remote shares ================= */

rule PE_Lateral_SCM_Service_Create
{
  meta: category="lateral" severity="high" rationale="CreateService/OpenSCManager/StartService"
  condition:
    __is_pe and __smallish and
    (
      pe.imports("advapi32.dll","OpenSCManagerW") or
      pe.imports("advapi32.dll","CreateServiceW")
    ) and
    ( pe.imports("advapi32.dll","StartServiceW") or pe.imports("advapi32.dll","StartServiceA") )
}

rule Win_Lateral_PsExec_PSEXESVC_Artifacts
{
  meta: category="lateral" severity="medium" rationale="PsExec service drop / ADMIN$"
  strings:
    $px1 = "PSEXESVC" ascii
    $px2 = /\\\\[A-Za-z0-9\.\-\_]{1,63}\\ADMIN\$/ ascii
    $px3 = /-accepteula/i ascii
  condition:
    ( __is_text and ( $px2 or ( $px1 and $px3 ) ) ) or ( __is_pe and __smallish and $px1 )
}

/* ================= 5) Lateral: WMI/WMIC/WinRM/SMB copy ================= */

rule Win_Lateral_WMIC_Process_Create
{
  meta: category="lateral" severity="medium" rationale="wmic /node: ... process call create"
  strings:
    $w1 = /wmic(\.exe)?\s+\/node:\s*[^\s]+\s+process\s+call\s+create/i ascii
    $w2 = /wmic(\.exe)?\s+process\s+call\s+create/i ascii
  condition:
    __is_text and ( $w1 or $w2 )
}

rule Win_Lateral_WinRM_PowerShell_Remoting
{
  meta: category="lateral" severity="medium" rationale="Enter-PSSession/Invoke-Command / WinRM"
  strings:
    $r1 = /Enter-PSSession\s+-ComputerName/i ascii
    $r2 = /Invoke-Command\s+-ComputerName/i ascii
    $r3 = /winrm\s+set|winrm\s+quickconfig/i ascii
  condition:
    __is_text and ( $r1 or $r2 or $r3 )
}

rule PE_Lateral_Tool_Transfer_Strings
{
  meta: category="lateral" technique="T1570" severity="high" rationale="CopyFileEx + UNC C$/ADMIN$"
  strings:
    $c1 = "CopyFileEx" ascii
    $c2 = "NetUseAdd" ascii
    $u1 = /\\\\[^\x00]+\\C\$/ ascii
    $u2 = /\\\\[^\x00]+\\ADMIN\$/ ascii
  condition:
    __is_pe and $c1 and ($u1 or $u2 or $c2)
}

rule Win_Lateral_SMB_Copy_And_Exec
{
  meta: category="lateral" technique="T1570" severity="medium" rationale="copy через ADMIN$ + ат/schtasks выполнение"
  strings:
    $c1 = /copy\s+[A-Za-z0-9_:\\\.]+\\\S+\s+\\\\[^\s]+\\ADMIN\$/i ascii
    $a1 = /AT\s+\\\\[^\s]+\s+\d{1,2}:\d{2}\s+\/interactive\s+/i ascii
    $s1 = /SCHTASKS\.EXE\s+\/Create\s+\/S\s+[^\s]+\s+\/TR\s+/i ascii
  condition:
    __is_text and ( $c1 or $a1 or $s1 )
}

/* ================= 6) LOLBins: mshta/regsvr32/msbuild/installutil/certutil/bitsadmin/msiexec/rundll32 ================= */

rule LOLBINS_mshta_remotescript
{
  meta: category="lolbins" severity="high" rationale="mshta http(s) remote script"
  strings:
    $h1 = /mshta(\.exe)?\s+https?:\/\//i ascii
  condition:
    __is_text and $h1
}

rule LOLBINS_regsvr32_sct_scrobj
{
  meta: category="lolbins" severity="high" rationale="regsvr32 /i scrobj.dll remote sct"
  strings:
    $r1 = /regsvr32(\.exe)?\s+\/[sqi ]*\/i\s+https?:\/\/[^\s]+/i ascii
    $r2 = /scrobj\.dll/i ascii
  condition:
    __is_text and ( $r1 or ($r2 and /regsvr32/i) )
}

rule LOLBINS_msbuild_inline_task
{
  meta: category="lolbins" severity="medium" rationale="msbuild inline task code exec"
  strings:
    $m1 = /msbuild(\.exe)?\s+[^\r\n]+\.xml/i ascii
    $i1 = /<UsingTask\s+TaskFactory=/i ascii
    $i2 = /CodeTaskFactory/i ascii
  condition:
    __is_text and ( $m1 and ( $i1 or $i2 ) )
}

rule LOLBINS_installutil_exec
{
  meta: category="lolbins" severity="medium" rationale="InstallUtil arbitrary assembly exec"
  strings:
    $i1 = /InstallUtil(\.exe)?\s+[^\r\n]+\.exe/i ascii
  condition:
    __is_text and $i1
}

rule LOLBINS_certutil_urlcache_decode
{
  meta: category="lolbins" severity="medium" rationale="certutil -urlcache/-decode loader"
  strings:
    $c1 = /certutil(\.exe)?\s+(-urlcache|-verifyctl|-decode)/i ascii
  condition:
    __is_text and $c1
}

rule LOLBINS_bitsadmin_transfer
{
  meta: category="lolbins" severity="medium" rationale="bitsadmin transfer http(s) loader"
  strings:
    $b1 = /bitsadmin(\.exe)?\s+\/transfer\s+/i ascii
  condition:
    __is_text and $b1
}

rule LOLBINS_msiexec_remote
{
  meta: category="lolbins" severity="medium" rationale="msiexec /i http(s)://..."
  strings:
    $x1 = /msiexec(\.exe)?\s+\/i\s+https?:\/\//i ascii
  condition:
    __is_text and $x1
}

rule LOLBINS_rundll32_javascript
{
  meta: category="lolbins" severity="medium" rationale="rundll32 javascript:code,RunDLL"
  strings:
    $rj = /rundll32(\.exe)?\s+javascript:[^\r\n]+,RunDLL/i ascii
  condition:
    __is_text and $rj
}

/* ================= 7) High-Confidence COMBOS (низкий FP) ================= */

/* HC1: MiniDump + lsass + SeDebugPrivilege */
rule HC_LSASS_Dump_Triplet
{
  meta: category="combo" severity="critical"
  condition:
    PE_CredDump_LSASS_MiniDump_APIs
}

/* HC2: Registry SAM/SYSTEM dump + lateral exec */
rule HC_SAM_Dump_And_Lateral
{
  meta: category="combo" severity="high"
  condition:
    Win_RegSave_SAM_System_Security and ( Win_Lateral_WMIC_Process_Create or Win_Lateral_SMB_Copy_And_Exec or Win_Lateral_WinRM_PowerShell_Remoting )
}

/* HC3: PsExec artifacts + SCM APIs (service create) */
rule HC_PsExec_SCM_Combo
{
  meta: category="combo" severity="high"
  condition:
    Win_Lateral_PsExec_PSEXESVC_Artifacts and PE_Lateral_SCM_Service_Create
}

/* HC4: LOLBins chain (download+execute) */
rule HC_LOLBins_Downloader_Chain
{
  meta: category="combo" severity="high"
  condition:
    ( LOLBINS_mshta_remotescript or LOLBINS_regsvr32_sct_scrobj or LOLBINS_msiexec_remote or LOLBINS_certutil_urlcache_decode or LOLBINS_bitsadmin_transfer )
    and
    ( Win_Lateral_WMIC_Process_Create or Win_Lateral_WinRM_PowerShell_Remoting )
}
