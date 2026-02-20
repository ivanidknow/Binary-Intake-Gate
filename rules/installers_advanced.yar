/* installers_advanced.yar
 * Unified & improved detection of Windows installers and risky behaviors inside them.
 * Families: MSI/WiX(Burn), NSIS, Inno Setup, InstallShield, 7z/rar SFX, Squirrel/Electron.
 * Behaviors: CustomAction → PowerShell/WSH, network download, LOLBins, persistence, TEMP drop-and-exec.
 * Author: ivan-gate
 */

import "pe"

/* ===================== Helpers ===================== */

private rule __is_pe { condition: uint16(0) == 0x5A4D and pe }

private rule __ole_cfb /* MSI (old) OLE Compound File: D0 CF 11 E0 A1 B1 1A E1 */
{
  condition:
    uint32(0) == 0xE011CFD0
}

private rule __zip /* APPX/MSIX or Squirrel/electron asar within .nupkg: PK\x03\x04 */
{
  condition:
    uint32(0) == 0x04034B50
}

private rule __smallish_bin { condition: filesize > 16KB and filesize < 250MB }

/* ===================== Families ===================== */

/* --- MSI container / WiX tables present in OLE CFB --- */
rule MSI_Generic_Container
{
  meta:
    family = "MSI"
    severity = "low"
  strings:
    $t1 = "Property" ascii
    $t2 = "CustomAction" ascii
    $t3 = "InstallExecuteSequence" ascii
    $t4 = "!_StringPool" ascii
  condition:
    __ole_cfb and 2 of ($t*)
}

/* --- WiX Burn bootstrapper (setup.exe bootstrap) --- */
rule PE_WiX_Burn_Bootstrapper
{
  meta:
    family = "WiX/Burn"
    severity = "low"
  strings:
    $w1 = "WixBurnBootstrapperApplication" ascii
    $w2 = "WixStandardBootstrapperApplication" ascii
    $w3 = "BAFunctions" ascii
  condition:
    __is_pe and 1 of ($w*)
}

/* --- NSIS Nullsoft --- */
rule PE_NSIS_Installer
{
  meta:
    family = "NSIS"
    severity = "low"
  strings:
    $n1 = "Nullsoft.NSIS" ascii
    $n2 = "Nullsoft Install System" ascii
    $n3 = "nsExec::Exec" ascii
    $n4 = "ExecWait" ascii
    $n5 = "Section" ascii
  condition:
    __is_pe and 2 of ($n*)
}

/* --- Inno Setup --- */
rule PE_InnoSetup_Installer
{
  meta:
    family = "InnoSetup"
    severity = "low"
  strings:
    $i1 = "Inno Setup Setup Data" ascii
    $i2 = "SetupLdr" ascii
    $i3 = "[Run]" ascii
    $i4 = "Code:" ascii
  condition:
    __is_pe and ( $i1 or $i2 or ( $i3 and $i4 ) )
}

/* --- InstallShield --- */
rule PE_InstallShield_Installer
{
  meta:
    family = "InstallShield"
    severity = "low"
  strings:
    $s1 = "InstallShield" ascii
    $s2 = "ISSetup" ascii
    $s3 = "ISBEW64" ascii
  condition:
    __is_pe and 1 of ($s*)
}

/* --- 7-Zip SFX self-extractor --- */
rule PE_7Zip_SFX_Installer
{
  meta:
    family = "7z-SFX"
    severity = "low"
  strings:
    $z1 = "7zS.sfx" ascii
    $z2 = "7-Zip SFX" ascii
    $z3 = "Setup SFX" ascii
  condition:
    __is_pe and 1 of ($z*)
}

/* --- RAR SFX --- */
rule PE_RAR_SFX_Installer
{
  meta:
    family = "RAR-SFX"
    severity = "low"
  strings:
    $r1 = "Rar!SFX" ascii
    $r2 = "SFX module" ascii
  condition:
    __is_pe and 1 of ($r*)
}

/* --- Squirrel/Electron (nupkg/RELEASES/Update.exe) --- */
rule PE_Squirrel_Electron_Update
{
  meta:
    family = "Squirrel/Electron"
    severity = "low"
  strings:
    $u1 = "SquirrelAwareVersion" ascii
    $u2 = "RELEASES" ascii
    $u3 = "nupkg" ascii
    $u4 = "Update.exe" ascii
  condition:
    ( __is_pe and 1 of ($u1,$u4) ) or ( __zip and 1 of ($u2,$u3) )
}

/* ===================== Risky behaviors inside installers ===================== */

/* --- MSI CustomAction → PowerShell/WSH/cmd --- */
rule MSI_CustomAction_PowerShell_WS
{
  meta:
    category = "behavior"
    severity = "high"
  strings:
    $ca = "CustomAction" ascii
    $ps = /powershell(\.exe)?/ nocase ascii
    $ec = /-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}/ nocase ascii
    $ix = /FromBase64String|IEX\s*\(/ nocase ascii
    $cm = /cmd(\.exe)?\s+\/c/ nocase ascii
    $ws = /wscript(\.exe)?|cscript(\.exe)?/ nocase ascii
    $dl = /Invoke-WebRequest|Start-BitsTransfer|URLDownloadToFile/ nocase ascii
  condition:
    __ole_cfb and $ca and ( $ps or $ws or $cm ) and ( $ec or $ix or $dl )
}

/* --- WiX Burn/InstallShield bootstrapper runs LOLBins --- */
rule PE_Bootstrapper_LOLBins_Exec
{
  meta:
    category = "behavior"
    severity = "high"
  strings:
    $ps1 = /powershell(\.exe)?\s+(-enc|--encodedcommand)\s+[A-Za-z0-9+/=]{20,}/ nocase ascii
    $hta = /mshta(\.exe)?\s+https?:\/\// nocase ascii
    $rdl = /rundll32(\.exe)?\s+(javascript:|zipfldr\.dll)/ nocase ascii
    $reg = /regsvr32(\.exe)?\s+\/s\s+\/i\s+https?:\/\// nocase ascii
    $wb  = /wscript(\.exe)?\s+\/\/E:jscript/ nocase ascii
  condition:
    __is_pe and ( PE_WiX_Burn_Bootstrapper or PE_InstallShield_Installer or PE_7Zip_SFX_Installer or PE_NSIS_Installer or PE_InnoSetup_Installer ) and
    ( $ps1 or $hta or $rdl or $reg or $wb )
}

/* --- Inno/NSIS running post-install commands with PS/curl/wget --- */
rule PE_Installer_PostRun_Network_Download
{
  meta:
    category = "behavior"
    severity = "medium"
  strings:
    $in_run = "[Run]" ascii
    $ns_exe = "ExecWait" ascii
    $ps     = "powershell" ascii nocase
    $curl   = /curl(\.exe)?\s+https?:\/\// nocase ascii
    $wget   = /wget(\.exe)?\s+https?:\/\// nocase ascii
    $bits   = "Start-BitsTransfer" ascii
  condition:
    __is_pe and
    (
      ( PE_InnoSetup_Installer and ( $in_run and ( $ps or $curl or $wget or $bits ) ) ) or
      ( PE_NSIS_Installer and ( $ns_exe and ( $ps or $curl or $wget or $bits ) ) )
    )
}

/* --- Persistence via Run/RunOnce/Startup/Schtasks from installers --- */
rule PE_Installer_Persistence_Run_Schtasks
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
    __is_pe and ( $rk1 or $rk2 or $st1 or $sp1 )
}

/* --- Drop & Execute from %TEMP% (common in SFX/bootstrappers) --- */
rule PE_Installer_Temp_Drop_And_Exec
{
  meta:
    category = "behavior"
    severity = "high"
  strings:
    $tmp = /\\(Temp|TMP)\\[A-Za-z0-9._\-\\\/]{1,64}\.(exe|dll|ps1|js|vbs)/ nocase ascii wide
    $exe = /cmd(\.exe)?\s+\/c|start\s+\"?/ nocase ascii
    $ps1 = /powershell(\.exe)?/ nocase ascii
    $ws  = /wscript(\.exe)?|cscript(\.exe)?/ nocase ascii
  condition:
    __is_pe and $tmp and ( $exe or $ps1 or $ws )
}

/* --- APPX/MSIX: AppxManifest + suspicious script exec --- */
rule ZIP_Appx_MSIX_Suspicious
{
  meta:
    family   = "APPX/MSIX"
    category = "behavior"
    severity = "medium"
  strings:
    $ax = "AppxManifest.xml" ascii
    $ps = /powershell(\.exe)?/ nocase ascii
    $js = /wscript|cscript|mshta/ nocase ascii
  condition:
    __zip and $ax and ( $ps or $js )
}

/* ===================== High-Confidence combos (low FP) ===================== */

/* --- MSI container + CustomAction + PS encoded / FromBase64 --- */
rule MSI_HC_CustomAction_PowerShell_Encoded
{
  meta:
    family   = "MSI"
    category = "hc-combo"
    severity = "high"
  strings:
    $ps = /powershell(\.exe)?/ nocase ascii
    $ec = /-enc(odedcommand)?\s+[A-Za-z0-9+/=]{24,}/ nocase ascii
    $ix = /FromBase64String|IEX\s*\(/ nocase ascii
  condition:
    MSI_Generic_Container and ( $ps and ( $ec or $ix ) )
}

/* --- Known installer family + LOLBins + network form-data (exfil/telemetry abuse) --- */
rule PE_HC_Installer_LOLBins_Multipart
{
  meta:
    category = "hc-combo"
    severity = "high"
  strings:
    $m1 = "multipart/form-data; boundary=" ascii
    $ua = "User-Agent:" ascii
    $ps = /powershell(\.exe)?\s+(-enc|--encodedcommand)/ nocase ascii
    $hta = /mshta(\.exe)?\s+https?:\/\// nocase ascii
  condition:
    __is_pe and
    ( PE_WiX_Burn_Bootstrapper or PE_InstallShield_Installer or PE_7Zip_SFX_Installer or PE_NSIS_Installer or PE_InnoSetup_Installer ) and
    ( $ps or $hta ) and
    ( $m1 or $ua )
}
