/* windows_scripts_loaders_advanced.yar
 * Focus: PowerShell / JScript / VBScript / HTA / LNK loaders & living-off-the-land chains
 * Author: ivan-gate
 */

/* ================= Helpers ================= */

private rule __small_text { condition: filesize > 200 and filesize < 5MB }
private rule __is_ps1     { condition: __small_text and /powershell(\.exe)?/ nocase }
private rule __looks_js   { condition: __small_text and ( /\.js$/ or /JScript|ActiveXObject|WScript\./ nocase ) }
private rule __looks_vbs  { condition: __small_text and ( /\.vb(s|e)?$/ or /CreateObject\("WScript\.Shell"\)/ nocase ) }
private rule __looks_hta  { condition: __small_text and ( /<html|<hta:/ nocase and /<script/i ) }
private rule __is_lnk     { condition: uint32be(0) == 0x4C000000 }  // .LNK magic

/* ================= PowerShell ================= */

/* 1) Скачай-и-выполни: web → memory/exec */
rule PS_Download_And_Execute
{
  meta: category="ps-loader" severity="high" rationale="IEX/DownloadString/WebClient/Base64"
  strings:
    $w1 = /Invoke-WebRequest|iwr\b|curl\b|wget\b|System\.Net\.WebClient/i
    $w2 = /DownloadString|DownloadFile|OpenRead/i
    $ix = /\bIEX\b|\bInvoke-Expression\b/i
    $b6 = /FromBase64String|::FromBase64String\(|-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}/i
    $dl = /Add-Type\s+-AssemblyName\s+System\.IO\.Compression|Expand-Archive/i
  condition:
    __small_text and ( __is_ps1 or /#\s*ps1|Set-ExecutionPolicy/i ) and
    ( ($w1 and ($w2 or $ix)) or ($b6 and ($ix or $w1)) or ($w1 and $dl) )
}

/* 2) AMSI/ETW bypass + exec */
rule PS_AMSI_ETW_Bypass
{
  meta: category="ps-evasion" severity="high" rationale="AMSI/ETW disable + exec"
  strings:
    $a1 = /\[Ref\].*Add-Type.*Amsi|amsiInitFailed/i
    $a2 = /\$?amsi(Utils|Scan|Context)|AmsiScanBuffer/i
    $a3 = /Set-MpPreference\s+-Disable(RealtimeMonitoring|IOAVProtection|ScriptScanning)/i
    $e1 = /Etw(EventWrite|EventProvider).*0x/i
    $ix = /\bIEX\b|\bInvoke-Expression\b/i
  condition:
    __small_text and ( __is_ps1 ) and ( (2 of ($a*)) or ($a1 and $e1) ) and $ix
}

/* 3) LOLBins из PowerShell */
rule PS_LOLBins_Exec_Chain
{
  meta: category="ps-lolbins" severity="medium" rationale="mshta/rundll32/regsvr32 вызовы из PS"
  strings:
    $h1 = /mshta(\.exe)?\s+https?:\/\//i
    $r1 = /rundll32(\.exe)?\s+javascript:/i
    $g1 = /regsvr32(\.exe)?\s+\/s\s+\/i\s+https?:\/\//i
  condition:
    __small_text and __is_ps1 and ( $h1 or $r1 or $g1 )
}

/* ================= JScript / VBScript / HTA ================= */

/* 4) JScript/VBScript download-&-exec */
rule JS_VBS_Download_And_Exec
{
  meta: category="wscript-loader" severity="high" rationale="XMLHTTP/ADODB.Stream + Run"
  strings:
    $ax = /CreateObject\("MSXML2\.XMLHTTP"|ActiveXObject\("MSXML2\.XMLHTTP/i
    $st = /CreateObject\("ADODB\.Stream"|ActiveXObject\("ADODB\.Stream/i
    $sh = /CreateObject\("WScript\.Shell"\)/i
    $rn = /\.Run\(|WScript\.Shell"\)\.Run/i
    $dl = /open\("GET",\s*["']https?:\/\//i
    $sv = /SaveToFile|Write|Type\s*=\s*1/i
  condition:
    __small_text and ( __looks_js or __looks_vbs or __looks_hta ) and
    ( $ax and $dl and $st and $sv and $sh and $rn )
}

/* 5) JScript/VBScript staged Base64 → eval/ExecuteGlobal */
rule JS_VBS_Base64_Stage_Exec
{
  meta: category="wscript-obf" severity="high" rationale="Base64 decode + Execute/Run"
  strings:
    $b6 = /FromBase64String|ADODB\.Stream|Microsoft\.XMLDOM/i
    $ev = /eval\(|Execute(Global)?\(/i
    $rx = /replace\((?:[^)]{0,40})?,\s*["'][A-Za-z0-9+/=]{10,}["']/i
  condition:
    __small_text and ( __looks_js or __looks_vbs or __looks_hta ) and
    ( ( $b6 and $ev ) or ( $rx and $ev ) )
}

/* 6) HTA runners (mshta payload) */
rule HTA_Suspicious_Runner
{
  meta: category="hta-loader" severity="medium" rationale="оболочка для запуска команд/скриптов"
  strings:
    $w1 = /WScript\.Shell/i
    $r1 = /\.Run\(|\.Exec\(/i
    $ps = /powershell(\.exe)?\s+(-enc|IEX|FromBase64String)/i
    $dl = /XMLHTTP|ADODB\.Stream/i
  condition:
    __small_text and __looks_hta and ( ($w1 and $r1) and ($ps or $dl) )
}

/* ================= LNK (ярлыки) ================= */

/* 7) LNK → PowerShell/JScript chain */
rule LNK_Encoded_PS_Or_WScript
{
  meta: category="lnk-loader" severity="high" rationale="LNK с -enc или wscript/mshta"
  strings:
    $ps = /powershell(\.exe)?\s+(-enc|--encodedcommand)\s+[A-Za-z0-9+/=]{20,}/ nocase ascii
    $js = /wscript(\.exe)?\s+\/\/E:jscript/i ascii
    $ht = /mshta(\.exe)?\s+https?:\/\//i ascii
  condition:
    __is_lnk and ( $ps or $js or $ht )
}

/* ================= WMI/COM, drop-to-temp, persistence ================= */

/* 8) WMI/COM exec из скриптов */
rule Script_WMI_COM_Exec
{
  meta: category="exec" severity="medium" rationale="WMI/COM запуск процессов/скриптов"
  strings:
    $wmi = /GetObject\(\s*["']winmgmts:/i
    $prc = /Win32_Process\.Create|ShellExecute/i
    $sch = /Win32_ScheduledJob|Schedule\.Service/i
  condition:
    __small_text and ( __is_ps1 or __looks_js or __looks_vbs ) and ( $wmi and ( $prc or $sch ) )
}

/* 9) Drop-and-exec в %TEMP% */
rule Script_Drop_To_Temp_And_Execute
{
  meta: category="loader" severity="medium" rationale="временный файл + запуск"
  strings:
    $tp = /%TEMP%|GetTempPath|Scripting\.FileSystemObject/i
    $wr = /WriteAllText|Write|SaveToFile/i
    $ex = /ShellExecute|Start-Process|\.Run\(/i
  condition:
    __small_text and ( __is_ps1 or __looks_js or __looks_vbs or __looks_hta ) and ( $tp and $wr and $ex )
}

/* 10) Persistence (Run/SchTasks) из скриптов */
rule Script_Persistence_Run_Schtasks
{
  meta: category="persistence" severity="medium" rationale="автозапуск через реестр/планировщик"
  strings:
    $rk = /Software\\Microsoft\\Windows\\CurrentVersion\\Run/i
    $st = /SCHTASKS\.EXE\s+\/Create\s+\/SC\s+(ONLOGON|ONSTART|MINUTE)/i
  condition:
    __small_text and ( __is_ps1 or __looks_js or __looks_vbs ) and ( $rk or $st )
}

/* ================= High-Confidence combos (низкий FP) ================= */

/* 11) PS: сетевой загрузчик + Base64/AMSI bypass */
rule PS_HC_NetLoader_With_Encode_Or_AMSI
{
  meta: category="combo" severity="critical"
  condition:
    PS_Download_And_Execute and ( PS_AMSI_ETW_Bypass or PS_LOLBins_Exec_Chain )
}

/* 12) JScript/VBScript: XMLHTTP+Stream+Run = классическая цепочка */
rule WScript_HC_Download_Save_Run
{
  meta: category="combo" severity="critical"
  condition:
    JS_VBS_Download_And_Exec and ( Script_Drop_To_Temp_And_Execute or Script_Persistence_Run_Schtasks )
}

/* 13) LNK → Encoded PowerShell/JScript */
rule LNK_HC_Loader
{
  meta: category="combo" severity="critical"
  condition:
    LNK_Encoded_PS_Or_WScript
}
