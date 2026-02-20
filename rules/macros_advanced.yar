/* macros_advanced.yar
 * Office & PDF macro abuse: VBA/XLM/DDE/OLE/Template + PDF JS/Launch
 * Author: ivan-gate
 */

/* ===================== Helpers ===================== */

private rule __is_ole_cfb   { condition: uint64(0) == 0xE11AB1A1E011CFD0 } // DOC/XLS (старые)
private rule __is_zip_pkg   { condition: uint32(0) == 0x504B0304 }         // OOXML: DOCX/XLSX/DOCM/XLSM/PPTM
private rule __is_pdf       { condition: uint32(0) == 0x25504446 }         // %PDF
private rule __small_doc    { condition: filesize > 1KB and filesize < 50MB }

/* ===================== 1) VBA автозапуск, опасные вызовы ===================== */

rule Office_VBA_AutoOpen_Dangerous_Calls
{
  meta: category="office-vba" severity="high" rationale="Автозапуск + Shell/загрузчик"
  strings:
    $tr1 = /Auto(Open|_Open|OpenMain|Exec|Close)/ nocase
    $tr2 = /Document_(Open|Close|BeforeClose|Change|ContentControlAdded)/ nocase
    $tr3 = /Workbook_(Open|Activate|SheetActivate)/ nocase
    $co1 = /CreateObject\(\s*["']WScript\.Shell["']\s*\)/ nocase
    $co2 = /GetObject\(\s*["']winmgmts:/ nocase
    $sh1 = /Shell\(\s*["'](cmd\.exe|powershell\.exe|mshta\.exe)/ nocase
    $dl1 = /URLDownloadToFile|WinHttpRequest|XMLHTTP|ADODB\.Stream/ nocase
    $ps1 = /powershell(\.exe)?\s+(-enc|--encodedcommand)\s+[A-Za-z0-9+/=]{20,}/ nocase
  condition:
    __small_doc and ( __is_ole_cfb or __is_zip_pkg ) and
    ( 1 of ($tr*) ) and ( $sh1 or $ps1 or $dl1 or $co1 or $co2 )
}

/* ===================== 2) XLM 4.0 (Excel) ===================== */

rule Excel_XLM4_Macro_Abuse
{
  meta: category="office-xlm" severity="high" rationale="XLM формулы с исполнялками"
  strings:
    $au = /AUTO_OPEN|AUTO_ACTIVATE/i
    $cl = /=\s*CALL\(/i
    $ex = /=\s*EXEC\(/i
    $wx = /WinExec|ShellExecute/i
    $kr = /kernel32|user32/i
    $hp = /HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE/i
    $ms = /MSFORM|Macro/i
  condition:
    __small_doc and ( __is_ole_cfb or __is_zip_pkg ) and
    ( $au or $ms ) and ( $cl or $ex or $wx or $kr or $hp )
}

/* ===================== 3) DDE/DDEAUTO (DOC/RTF) ===================== */

rule Office_DDE_DDEAUTO_Command
{
  meta: category="office-dde" severity="high" rationale="Выполнение через DDE"
  strings:
    $dde1 = /DDEAUTO\s+["'][^"']{1,80}["']/ nocase
    $dde2 = /\\ddeauto/i
    $ps   = /powershell(\.exe)?\s+(-enc|IEX|FromBase64String)/ nocase
    $cmd  = /cmd\.exe\s+\/c\s+/ nocase
  condition:
    __small_doc and ( __is_ole_cfb or __is_zip_pkg ) and
    ( $dde1 or $dde2 ) and ( $ps or $cmd )
}

/* ===================== 4) OLE Packager / Embedded objects ===================== */

rule Office_OLE_Packager_Exec
{
  meta: category="office-ole" severity="high" rationale="Пакетированный EXE/скрипт"
  strings:
    $pk1 = "OLE Package" ascii
    $pk2 = "Package" ascii
    $e1  = /cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe/i
    $s1  = /\.vbs|\.js|\.jse|\.ps1|\.bat|\.cmd|\.hta/i
  condition:
    __small_doc and __is_ole_cfb and ( $pk1 or $pk2 ) and ( $e1 or $s1 )
}

/* ===================== 5) Remote Template Injection (DOTM/DOTX) ===================== */

rule Office_Remote_Template_Inject
{
  meta: category="office-template" severity="high" rationale="Внешний шаблон"
  strings:
    $rel = /Target\s*=\s*["']https?:\/\/[^\s"']+\.dotm?["']/ nocase
    $ct  = /Relationship\s+Type=["'][^"']*officeDocument\/relationships\/attachedTemplate["']/ nocase
  condition:
    __small_doc and __is_zip_pkg and ( $rel or $ct )
}

/* ===================== 6) Equation/старые опасные классы ===================== */

rule Office_Embedded_Equation_Or_Unsafe_OLEClass
{
  meta: category="office-ole" severity="medium" rationale="Наследуемые уязвимые классы/объекты"
  strings:
    $eq1 = "Equation.3" ascii
    $cl1 = "Package" ascii
    $cl2 = "Shell Object" ascii
    $cl3 = "WScript.Shell" ascii
  condition:
    __small_doc and __is_ole_cfb and ( 1 of ($eq1,$cl1,$cl2,$cl3) )
}

/* ===================== 7) Download & Execute chain ===================== */

rule Office_Download_And_Execute
{
  meta: category="office-loader" severity="high" rationale="Скачай и выполни"
  strings:
    $dl1 = /URLDownloadToFile|WinHttpRequest|XMLHTTP|ADODB\.Stream/i
    $wr  = /ADODB\.Stream.*Write|SaveToFile/i
    $sh  = /Shell\(|WScript\.Shell|ShellExecute/i
    $ps1 = /powershell(\.exe)?\s+(-enc|IEX|FromBase64String)/i
    $cu1 = /curl\s+https?:\/\//i
    $wg1 = /wget\s+https?:\/\//i
  condition:
    __small_doc and ( __is_ole_cfb or __is_zip_pkg ) and
    ( ($dl1 and ($wr or $sh)) or $ps1 or $cu1 or $wg1 )
}

/* ===================== 8) PDF JS/Launch/AutoAction ===================== */

rule PDF_JS_Launch_OpenAction
{
  meta: category="pdf" severity="high" rationale="Авто-скрипты/запуск в PDF"
  strings:
    $js1 = "/JS" ascii
    $ja1 = "/JavaScript" ascii
    $oa1 = "/OpenAction" ascii
    $aa1 = "/AA" ascii
    $ln1 = "/Launch" ascii
    $ac1 = "/Action" ascii
  condition:
    __small_doc and __is_pdf and ( $js1 or $ja1 or $ln1 or ( $oa1 and $ac1 ) or $aa1 )
}

/* ===================== 9) High-confidence combo ===================== */

rule Office_HC_Macro_Combo
{
  meta: category="combo" severity="critical" rationale="Автотриггер + загрузчик/выполнение"
  condition:
    __small_doc and ( __is_ole_cfb or __is_zip_pkg ) and
    ( Office_VBA_AutoOpen_Dangerous_Calls or Excel_XLM4_Macro_Abuse ) and
    ( Office_Download_And_Execute or Office_OLE_Packager_Exec or Office_DDE_DDEAUTO_Command )
}
