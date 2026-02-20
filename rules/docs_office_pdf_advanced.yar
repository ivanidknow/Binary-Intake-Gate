/* docs_office_pdf_advanced.yar
 * Office (DOC/RTF/OOXML) & PDF: remote template, DDE/XLM/VBA, OLE/OLE2Link, ms-msdt, PDF JS/Launch/Embedded.
 * Author: ivan-gate
 */

/* ================= Helpers ================= */
private rule __is_ole_cfb { condition: uint64(0) == 0xE11AB1A1E011CFD0 } // DOC/старые XLS/PPT
private rule __is_zip_pkg { condition: uint32(0) == 0x504B0304 }          // OOXML (docx/docm/xlsm/…)
private rule __is_pdf     { condition: uint32(0) == 0x25504446 }          // %PDF
private rule __is_rtf     { condition: uint32(0) == 0x7B5C7274 }          // {\rtf
private rule __small_doc  { condition: filesize > 1KB and filesize < 80MB }

/* ================= OOXML: Remote Template / External Links ================= */
rule Office_OOXML_RemoteTemplate_ExternalLink
{
  meta: category="office-template" severity="high" rationale="Внешний шаблон/линк с http(s)"
  strings:
    $rel_tpl = /Relationship\s+.*Type=["'][^"']*attachedTemplate["'].*Target=["']https?:\/\/[^"']+\.dotm?["']/ nocase
    $rel_xls = /Relationship\s+.*Type=["'][^"']*externalLink["'].*Target=["']https?:\/\/[^"']+["']/ nocase
    $vba     = "vbaProject.bin" ascii
  condition:
    __small_doc and __is_zip_pkg and ( $rel_tpl or $rel_xls or $vba )
}

/* ================= OOXML/RTF/DOC: DDE/DDEAUTO и Follina (ms-msdt) ================= */
rule Office_DDE_or_MSMSDT_Exploit_Vector
{
  meta: category="office-dde" severity="high" rationale="DDE/DDEAUTO/‘Follina’ ms-msdt:"
  strings:
    $dde1 = /DDEAUTO\s+["'][^"']{1,120}["']/ nocase
    $dde2 = /\\ddeauto/i
    $msdt = /ms-msdt:/ nocase
    $cmd  = /cmd\.exe\s+\/c\s+/ nocase
    $ps   = /powershell(\.exe)?\s+(-enc|IEX|FromBase64String)/ nocase
  condition:
    __small_doc and ( __is_ole_cfb or __is_zip_pkg or __is_rtf ) and
    ( $msdt or $dde1 or $dde2 ) and ( $cmd or $ps or $msdt )
}

/* ================= RTF/DOC: OLE Packager/Embedded с исполнялкой ================= */
rule Office_OLE_Packager_Embedded_Exec
{
  meta: category="office-ole" severity="high" rationale="Встроенный ‘Package’/OLE с запуском"
  strings:
    $pk1 = "OLE Package" ascii
    $pkg = "Package" ascii
    $exe = /cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe/i
    $scr = /\.(vbs|js|jse|ps1|bat|cmd|hta)/ nocase
    $obj = /\\object|\\objdata/i
  condition:
    __small_doc and ( __is_ole_cfb or __is_rtf ) and ( ($pk1 or $pkg) or $obj ) and ( $exe or $scr )
}

/* ================= OOXML/RTF: Equation/OLE2Link/опасные классы ================= */
rule Office_Equation_OLE2Link_Unsafe_Class
{
  meta: category="office-ole" severity="medium" rationale="Equation.3/’OLE2Link’/Shell Object"
  strings:
    $eq  = "Equation.3" ascii
    $ol  = "OLE2Link" ascii
    $cl1 = "Shell Object" ascii
    $cl2 = "WScript.Shell" ascii
  condition:
    __small_doc and ( __is_ole_cfb or __is_rtf ) and ( $eq or $ol or $cl1 or $cl2 )
}

/* ================= VBA/XLM: авто-триггеры + загрузка/выполнение ================= */
rule Office_VBA_XLM_Autostart_Loader
{
  meta: category="office-macro" severity="high" rationale="Автозапуск + download/exec"
  strings:
    $vba_tr = /Auto(Open|_Open|OpenMain|Close)|Document_Open|Workbook_Open/i
    $xla_tr = /AUTO_OPEN|AUTO_ACTIVATE|Macro/i
    $dl1    = /URLDownloadToFile|WinHttpRequest|XMLHTTP|ADODB\.Stream/i
    $sh1    = /Shell\(|WScript\.Shell|ShellExecute/i
    $ps1    = /powershell(\.exe)?\s+(-enc|IEX|FromBase64String)/i
  condition:
    __small_doc and ( __is_ole_cfb or __is_zip_pkg ) and
    ( $vba_tr or $xla_tr ) and ( $dl1 or $sh1 or $ps1 )
}

/* ================= OOXML: вхождение vbaProject + опасные строки в контейнере ================= */
rule Office_OOXML_VBAProject_Suspicious_Strings
{
  meta: category="office-macro" severity="medium" rationale="OOXML содержит vbaProject и ‘опасные’ строки"
  strings:
    $vba = "vbaProject.bin" ascii
    $ps  = /powershell(\.exe)?\s+(-enc|IEX|FromBase64String)/ nocase
    $ms  = "mshta.exe" ascii nocase
    $dl  = /http[s]?:\/\/[^\s"']{1,120}\.(exe|ps1|vbs|js|hta)/ nocase
  condition:
    __small_doc and __is_zip_pkg and $vba and ( $ps or $ms or $dl )
}

/* ================= PDF: JavaScript / Launch / OpenAction / EmbeddedFiles / RichMedia ================= */
rule PDF_JS_Launch_OpenAction_Embedded
{
  meta: category="pdf" severity="high" rationale="Автовыполнение/JS/запуск/встроенные файлы"
  strings:
    $js1 = "/JS" ascii
    $js2 = "/JavaScript" ascii
    $oa1 = "/OpenAction" ascii
    $aa1 = "/AA" ascii
    $ln1 = "/Launch" ascii
    $ef1 = "/EmbeddedFiles" ascii
    $nm1 = "/Names" ascii
    $rm1 = "/RichMedia" ascii
  condition:
    __small_doc and __is_pdf and ( $js1 or $js2 or $ln1 or ($oa1 and $nm1) or $aa1 or $ef1 or $rm1 )
}

/* ================= PDF: Сетевые/скриптовые признаки ================= */
rule PDF_URI_External_Action
{
  meta: category="pdf" severity="medium" rationale="Внешние URI/действия"
  strings:
    $ur1 = "/URI" ascii
    $ac1 = "/Action" ascii
    $goe = "/GoToE" ascii
    $fl1 = "/Filespec" ascii
  condition:
    __small_doc and __is_pdf and ( ($ur1 and $ac1) or $goe or $fl1 )
}

/* ================= High-confidence комбо: Office ================= */
rule Office_HC_Combo_TemplateOrMacro_Exec
{
  meta: category="combo" severity="critical" rationale="Внешний шаблон/макро + исполнение"
  condition:
    __small_doc and
    ( Office_OOXML_RemoteTemplate_ExternalLink or Office_VBA_XLM_Autostart_Loader ) and
    ( Office_OLE_Packager_Embedded_Exec or Office_DDE_or_MSMSDT_Exploit_Vector )
}

/* ================= High-confidence комбо: PDF ================= */
rule PDF_HC_Combo_JS_Launch_Embedded
{
  meta: category="combo" severity="critical" rationale="JS/Launch + встроенные файлы/автодействие"
  condition:
    __small_doc and __is_pdf and
    PDF_JS_Launch_OpenAction_Embedded and
    ( PDF_URI_External_Action )
}
