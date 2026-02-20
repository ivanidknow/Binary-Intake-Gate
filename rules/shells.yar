/* webshells_advanced.yar
 * Focus: PHP / ASP / ASPX / JSP web shells (generic + families)
 * Design: low-FP triage (size caps + multiple signals + simple excludes)
 * Author: ivan-gate
 */

/* ===================== Helpers ===================== */

private rule __small_text
{
  condition:
    filesize > 100 and filesize < 2MB
}

private rule __has_user_input
{
  strings:
    $g1 = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
    $g2 = /Request\.(QueryString|Form|Cookies)\[/ nocase        // ASP/ASPX
    $g3 = /request\.getParameter\s*\(/ nocase                    // JSP
  condition:
    any of them
}

private rule __php_file
{
  strings:
    $p1 = "<?php" ascii nocase
    $p2 = "<?= " ascii
  condition:
    1 of ($p*)
}

private rule __asp_classic
{
  strings:
    $a1 = "<%" ascii
    $a2 = "Response.Write" ascii nocase
  condition:
    $a1 and $a2
}

private rule __aspx_managed
{
  strings:
    $x1 = "<%@ Page" ascii nocase
    $x2 = "System.Web" ascii
    $x3 = "System.Diagnostics.ProcessStartInfo" ascii
  condition:
    $x1 or ($x2 and $x3)
}

private rule __jsp_file
{
  strings:
    $j1 = "<%@ page" ascii nocase
    $j2 = "<jsp:" ascii nocase
  condition:
    $j1 or $j2
}

/* ===================== PHP: generic one-liners / obfuscation ===================== */

rule PHP_Webshell_Generic_OneLiner
{
  meta:
    family   = "generic"
    severity = "high"
  strings:
    $e1 = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[/ nocase
    $e2 = /assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[/ nocase
    $e3 = /preg_replace\s*\(\s*["'][^"']*\/e["']\s*,\s*\$_(GET|POST|REQUEST|COOKIE)\[/ nocase
    $e4 = /create_function\s*\(\s*["'][^"']*["']\s*,\s*\$_(GET|POST|REQUEST|COOKIE)\[/ nocase
  condition:
    __small_text and __php_file and (1 of ($e*))
}

rule PHP_Webshell_Obfuscated_Base64
{
  meta:
    family   = "generic"
    severity = "high"
  strings:
    $b1 = /eval\s*\(\s*base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[/ nocase
    $b2 = /eval\s*\(\s*gz(inflate|uncompress)\s*\(\s*base64_decode\s*\(/ nocase
    $b3 = /assert\s*\(\s*base64_decode\s*\(/ nocase
  condition:
    __small_text and __php_file and (1 of ($b*))
}

/* ===================== PHP: known families / indicators ===================== */

rule PHP_Webshell_ChinaChopper
{
  meta:
    family   = "ChinaChopper"
    severity = "high"
  strings:
    $s1 = "eval($_POST" ascii nocase
    $s2 = "assert($_POST" ascii nocase
    $s3 = "function Godzilla" ascii
    $s4 = "->readfile(" ascii
  condition:
    __small_text and __php_file and ( 2 of ($s*) )
}

rule PHP_Webshell_WSO_r57_c99
{
  meta:
    family   = "WSO/r57/c99"
    severity = "high"
  strings:
    $w1 = "WSO web shell" ascii nocase
    $w2 = "c99shell" ascii nocase
    $w3 = "r57shell" ascii nocase
    $w4 = "Safe mode:" ascii
    $w5 = "disable_functions" ascii
    $w6 = "Mini Shell" ascii
  condition:
    __small_text and __php_file and ( 2 of ($w*) )
}

rule PHP_Webshell_Weevely_Backdoor
{
  meta:
    family   = "Weevely"
    severity = "high"
  strings:
    $v1 = /@\$\w+=create_function\(/ nocase
    $v2 = /gz(inflate|uncompress)\(base64_decode\(/ nocase
    $v3 = /function\s+\w{1,3}\(\$\w{1,3},\$\w{1,3}\)\{/ nocase
  condition:
    __small_text and __php_file and ( $v2 and ( $v1 or $v3 ) )
}

rule PHP_Webshell_b374k_Indicators
{
  meta:
    family   = "b374k"
    severity = "high"
  strings:
    $b1 = "b374k" ascii nocase
    $b2 = "B374K" ascii
    $b3 = "shell.php?pass" ascii nocase
  condition:
    __small_text and __php_file and 1 of ($b*)
}

/* ===================== PHP: uploaders & cmd exec & sockets ===================== */

rule PHP_Malicious_Uploader
{
  meta:
    family   = "uploader"
    severity = "medium"
  strings:
    $u1 = /move_uploaded_file\s*\(\s*\$\w+\s*,\s*\$\w+\s*\)/ nocase
    $u2 = /preg_match\s*\(\s*["']\.(php|phtml|phar)["']/ nocase
    $u3 = /Content\-Type:\s*image\/(png|jpeg|gif)/ nocase
  condition:
    __small_text and __php_file and $u1 and ( $u2 or $u3 )
}

rule PHP_Command_Exec_Shell
{
  meta:
    family   = "cmdexec"
    severity = "high"
  strings:
    $c1 = /system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[/ nocase
    $c2 = /exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[/ nocase
    $c3 = /shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[/ nocase
    $c4 = /popen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[/ nocase
  condition:
    __small_text and __php_file and (1 of ($c*))
}

rule PHP_Backconnect_Sockets
{
  meta:
    family   = "backconnect"
    severity = "high"
  strings:
    $s1 = "fsockopen" ascii nocase
    $s2 = "stream_socket_client" ascii nocase
    $s3 = /pcntl_fork|posix_mkfifo/ nocase
  condition:
    __small_text and __php_file and $s1 and ( $s2 or $s3 ) and __has_user_input
}

/* ===================== ASP / ASPX ===================== */

rule ASP_Classic_Webshell_Cmd
{
  meta:
    family   = "ASP"
    severity = "high"
  strings:
    $r1 = "WScript.Shell" ascii
    $r2 = "CreateObject(\"WScript.Shell\")" ascii
    $r3 = "cmd.exe /c" ascii nocase
  condition:
    __small_text and __asp_classic and __has_user_input and (2 of ($r*))
}

rule ASPX_CSharp_ProcessStart_Webshell
{
  meta:
    family   = "ASPX"
    severity = "high"
  strings:
    $p1 = "System.Diagnostics.ProcessStartInfo" ascii
    $p2 = "ProcessStartInfo(" ascii
    $p3 = "UseShellExecute = false" ascii
    $p4 = "RedirectStandardOutput = true" ascii
    $c1 = "cmd.exe" ascii
  condition:
    __small_text and __aspx_managed and __has_user_input and ( ( $p1 or $p2 ) and $c1 and ( $p3 or $p4 ) )
}

/* ===================== JSP ===================== */

rule JSP_Runtime_Exec_Webshell
{
  meta:
    family   = "JSP"
    severity = "high"
  strings:
    $e1 = "java.lang.Runtime.getRuntime().exec" ascii
    $e2 = "ProcessBuilder(" ascii
    $r1 = "request.getParameter(" ascii
  condition:
    __small_text and __jsp_file and $r1 and ( $e1 or $e2 )
}

/* ===================== High confidence generic ===================== */

rule WebShell_HighConfidence_Generic
{
  meta:
    family   = "generic"
    severity = "critical"
    note     = "multi-signal: user input + exec/eval + output"
  strings:
    $o1 = "echo" ascii nocase
    $o2 = "print" ascii nocase
    $o3 = "Response.Write" ascii nocase
    $o4 = "out.print" ascii nocase
    $ex1 = /eval|assert|preg_replace\s*\(\s*["'][^"']*\/e/i
    $ex2 = /system|exec|shell_exec|popen|proc_open/i
  condition:
    __small_text and __has_user_input and ( any of ($o*) ) and ( $ex1 or $ex2 )
}

/* ===================== Simple FP guard for phpMyAdmin ===================== */

rule FP_Exclude_phpMyAdmin
{
  meta:
    severity = "info"
  strings:
    $pma = "phpMyAdmin" ascii
  condition:
    $pma
}
