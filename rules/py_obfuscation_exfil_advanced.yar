/* py_obfuscation_exfil_advanced.yar
 * Python obfuscation chains + practical exfil vectors (HTTP/webhooks/SMTP/FTP/S3/DNS).
 * Author: ivan-gate
 */

/* ================= Helpers ================= */
private rule __small        { condition: filesize > 1KB and filesize < 200MB }
private rule __is_zip       { condition: uint32(0) == 0x504B0304 }  // zip/wheel/pyz
private rule __is_pe        { condition: uint16(0) == 0x5A4D }      // PyInstaller/Nuitka exe
private rule __is_text_like { condition: !__is_zip and !__is_pe }   // .py/.pyc extract/.txt cfg etc.

/* ================= 1) Многоступенчатая декодировка → исполнение ================= */
rule PY_Obf_MultiLayer_Decode_Exec
{
  meta: category="py-obfuscation" severity="high" rationale="base64/zlib/marshal/lzma/bz2 -> exec/eval/compile"
  strings:
    $b64 = /base64\.(b64decode|urlsafe_b64decode)\(/ nocase
    $bz2 = /bz2\.(decompress|BZ2Decompressor)\(/ nocase
    $lz  = /lzma\.(decompress|LZMADecompressor)\(/ nocase
    $zl  = /zlib\.(decompress|decompressobj)\(/ nocase
    $mh  = /marshal\.loads\(/ nocase
    $hx  = /bytes\.fromhex\(\s*["'][0-9a-fA-F\s]+["']\s*\)/ nocase
    $cd  = /codecs\.(decode|encode)\(/ nocase
    $ev  = /exec\(|eval\(|compile\(/ nocase
  condition:
    __small and __is_text_like and
    ( ( 2 of ($b64,$zl,$mh,$bz2,$lz,$hx,$cd) and $ev ) or ( 3 of ($b64,$zl,$mh,$bz2,$lz,$hx,$cd) ) )
}

/* ================= 2) Динамическая загрузка кода/модулей ================= */
rule PY_Obf_Dynamic_Import_And_Loader
{
  meta: category="py-obfuscation" severity="high" rationale="importlib/types loader + exec"
  strings:
    $il1 = /importlib\.(machinery|util)\./ nocase
    $il2 = /SourceFileLoader|spec_from_loader|module_from_spec/ nocase
    $tp1 = /types\.ModuleType\(/ nocase
    $bi1 = /builtins\.__import__\(/ nocase
    $gt1 = /getattr\(\s*(?:__import__|globals\(\)|locals\(\))\s*,\s*["'][\w\.]+["']\s*\)/ nocase
    $ex  = /exec\(|eval\(/ nocase
  condition:
    __small and __is_text_like and ( ( $il1 and $il2 and $ex ) or ( $tp1 and $ex ) or ( $bi1 and $ex ) or ( $gt1 and $ex ) )
}

/* ================= 3) Строковые строительные блоки/фрагментация ================= */
rule PY_Obf_String_Fragment_Join
{
  meta: category="py-obfuscation" severity="medium" rationale="склейка строк/символов для обхода сигнатур"
  strings:
    $j1 = /["'][^"']{1,40}["']\s*\+\s*["'][^"']{1,40}["']/ nocase
    $j2 = /"".join\(\s*\[\s*(?:["'][^"']{1,8}["']\s*,\s*){3,}["'][^"']{1,8}["']\s*\]\s*\)/ nocase
    $j3 = /chr\(\d{2,3}\)\s*(\+|,)\s*chr\(\d{2,3}\)/ nocase
  condition:
    __small and __is_text_like and ( $j2 or $j3 or ( $j1 and PY_Obf_MultiLayer_Decode_Exec ) )
}

/* ================= 4) Anti-analysis / anti-debug для Python ================= */
rule PY_AntiAnalysis_Debugger_Trace
{
  meta: category="evasion" severity="medium" rationale="обнаружение отладчика/песочницы"
  strings:
    $tr = /sys\.gettrace\(\)/ nocase
    $db = /pydevd|pdb\.set_trace\(|debugpy/ nocase
    $tm = /time\.sleep\(\s*(0(\.0+)?|1|2)\s*\)/ nocase
    $ev = /os\.environ\[\s*["'](PYTHONINSPECT|PYTHONDEBUG)["']\s*\]/ nocase
  condition:
    __small and __is_text_like and ( $tr or $db or $ev or $tm )
}

/* ================= 5) Экcфиль через HTTP/Webhooks/Pastebin/Gist ================= */
rule PY_Exfil_HTTP_Webhooks_Paste_Gist
{
  meta: category="exfiltration" severity="high" rationale="requests/webhook + популярные сервисы"
  strings:
    $rq1 = /requests\.(post|get|put)\(/ nocase
    $dc1 = /https?:\/\/(discord(app)?\.com\/api\/webhooks\/)/ nocase
    $tg1 = /https?:\/\/api\.telegram\.org\/bot/ nocase
    $ps1 = /https?:\/\/pastebin\.com\/(api|raw)/ nocase
    $gh1 = /https?:\/\/api\.github\.com\/gists/ nocase
    $ua  = /headers\s*=\s*{[^}]*User-Agent/i
  condition:
    __small and ( ($rq1 and ($dc1 or $tg1 or $ps1 or $gh1)) or $dc1 or $tg1 )
}

/* ================= 6) SMTP/IMAP/FTP/SFTP эксфиль ================= */
rule PY_Exfil_SMTP_IMAP_FTP_SFTP
{
  meta: category="exfiltration" severity="medium" rationale="почта/файловые протоколы"
  strings:
    $sm1 = /smtplib\.SMTP(?:_SSL)?\(/ nocase
    $im1 = /imaplib\.IMAP4(?:_SSL)?\(/ nocase
    $fp1 = /ftplib\.FTP(?:_TLS)?\(/ nocase
    $sf1 = /paramiko\.SFTPClient\.from_transport\(/ nocase
    $cr1 = /(login|auth)\s*\(\s*["'][^"']{1,64}["']\s*,\s*["'][^"']{4,64}["']\s*\)/ nocase
  condition:
    __small and ( $sm1 or $im1 or $fp1 or $sf1 ) and ( $cr1 or PY_Obf_MultiLayer_Decode_Exec )
}

/* ================= 7) S3/Cloud/Raw HTTP push ================= */
rule PY_Exfil_S3_RawHTTP
{
  meta: category="exfiltration" severity="medium" rationale="S3/HTTP push без webhooks"
  strings:
    $s3a = /boto3\.client\(\s*["']s3["']\s*\)/ nocase
    $s3p = /\.put_object\(/ nocase
    $htp = /http\.client\.HTTPSConnection|urllib3\.PoolManager/ nocase
  condition:
    __small and ( ($s3a and $s3p) or $htp )
}

/* ================= 8) DNS-эксфиль (base32/64 в имени, txt-запросы) ================= */
rule PY_Exfil_DNS_Base_Enc
{
  meta: category="exfiltration" severity="medium" rationale="DNS TXT/NS с кодированными чанками"
  strings:
    $dn1 = /dns\.(resolver|message|query)\./ nocase
    $tx1 = /QTYPE\.TXT|rdatatype\.TXT/ nocase
    $b3  = /[a-z2-7]{16,}\.[\w\-\.]{3,}/ nocase  // похожее на base32 в имени
    $b6  = /[A-Za-z0-9+\/]{12,}={0,2}\.[\w\-\.]{3,}/ nocase
  condition:
    __small and ( $dn1 or $tx1 ) and ( $b3 or $b6 )
}

/* ================= 9) Пакеты/Onefile: PyInstaller/Nuitka контейнеры ================= */
rule PY_Packed_PyInstaller_Nuitka
{
  meta: category="packer/loader" severity="info" rationale="контейнер для скрытого кода"
  strings:
    $pi1 = "pyi-archive-manifest"
    $pi2 = "PYZ"
    $pi3 = "MEIPASS"
    $nk1 = "Nuitka" ascii
    $nk2 = "onefile" ascii
  condition:
    __small and ( __is_pe or __is_zip ) and ( 2 of ($pi*) or 2 of ($nk*) )
}

/* ================= 10) High-Confidence Combos ================= */
/* HC1: обфускация + HTTP/webhook */
rule PY_HC_Obf_And_HTTP_Exfil
{
  meta: category="combo" severity="critical" note="Обфускация и сетевой вывод в популярные сервисы"
  condition:
    PY_Obf_MultiLayer_Decode_Exec and ( PY_Exfil_HTTP_Webhooks_Paste_Gist or PY_Exfil_S3_RawHTTP )
}

/* HC2: динамический импорт + DNS/SMTP/FTP эксфиль */
rule PY_HC_Loader_And_SideChannel_Exfil
{
  meta: category="combo" severity="critical"
  condition:
    PY_Obf_Dynamic_Import_And_Loader and ( PY_Exfil_DNS_Base_Enc or PY_Exfil_SMTP_IMAP_FTP_SFTP )
}

/* HC3: строковая фрагментация + анти-анализ + любой эксфил */
rule PY_HC_Stealthy_And_Any_Exfil
{
  meta: category="combo" severity="high"
  condition:
    PY_Obf_String_Fragment_Join and PY_AntiAnalysis_Debugger_Trace and
    ( PY_Exfil_HTTP_Webhooks_Paste_Gist or PY_Exfil_SMTP_IMAP_FTP_SFTP or PY_Exfil_S3_RawHTTP or PY_Exfil_DNS_Base_Enc )
}
