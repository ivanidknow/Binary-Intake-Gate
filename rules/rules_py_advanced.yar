/* rules_py_advanced.yar
 * Python malware & supply-chain detection (scripts, wheels, PyInstaller/Nuitka)
 * Author: ivan-gate
 */

/* ================= Helpers ================= */
private rule __small     { condition: filesize > 1KB and filesize < 200MB }
private rule __is_zip    { condition: uint32(0) == 0x504B0304 }     // wheel/zip/app archive
private rule __is_pe     { condition: uint16(0) == 0x5A4D }         // PyInstaller/Nuitka exe
private rule __is_text   { condition: !__is_zip and !__is_pe }      // heuris: plain .py, cfg, etc.

/* ================= 1) Download & Execute (скрипты) ================= */
rule PY_Download_And_Exec
{
  meta: category="py-loader" severity="high" rationale="Скачай и выполни"
  strings:
    $m1 = /urllib\.request\.url(open|retrieve)|requests\.(get|post)|urlopen/ nocase
    $w1 = /subprocess\.Popen|os\.system|os\.popen|execfile|exec\(|eval\(|compile\(/ nocase
    $p1 = /powershell(\.exe)?\s+(-enc|IEX|FromBase64String)/ nocase
    $c1 = /curl\s+https?:\/\// nocase
    $g1 = /wget\s+https?:\/\// nocase
  condition:
    __small and __is_text and
    ( $m1 and $w1 ) or $p1 or $c1 or $g1
}

/* ================= 2) Deobf chain: base64/zlib/marshal → exec ================= */
rule PY_Embedded_Decrypt_Exec
{
  meta: category="py-obfuscation" severity="high" rationale="Дешифровка и exec"
  strings:
    $b1 = /base64\.b64decode\(/ nocase
    $z1 = /zlib\.(decompress|decompressobj)\(/ nocase
    $m1 = /marshal\.loads\(/ nocase
    $e1 = /exec\(|eval\(|compile\(/ nocase
  condition:
    __small and __is_text and
    ( ( $b1 and $z1 and $e1 ) or ( $b1 and $m1 and $e1 ) or ( $z1 and $m1 and $e1 ) )
}

/* ================= 3) Token stealers (Discord/Telegram) ================= */
rule PY_Token_Stealer_Discord_Telegram
{
  meta: category="token-stealer" severity="high"
  strings:
    $dc = /[MN][A-Za-z\d]{23}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}/ ascii         // Discord
    $tg = /[\w\-]{24,35}:[A-Za-z0-9_-]{30,40}/ ascii                             // Telegram bot
    $dl = /\\Discord\\Local Storage\\leveldb|\/discord\/Local Storage\/leveldb/ nocase
  condition:
    __small and ( $dc or $tg or $dl )
}

/* ================= 4) Cloud creds & exfil (AWS/Azure/GCP) ================= */
rule PY_Cloud_Creds_Abuse
{
  meta: category="cloud-creds" severity="high"
  strings:
    $a1 = "AWS_ACCESS_KEY_ID"
    $a2 = "AWS_SECRET_ACCESS_KEY"
    $a3 = "AWS_SESSION_TOKEN"
    $g1 = "Metadata-Flavor: Google"
    $g2 = "http://169.254.169.254"
    $z1 = "AZURE_CLIENT_ID"
    $z2 = "AZURE_CLIENT_SECRET"
    $z3 = "AZURE_TENANT_ID"
    $kc = "/.kube/config"
  condition:
    __small and ( any of ($a1,$a2,$a3) or any of ($z1,$z2,$z3) or any of ($g1,$g2) or $kc )
}

/* ================= 5) Browser creds via sqlite + DPAPI/keychain через ctypes ================= */
rule PY_Browser_Cred_Steal
{
  meta: category="credential-access" severity="high"
  strings:
    $sq = /sqlite3\.connect\(|sqlcipher/i
    $ch = /Login Data|Cookies|Web Data|Local State/i
    $dp = /ctypes\.windll\.crypt32\.Crypt(Un)?protectData/i
    $kc = /security\s+find-generic-password|Keychain/i
  condition:
    __small and __is_text and
    ( $sq and $ch ) and ( $dp or $kc )
}

/* ================= 6) Keylogger / Clipboard clipper ================= */
rule PY_Keylogger_Clipboard
{
  meta: category="collection" severity="medium"
  strings:
    $k1 = /from\s+pynput\.keyboard|import\s+keyboard/ nocase
    $k2 = /GetAsyncKeyState|SetWindowsHookEx/ nocase
    $cb = /pyperclip|win32clipboard|QtGui\.QClipboard/ nocase
    $cr = /re\.compile\(\s*r?["'](0x)?[a-f0-9]{26,}["']/ nocase
  condition:
    __small and ( 1 of ($k1,$k2) or $cb ) and not __is_zip
}

/* ================= 7) Persistence (Windows/Unix/macOS) ================= */
rule PY_Persistence_CrossPlatform
{
  meta: category="persistence" severity="medium"
  strings:
    $rw = /Software\\Microsoft\\Windows\\CurrentVersion\\Run/ nocase
    $st = /SCHTASKS\.EXE\s+\/Create/i
    $cr = /crontab\s+-[el]/i
    $sd = /systemctl\s+enable|\/etc\/systemd\/system\//i
    $pl = /Library\/LaunchAgents\/|LaunchDaemons/i
  condition:
    __small and ( $rw or $st or $cr or $sd or $pl )
}

/* ================= 8) Supply-chain: setup.py/postinstall/.pth ================= */
rule PY_SupplyChain_Setup_PostInstall
{
  meta: category="supply-chain" severity="high"
  strings:
    $su = /setup\.py|setup\.cfg/i
    $pi = /(entry_points|cmdclass).*(install|post_?install)/ nocase
    $pt = /\.pth["']?\s*;?\s*import\s+/ nocase
    $wh = /wheel|bdist_wheel|distutils\.|setuptools\./ nocase
    $ex = /exec\(|eval\(|subprocess\.Popen|os\.system/ nocase
  condition:
    __small and ( $su or $wh ) and ( $pi or $pt or $ex )
}

/* ================= 9) PyInstaller / Nuitka / onefile droppers ================= */
rule PY_PyInstaller_OneFile_Dropper
{
  meta: category="packer/loader" severity="medium"
  strings:
    $pi1 = "pyi-windows-manifest-filename" ascii
    $pi2 = "pyi-archive-manifest" ascii
    $pi3 = "PYZ" ascii
    $pi4 = "MEIPASS" ascii
    $nk1 = "Nuitka" ascii
    $nk2 = "onefile" ascii
  condition:
    __small and ( __is_pe or __is_zip ) and ( 2 of ($pi*) or 2 of ($nk*) )
}

/* ================= 10) Importlib/loader инжект из строки/сети ================= */
rule PY_Import_From_String_SourceLoader
{
  meta: category="py-loader" severity="high"
  strings:
    $il1 = /importlib\.machinery\.SourceFileLoader\(/ nocase
    $il2 = /types\.ModuleType\(/ nocase
    $ex  = /exec\(|eval\(/ nocase
  condition:
    __small and __is_text and ( $il1 or $il2 ) and $ex
}

/* ================= 11) Discord/Telegram exfil via requests/webhook ================= */
rule PY_Exfil_Discord_Telegram_Webhook
{
  meta: category="exfiltration" severity="medium"
  strings:
    $wh = /https?:\/\/(discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot)/ nocase
    $rq = /requests\.(post|put)/ nocase
  condition:
    __small and ( $wh or ( $rq and PY_Token_Stealer_Discord_Telegram ) )
}

/* ================= High-Confidence COMBOS ================= */

/* HC1: decrypt+exec + network fetch */
rule PY_HC_DecryptExec_Downloader
{
  meta: category="combo" severity="critical" note="Low-FP: встроенная расшифровка + загрузчик"
  condition:
    PY_Embedded_Decrypt_Exec and PY_Download_And_Exec
}

/* HC2: supply-chain + exec hooks */
rule PY_HC_SupplyChain_Exec
{
  meta: category="combo" severity="critical"
  condition:
    PY_SupplyChain_Setup_PostInstall and ( PY_Download_And_Exec or PY_Exfil_Discord_Telegram_Webhook )
}

/* HC3: browser creds + exfil */
rule PY_HC_BrowserCreds_Exfil
{
  meta: category="combo" severity="critical"
  condition:
    PY_Browser_Cred_Steal and ( PY_Exfil_Discord_Telegram_Webhook or PY_Cloud_Creds_Abuse )
}
