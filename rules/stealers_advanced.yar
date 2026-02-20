/*  stealers_advanced.yar
 *  Focus: Windows PE infostealers (browser creds, tokens, wallets, exfil)
 *  Author: ivan-gate
 *  Notes:
 *    - Designed to work fast and low-FP in triage pipelines
 *    - Uses multiple signals (paths + DPAPI + targets) to reduce noise
 */

private rule __is_pe
{
  condition:
    uint16(0) == 0x5A4D and pe
}

private rule __smallish
{
  condition:
    filesize > 10KB and filesize < 30MB
}

private rule __uses_http_stack
{
  strings:
    $w1 = "WinHttpOpen" ascii wide
    $w2 = "WinHttpSendRequest" ascii wide
    $i1 = "InternetOpenA" ascii
    $i2 = "InternetOpenW" wide
    $u1 = "URLDownloadToFile" ascii wide
  condition:
    any of them or
    pe.imports("winhttp.dll", "WinHttpOpen") or
    pe.imports("wininet.dll", "InternetOpenA", "InternetOpenW")
}

private rule __uses_dpapi_or_vault
{
  strings:
    $d1 = "CryptUnprotectData" ascii wide
    $d2 = "CryptProtectData" ascii wide
    $v1 = "VaultEnumerateItems" ascii wide
    $v2 = "VaultGetItem" ascii wide
  condition:
    any of them or
    pe.imports("crypt32.dll","CryptUnprotectData") or
    pe.imports("vaultcli.dll","VaultEnumerateItems","VaultGetItem")
}

private rule __chromium_artifacts
{
  strings:
    $c1 = "Login Data" ascii wide
    $c2 = "Cookies" ascii wide
    $c3 = "Web Data" ascii wide
    $c4 = "Local State" ascii wide
    $c5 = "\\User Data\\Default" ascii wide nocase
  condition:
    2 of ($c*)
}

private rule __firefox_artifacts
{
  strings:
    $f1 = "key4.db" ascii wide
    $f2 = "logins.json" ascii wide
    $f3 = "cookies.sqlite" ascii wide
    $f4 = "places.sqlite" ascii wide
  condition:
    2 of ($f*)
}

private rule __discord_telegram_tokens
{
  strings:
    $dc = /[MN][A-Za-z\d]{23}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}/ ascii // Discord token
    $tg = /[\w\-]{24,35}:[A-Za-z0-9_-]{30,40}/ ascii                     // Telegram bot token
    $dp = "\\Discord\\Local Storage\\leveldb" ascii wide nocase
    $td = "\\Telegram Desktop\\tdata" ascii wide nocase
  condition:
    $dc or $tg or 1 of ($dp,$td)
}

private rule __wallet_targets
{
  strings:
    $mm1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii // MetaMask ext id
    $mm2 = "MetaMask" ascii wide
    $ex1 = "Exodus" ascii wide
    $el1 = "Electrum" ascii wide
    $btc = "wallet.dat" ascii wide
    $mmk = "keyring" ascii wide
  condition:
    2 of ($mm*,$ex1,$el1,$btc,$mmk)
}

private rule __ftp_mail_targets
{
  strings:
    $fz1 = "FileZilla" ascii wide
    $fz2 = "sitemanager.xml" ascii wide
    $fz3 = "recentservers.xml" ascii wide
    $tb1 = "Thunderbird" ascii wide
    $tb2 = "logins.json" ascii wide
    $tb3 = "key4.db" ascii wide
  condition:
    any of ($fz*) or ( $tb1 and ( $tb2 or $tb3 ) )
}

private rule __family_words
{
  meta:
    note = "heuristic words often seen in RedLine/Vidar/Lumma/Raccoon configs"
  strings:
    $w1 = "grabber" ascii wide nocase
    $w2 = "browsers" ascii wide nocase
    $w3 = "wallets" ascii wide nocase
    $w4 = "screenshot" ascii wide nocase
    $w5 = "clipper" ascii wide nocase
    $w6 = "hwid" ascii wide
  condition:
    3 of ($w*)
}

/* ------------ 1) Generic: Browser credential stealer (Chromium/Firefox + DPAPI + net) ------------ */
rule PE_Generic_Credential_Stealer_Browsers
{
  meta:
    family   = "generic-stealer"
    tactic   = "credential-access"
    severity = "high"
    author   = "ivan-gate"
  condition:
    __is_pe and __smallish and
    ( __chromium_artifacts or __firefox_artifacts ) and
    __uses_dpapi_or_vault and
    ( __uses_http_stack or (defined floss_url_cnt and floss_url_cnt >= 3) )
}

/* ------------ 2) Token stealers (Discord/Telegram) ------------ */
rule PE_Token_Stealer_Discord_Telegram
{
  meta:
    family   = "token-stealer"
    tactic   = "credential-access"
    severity = "high"
  condition:
    __is_pe and __smallish and
    __discord_telegram_tokens and
    ( __chromium_artifacts or __uses_http_stack or (defined floss_has_strings and floss_has_strings) )
}

/* ------------ 3) Crypto wallet stealers (MetaMask/Exodus/Electrum) ------------ */
rule PE_Crypto_Wallet_Stealer
{
  meta:
    family   = "wallet-stealer"
    tactic   = "credential-access"
    severity = "high"
  condition:
    __is_pe and __smallish and
    __wallet_targets and
    ( __chromium_artifacts or __uses_http_stack or __family_words )
}

/* ------------ 4) FTP/Mail credential theft (FileZilla/Thunderbird) ------------ */
rule PE_FTP_Mail_Credential_Stealer
{
  meta:
    family   = "stealer-ftp-mail"
    tactic   = "credential-access"
    severity = "medium"
  condition:
    __is_pe and __smallish and
    __ftp_mail_targets and
    ( __uses_dpapi_or_vault or __uses_http_stack )
}

/* ------------ 5) .NET stealers (reflection + DPAPI + browsers) ------------ */
rule PE_DotNet_Infostealer_Heuristic
{
  meta:
    family   = ".net-stealer"
    tactic   = "credential-access"
    severity = "high"
  strings:
    $r1 = "System.Reflection.Assembly::Load" ascii
    $r2 = "System.Reflection.MethodInfo" ascii
    $n1 = "System.Net.Http.HttpClient" ascii
    $c1 = "System.Security.Cryptography.ProtectedData" ascii
    $m1 = "mscoree.dll" ascii
  condition:
    __is_pe and __smallish and
    ( pe.imports("mscoree.dll") or $m1 ) and
    ( 1 of ($r*) ) and
    ( $n1 or $c1 or __chromium_artifacts ) and
    ( __uses_http_stack or defined floss_url_cnt )
}

/* ------------ 6) Config/Panel words + exfil (multipart/gate.php) ------------ */
rule PE_Stealer_Exfil_Config_Words
{
  meta:
    family   = "stealer-exfil"
    tactic   = "exfiltration"
    severity = "medium"
  strings:
    $b1 = "multipart/form-data; boundary=" ascii
    $b2 = "/gate.php" ascii
    $b3 = "/upload.php" ascii
    $k1 = "BuildID" ascii
    $k2 = "Panel" ascii nocase
    $k3 = "Logs" ascii
  condition:
    __is_pe and __smallish and
    ( $b1 or $b2 or $b3 ) and
    ( __chromium_artifacts or __family_words or __discord_telegram_tokens ) and
    ( __uses_http_stack or (defined floss_url_cnt and floss_url_cnt >= 3) )
}

/* ------------ 7) Clipboard crypto clipper (more conservative) ------------ */
rule PE_Crypto_Clipper_Conservative
{
  meta:
    family   = "clipper"
    tactic   = "collection"
    severity = "medium"
  strings:
    $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii  // BTC (very broad)
    $eth = /0x[a-fA-F0-9]{40}/ ascii                 // ETH
    $clp = "Clipboard" ascii wide nocase
    $set = "SetClipboardData" ascii wide
    $get = "GetClipboardData" ascii wide
  condition:
    __is_pe and __smallish and
    ( ($btc and $eth) or ( ($btc or $eth) and ($clp or $set or $get) ) ) and
    ( __uses_http_stack or __family_words )
}

/* ------------ 8) High-confidence combo (few FPs): DPAPI + Chromium + Tokens/Wallets ------------ */
rule PE_Stealer_HC_DPAPI_Browser_Tokens
{
  meta:
    family   = "hc-stealer"
    tactic   = "credential-access"
    severity = "critical"
  condition:
    __is_pe and __smallish and
    __uses_dpapi_or_vault and
    __chromium_artifacts and
    ( __discord_telegram_tokens or __wallet_targets ) and
    ( __uses_http_stack or (defined floss_url_cnt and floss_url_cnt >= 2) )
}
