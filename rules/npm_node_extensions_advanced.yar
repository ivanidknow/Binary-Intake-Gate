/* npm_node_extensions_advanced.yar
 * Advanced supply-chain detection for NPM/Node + Chrome/Firefox extensions.
 * Author: ivan-gate
 */

/* ================= Helpers ================= */
private rule __small_text     { condition: filesize > 256 and filesize < 10MB }
private rule __is_zip_like    { condition: uint32(0) == 0x504B0304 }          // ZIP (CRX/ZIP/ext sources)
private rule __is_crx         { condition: uint32(0) == 0x43723234 }          // "Cr24" header
private rule __is_text_like   { condition: !__is_zip_like and !__is_crx }     // .js/.json/.ts/.mjs etc.

/* =============== NPM / Node (supply-chain) =============== */

/* package.json: postinstall/install/prepare + сетевые/exec команды */
rule NPM_Supply_PostInstall_Net_Exec
{
  meta: category="npm-supply" severity="high" rationale="postinstall/install scripts + curl/wget/node -e/powershell"
  strings:
    $p1 = /"scripts"\s*:\s*{[^}]*"(postinstall|install|prepare|preinstall)"\s*:\s*"(?:[^"]{0,400})"/ nocase
    $c1 = /\b(curl|wget)\b\s+https?:\/\// nocase
    $c2 = /\bpowershell\b\s+(-enc|IEX|FromBase64String)/ nocase
    $c3 = /\bnode\b\s+-e\s+/ nocase
    $c4 = /\bnpx\b\s+[a-z0-9._-]+/ nocase
    $d1 = /\bunzip|tar\s+-x|chmod\s+\+x|%TEMP%|\/tmp\// nocase
  condition:
    __small_text and __is_text_like and $p1 and ( $c1 or $c2 or $c3 or $c4 ) and $d1
}

/* .js: eval/new Function + Base64/Buffer.from + obf строкосклейки */
rule NODE_Obf_Eval_Base64_NewFunction
{
  meta: category="node-obf" severity="high" rationale="eval/new Function + Base64/Buffer.from concat"
  strings:
    $e1 = /\beval\s*\(/ nocase
    $e2 = /\bnew\s+Function\s*\(/ nocase
    $b1 = /Buffer\.from\s*\(\s*["'][A-Za-z0-9+\/=]{40,}["']\s*,\s*["']base64["']\s*\)/ nocase
    $b2 = /atob\s*\(\s*["'][A-Za-z0-9+\/=]{40,}["']\s*\)/ nocase
    $j1 = /""\.concat\(|"\s*"\s*\+\s*["']/ nocase
  condition:
    __small_text and __is_text_like and ( ($e1 or $e2) and ( $b1 or $b2 or $j1 ) )
}

/* Сбор секретов/кредов из окружения/файлов */
rule NODE_Secrets_Env_and_Files
{
  meta: category="secrets" severity="high" rationale="process.env AWS/GH tokens, ~/.npmrc, ~/.ssh"
  strings:
    $ev1 = /process\.env\.(AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)|GITHUB_TOKEN|NPM_TOKEN)/ nocase
    $ev2 = /process\.env\.[A-Z0-9_]{8,}\b/ nocase
    $fs1 = /\/\.npmrc|\\\.npmrc|\/\.ssh\/id_(rsa|ed25519)|\\\.ssh\\id_/ nocase
    $nt1 = /_authToken\s*=\s*[A-Za-z0-9_\-]{20,}/ nocase
  condition:
    __small_text and __is_text_like and ( $ev1 or ($ev2 and ($fs1 or $nt1)) )
}

/* HTTP/webhooks эксфиль: axios/fetch/http/https + Discord/Telegram/Gist/Paste */
rule NODE_Exfil_HTTP_Webhooks
{
  meta: category="exfiltration" severity="high" rationale="axios/fetch/https.request → popular endpoints"
  strings:
    $ax = /axios\.(post|get|put)\(/ nocase
    $fh = /fetch\s*\(/ nocase
    $hr = /https?\.(request|get)\(/ nocase
    $dc = /https?:\/\/(discord(app)?\.com\/api\/webhooks)/ nocase
    $tg = /https?:\/\/api\.telegram\.org\/bot/ nocase
    $ps = /https?:\/\/pastebin\.com\/(api|raw)/ nocase
    $gs = /https?:\/\/api\.github\.com\/gists/ nocase
  condition:
    __small_text and __is_text_like and ( ($ax or $fh or $hr) and ( $dc or $tg or $ps or $gs ) )
}

/* Подмена npmrc/registry (supply chain hijack) */
rule NPM_Tamper_NPMRC_Registry
{
  meta: category="npm-supply" severity="medium" rationale="запись в ~/.npmrc/registry креды"
  strings:
    $wr = /fs\.(writeFile|appendFile|writeFileSync)\(/ nocase
    $np = /"registry"\s*:\s*"https?:\/\/[^"]+"/ nocase
    $au = /_auth(Token)?\s*=\s*[A-Za-z0-9_\-]{16,}/ nocase
    $hn = /\/\/[^\/]+\/:_authToken=/ nocase
  condition:
    __small_text and __is_text_like and ( $wr and ( $np or $au or $hn ) )
}

/* node-pre-gyp / prebuild-install из сторонних URL (бинари-дроппер) */
rule NPM_Binary_Dropper_Prebuild_URL
{
  meta: category="npm-binary" severity="medium" rationale="prebuild-install/node-pre-gyp из кастомных URL"
  strings:
    $pb = /prebuild-install|node-pre-gyp/ nocase
    $ul = /https?:\/\/[^"'\s]{10,}\/(releases|download|bin|assets)\// nocase
  condition:
    __small_text and __is_text_like and ( $pb and $ul )
}

/* =============== Browser Extensions (Chrome/Firefox) =============== */

/* ZIP/CRX+manifest.json присутствует */
private rule __has_manifest_in_zip
{
  condition:
    ( __is_zip_like or __is_crx ) and /manifest\.json/ nocase
}

/* Опасные разрешения и доступ ко всем сайтам */
rule EXT_Permissions_AllUrls_Risky
{
  meta: category="ext-permissions" severity="high" rationale="пермишены широкие/чувствительные"
  strings:
    $p1 = /"permissions"\s*:\s*\[[^\]]*(<all_urls>|webRequest|webRequestBlocking|cookies|history|downloads|nativeMessaging|clipboardRead|tabs|declarativeNetRequestWithHostAccess)/ nocase
    $h1 = /"host_permissions"\s*:\s*\[[^\]]*<all_urls>/ nocase
  condition:
    __has_manifest_in_zip and ( $p1 or $h1 )
}

/* eval/new Function/unsafe-eval в фоне (background/service_worker) */
rule EXT_Background_Eval_Unsafe
{
  meta: category="ext-eval" severity="high" rationale="background/service_worker с eval/new Function/unsafe-eval"
  strings:
    $bg = /"background"\s*:\s*{[^}]*("scripts"| "service_worker")/ nocase
    $ev = /\beval\s*\(|\bnew\s+Function\s*\(/ nocase
    $cp = /"content_security_policy"[^"\n]*unsafe-eval/i
  condition:
    ( __has_manifest_in_zip or __small_text ) and ( $bg and ( $ev or $cp ) )
}

/* Контент-скрипты: кейлоггер/формы + отправка наружу */
rule EXT_ContentScript_Keylog_Exfil
{
  meta: category="ext-content" severity="high" rationale="keydown/submit + fetch/axios/webhook"
  strings:
    $cs = /"content_scripts"\s*:\s*\[/ nocase
    $kd = /addEventListener\(\s*["']keydown["']/ nocase
    $sm = /addEventListener\(\s*["']submit["']/ nocase
    $fv = /(FormData|querySelector\(["'][^"']*(password|token|otp)["']\))/ nocase
    $ex = /fetch\s*\(|axios\.(post|get)|websocket|new\s+WebSocket/i
  condition:
    ( __has_manifest_in_zip or __small_text ) and ( $cs and ( ($kd or $sm) and ($fv or $ex) ) )
}

/* Доверенные обновления → подозрительный update_url вне WebStore */
rule EXT_Suspicious_Update_URL
{
  meta: category="ext-update" severity="medium" rationale="update_url на сторонний домен"
  strings:
    $uu = /"update_url"\s*:\s*"https?:\/\/(?!clients2\.google\.com\/service\/update2\/crx|addons\.mozilla\.org)[^"]+"/ nocase
  condition:
    __has_manifest_in_zip and $uu
}

/* Сторонние webhooks/эксфил из расширения */
rule EXT_Webhooks_Exfil
{
  meta: category="ext-exfil" severity="high" rationale="Discord/Telegram/Paste/Gist из расширения"
  strings:
    $dc = /https?:\/\/(discord(app)?\.com\/api\/webhooks)/ nocase
    $tg = /https?:\/\/api\.telegram\.org\/bot/ nocase
    $ps = /https?:\/\/pastebin\.com\/(api|raw)/ nocase
    $gs = /https?:\/\/api\.github\.com\/gists/ nocase
  condition:
    ( __has_manifest_in_zip or __small_text ) and ( $dc or $tg or $ps or $gs )
}

/* Экстремально широкая externally_connectable + messaging наружу */
rule EXT_Externally_Connectable_Wide
{
  meta: category="ext-permissions" severity="medium" rationale="externally_connectable практически для всех"
  strings:
    $ex = /"externally_connectable"\s*:\s*{[^}]*"matches"\s*:\s*\[\s*"\*:\/\/\*\/\*"\s*\]/ nocase
  condition:
    __has_manifest_in_zip and $ex
}

/* CSP ослаблен + удалённый код через fetch+eval */
rule EXT_Remote_Code_Fetch_Eval
{
  meta: category="ext-remote-code" severity="high" rationale="fetch → eval/new Function при слабом CSP"
  strings:
    $cp = /"content_security_policy"[^"\n]*unsafe-eval/i
    $fe = /fetch\s*\(\s*["']https?:\/\/[^"']{10,}["']\s*\)/ nocase
    $ev = /\beval\s*\(|\bnew\s+Function\s*\(/ nocase
  condition:
    ( __has_manifest_in_zip or __small_text ) and ( $cp and $fe and $ev )
}

/* =============== High-Confidence COMBOS (низкий FP) =============== */

/* HC1: NPM postinstall + eval/base64/Buffer.from */
rule NPM_HC_PostInstall_Obf_Exec
{
  meta: category="combo" severity="critical"
  condition:
    NPM_Supply_PostInstall_Net_Exec and NODE_Obf_Eval_Base64_NewFunction
}

/* HC2: Node сбор секретов + webhooks эксфиль */
rule NODE_HC_Secrets_To_Webhooks
{
  meta: category="combo" severity="critical"
  condition:
    NODE_Secrets_Env_and_Files and NODE_Exfil_HTTP_Webhooks
}

/* HC3: Extension опасные пермишены + eval/unsafe-eval в фоне */
rule EXT_HC_Perms_Background_Eval
{
  meta: category="combo" severity="critical"
  condition:
    EXT_Permissions_AllUrls_Risky and EXT_Background_Eval_Unsafe
}

/* HC4: Extension контент-скрипт (кейлог/формы) + эксфиль/webhooks */
rule EXT_HC_Content_Exfil
{
  meta: category="combo" severity="critical"
  condition:
    EXT_ContentScript_Keylog_Exfil and ( EXT_Webhooks_Exfil or EXT_Permissions_AllUrls_Risky )
}
