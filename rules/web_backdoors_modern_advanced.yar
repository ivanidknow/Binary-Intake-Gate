/* web_backdoors_modern_advanced.yar
 * Modern web backdoors & risky handlers in Node.js and Python frameworks
 * Author: ivan-gate
 */

/* ============== Helpers ============== */
private rule __small_text { condition: filesize > 256 and filesize < 8MB }
private rule __is_text    { condition: __small_text }

/* ============== A) Node.js / Express / Koa / Nest ============== */

/* A1) Express/Koa: скрытые роуты + RCE (eval/Function/child_process) */
rule NODE_Express_Hidden_Route_RCE
{
  meta: category="node-backdoor" severity="high" rationale="Скрытые маршруты + eval/new Function/child_process"
  strings:
    $ex1 = /app\.(get|post|all)\s*\(\s*["']\/(shell|cmd|exec|backdoor|_debug|_admin)["']\s*,/ nocase
    $ex2 = /router\.(get|post|all)\s*\(\s*["']\/(shell|cmd|exec)["']\s*,/ nocase
    $fn1 = /\beval\s*\(|\bnew\s+Function\s*\(/ nocase
    $cp1 = /require\(\s*["']child_process["']\s*\)\.(exec|spawn|execFile)/ nocase
    $vm1 = /require\(\s*["']vm["']\s*\)\.runIn(NewContext|ThisContext)/ nocase
    $rq1 = /req\.(query|body|headers|params)\[[^]]+\]/ nocase
  condition:
    __is_text and ( ($ex1 or $ex2) and ( $fn1 or $cp1 or $vm1 ) and $rq1 )
}

/* A2) Dynamic require/remote code puller */
rule NODE_Remote_Code_Puller
{
  meta: category="node-loader" severity="high" rationale="fetch/axios + eval/new Function"
  strings:
    $ax  = /axios\.(get|post)\(/ nocase
    $fh  = /fetch\s*\(/ nocase
    $rq  = /https?\.(request|get)\(/ nocase
    $ev  = /\beval\s*\(|\bnew\s+Function\s*\(/ nocase
    $bf  = /Buffer\.from\(\s*["'][A-Za-z0-9+\/=]{40,}["']\s*,\s*["']base64["']\s*\)/ nocase
  condition:
    __is_text and ( ($ax or $fh or $rq) and ($ev or $bf) )
}

/* A3) Upload-ручка → exec (multer, tmp → exec) */
rule NODE_Upload_Multer_Drop_Exec
{
  meta: category="node-upload" severity="high" rationale="multer/save temp + child_process.exec"
  strings:
    $m1 = /require\(\s*["']multer["']\s*\)/ nocase
    $t1 = /(os\.tmpdir\(\)|\/tmp\/|\\AppData\\Local\\Temp)/ nocase
    $cp = /child_process["']?\)\.(exec|spawn|execFile)\(/ nocase
  condition:
    __is_text and $m1 and $t1 and $cp
}

/* A4) Path Traversal / sendFile на параметре */
rule NODE_Path_Traversal_SendFile
{
  meta: category="node-path" severity="medium" rationale="sendFile/readFile с сырым параметром"
  strings:
    $sf = /\.sendFile\(|fs\.(readFile|createReadStream)\(/ nocase
    $rq = /req\.(query|params|body)\[[^]]+\]/ nocase
    $pt = /\.\.\// nocase
  condition:
    __is_text and $sf and ( $rq or $pt )
}

/* A5) SSRF через запросы по параметру */
rule NODE_SSRF_Parameter_Fetch
{
  meta: category="node-ssrf" severity="medium" rationale="fetch/axios url из req.*"
  strings:
    $ax = /axios\.(get|post)\(\s*req\.(query|body|params)\[[^]]+\]/ nocase
    $fh = /fetch\(\s*req\.(query|body|params)\[[^]]+\]/ nocase
    $rq = /https?\.(get|request)\(\s*req\.(query|body|params)\[[^]]+\]/ nocase
  condition:
    __is_text and ( $ax or $fh or $rq )
}

/* A6) Templating SSTI: Nunjucks/EJS/Handlebars с небезопасной строкой */
rule NODE_SSTI_Templating_Unsanitized
{
  meta: category="node-ssti" severity="high" rationale="render из строки/пользовательского ввода"
  strings:
    $nj = /nunjucks\.(render|renderString)\(/ nocase
    $ej = /ejs\.render\(/ nocase
    $hb = /handlebars\.compile\(/ nocase
    $rq = /req\.(query|body|params)\[[^]]+\]/ nocase
  condition:
    __is_text and ( ($nj or $ej or $hb) and $rq )
}

/* ============== B) Python / Flask / Django / FastAPI ============== */

/* B1) Flask/FastAPI: скрытые роуты + RCE/eval/exec/subprocess */
rule PY_Web_Route_RCE
{
  meta: category="py-backdoor" severity="high" rationale="@app.route('/cmd|/shell') + eval/exec/subprocess/os.popen"
  strings:
    $rt1 = /@app\.route\(\s*["']\/(cmd|shell|exec|backdoor|_debug)["']/ nocase
    $rt2 = /@app\.(get|post)\(\s*["']\/(cmd|shell|exec)["']/ nocase
    $fa1 = /@app\.(api_route|websocket)\(|APIRouter\(.+\)\.(get|post)\(/ nocase
    $ev1 = /\beval\(|\bexec\(/ nocase
    $sb1 = /subprocess\.(Popen|call|run|check_output)\(/ nocase
    $os1 = /os\.popen\(/ nocase
    $rq1 = /request\.(args|get_json|form|values)\[/ nocase
  condition:
    __is_text and ( ($rt1 or $rt2 or $fa1) and ( $ev1 or $sb1 or $os1 ) and $rq1 )
}

/* B2) Опасная десериализация: pickle/yaml/jsonpickle */
rule PY_Unsafe_Deserialization
{
  meta: category="py-deser" severity="critical" rationale="pickle.loads / yaml.load (без SafeLoader) / jsonpickle.decode из запроса"
  strings:
    $pk = /pickle\.loads\(/ nocase
    $yl = /yaml\.load\(/ nocase
    $ys = /yaml\.FullLoader|yaml\.UnsafeLoader/ nocase
    $jp = /jsonpickle\.decode\(/ nocase
    $rq = /request\.(data|get_data|json|form|values)\[/ nocase
    $b6 = /base64\.b64decode\(/ nocase
  condition:
    __is_text and ( ($pk or ($yl and not $ys) or $jp) and ($rq or $b6) )
}

/* B3) Jinja2 SSTI / Template.render на пользовательском вводе */
rule PY_Jinja2_SSTI_Unsanitized
{
  meta: category="py-ssti" severity="high" rationale="Template/Environment.render из request.*"
  strings:
    $tj = /from\s+jinja2\s+import\s+(Template|Environment)|jinja2\.Environment/ nocase
    $rs = /(Template\(|Environment\().*render(String)?\(/ nocase
    $rq = /request\.(args|values|form|get_json)\[/ nocase
  condition:
    __is_text and $tj and $rs and $rq
}

/* B4) Flask/Werkzeug debug PIN/console наличие */
rule PY_Werkzeug_Debug_Artifacts
{
  meta: category="py-debug" severity="medium" rationale="Werkzeug debugger / PIN артефакты"
  strings:
    $wk = /WERKZEUG_DEBUG_PIN|Debugger PIN/i
    $db = /from\s+werkzeug\.debug\s+import|evalex=True/i
  condition:
    __is_text and ( $wk or $db )
}

/* B5) Django небезопасные настройки */
rule PY_Django_Insecure_Settings
{
  meta: category="py-config" severity="medium" rationale="DEBUG=True, SECRET_KEY hardcoded, ALLOWED_HOSTS=['*']"
  strings:
    $dg = /DEBUG\s*=\s*True/ nocase
    $sk = /SECRET_KEY\s*=\s*["'][^"']{16,}["']/ nocase
    $ah = /ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']\s*\]/ nocase
  condition:
    __is_text and ( $dg or $sk or $ah )
}

/* B6) SSRF/траверс: requests.get(open_url) или send_file на параметре */
rule PY_SSRF_Path_Traversal
{
  meta: category="py-ssrf-path" severity="medium" rationale="requests.* с параметром; send_file/open с user input"
  strings:
    $rq = /requests\.(get|post|head)\(\s*request\.(args|form|values)\[[^]]+\]/ nocase
    $sf = /send_file\(\s*request\.(args|values|form)\[[^]]+\]/ nocase
    $op = /open\(\s*request\.(args|values|form)\[[^]]+\]/ nocase
    $pt = /\.\.\// nocase
  condition:
    __is_text and ( $rq or $sf or $op or $pt )
}

/* B7) Upload-ручка → exec/deserialize (werkzeug/FileStorage) */
rule PY_Upload_Exec_or_Deserialize
{
  meta: category="py-upload" severity="high" rationale="request.files + exec/pickle"
  strings:
    $uf = /request\.files\[[^]]+\]/ nocase
    $sv = /(save\(|stream\.read\()/ nocase
    $ex = /\bexec\(|subprocess\.(run|Popen|call)\(/ nocase
    $pk = /pickle\.loads\(/ nocase
  condition:
    __is_text and $uf and $sv and ( $ex or $pk )
}

/* ============== C) Generic exfil/webhooks & secrets (общие для Node/Python) ============== */
rule WEB_Exfil_To_Webhooks
{
  meta: category="exfiltration" severity="high" rationale="Discord/Telegram/Paste/Gist"
  strings:
    $dc = /https?:\/\/(discord(app)?\.com\/api\/webhooks)/ nocase
    $tg = /https?:\/\/api\.telegram\.org\/bot/ nocase
    $ps = /https?:\/\/pastebin\.com\/(api|raw)/ nocase
    $gs = /https?:\/\/api\.github\.com\/gists/ nocase
  condition:
    __is_text and ( $dc or $tg or $ps or $gs )
}

rule WEB_Secrets_Env_Dotfiles
{
  meta: category="secrets" severity="high" rationale="доступ к env/секретам/ssh"
  strings:
    $ev = /process\.env\.|os\.environ\[/ nocase
    $sf = /\/\.env|\\\.env|\/\.ssh\/id_(rsa|ed25519)|\\\.ssh\\id_/ nocase
    $ak = /(AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|TELEGRAM_BOT_TOKEN|DISCORD_TOKEN)/ nocase
  condition:
    __is_text and ( $ev or $sf or $ak )
}

/* ============== D) High-Confidence COMBOS (низкий FP) ============== */

/* D1) Node: скрытый роут + RCE + эксфиль */
rule HC_NODE_Backdoor_RCE_Exfil
{
  meta: category="combo" severity="critical"
  condition:
    NODE_Express_Hidden_Route_RCE and ( WEB_Exfil_To_Webhooks or WEB_Secrets_Env_Dotfiles )
}

/* D2) Python: скрытый роут + десериализация/exec */
rule HC_PY_Backdoor_Deserialize
{
  meta: category="combo" severity="critical"
  condition:
    PY_Web_Route_RCE and PY_Unsafe_Deserialization
}

/* D3) Upload-цепочка: загрузка → exec/deserialize (любой стек) */
rule HC_Upload_To_Exec_Or_Deserialize
{
  meta: category="combo" severity="high"
  condition:
    ( NODE_Upload_Multer_Drop_Exec or PY_Upload_Exec_or_Deserialize ) and ( WEB_Exfil_To_Webhooks or WEB_Secrets_Env_Dotfiles )
}

/* D4) SSTI + опасные настройки/шаблоны */
rule HC_SSTI_And_Insecure_Config
{
  meta: category="combo" severity="high"
  condition:
    ( NODE_SSTI_Templating_Unsanitized or PY_Jinja2_SSTI_Unsanitized ) and ( PY_Django_Insecure_Settings or PY_Werkzeug_Debug_Artifacts )
}
