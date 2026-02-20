/* cicd_secrets_advanced.yar
 * CI/CD pipelines & secrets hunting (GitHub Actions/GitLab/Jenkins/etc.) + common tokens/configs
 * Author: ivan-gate
 */

/* ================= Helpers ================= */
private rule __small_text { condition: filesize > 200 and filesize < 15MB }
private rule __is_zip     { condition: uint32(0) == 0x504B0304 }   // archives/workspace zips
private rule __is_text    { condition: __small_text and !__is_zip }

/* ================= 1) Tokens & Credentials (generic, high-signal) ================= */
rule TOKENS_Common_DevOps_Cloud
{
  meta: category="secrets" severity="critical" rationale="PATs, cloud keys, chat/webhooks"
  strings:
    // GitHub/GitLab PAT
    $gh = /ghp_[A-Za-z0-9]{36}/ ascii
    $gl = /glpat-[A-Za-z0-9_-]{20,}/ ascii
    // Slack/Telegram/Discord
    $sl = /xox[abpr]-[A-Za-z0-9-]{10,48}/ ascii
    $tg = /[\w\-]{24,35}:[A-Za-z0-9_-]{30,40}/ ascii
    $dw = /https?:\/\/(discord(app)?\.com\/api\/webhooks\/)[A-Za-z0-9\/._-]{20,}/ nocase ascii
    // AWS
    $ak = /AKIA[0-9A-Z]{16}/ ascii
    $as = /(?i)aws_secret_access_key(\s*[:=]\s*["']?[A-Za-z0-9\/+=]{32,}["']?)/ ascii
    // GCP
    $gc = /"type"\s*:\s*"service_account".*"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/s ascii
    // Azure
    $az = /(AZURE_(CLIENT_ID|TENANT_ID|CLIENT_SECRET)\s*[:=]\s*["']?[A-Za-z0-9-_]{6,}["']?)/ ascii
    // NPM / PyPI / DockerHub
    $np = /_authToken\s*=\s*[A-Za-z0-9_-]{20,}/ ascii
    $pp = /pypi-AgEI[0-9A-Za-z_\-]{20,}/ ascii
    $dh = /(DOCKERHUB_)?PASSWORD\s*[:=]\s*["']?.{8,}["']?/ ascii
  condition:
    __is_text and ( any of ($gh,$gl,$sl,$tg,$dw,$ak,$as,$gc,$az,$np,$pp,$dh) )
}

/* ================= 2) Secret files & config markers ================= */
rule SECRETS_Config_Markers
{
  meta: category="secrets" severity="high" rationale=".env, .npmrc, .pypirc, kubeconfig, SSH keys, docker config.json"
  strings:
    $env = /(^|\n)\s*([A-Z0-9_]{3,})\s*=\s*.+/ ascii
    $nr  = "/.npmrc" ascii nocase
    $prc = "/.pypirc" ascii nocase
    $ssh = /-----BEGIN (OPENSSH|RSA|EC|DSA) PRIVATE KEY-----/ ascii
    $cfg = /"auths"\s*:\s*{[^}]*"auth"\s*:\s*"[A-Za-z0-9+=/]{20,}"/ ascii   // docker config.json
    $kbc = /current-context\s*:/ ascii
    $kbs = /apiVersion:\s*v1\s*\n(kind:\s*Config)?/ ascii
    $kh  = "/.ssh/known_hosts" ascii
  condition:
    __is_text and ( $ssh or $cfg or ($nr or $prc or $env) or ( $kbc and $kbs ) or $kh )
}

/* ================= 3) GitHub Actions (workflow) risk patterns ================= */
rule GHA_Workflow_Risky_Patterns
{
  meta: category="cicd-workflow" severity="high" rationale="curl|bash, secrets.* echo, remote binaries in workflow YAML"
  strings:
    $wf = /name:\s*[^\n]+\n(?:.|\n)*?on:\s*/ ascii
    $rb = /\brun:\s*.+/ ascii
    $cb = /\brun:\s*(curl|wget)\s+[-\w ]*https?:\/\/[^\s|]+(\s*\|\s*(bash|sh))/ nocase
    $ps = /\brun:\s*powershell\s+(-enc|IEX|FromBase64String)/ nocase
    $se = /echo\s+\$?\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}/ nocase
    $dl = /\brun:\s*(Invoke-WebRequest|Expand-Archive)/ nocase
  condition:
    __is_text and ( $wf and ( $cb or $ps or $se or $dl ) )
}

/* ================= 4) GitLab CI risk patterns ================= */
rule GLabCI_Risky_Patterns
{
  meta: category="cicd-workflow" severity="high" rationale=".gitlab-ci.yml with curl|bash, artifacts with secrets"
  strings:
    $gl = /\sstages:\s*\n/ ascii
    $rb = /\s(script|before_script|after_script):\s*\n(\s*-\s*.+\n)+/ ascii
    $cb = /\s-\s*(curl|wget)\s+[-\w ]*https?:\/\/[^\s|]+(\s*\|\s*(bash|sh))/ nocase
    $ex = /\s-\s*export\s+[A-Z0-9_]{3,}=.+/ ascii
    $se = /\$\{CI_JOB_TOKEN\}|\$\{CI_REGISTRY_PASSWORD\}/ ascii
  condition:
    __is_text and ( $gl and $rb and ( $cb or $se or $ex ) )
}

/* ================= 5) Jenkins/TeamCity/CircleCI pipelines ================= */
rule Jenkinsfile_Risky_Steps
{
  meta: category="cicd-workflow" severity="high" rationale="Jenkinsfile sh 'curl|bash', withCredentials misuse"
  strings:
    $jk = /pipeline\s*\{|node\s*\{/ ascii
    $sh = /sh\s+['"]\s*(curl|wget)\s+.*https?:\/\/[^\s|]+(\s*\|\s*(bash|sh))/ nocase
    $wc = /withCredentials\(\s*\[.*\]\s*\)/ ascii
    $ec = /echo\s+env\.[A-Z0-9_]{3,}/ ascii
  condition:
    __is_text and $jk and ( $sh or $wc or $ec )
}

rule TC_Circle_Risky_Steps
{
  meta: category="cicd-workflow" severity="medium" rationale="TeamCity/CircleCI steps with curl|bash or secrets echo"
  strings:
    $tc = /steps:\s*\n(\s*step\(|\s*script:)/ ascii
    $cc = /circleci/ ascii
    $cb = /(curl|wget)\s+https?:\/\/[^\s|]+(\s*\|\s*(bash|sh))/ nocase
    $ec = /echo\s+\$?(AWS_|GITHUB_|NPM_|CI_|DOCKER_)[A-Z0-9_]+/ ascii
  condition:
    __is_text and ( ($tc or $cc) and ( $cb or $ec ) )
}

/* ================= 6) Terraform/Helm state & charts with secrets ================= */
rule Terraform_State_Or_Variables_Secrets
{
  meta: category="iac-secrets" severity="high" rationale="terraform.tfstate / variables with tokens/passwords"
  strings:
    $ts = /"terraform_version"\s*:\s*"[0-9.]+"/ ascii
    $ps = /"(?i)(password|token|secret|access_key|private_key)"\s*:\s*".{4,}"/ ascii
    $tfv= /variable\s*"(?:password|token|secret|access_key|private_key)"/ nocase
  condition:
    __is_text and ( $ts and $ps or $tfv )
}

rule Helm_Chart_Values_Secrets
{
  meta: category="iac-secrets" severity="medium" rationale="Helm values.yaml with tokens/passwords"
  strings:
    $vl = /values\.yaml/ ascii
    $ky = /(?i)(password|token|secret|accessKey|secretKey)\s*:\s*.{3,}/ ascii
  condition:
    __is_text and ( $ky or $vl )
}

/* ================= 7) Docker registry & image push with creds ================= */
rule Docker_Login_Plain_Push
{
  meta: category="registry" severity="high" rationale="docker login with password in CI, push to external registry"
  strings:
    $dl = /docker\s+login\s+(-u\s+\S+\s+)?(-p\s+\S+|\s*--password\s+\S+)/ nocase
    $ps = /docker\s+push\s+[A-Za-z0-9\.\-:\/]+/ ascii
    $er = /(ghcr\.io|registry\.gitlab\.com|docker\.io|[a-z0-9.-]+\/[a-z0-9._-]+\/[a-z0-9._-]+)/ ascii
  condition:
    __is_text and $dl and $ps and $er
}

/* ================= 8) Kubernetes context usage in CI ================= */
rule Kubeconfig_and_kubectl_or_helm
{
  meta: category="cluster" severity="high" rationale="kubeconfig + kubectl/helm in pipeline"
  strings:
    $kc1 = /apiVersion:\s*v1\s*\n(kind:\s*Config)?/ ascii
    $kc2 = /current-context\s*:/ ascii
    $kb1 = /\bkubectl\s+(apply|delete|create|exec|cp|port-forward)/ ascii
    $hl1 = /\bhelm\s+(install|upgrade|template|uninstall)/ ascii
  condition:
    __is_text and ( ($kc1 and $kc2) and ( $kb1 or $hl1 ) )
}

/* ================= 9) Risky CI habits: curl|bash + writing SSH keys ================= */
rule CI_CurlPipeBash_AddSSH
{
  meta: category="cicd-risk" severity="high" rationale="curl|bash & writes id_rsa/known_hosts"
  strings:
    $cb = /(curl|wget)\s+[-\w ]*https?:\/\/[^\s|]+(\s*\|\s*(bash|sh))/ nocase
    $wr = /(echo|printf)\s+["'][A-Za-z0-9+\/=\n\r\-]{50,}["']\s*>\s*~\/\.ssh\/id_(rsa|ed25519)/ nocase
    $kh = /(ssh-keyscan|echo\s+\S+\s+>>\s*~\/\.ssh\/known_hosts)/ nocase
  condition:
    __is_text and $cb and ( $wr or $kh )
}

/* ================= 10) High-Confidence COMBOS (низкий FP) ================= */

/* HC1: CI workflow (any) + curl|bash + webhook/exfil */
rule HC_CI_CurlBash_To_Webhook
{
  meta: category="combo" severity="critical"
  condition:
    ( GHA_Workflow_Risky_Patterns or GLabCI_Risky_Patterns or Jenkinsfile_Risky_Steps or TC_Circle_Risky_Steps )
    and
    ( TOKENS_Common_DevOps_Cloud or CI_CurlPipeBash_AddSSH )
}

/* HC2: Terraform/Helm state with secrets + tokens */
rule HC_IaC_State_And_Tokens
{
  meta: category="combo" severity="critical"
  condition:
    ( Terraform_State_Or_Variables_Secrets or Helm_Chart_Values_Secrets ) and TOKENS_Common_DevOps_Cloud
}

/* HC3: kubeconfig + kubectl/helm + tokens */
rule HC_Kubeconfig_And_Exec_With_Tokens
{
  meta: category="combo" severity="critical"
  condition:
    Kubeconfig_and_kubectl_or_helm and ( TOKENS_Common_DevOps_Cloud or SECRETS_Config_Markers )
}

/* HC4: Docker registry login + push + secrets in env */
rule HC_Docker_Login_Push_Secrets
{
  meta: category="combo" severity="high"
  condition:
    Docker_Login_Plain_Push and ( TOKENS_Common_DevOps_Cloud or SECRETS_Config_Markers )
}
