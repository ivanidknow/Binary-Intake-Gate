/* cloud_k8s_abuse_advanced.yar
 * Coverage: cloud creds, kubeconfig/SA tokens, metadata SSRF, privileged containers,
 * dangerous mounts, cluster persistence, secret exfil, lateral tools, miners.
 * Author: ivan-gate
 */

rule Cloud_AWS_Creds_Files_Env
{
  meta: category="cloud-creds" severity="high"
  strings:
    $e1 = "AWS_ACCESS_KEY_ID"
    $e2 = "AWS_SECRET_ACCESS_KEY"
    $e3 = "AWS_SESSION_TOKEN"
    $p1 = "/.aws/credentials"
    $p2 = "[default]\naws_access_key_id"
  condition:
    filesize < 20MB and ( any of ($e*) or any of ($p*) )
}

rule Cloud_GCP_ADC_and_Metadata
{
  meta: category="cloud-creds" severity="high"
  strings:
    $adc1 = "\"type\": \"service_account\"" ascii
    $adc2 = "\"private_key_id\": \"" ascii
    $md1  = "Metadata-Flavor: Google"
    $md2  = "http://169.254.169.254/computeMetadata/v1"
  condition:
    filesize < 20MB and ( ($adc1 and $adc2) or any of ($md*) )
}

rule Cloud_Azure_MSI_and_Secrets
{
  meta: category="cloud-creds" severity="high"
  strings:
    $az1 = "AZURE_TENANT_ID"
    $az2 = "AZURE_CLIENT_ID"
    $az3 = "AZURE_CLIENT_SECRET"
    $msi = "http://169.254.169.254/metadata/identity/oauth2/token"
  condition:
    filesize < 20MB and ( any of ($az*) or $msi )
}

rule K8s_Kubeconfig_SA_Tokens
{
  meta: category="k8s-creds" severity="high"
  strings:
    $kc1 = "/.kube/config"
    $kc2 = "current-context:"
    $sa1 = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    $ca1 = "certificate-authority-data:"
  condition:
    filesize < 50MB and ( any of ($kc*) or $sa1 or $ca1 )
}

rule K8s_Metadata_Azure_AKS_EKS_GKE
{
  meta: category="k8s-metadata" severity="medium"
  strings:
    $aws = "http://169.254.170.2/v2/credentials"     // ECS task metadata
    $eks = "eks.amazonaws.com"
    $gke = "metadata.google.internal"
    $aks = "aks-nodepool" ascii
  condition:
    filesize < 10MB and ( $aws or $gke or $aks or $eks )
}

rule Container_Privileged_Caps_UnsafeProfiles
{
  meta: category="container-hardening" severity="high"
  strings:
    $pr = "privileged: true"
    $ae = "allowPrivilegeEscalation: true"
    $hp = "hostPID: true"
    $hn = "hostNetwork: true"
    $ca = "cap_add: [\"SYS_ADMIN\"" ascii
    $yc1= "capAdd:" ascii
    $yc2= "- SYS_ADMIN" ascii
    $sec1= "seccomp: unconfined"
    $app1= "apparmor.security.beta.kubernetes.io/allowedProfileNames=unconfined"
  condition:
    filesize < 5MB and 1 of ($pr,$ae,$hp,$hn,$sec1,$app1) or 1 of ($ca,$yc1,$yc2)
}

rule Container_Dangerous_Sockets_and_HostPath
{
  meta: category="container-escape" severity="high"
  strings:
    $ds1 = "/var/run/docker.sock"
    $cs1 = "/run/containerd/containerd.sock"
    $hp1 = "hostPath:" ascii
    $hp2 = "path: /etc/kubernetes" ascii
    $hp3 = "path: /var/lib/kubelet" ascii
  condition:
    filesize < 10MB and ( any of ($ds1,$cs1) or any of ($hp*) )
}

rule Container_Escape_Tools_and_Binaries
{
  meta: category="container-escape" severity="high"
  strings:
    $ns = "nsenter"
    $ch = "chroot"
    $mt = "mount -t proc proc /proc"
    $pf = "/proc/1/root"
  condition:
    filesize < 100MB and ( any of ($ns,$ch) or $mt or $pf )
}

rule K8s_Cluster_Persistence_Objects
{
  meta: category="k8s-persistence" severity="medium"
  strings:
    $cj = "kind: CronJob"
    $ds = "kind: DaemonSet"
    $mw = "kind: MutatingWebhookConfiguration"
    $vw = "kind: ValidatingWebhookConfiguration"
    $rb = "kind: ClusterRoleBinding"
    $cr = "kind: ClusterRole"
  condition:
    filesize < 2MB and 1 of ($cj,$ds,$mw,$vw,$rb,$cr)
}

rule K8s_Secret_Exfiltration_Commands
{
  meta: category="exfiltration" severity="high"
  strings:
    $k1 = "kubectl get secrets -o json"
    $k2 = "jq -r .data"
    $b6 = "base64 -d"
    $k3 = "kubectl config view --raw"
  condition:
    filesize < 5MB and ( ($k1 and ($k2 or $b6)) or $k3 )
}

rule K8s_Lateral_kubectl_crictl_tools
{
  meta: category="lateral" severity="medium"
  strings:
    $kt = "kubectl"
    $kc = "kubeletctl"
    $ct = "crictl"
    $hl = "helm"
    $pf = "kubectl port-forward"
    $ex = "kubectl exec"
  condition:
    filesize < 50MB and ( 2 of ($kt,$kc,$ct,$hl,$pf,$ex) )
}

rule Cloud_Miner_in_Container
{
  meta: category="mining" severity="high"
  strings:
    $xm = "xmrig" nocase
    $st = /stratum\+((tcp|ssl))/ nocase
    $p1 = ":3333"
    $p2 = ":4444"
    $p3 = ":5555"
    $p4 = ":7777"
  condition:
    filesize < 200MB and ( $xm or ( $st and 1 of ($p1,$p2,$p3,$p4) ) )
}

rule K8s_Image_Secrets_and_SSH
{
  meta: category="secrets" severity="medium"
  strings:
    $dk1 = "/.docker/config.json"
    $dk2 = "\"auths\"" ascii
    $gh1 = "GITHUB_TOKEN"
    $gl1 = "CI_JOB_TOKEN"
    $ssh = "/.ssh/id_rsa"
  condition:
    filesize < 20MB and ( $dk1 or ($dk2 and $dk1) or $gh1 or $gl1 or $ssh )
}

/* High-confidence combo: creds + metadata or kubeconfig + kubectl */
rule CloudK8s_HC_Compromise_Combo
{
  meta: category="combo" severity="critical"
  condition:
    ( Cloud_AWS_Creds_Files_Env or Cloud_GCP_ADC_and_Metadata or Cloud_Azure_MSI_and_Secrets ) and
    ( K8s_Kubeconfig_SA_Tokens or K8s_Metadata_Azure_AKS_EKS_GKE or K8s_Secret_Exfiltration_Commands or K8s_Lateral_kubectl_crictl_tools )
}

/* High-confidence container escape combo */
rule Container_HC_Escape_Combo
{
  meta: category="combo" severity="critical"
  condition:
    Container_Privileged_Caps_UnsafeProfiles and
    ( Container_Dangerous_Sockets_and_HostPath or Container_Escape_Tools_and_Binaries )
}
