/* elf_miners_persist_advanced.yar
 * Linux miners + persistence & stealth (families, pools, configs, autostart, LD tricks)
 * Author: ivan-gate
 */

import "elf"

/* ================= Helpers ================= */
private rule __is_elf        { condition: uint32(0) == 0x7F454C46 and elf }
private rule __smallish_bin  { condition: filesize > 10KB and filesize < 200MB }

private rule __rwx_section {
  // section flags: SHF_WRITE=0x1, SHF_EXECINSTR=0x4
  condition:
    for any i in (0 .. elf.number_of_sections - 1):
      ( (elf.sections[i].flags & 0x1) == 0x1 and (elf.sections[i].flags & 0x4) == 0x4 )
}

/* ================= Pools / generic miner indicators ================= */
rule ELF_Miner_Pools_Generic
{
  meta: category="mining" severity="high"
  strings:
    $s1 = /stratum\+(tcp|ssl):\/\// nocase
    $p1 = ":3333" ascii
    $p2 = ":4444" ascii
    $p3 = ":5555" ascii
    $p4 = ":7777" ascii
    $w1 = /wallet|rig-id|rig_id|pass|user/i
    $h1 = /hashrate|donate-level|algo|rx|cryptonight/i
  condition:
    __is_elf and __smallish_bin and
    $s1 and 1 of ($p1,$p2,$p3,$p4) and ( $w1 or $h1 )
}

/* ================= Families ================= */
rule ELF_Miner_XMRig_Family
{
  meta: family="xmrig" category="mining" severity="high"
  strings:
    $x1 = "xmrig" ascii nocase
    $x2 = "donate-level" ascii
    $x3 = "rx/0" ascii
    $x4 = "\"pools\"" ascii
    $x5 = "MSR Mod" ascii
  condition:
    __is_elf and __smallish_bin and ( 2 of ($x*) )
}

rule ELF_Miner_Cpuminer_Family
{
  meta: family="cpuminer" category="mining" severity="high"
  strings:
    $c1 = "cpuminer" ascii
    $c2 = "yespower" ascii
    $c3 = "cpupower" ascii
  condition:
    __is_elf and ( 2 of ($c*) )
}

rule ELF_Miner_ETH_Family
{
  meta: family="ethminer/lolminer/nbminer" category="mining" severity="medium"
  strings:
    $e1 = "ethminer" ascii
    $e2 = "lolMiner" ascii
    $e3 = "nbminer" ascii
    $e4 = "stratum+tcp://eth" ascii nocase
  condition:
    __is_elf and ( 1 of ($e1,$e2,$e3) or $e4 )
}

rule ELF_Miner_Kdevtmpfsi_Sysupdate_Clone
{
  meta: family="kdevtmpfsi/sysupdate" category="mining" severity="high"
  strings:
    $k1 = "kdevtmpfsi" ascii
    $k2 = "kinsing" ascii
    $k3 = "sysupdate" ascii
    $k4 = "/tmp/.X" ascii
    $k5 = "/var/tmp" ascii
  condition:
    __is_elf and ( 2 of ($k*) )
}

/* ================= Masquerade & competitor killer ================= */
rule ELF_Miner_Masquerade_Killer
{
  meta: category="stealth" severity="medium"
  strings:
    $m1 = "kworker/" ascii
    $m2 = "dbus-daemon" ascii
    $m3 = "rsyslogd" ascii
    $m4 = "sshguard" ascii
    $kl = /killall\s+-(9|KILL)\s+(xmrig|cpuminer|minerd|kdevtmpfsi|kinsing|watchd)/ nocase
    $pk = /pkill\s+-(9|KILL)\s+(xmrig|cpuminer|minerd|kdevtmpfsi|kinsing)/ nocase
  condition:
    __is_elf and ( any of ($m1,$m2,$m3,$m4) or $kl or $pk )
}

/* ================= Persistence vectors ================= */
rule ELF_Persist_Systemd_Units
{
  meta: category="persistence" severity="high"
  strings:
    $sd1 = "/etc/systemd/system/" ascii
    $sd2 = "[Service]" ascii
    $sd3 = "ExecStart=" ascii
    $sd4 = "systemctl enable" ascii
  condition:
    __is_elf and ( $sd1 or ($sd2 and $sd3) or $sd4 )
}

rule ELF_Persist_Cron_At
{
  meta: category="persistence" severity="medium"
  strings:
    $cr1 = "/etc/cron." ascii
    $cr2 = "crontab -l" ascii
    $cr3 = "echo \"* * * * *" ascii
    $at1 = "/var/spool/cron/" ascii
  condition:
    __is_elf and ( any of ($cr*) or $at1 )
}

rule ELF_Persist_RcLocal_Profile
{
  meta: category="persistence" severity="medium"
  strings:
    $rc = "/etc/rc.local" ascii
    $pf = "/etc/profile" ascii
    $ba = "/root/.bashrc" ascii
    $pr = "printf '# miner" ascii
  condition:
    __is_elf and ( $rc or $pf or $ba or $pr )
}

rule ELF_Persist_LDPreload_Files
{
  meta: category="persistence/hijack" severity="high"
  strings:
    $ld1 = "/etc/ld.so.preload" ascii
    $ld2 = "LD_PRELOAD" ascii
    $ld3 = "__attribute__((constructor))" ascii
    $ld4 = "readdir64" ascii
    $ld5 = "getdents64" ascii
  condition:
    __is_elf and ( $ld1 or $ld2 or ( $ld3 and ( $ld4 or $ld5 ) ) )
}

/* ================= Delivery/update chain ================= */
rule ELF_Miner_Dropper_Curl_Wget_Busybox
{
  meta: category="loader" severity="high"
  strings:
    $cu = /curl\s+(-fsSL|https?:\/\/)/ nocase
    $wg = /wget\s+(-qO|-O|-q)\s/ nocase
    $bb = /busybox\s+(wget|sh|ash)/ nocase
    $sh = /sh\s+-c\s+|chmod\s+\+x/ nocase
  condition:
    __is_elf and ( ( $cu or $wg or $bb ) and $sh )
}

/* ================= Network hardening disable / watchdog ================= */
rule ELF_Miner_AntiWatchdog_DisableSecurity
{
  meta: category="evasion" severity="medium"
  strings:
    $ip1 = /iptables\s+-F/ nocase
    $ip2 = /ufw\s+disable/ nocase
    $se1 = "setenforce 0" ascii
    $wd1 = "killall watchdog" ascii nocase
  condition:
    __is_elf and ( $ip1 or $ip2 or $se1 or $wd1 )
}

/* ================= High-confidence combos ================= */
rule ELF_HC_Miner_Persist_Combo
{
  meta: category="combo" severity="critical"
  condition:
    ELF_Miner_Pools_Generic and
    ( ELF_Persist_Systemd_Units or ELF_Persist_Cron_At or ELF_Persist_LDPreload_Files )
}

rule ELF_HC_Kdevtmpfsi_Stealth_Combo
{
  meta: category="combo" severity="critical"
  condition:
    ELF_Miner_Kdevtmpfsi_Sysupdate_Clone and
    ( ELF_Persist_Cron_At or ELF_Miner_Masquerade_Killer or ELF_Miner_Dropper_Curl_Wget_Busybox )
}

/* ================= Suspicious memory behavior (optional but useful) ================= */
rule ELF_Suspicious_RWX_Runtime
{
  meta: category="memory" severity="high"
  strings:
    $mp = "mprotect" ascii
    $mm = "mmap" ascii
    $dl = "dlsym" ascii
  condition:
    __is_elf and ( __rwx_section or ( elf.imports("mprotect") and ( elf.imports("mmap") or $mm ) and ( elf.imports("dlsym") or $dl ) ) )
}
