/* family_hints_pe_elf_advanced.yar
 * Family-hints for PE/ELF (ransomware & miners/bots) + HC combos
 * Author: ivan-gate
 */

import "pe"
import "elf"

/* ================= Helpers ================= */
private rule __is_pe    { condition: uint16(0) == 0x5A4D and pe }
private rule __is_elf   { condition: uint32(0) == 0x7F454C46 and elf }
private rule __smallish { condition: filesize > 10KB and filesize < 200MB }

/* ========= RANSOMWARE (PE) — FAMILY HINTS ========= */

rule PE_FH_LockBit
{
  meta: family="LockBit" category="family-hints" severity="info"
  strings:
    $n1 = /Restore-My-Files\.(txt|hta)/ nocase
    $l1 = /LockBit/i
    $x1 = /\.lockbit/i
  condition:
    __is_pe and __smallish and ( 1 of ($n1,$l1,$x1) )
}

rule PE_FH_BlackCat_ALPHV
{
  meta: family="ALPHV/BlackCat" category="family-hints" severity="info"
  strings:
    $a1 = /ALPHV|BlackCat/i
    $n1 = /(RECOVER|RESTORE|HOW_TO)_.*\.(txt|html|hta)/ nocase
    $o1 = /\.alphv/i
  condition:
    __is_pe and ( $a1 or $o1 or $n1 )
}

rule PE_FH_BlackBasta
{
  meta: family="BlackBasta" category="family-hints" severity="info"
  strings:
    $b1 = /Black\s?Basta/i
    $n1 = /(readme|recovery)_\w{4,12}\.txt/i
  condition:
    __is_pe and ( $b1 or $n1 )
}

rule PE_FH_STOP_DJVU
{
  meta: family="STOP/DJVU" category="family-hints" severity="medium"
  strings:
    $r1 = /_readme\.txt/i
    $x1 = /\.djvu/i
    $x2 = /\.(gero|hoto|koti|nile|nppp|qoob|qqqq|zqqw|mzlq|udjy|paas)/ nocase
  condition:
    __is_pe and ( $r1 or $x1 or $x2 )
}

/* ========= MINERS / LOADERS (ELF & PE) — FAMILY HINTS ========= */

rule ELF_FH_Kinsing
{
  meta: family="kinsing" category="family-hints" severity="medium"
  strings:
    $k1 = /kinsing/i
    $c1 = /curl\s+(-fsSL)?\s*https?:\/\/[^\s]+\/k\.sh\|sh/i
  condition:
    __is_elf and __smallish and ( $k1 or $c1 )
}

rule ELF_FH_Kdevtmpfsi_Sysupdate
{
  meta: family="kdevtmpfsi/sysupdate" category="family-hints" severity="medium"
  strings:
    $k1 = /kdevtmpfsi/i
    $s1 = /sysupdate/i
    $t1 = /\/tmp\/\.[A-Za-z0-9]{2,6}/
  condition:
    __is_elf and ( 1 of ($k1,$s1) or ( $t1 and __smallish ) )
}

rule ELF_FH_Skidmap
{
  meta: family="skidmap" category="family-hints" severity="medium"
  strings:
    $s1 = /skidmap/i
    $w1 = /watchdog\.sh/i
    $ld = /ld\.so\.preload/i
  condition:
    __is_elf and ( $s1 or ( $w1 and $ld ) )
}

rule ELF_FH_Mirai_Gafgyt
{
  meta: family="Mirai/Gafgyt" category="family-hints" severity="info"
  strings:
    $m1 = /mirai/i
    $g1 = /gafgyt|bashlite/i
    $ua = /User-Agent:\s*(mirai|loader)/ nocase
    $tn = /\/bin\/(busybox|sh)\s+-c/ nocase
  condition:
    __is_elf and ( 1 of ($m1,$g1,$ua,$tn) )
}

rule XPLAT_FH_XMRig_Cpuminer
{
  meta: family="XMRig/cpuminer" category="family-hints" severity="info"
  strings:
    $x1 = /xmrig/i
    $x2 = /donate-level/i
    $c1 = /cpuminer/i
  condition:
    ( __is_elf or __is_pe ) and ( 1 of ($x1,$x2,$c1) )
}

/* ========= OTHER HINTS useful for triage ========= */

rule ELF_FH_Sysctl_Hide_and_CRON
{
  meta: family="stealth-persist" category="family-hints" severity="info"
  strings:
    $h1 = /hide(pid|port)/ nocase
    $c1 = /\/etc\/cron\.(hourly|daily|weekly)/ nocase
  condition:
    __is_elf and ( $h1 or $c1 )
}

rule PE_FH_Ransom_Generic_Note_TOR
{
  meta: family="generic-ransom" category="family-hints" severity="info"
  strings:
    $rn = /(README|HOW_TO|RECOVER|UNLOCK|DECRYPT)[^\/\n]{0,20}\.(txt|hta|html)/ nocase
    $on = /\.onion/i
  condition:
    __is_pe and ( $rn or $on )
}

/* ========= HIGH-CONFIDENCE COMBOS (поднимают приоритет) ========= */
/* Комбо требуют: 1) семейную подсказку и 2) поведенческий сигнал класса */

rule PE_HC_Ransom_FamilyPlusCrypto
{
  meta: category="combo" severity="critical" note="family-hint + crypto/files loop"
  strings:
    $ff = "FindFirstFileW" wide ascii
    $fn = "FindNextFileW"  wide ascii
    $wf = "WriteFile"      wide ascii
  condition:
    __is_pe and
    ( PE_FH_LockBit or PE_FH_BlackCat_ALPHV or PE_FH_BlackBasta or PE_FH_STOP_DJVU or PE_FH_Ransom_Generic_Note_TOR ) and
    (
      // CryptoAPI/CNG hints
      pe.imports("crypt32.dll","CryptProtectData") or
      pe.imports("bcrypt.dll","BCryptEncrypt") or
      // file-walking loop
      ( $ff and $fn and $wf )
    )
}

rule ELF_HC_Miner_FamilyPlusPool
{
  meta: category="combo" severity="critical" note="family-hint + stratum pool"
  strings:
    $st = /stratum\+(tcp|ssl):\/\// nocase
    $pt = /:(3333|4444|5555|7777)/ ascii
  condition:
    __is_elf and
    ( XPLAT_FH_XMRig_Cpuminer or ELF_FH_Kinsing or ELF_FH_Kdevtmpfsi_Sysupdate or ELF_FH_Skidmap ) and
    ( $st and $pt )
}

rule ELF_HC_Botnet_FamilyPlusNetOps
{
  meta: category="combo" severity="high" note="Mirai/Gafgyt + сетевые exec/скан"
  strings:
    $sc = /busybox\s+(wget|tftp)|/ nocase
    $ex = /sh\s+-c\s+[^\n]{0,80}(wget|curl|tftp)/ nocase
  condition:
    __is_elf and ELF_FH_Mirai_Gafgyt and ( $sc or $ex )
}
