/* pe_ransomware_advanced.yar
 * Coverage: backup wipe, mass encryption, ransom note drop, share traversal, service kill, TOR/onion, HC combos.
 * Author: ivan-gate
 */

import "pe"

/* ================= Helpers ================= */
private rule __is_pe      { condition: uint16(0) == 0x5A4D and pe }
private rule __smallish   { condition: filesize > 20KB and filesize < 200MB }
private rule __has_crypto {
  condition:
    pe.imports("crypt32.dll","CryptProtectData") or
    pe.imports("crypt32.dll","CryptUnprotectData") or
    pe.imports("advapi32.dll","CryptAcquireContextA") or
    pe.imports("advapi32.dll","CryptGenRandom") or
    pe.imports("bcrypt.dll","BCryptGenRandom") or
    pe.imports("bcrypt.dll","BCryptEncrypt") or
    pe.imports("bcrypt.dll","BCryptOpenAlgorithmProvider")
}

/* ================= H1: Anti-recovery (теневые копии/загрузка) ================= */
rule PE_Ransom_BackupWipe_VSS_WBADMIN_BCD
{
  meta: category="ransomware" ttp="defense-evasion" severity="high"
  strings:
    $vss = /vssadmin(\.exe)?\s+delete\s+shadows/i ascii
    $wb1 = /wbadmin(\.exe)?\s+delete\s+catalog/i ascii
    $wb2 = /wbadmin(\.exe)?\s+delete\s+systemstatebackup/i ascii
    $b1  = /bcdedit(\.exe)?\s+\/set\s+{default}\s+recoveryenabled\s+no/i ascii
    $b2  = /bcdedit(\.exe)?\s+\/set\s+{default}\s+bootstatuspolicy\s+ignoreallfailures/i ascii
    $rg  = /reagentc(\.exe)?\s+\/disable/i ascii
    $wm  = /wmic(\.exe)?\s+shadowcopy\s+delete/i ascii
  condition:
    __is_pe and __smallish and ( $vss or $wb1 or $wb2 or $b1 or $b2 or $rg or $wm )
}

/* ================= H2: Массовое шифрование (цикл по файлам + Crypto) ================= */
rule PE_Ransom_Encrypt_Loops_Crypto
{
  meta: category="ransomware" ttp="impact" severity="critical"
  strings:
    // файловый цикл
    $ff = "FindFirstFileW" wide ascii
    $fn = "FindNextFileW"  wide ascii
    $cf = "CreateFileW"    wide ascii
    $wf = "WriteFile"      wide ascii
    $sm = "SetFilePointerEx" wide ascii
    $tr = "SetEndOfFile"     wide ascii
    // паттерны расширений
    $ex = /\.(docx?|xlsx?|pptx?|pdf|jpg|png|sql|mdb|accdb|pst|ost|7z|zip|rar|bak|vmdk|vhdx)/ nocase ascii
    // crypto words
    $c1 = /AES-(GCM|CBC)|ChaCha20|Curve25519|RSA-(1024|2048|4096)/ nocase ascii
  condition:
    __is_pe and __smallish and
    ( (__has_crypto or $c1) ) and
    ( ( $ff or pe.imports("kernel32.dll","FindFirstFileW") ) and ( $fn or pe.imports("kernel32.dll","FindNextFileW") ) and ( $cf or pe.imports("kernel32.dll","CreateFileW") ) ) and
    ( $wf or $sm or $tr or pe.imports("kernel32.dll","WriteFile") )
}

/* ================= H3: Заметка + расширения-«хвосты» ================= */
rule PE_Ransom_RansomNote_Drop_ExtensionTail
{
  meta: category="ransomware" ttp="impact" severity="high"
  strings:
    $rn1 = /(README|HOW_TO_DECRYPT|RECOVER|DECRYPTION|UNLOCK)_?([A-Z]{0,6})?(\.txt|\.html|\.hta)/ nocase ascii
    $rn2 = "all your files" nocase ascii
    $rn3 = "decrypt" nocase ascii
    $xt1 = /\.lockbit|\.conti|\.darkside|\.blackcat|\.onion|\.zeg|\.djvu/ nocase ascii
  condition:
    __is_pe and __smallish and ( $rn1 or ( $rn2 and $rn3 ) or $xt1 )
}

/* ================= H4: Сетевые шары / латераль ================= */
rule PE_Ransom_NetworkShares_Traversal
{
  meta: category="ransomware" ttp="lateral-movement" severity="medium"
  condition:
    __is_pe and __smallish and
    (
      pe.imports("mpr.dll","WNetAddConnection2W") or
      pe.imports("mpr.dll","WNetUseConnectionW") or
      pe.imports("netapi32.dll","NetShareEnum") or
      pe.imports("netapi32.dll","NetServerEnum")
    )
}

/* ================= H5: Убийство процессов/сервисов БД и ПО резервирования ================= */
rule PE_Ransom_Kill_DB_Backup_Services
{
  meta: category="ransomware" ttp="defense-evasion" severity="high"
  strings:
    $sc  = /sc(\.exe)?\s+stop\s+(SQL|MSSQL|VSS|VEAM|VEEAM|MEGA|MEGABACKUP|postgres|mysql)/ nocase ascii
    $nt  = /net(\.exe)?\s+stop\s+(sql|mssql|vss|veeam)/ nocase ascii
    $ps1 = /taskkill(\.exe)?\s+\/f\s+\/im\s+(sqlservr|oracle|postgres|vmwp|veeam|backup|elastic|mongodb)/ nocase ascii
  condition:
    __is_pe and __smallish and ( $sc or $nt or $ps1 )
}

/* ================= H6: Контакты/TOR/кошельки ================= */
rule PE_Ransom_TOR_Onion_Contacts
{
  meta: category="ransomware" ttp="command-and-control" severity="medium"
  strings:
    $on1 = ".onion" ascii
    $tg1 = "@support" ascii
    $em1 = /[a-z0-9._%+-]+@[a-z0-9.-]+\.(pro|top|email|msg|tuta|keemail|onion)/ nocase ascii
    $ic1 = "Session ID" ascii nocase
  condition:
    __is_pe and __smallish and ( $on1 or $em1 or $ic1 or $tg1 )
}

/* ================= H7: Распаковка/самоинжект (обфускация) ================= */
rule PE_Ransom_RuntimeUnpack_RWX_GPA_LL
{
  meta: category="ransomware" ttp="defense-evasion" severity="medium"
  condition:
    __is_pe and
    (
      pe.imports("kernel32.dll","GetProcAddress") and
      pe.imports("kernel32.dll","LoadLibraryA")
    ) and
    for any i in (0 .. pe.number_of_sections - 1):
      ( (pe.sections[i].characteristics & 0xA0000000) == 0xA0000000 )
}

/* ================= High-Confidence COMBOS ================= */

/* Классический «триплет»: крипто + файловый цикл + зачистка бэкапов */
rule PE_Ransom_HC_Crypto_Loop_BackupWipe
{
  meta: category="ransomware" ttp="impact" severity="critical" note="Low-FP multi-signal"
  condition:
    __is_pe and __smallish and
    ( PE_Ransom_Encrypt_Loops_Crypto ) and
    ( PE_Ransom_BackupWipe_VSS_WBADMIN_BCD )
}

/* Массовое шифрование + заметка/расширения + сеть (шары) */
rule PE_Ransom_HC_Encrypt_Note_Shares
{
  meta: category="ransomware" ttp="impact/lateral" severity="critical"
  condition:
    __is_pe and __smallish and
    ( PE_Ransom_Encrypt_Loops_Crypto ) and
    ( PE_Ransom_RansomNote_Drop_ExtensionTail ) and
    ( PE_Ransom_NetworkShares_Traversal or PE_Ransom_Kill_DB_Backup_Services )
}
