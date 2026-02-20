/* fp_guards_allowlists_advanced.yar
 * False-positive guards & allow-lists for multi-stack scanners
 * Usage:
 *   - as hard exclude:    <your_rule> ... and not ( ALLOW_* or FP_* )
 *   - as soft downgrade:  if ALLOW_*/FP_* matched → lower severity/score
 * Author: ivan-gate
 */

import "pe"
import "elf"
import "macho"

/* ======================== PE / Windows ========================= */

/* Крупные вендоры по VersionInfo (soft allow — spoofable, лучше даунгрейд) */
private rule ALLOW_PE_Major_Vendors
{
  meta: scope="pe" action="downrank"
  condition:
    uint16(0) == 0x5A4D and pe and pe.version_info and
    (
      for any k in ( "CompanyName", "FileDescription", "ProductName" ):
        ( pe.version_info[k] contains "Microsoft" or
          pe.version_info[k] contains "Google" or
          pe.version_info[k] contains "Cisco" or
          pe.version_info[k] contains "Adobe" or
          pe.version_info[k] contains "VMware" )
    )
}

/* Sysinternals/админ-тулзы (частые FP на латерали/дампах) */
private rule ALLOW_PE_Sysinternals_AdminTools
{
  meta: scope="pe" action="downrank"
  strings:
    $p0 = "Sysinternals" ascii
    $p1 = "PsExec" ascii
    $p2 = "ProcDump" ascii
    $p3 = "Sigcheck" ascii
    $p4 = "Process Explorer" ascii
  condition:
    uint16(0) == 0x5A4D and pe and ( $p0 or 2 of ($p1,$p2,$p3,$p4) )
}

/* 7-Zip SFX/NSIS/MSI — типовой инсталлерный шум */
private rule ALLOW_PE_Common_Installers
{
  meta: scope="pe" action="downrank"
  strings:
    $sfx = "7zS.sfx" ascii
    $ns1 = "Nullsoft Install System" ascii
    $msi = "Windows Installer" ascii
  condition:
    uint16(0) == 0x5A4D and pe and ( $sfx or $ns1 or $msi )
}

/* ======================== ELF / Linux ========================= */

/* Дистрибутивные LKM (GPL лицензия в .modinfo) — только даунгрейд */
private rule ALLOW_ELF_LKM_GPL
{
  meta: scope="elf" action="downrank"
  condition:
    uint32(0) == 0x7F454C46 and elf and elf.type == elf.ET_REL and
    for any i in (0 .. elf.number_of_sections - 1):
      ( elf.sections[i].name == ".modinfo" ) and
    for any j in (0 .. elf.number_of_sections - 1):
      ( elf.sections[j].name == ".rodata" and
        @elf.sections[j].raw_data_offset != 0 and
        @elf.sections[j].raw_data_offset + elf.sections[j].raw_data_size <= filesize and
        /* эвристика: ищем 'license=GPL' в общей строковой области */
        for any k in (@elf.sections[j].raw_data_offset .. @elf.sections[j].raw_data_offset + elf.sections[j].raw_data_size - 8):
          ( uint8(k) == 0x6C /* 'l' */ and
            string k in ( "license=GPL", "license=GPL v2" ) ) )
}

/* Частые легит-демоны/утилиты (ssh, rsyslog, systemd) */
private rule ALLOW_ELF_System_Daemons
{
  meta: scope="elf" action="downrank"
  strings:
    $s1 = "systemd" ascii
    $s2 = "rsyslogd" ascii
    $s3 = "sshd" ascii
    $s4 = "dbus-daemon" ascii
  condition:
    uint32(0) == 0x7F454C46 and elf and 2 of ($s1,$s2,$s3,$s4)
}

/* ======================== Mach-O / macOS ========================= */

private rule ALLOW_Mac_Common_Frameworks
{
  meta: scope="macho" action="downrank"
  strings:
    $cf = "CoreFoundation" ascii
    $sf = "SecurityFoundation" ascii
    $sp = "Sparkle" ascii  // автообновлялка у многих приложений (FP в сетевых загрузчиках)
  condition:
    ( uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or uint32(0) == 0xBEBAFECA ) and ( $cf or $sf or $sp )
}

/* ======================== Office / PDF ========================= */

/* Корпоративные OOXML-шаблоны (заполни свои маркеры в $co1/$co2) */
private rule ALLOW_OOXML_Corporate_Templates
{
  meta: scope="ooxml" action="exclude" note="подставь свои маркеры компании/шаблонов"
  strings:
    $rels = "docProps/custom.xml" ascii
    $co1  = "AcmeTemplateID" ascii         // <— ЗАМЕНИ на свой идентификатор шаблона
    $co2  = "Acme Corporation" ascii       // <— ЗАМЕНИ на точное имя компании
  condition:
    uint32(0) == 0x504B0304 and $rels and ( $co1 or $co2 )
}

/* PDF, сгенерированные корпоративными системами (заполни издателя/ProdName) */
private rule ALLOW_PDF_Corporate_Generator
{
  meta: scope="pdf" action="downrank" note="замени строки на свои генераторы PDF"
  strings:
    $g1 = "/Producer (SAP Smart Forms)" ascii
    $g2 = "/Producer (Oracle BI Publisher)" ascii
    $g3 = "/Creator (DocuSign)" ascii
  condition:
    uint32(0) == 0x25504446 and ( $g1 or $g2 or $g3 )
}

/* ======================== Python / Node ========================= */

/* Dev-toolchain и менеджеры пакетов — часто триггерят обфускацию/загрузку в CI */
private rule ALLOW_Python_DevTools
{
  meta: scope="python" action="downrank"
  strings:
    $p1 = "setuptools" ascii
    $p2 = "wheel" ascii
    $p3 = "pip " ascii
    $p4 = "pipenv" ascii
  condition:
    filesize > 512 and filesize < 50MB and 2 of ($p1,$p2,$p3,$p4)
}

private rule ALLOW_Node_Common_Deps
{
  meta: scope="node" action="downrank"
  strings:
    $a1 = "axios" ascii
    $w1 = "webpack" ascii
    $r1 = "react" ascii
  condition:
    filesize > 512 and filesize < 50MB and 2 of ($a1,$w1,$r1)
}

/* ======================== Browser Extensions ========================= */

/* Разрешённые расширения (пример — подставь свои имена/ID) */
private rule ALLOW_Extensions_Trusted
{
  meta: scope="extensions" action="exclude" note="замени имена/ID на approved list"
  strings:
    $n1 = /"name"\s*:\s*"uBlock Origin"/ nocase
    $n2 = /"name"\s*:\s*"Privacy Badger"/ nocase
    $i1 = /"key"\s*:\s*".{120,}"/      // статичный ключ Chrome; опционально
  condition:
    ( uint32(0) == 0x504B0304 or uint32(0) == 0x43723234 ) and ( $n1 or $n2 or $i1 )
}

/* ======================== Android (APK/DEX) ========================= */

/* Доверенные пакеты (заполни packageName’ы) */
private rule ALLOW_Android_Packages_Trusted
{
  meta: scope="android" action="exclude" note="добавь свои packageName"
  strings:
    $p1 = "package=\"com.acme.app\"" ascii      // <— поменяй
    $p2 = "package=\"com.google.android." ascii // системные гугл-пакеты
  condition:
    ( uint32(0) == 0x504B0304 and "AndroidManifest.xml" ascii ) and ( $p1 or $p2 )
}

/* ======================== Docker/CI артефакты ========================= */

/* Docker config.json c публичными реестрами — понижать, не исключать */
private rule ALLOW_Docker_Public_Auths
{
  meta: scope="devops" action="downrank"
  strings:
    $cfg = "\"auths\"" ascii
    $do  = "registry-1.docker.io" ascii
    $gh  = "ghcr.io" ascii
  condition:
    filesize < 2MB and $cfg and ( $do or $gh )
}

/* ======================== Примеры интеграции ========================= */

/*
 * Пример жёсткого исключения (в вашем детекте):
 *   condition:
 *     <ваш_условный_детект> and not ( ALLOW_OOXML_Corporate_Templates or ALLOW_Extensions_Trusted )
 *
 * Пример мягкого даунгрейда (в движке):
 *   if any(ALLOW_*) matched → score *= 0.4; if scope="pe" and ALLOW_PE_Sysinternals_AdminTools → score *= 0.2
 */
