import "pe"
import "elf"

///////////////////////////////////////////////////////////////////////////////
// UPX
///////////////////////////////////////////////////////////////////////////////

rule PACKER_UPX_Generic
{
  meta:
    author  = "bin-gate"
    family  = "upx"
    category= "packer"
    ref     = "UPX generic marker"
  strings:
    $m1 = "UPX!" ascii
    $m2 = ".UPX" ascii nocase
  condition:
    any of them or
    (pe.is_pe and pe.number_of_sections > 0 and
      for any i in (0..pe.number_of_sections-1):
        (pe.sections[i].name matches /(\.UPX\d?)/i)) or
    (elf and elf.number_of_sections > 0 and
      for any i in (0..elf.number_of_sections-1):
        (elf.sections[i].name matches /(\.UPX\d?)/i))
}

///////////////////////////////////////////////////////////////////////////////
// VMProtect
///////////////////////////////////////////////////////////////////////////////

rule PACKER_VMProtect_Generic
{
  meta:
    author  = "bin-gate"
    family  = "vmprotect"
    category= "packer"
  strings:
    $s1 = "VMProtect" ascii nocase
    $s2 = "__vmprotect" ascii nocase
    $s3 = ".vmp" ascii nocase
  condition:
    any of ($s*) or
    (pe.is_pe and pe.number_of_sections > 0 and
      for any i in (0..pe.number_of_sections-1):
        (pe.sections[i].name matches /(\.vmp\d?)/i))
}

///////////////////////////////////////////////////////////////////////////////
// Themida / WinLicense
///////////////////////////////////////////////////////////////////////////////

rule PACKER_Themida_WinLicense
{
  meta:
    author  = "bin-gate"
    family  = "themida"
    category= "packer"
  strings:
    $t1 = "Themida" ascii nocase
    $t2 = "WinLicense" ascii nocase
    $t3 = "WProtect" ascii nocase
    $t4 = ".themida" ascii nocase
    $t5 = ".winlice" ascii nocase
  condition:
    any of ($t*)
}

///////////////////////////////////////////////////////////////////////////////
// MPRESS
///////////////////////////////////////////////////////////////////////////////

rule PACKER_MPRESS_Generic
{
  meta:
    author  = "bin-gate"
    family  = "mpress"
    category= "packer"
  strings:
    $a1 = "MPRESS" ascii nocase
    $a2 = ".MPRESS" ascii nocase
  condition:
    any of them
}

///////////////////////////////////////////////////////////////////////////////
// ASPack
///////////////////////////////////////////////////////////////////////////////

rule PACKER_ASPack_Generic
{
  meta:
    author  = "bin-gate"
    family  = "aspack"
    category= "packer"
  strings:
    $a1 = "ASPack" ascii nocase
    $a2 = ".aspack" ascii
    $a3 = ".adata" ascii
  condition:
    $a1 or $a2 or $a3
}

///////////////////////////////////////////////////////////////////////////////
// ASProtect
///////////////////////////////////////////////////////////////////////////////

rule PACKER_ASProtect_Generic
{
  meta:
    author  = "bin-gate"
    family  = "asprotect"
    category= "packer"
  strings:
    $s1 = "ASProtect" ascii nocase
    $s2 = ".aspr" ascii nocase
  condition:
    any of them
}

///////////////////////////////////////////////////////////////////////////////
// PECompact
///////////////////////////////////////////////////////////////////////////////

rule PACKER_PECompact_Generic
{
  meta:
    author  = "bin-gate"
    family  = "pecompact"
    category= "packer"
  strings:
    $p1 = "PECompact" ascii nocase
    $p2 = "PEC2" ascii
    $p3 = ".pec1" ascii
    $p4 = ".pec2" ascii
  condition:
    any of ($p*)
}

///////////////////////////////////////////////////////////////////////////////
// FSG
///////////////////////////////////////////////////////////////////////////////

rule PACKER_FSG_Generic
{
  meta:
    author  = "bin-gate"
    family  = "fsg"
    category= "packer"
  strings:
    $f1 = "FSG!" ascii
    $f2 = ".FSG" ascii nocase
  condition:
    any of them
}

///////////////////////////////////////////////////////////////////////////////
// Enigma Protector
///////////////////////////////////////////////////////////////////////////////

rule PACKER_Enigma_Generic
{
  meta:
    author  = "bin-gate"
    family  = "enigma"
    category= "packer"
  strings:
    $e1 = "Enigma Protector" ascii nocase
    $e2 = ".enigma" ascii nocase
  condition:
    any of them
}

///////////////////////////////////////////////////////////////////////////////
// MoleBox
///////////////////////////////////////////////////////////////////////////////

rule PACKER_MoleBox_Generic
{
  meta:
    author  = "bin-gate"
    family  = "molebox"
    category= "packer"
  strings:
    $m1 = "MoleBox" ascii nocase
    $m2 = "MOLEBOX" ascii
    $m3 = ".mole" ascii nocase
  condition:
    any of them
}

///////////////////////////////////////////////////////////////////////////////
// tElock / TElock
///////////////////////////////////////////////////////////////////////////////

rule PACKER_TElock_Generic
{
  meta:
    author  = "bin-gate"
    family  = "telock"
    category= "packer"
  strings:
    $t1 = "tElock" ascii
    $t2 = "TElock" ascii
  condition:
    any of them
}

///////////////////////////////////////////////////////////////////////////////
// Obsidium
///////////////////////////////////////////////////////////////////////////////

rule PACKER_Obsidium_Generic
{
  meta:
    author  = "bin-gate"
    family  = "obsidium"
    category= "packer"
  strings:
    $o1 = "Obsidium" ascii nocase
    $o2 = ".obsidium" ascii nocase
  condition:
    any of them
}

///////////////////////////////////////////////////////////////////////////////
// .NET Confuser / ConfuserEx (managed)
///////////////////////////////////////////////////////////////////////////////

rule PACKER_Confuser_DotNet
{
  meta:
    author  = "bin-gate"
    family  = "confuser"
    category= "protector"
    note    = ".NET only"
  strings:
    $c1 = "ConfusedByAttribute" wide ascii
    $c2 = "ConfuserEx" wide ascii
    $c3 = "Confuser" wide ascii
  condition:
    any of ($c*)
}

///////////////////////////////////////////////////////////////////////////////
// .NET Dotfuscator (managed)
///////////////////////////////////////////////////////////////////////////////

rule PACKER_Dotfuscator_DotNet
{
  meta:
    author  = "bin-gate"
    family  = "dotfuscator"
    category= "protector"
    note    = ".NET only"
  strings:
    $d1 = "DotfuscatorAttribute" wide ascii
    $d2 = "Dotfuscator" wide ascii
  condition:
    any of ($d*)
}

///////////////////////////////////////////////////////////////////////////////
// Petite
///////////////////////////////////////////////////////////////////////////////

rule PACKER_Petite_Generic
{
  meta:
    author  = "bin-gate"
    family  = "petite"
    category= "packer"
  strings:
    $p1 = "Petite" ascii nocase
  condition:
    $p1
}

///////////////////////////////////////////////////////////////////////////////
// NsPack
///////////////////////////////////////////////////////////////////////////////

rule PACKER_NsPack_Generic
{
  meta:
    author  = "bin-gate"
    family  = "nspack"
    category= "packer"
  strings:
    $n1 = "NsPack" ascii nocase
    $n2 = ".nsp" ascii nocase
  condition:
    any of them
}

///////////////////////////////////////////////////////////////////////////////
// Armadillo
///////////////////////////////////////////////////////////////////////////////

rule PACKER_Armadillo_Generic
{
  meta:
    author  = "bin-gate"
    family  = "armadillo"
    category= "protector"
  strings:
    $a1 = "Armadillo" ascii nocase
    $a2 = "Software Passport" ascii
  condition:
    any of them
}

///////////////////////////////////////////////////////////////////////////////
// UPack
///////////////////////////////////////////////////////////////////////////////

rule PACKER_UPack_Generic
{
  meta:
    author  = "bin-gate"
    family  = "upack"
    category= "packer"
  strings:
    $u1 = "UPack" ascii nocase
  condition:
    $u1
}

///////////////////////////////////////////////////////////////////////////////
// Generic High-Entropy Hint (PE/ELF)
// Осторожно: эвристика — даёт только «подозрение», не метка конкретного packer’a
///////////////////////////////////////////////////////////////////////////////

rule PACKER_Generic_HighEntropy_PE
{
  meta:
    author   = "bin-gate"
    family   = "generic"
    category = "heuristic"
    note     = "High-entropy sections ≥ 7.2 (PE)"
  condition:
    pe.is_pe and pe.number_of_sections > 0 and
    for any i in (0..pe.number_of_sections-1):
      (pe.sections[i].entropy >= 7.20)
}

rule PACKER_Generic_HighEntropy_ELF
{
  meta:
    author   = "bin-gate"
    family   = "generic"
    category = "heuristic"
    note     = "High-entropy sections ≥ 7.2 (ELF)"
  condition:
    elf and elf.number_of_sections > 0 and
    for any i in (0..elf.number_of_sections-1):
      (elf.sections[i].entropy >= 7.20)
}
