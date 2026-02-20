rule OBF_PackerHints_Generic {
  meta:
    name = "OBF_PackerHints_Generic"
    family = "packers"  // чтобы сработало существующее правило policy 'packer-unsigned'
    description = "Common packer hints (UPX/MPRESS/ASPack/VMProtect/Themida)"
    author = "binary-intake-gate"
    confidence = "low"
  strings:
    $u1 = "UPX!" ascii nocase
    $u2 = ".upx" ascii nocase
    $m1 = "mpress" ascii nocase
    $a1 = "aspack" ascii nocase
    $v1 = "vmp" ascii nocase
    $t1 = "themida" ascii nocase
  condition:
    1 of ($*)
}
