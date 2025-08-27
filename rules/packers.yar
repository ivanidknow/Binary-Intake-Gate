rule UPX_Packed {
    meta: author="builtin" family="packers"
    strings:
        $a = "UPX!" ascii
    condition:
        $a
}
rule MPRESS_Packed {
    meta: author="builtin" family="packers"
    strings:
        $a = "MPRESS" nocase ascii
    condition:
        $a
}
rule ASPACK_Packed {
    meta: author="builtin" family="packers"
    strings:
        $a = "ASPack" nocase ascii
    condition:
        $a
}
rule THEMIDA_Packed {
    meta: author="builtin" family="packers"
    strings:
        $a = "Themida" nocase ascii
    condition:
        $a
}
