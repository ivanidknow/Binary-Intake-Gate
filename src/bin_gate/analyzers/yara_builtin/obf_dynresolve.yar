rule OBF_DynamicResolve_PE {
  meta:
    name = "OBF_DynamicResolve_PE"
    family = "obf_dynresolve"
    description = "Dynamic API resolving (PE)"
    author = "binary-intake-gate"
    confidence = "medium"
  strings:
    $p1 = "LoadLibraryA" ascii
    $p2 = "LoadLibraryW" ascii
    $p3 = "GetProcAddress" ascii
  condition:
    2 of ($p*)
}

rule OBF_DynamicResolve_ELF {
  meta:
    name = "OBF_DynamicResolve_ELF"
    family = "obf_dynresolve"
    description = "Dynamic API resolving (ELF)"
    author = "binary-intake-gate"
    confidence = "medium"
  strings:
    $d1 = "dlopen" ascii
    $d2 = "dlsym" ascii
  condition:
    2 of ($d*)
}
