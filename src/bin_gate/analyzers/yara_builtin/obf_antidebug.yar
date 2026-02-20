rule OBF_AntiDebug_WinAPI {
  meta:
    name = "OBF_AntiDebug_WinAPI"
    family = "obf_antidebug"
    description = "Anti-debugging API usage (Windows)"
    author = "binary-intake-gate"
    confidence = "medium"
  strings:
    $a1 = "IsDebuggerPresent" ascii
    $a2 = "CheckRemoteDebuggerPresent" ascii
    $a3 = "NtQueryInformationProcess" ascii
    $a4 = "OutputDebugStringA" ascii
    $a5 = "OutputDebugStringW" ascii
  condition:
    1 of ($a*)
}

rule OBF_AntiDebug_ELF {
  meta:
    name = "OBF_AntiDebug_ELF"
    family = "obf_antidebug"
    description = "Anti-debugging indicators (ELF)"
    author = "binary-intake-gate"
    confidence = "medium"
  strings:
    $e1 = "ptrace" ascii
    $e2 = "TracerPid" ascii
    $e3 = "PR_SET_DUMPABLE" ascii
    $e4 = "prctl" ascii
  condition:
    1 of ($e*)
}
