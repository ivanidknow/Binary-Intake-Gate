rule EICAR_Test {
    meta:
        description = "EICAR standard antivirus test string (memory/disk)"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
