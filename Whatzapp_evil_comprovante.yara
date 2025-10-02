rule Whatzapp_evil_comprovante : misused remote_access {
    meta:
        description = "LNK files that use obfuscated commands (like 'for' loops) to launch PowerShell downloaders. Associated with Brazilian phishing campaigns."
        author = "Felipe Schiel"
        date = "2025-10-02"
        reference = "054bdcf37e05006622a0584a55185a40ea3ce70e437288af654579112abe285"
        version = "2.0"

    strings:
        $target_cmd = "cmd.exe" wide
        $arg_cmd_switch = "/c " wide ascii
        $arg_for_loop = "for %" wide ascii
        $b64_iex = "SQBFAFgA" wide ascii
        $b64_webclient = "AE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0" wide ascii
        $ps_piece1 = "pow" wide ascii
        $ps_piece2 = "ers" wide ascii
        $ps_piece3 = "hell" wide ascii

    condition:
        uint32(0) == 0x0000004C and
        (
            (
                $target_cmd and $arg_cmd_switch and $arg_for_loop and all of ($ps_piece*)
            )
            or
            (
                1 of ($b64_*)
            )
        )
}
