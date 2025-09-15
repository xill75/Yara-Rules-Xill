import "pe"

rule RAT_Win32_LogMeIn_SuspiciousBehavior : misused remote_access ransomware trojan {
    meta:
        description = "Detects LogMeIn RAT variants or other malware exhibiting suspicious behavioral indicators based on strings, imphash, or a combination of suspicious imports."
        author = "Felipe Schiel"
        date = "2025-09-15"
        reference = "054bdcf37e05006622a0584a55185a40ea3ce70e437288af654579112abe285"
        version = "2.5"

    strings:
        $string1 = "C:\\a\\rescue-native-rescueassist\\rescue-native-rescueassist\\build\\RelWithDebInfo\\GoToResolveUnattendedUpdater.pdb" wide ascii
        $string2 = ".?AV?$I_formatter@Unull_scoped_padder@details@spdlog@@@details@spdlog@@" wide ascii

    condition:
        uint16(0) == 0x5A4D and
        (filesize > 20MB and filesize < 25MB) and
        (
            pe.imphash() == "f8e4a22bcb1b836585534b93f63c1414" or
            all of them or
            (
                pe.imports("RstrtMgr.DLL", "RmStartSession") and
                (pe.imports("CRYPT32.dll", "CryptProtectData") or pe.imports("CRYPT32.dll", "CertDeleteCertificateFromStore")) and
                pe.imports("WS2_32.dll", "WSAStartup")
            )
        ) and
        not (
            pe.number_of_signatures > 0 and
            pe.signatures[0].subject contains "LogMeIn, Inc."
        )
}