rule HackTool_Mimikatz
{
    meta:
        threat_name = "HackTool.Mimikatz"
        description = "Mimikatz, verktyg som stjal inloggningsuppgifter fran Windows"
    strings:
        $a1 = "gentilkiwi" wide ascii nocase
        $a2 = "mimikatz" wide ascii nocase
        $a3 = "sekurlsa::logonpasswords" wide ascii nocase
        $a4 = "Benjamin DELPY" wide ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
