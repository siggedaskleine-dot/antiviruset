/*
    Hittar EICAR-testfilen även när den har extra tecken runt sig.
    Strängen är delad i två så att den här regelfilen inte själv ser ut som testfilen.
*/
rule EICAR_Test_File
{
    meta:
        threat_name = "EICAR-Test-File"
        description = "Ofarlig testfil for antivirusprogram"
    strings:
        $start = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
        $name = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        filesize < 1KB and $start at 0 and $name
}
