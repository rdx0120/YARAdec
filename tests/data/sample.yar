import "pe"

private rule Helper_Priv
{
    strings:
        $h = "helper" ascii
    condition:
        $h
}

global rule Size_Gate
{
    condition:
        filesize < 10MB
}

rule Demo_Rule : trojan banker
{
    meta:
        author = "rdx0120"
        description = "demo rule for decompiler test"
        version = 3
        is_test = true
    strings:
        $a = "malicious_string" ascii wide nocase
        $b = { 4D 5A 90 00 03 ?? 00 00 }
        $c = /evil[0-9]{2,4}regex/i
        $d = "xored" xor(0x01-0xff)
        $e = "b64me" base64
        $f = "fullword_hit" fullword
    condition:
        Helper_Priv and 2 of ($a,$b,$c) and #d > 1 and $e at 0 and pe.number_of_sections > 2 and $f
}
