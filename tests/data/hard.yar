import "pe"
import "math"

rule Sets_And_Ranges
{
    strings:
        $a = "alpha"
        $b = "bravo"
        $c = "charlie"
    condition:
        all of them and any of ($a,$b) and 1 of ($*)
}

rule Loops
{
    strings:
        $x = "needle"
    condition:
        for any i in (1..#x) : ( @x[i] < 100 ) and
        for all section in pe.sections : ( section.name != ".evil" )
}

rule Arithmetic
{
    condition:
        uint16(0) == 0x5A4D and (filesize \ 1024) > 4 and math.entropy(0, filesize) > 7.0
}

rule StringOps
{
    condition:
        pe.pdb_path contains "release" and pe.pdb_path matches /[a-z]+\.pdb/i
}

rule Ranges
{
    strings:
        $r = { 90 90 90 90 }
    condition:
        $r in (0..1024) and #r in (0..500) > 2
}
