import "hash"
import "pe"
import "math"

rule Sample_A1

{
	meta:
	description = "Detects if the conditions in this rule match the sample"
	author = "Susan Verdin"
	date = 07272021
	
	strings:
		$a = {4d 5a}
		$b = {2F 75 73 65 72 31 2E 65 78 65}
		$c = {64 6F 77 6E 6C 6F 61 64 65 72 2E 65 78 65}
		
		
	condition:
		($a at 0) and ($b at 0x7FB9) and ($c at 0x8036)
}