import "hash"
import "pe"
import "math"

rule sampleA2

{
	meta:
		description = "Checks to see if Magic numbers and hash are found in this sample"
		author = "Susan Verdin"
		date = 07272021
		
	strings:
	
		$a = {4d 5a}
		
	condition:
		($a at 0) and (hash.md5(0, filesize) == "67B561DB4AB848AA2E6D4C470CDEA7D0")
}