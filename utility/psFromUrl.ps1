function s {
	param (
		[ValidateNotNullOrEmpty()]
		[string]$url
	)
	$sb = [ScriptBlock]::Create((irm $url -UseBasicParsing))
	New-Module -ScriptBlock $sb | Import-Module
}