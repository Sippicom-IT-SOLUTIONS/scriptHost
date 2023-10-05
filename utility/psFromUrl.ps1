function s {
	param (
        [ValidateNotNullOrEmpty()]
		[string]$url
	)
	irm $url | iex
}