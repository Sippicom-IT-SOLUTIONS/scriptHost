[![Static-Badge](https://img.shields.io/badge/SIPPICOM-IT--SOLUTIONS-ff9126?style=for-the-badge&labelColor=000000&color=ff9126)](https://sippicom.com) [![HTML-directory-listing](https://img.shields.io/github/actions/workflow/status/Sippicom-IT-SOLUTIONS/scriptHost/html-directory-listing.yml?style=for-the-badge&labelColor=ff9126)](https://github.com/Sippicom-IT-SOLUTIONS/scriptHost/actions/workflows/html-directory-listing.yml)

# Welcome to the Sippicom IT-SOLUTIONS utility script repository
> 
> This repository hosts some scripts that might be useful to some.
> 
> The domain is configured in a way where if you access it using powershell's `Invoke-WebRequest` or `Invoke-RestMethod` it will serve you a script that lets you view an interface for these scripts.

## **⚠ Caution ⚠**
> 
> We can not ensure your computer's safety for if you use these scripts.
> 
> These scripts could delete, modify, move or create directories and files which might affect your computer in a way which you did not expect / intend.

## Usage

> In a PowerShell Console run the following:
> ```pwsh
> iex(irm ncscript.xyz)
> ```
> 
> or:
> ```pwsh
> Invoke-Expression -Command $(Invoke-RestMethod -Uri ncscript.xyz)
> ```
