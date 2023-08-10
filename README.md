[![directory-listing](https://github.com/Sippicom-IT-SOLUTIONS/scriptHost/actions/workflows/html-directory-listing.yml/badge.svg?branch=main)](https://github.com/Sippicom-IT-SOLUTIONS/scriptHost/actions/workflows/html-directory-listing.yml)

## **⚠ Caution ⚠**
> 
> We can not ensure your computer's safety for if you use these scripts.
> 
> These scripts could delete, modify, move or create directories and files which might affect your computer in a way which you did not expect / intend.

# Welcome to the Sippicom IT-SOLUTIONS utility script repository

This repository hosts some scripts that might be useful to some.

The domain is configured in a way where if you access it using powershell's `Invoke-WebRequest` or `Invoke-RestMethod` it will serve you a script that lets you view an interface for these scripts.

## Usage

In a PowerShell Console run the following:
```pwsh
iex(irm ncscripts.xyz)
```

or:
```pwsh
Invoke-Expression -Command $(Invoke-RestMethod -Uri ncscripts.xyz)
```
