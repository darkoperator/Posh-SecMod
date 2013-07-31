
function Get-LogDateString
{
    (get-date).toString(‘yyyyMMddhhmm’)
}

function Confirm-IsAdmin 
{
	<#
	.Synopsis
	   Checks if current PowerShell Session is running with administrative privelages.
	.DESCRIPTION
	   Checks if current PowerShell Session is running with administrative privelages
	.EXAMPLE
	   Return True or False if curremt PowerShell session is running with adminitratibe privelages.
	   PS c:\> Confirm-IsAdmin
       True
	#>
    $sign = @"
using System;
using System.Runtime.InteropServices;
public static class priv
{
    [DllImport("shell32.dll")]
    public static extern bool IsUserAnAdmin();
}

"@

    $adminasembly = Add-Type -TypeDefinition $sign -Language CSharp -PassThru

    return [priv]::IsUserAnAdmin()
}

