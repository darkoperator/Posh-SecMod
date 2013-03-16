
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
    (whoami /all | Select-String S-1-16-12288) -ne $null
}

function Get-RegKeyLastWriteTime {            
 <#
	.SYNOPSIS
	Retrieves the last write time of the supplied registry key

	.DESCRIPTION
	The Registry data that a hive stores in containers are called cells. A cell 
	can hold a key, a value, a security descriptor, a list of subkeys, or a 
	list of key values.

	Get-RegKeyLastWriteTime retrieves the LastWriteTime through a pointer to the
	FILETIME structure that receives the time at which the enumerated subkey was
	last written. Values do not contain a LastWriteTime property, but changes to
	child values update the parent keys lpftLastWriteTime.
	
	The LastWriteTime is updated when a key is created, modified, accessed, or
	deleted.

	.PARAMETER ComputerName
	Computer name to query

	.PARAMETER Key
	Root Key to query

	HKCR - Symbolic link to HKEY_LOCAL_MACHINE \SOFTWARE \Classes.
	HKCU - Symbolic link to a key under HKEY_USERS representing a user's profile
	hive.
	HKLM - Placeholder with no corresponding physical hive. This key contains
	other keys that are hives.
	HKU  - Placeholder that contains the user-profile hives of logged-on
	accounts.
	HKCC - Symbolic link to the key of the current hardware profile

	.PARAMETER SubKey
	Registry Key to query

	.EXAMPLE
	Get-RegKeyLastWriteTime -ComputerName testwks -Key HKLM -SubKey Software

        .EXAMPLE
	Get-RegKeyLastWriteTime -ComputerName testwks1,testwks2 -SubKey Software

	.EXAMPLE
	Get-RegKeyLastWriteTime -SubKey Software\Microsoft

	.EXAMPLE
	"testwks1","testwks2" | Get-RegKeyLastWriteTime -SubKey Software\Microsoft `
	\Windows\CurrentVersion

	.NOTES
	NAME: Get-RegKeyLastWriteTime
	AUTHOR: Shaun Hess
	VERSION: 1.0
	LASTEDIT: 01JUL2011
	LICENSE: Creative Commons Attribution 3.0 Unported License
	(http://creativecommons.org/licenses/by/3.0/)

	.LINK
	http://www.shaunhess.com
	#>            
            
 [CmdletBinding()]            
            
 param(            
    [parameter(            
    ValueFromPipeline=$true,            
    ValueFromPipelineByPropertyName=$true)]            
    [Alias("CN","__SERVER","Computer","CNAME")]            
    [string[]]$ComputerName=$env:ComputerName,            
    [string]$Key = "HKLM",            
    [string]$SubKey            
)            
            
 BEGIN {            
  switch ($Key) {            
   "HKCR" { $searchKey = 0x80000000} #HK Classes Root            
   "HKCU" { $searchKey = 0x80000001} #HK Current User            
   "HKLM" { $searchKey = 0x80000002} #HK Local Machine            
   "HKU"  { $searchKey = 0x80000003} #HK Users            
   "HKCC" { $searchKey = 0x80000005} #HK Current Config            
   default {            
   "Invalid Key. Use one of the following options:
			HKCR, HKCU, HKLM, HKU, HKCC"}            
  }            
            
  $KEYQUERYVALUE = 0x1            
  $KEYREAD = 0x19            
  $KEYALLACCESS = 0x3F            
 }            
 PROCESS {            
  foreach($computer in $ComputerName) {            
              
$sig0 = @'
[DllImport("advapi32.dll", SetLastError = true)]
  public static extern int RegConnectRegistry(
  	string lpMachineName,
	int hkey,
	ref int phkResult);
'@            
  $type0 = Add-Type -MemberDefinition $sig0 -Name Win32Utils `   -Namespace
 RegConnectRegistry -Using System.Text -PassThru            
            
$sig1 = @'
[DllImport("advapi32.dll", CharSet = CharSet.Auto)]
  public static extern int RegOpenKeyEx(
    int hKey,
    string subKey,
    int ulOptions,
    int samDesired,
    out int hkResult);
'@            
  $type1 = Add-Type -MemberDefinition $sig1 -Name Win32Utils `
 -Namespace RegOpenKeyEx -Using System.Text -PassThru            
            
$sig2 = @'
[DllImport("advapi32.dll", EntryPoint = "RegEnumKeyEx")]
extern public static int RegEnumKeyEx(
    int hkey,
    int index,
    StringBuilder lpName,
    ref int lpcbName,
    int reserved,
    int lpClass,
    int lpcbClass,
    out long lpftLastWriteTime);
'@            
  $type2 = Add-Type -MemberDefinition $sig2 -Name Win32Utils `
 -Namespace RegEnumKeyEx -Using System.Text -PassThru            
            
$sig3 = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern int RegCloseKey(
    int hKey);
'@            
  $type3 = Add-Type -MemberDefinition $sig3 -Name Win32Utils ` 
 -Namespace RegCloseKey -Using System.Text -PassThru            
            
            
  $hKey = new-object int            
  $hKeyref = new-object int            
  $searchKeyRemote = $type0::RegConnectRegistry($computer, $searchKey, `  [ref]$hKey)            
  $result = $type1::RegOpenKeyEx($hKey, $SubKey, 0, $KEYREAD, `  [ref]$hKeyref)            
            
  #initialize variables            
  $builder = New-Object System.Text.StringBuilder 1024            
  $index = 0            
  $length = [int] 1024            
  $time = New-Object Long            
            
  #234 means more info, 0 means success. Either way, keep reading            
  while ( 0,234 -contains $type2::RegEnumKeyEx($hKeyref, $index++, `      $builder, [ref] $length, $null, $null, $null, [ref] $time) )            
  {            
      #create output object            
      $o = "" | Select Key, LastWriteTime, ComputerName             
   $o.ComputerName = "$computer"             
      $o.Key = $builder.ToString()            
   # TODO Change to use the time api            
      $o.LastWriteTime = (Get-Date $time).AddYears(1600).AddHours(-4)            
      $o            
            
      #reinitialize for next time through the loop            
      $length = [int] 1024            
      $builder = New-Object System.Text.StringBuilder 1024            
  }            
            
  $result = $type3::RegCloseKey($hKey);            
  }            
 }            
} 