$Global:sqliteconn = @()



function Get-LogDateString
{
    (get-date).toString(‘yyyyMMddhhmm’)
}

function Connect-SQLite3 
{
    [CmdletBinding()]
	param (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$DataBase
    )
    
    Begin{}
    Process
    {
	    # Load the appropiate DLL Depending on the Archiecture
	    switch ([intptr]::size)
	    {
		    4 {$sqlitedll = [System.Reflection.Assembly]::LoadFrom("$PSScriptRoot\x86\System.Data.SQLite.dll")} 
		    8 {$sqlitedll = [System.Reflection.Assembly]::LoadFrom("$PSScriptRoot\x64\System.Data.SQLite.dll")}
	    }
	    $cn = New-Object -TypeName System.Data.SQLite.SQLiteConnection
	    $cn.ConnectionString = "Data Source=$DataBase"
	    $cn.Open()
        $conn_obj = $cn
        if ($Global:sqliteconn -notcontains $conn_obj)
        {
            $Global:sqliteconn += $conn_obj
        }
    }

    End
    {
        $Global:sqliteconn
    }

}

function Invoke-SQLite3Query           
{
    [CmdletBinding()]            
    param( [string]$SQL,            
           [System.Data.SQLite.SQLiteConnection]$Connection            
           )            
    $cmd = new-object System.Data.SQLite.SQLiteCommand($SQL,$Connection)            
    $ds = New-Object system.Data.DataSet            
    $da = New-Object System.Data.SQLite.SQLiteDataAdapter($cmd)            
    $da.fill($ds) | Out-Null            
    return $ds.tables[0]            
}

function Get-FileHash 
{
	<#
		.SYNOPSIS
			cmdlet for calculatingt the hash of a given file.

		.DESCRIPTION
			Calculates either the MD5, SHA1, SHA256, SHA384 or SHA512 checksum of a given file.

		.PARAMETER  File
			The description of the ParameterA parameter.

		.PARAMETER  HashAlgorithm
			The description of the ParameterB parameter.

		.EXAMPLE
			PS C:\> Get-Something -ParameterA 'One value' -ParameterB 32
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateScript({Test-Path $_})] 
        $File,

		[ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512")]
    	$HashAlgorithm = "MD5"
	)
	 Begin
    {
		$hashType = [Type] "System.Security.Cryptography.$HashAlgorithm"
		$hasher = $hashType::Create()
	}
	
	Process
	{
		$inputStream = New-Object IO.StreamReader $File
    	$hashBytes = $hasher.ComputeHash($inputStream.BaseStream)
    	$inputStream.Close()

   		 # Convert the result to hexadecimal
    	$builder = New-Object System.Text.StringBuilder
    	$hashBytes | Foreach-Object { [void] $builder.Append($_.ToString("X2")) }
		# Create Object
    	$output = New-Object PsObject -Property @{
        		Path = ([IO.Path]::GetFileName($file));
        		HashAlgorithm = $hashAlgorithm;
        		HashValue = $builder.ToString()
			}
	}
	End
	{
		$output
	}
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

function New-Zip
{
	[CmdletBinding()]
    Param
    (
	[Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
	$ZipFile
	)
	set-content $ZipFile ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
	(dir $ZipFile).IsReadOnly = $false
}

function Add-Zip
{
	[CmdletBinding()]
    Param
    (
	[Parameter(Mandatory=$true)]
		$ZipFile,
		
		[Parameter(Mandatory=$true,
                  ValueFromPipeline=$true,
                   Position=1)]
        [ValidateScript({Test-Path $_})]
		$File
		
	)
	if(-not (test-path($ZipFile)))
	{
		set-content $ZipFile ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
		(dir $ZipFile).IsReadOnly = $false	
	}
	Write-Verbose $File
	$shellApplication = new-object -com shell.application
	$zipPackage = (new-object -com shell.application).NameSpace(((get-item $ZipFile).fullname))
	$zipPackage.CopyHere((get-item $File).FullName)
}

function Get-ZipChildItems_Recurse 
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [object]$items
    )
     
    foreach($si in $items) 
    { 
        if($si.getfolder -ne $null) 
        { 
            Get-ZipChildItems_Recurse $si.getfolder.items() 
        } 
      $si | select path
      } 
}

function Get-Zip
{
	[CmdletBinding()]
    Param
    (
	    [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateScript({Test-Path $_})]
		$ZipFile,
		$Recurse = $true
	)

	$shellApplication = new-object -com shell.application
	$zipPackage = $shellApplication.NameSpace(((get-item $ZipFile).fullname))
	if ($Recurse -eq $false)
	{
		$zipPackage.Items() | select path
	}
	else
	{
		Get-ZipChildItems_Recurse $zipPackage.Items()
	}
}

function Expand-Zip
{
	[CmdletBinding()]
    Param
    (
	    [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateScript({Test-Path $_})]
		$ZipFile,
		
	    [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
		$Destination
	)
	
	if (Test-Path -PathType Container $Destination)
	{
		$destinationFolder = $shellApplication.NameSpace(((get-item $Destination).fullname))
	}
	else
	{
		New-Item -ItemType container -Path $Destination | Out-Null
		$destinationFolder = $shellApplication.NameSpace(((get-item $Destination).fullname))
	}

	$shellApplication = new-object -com shell.application
	$zipPackage = $shellApplication.NameSpace(((get-item $ZipFile).fullname))
	$destinationFolder = $shellApplication.NameSpace(((get-item $Destination).fullname))
	$destinationFolder.CopyHere($zipPackage.Items())
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