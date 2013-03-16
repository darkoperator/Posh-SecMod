 Function Get-WebFile
 {
     Param(
        [Parameter(Mandatory = $true)]
        [uri]$URL,

        [Parameter(Mandatory = $true)]
        $LocalFile
     )
  
    Begin
    {
        $WebClient = New-Object System.Net.WebClient
    }
    
    Process
    {
        try 
        {
            Register-ObjectEvent $WebClient DownloadProgressChanged -action {     

                Write-Progress -Activity "Downloading" -Status `
                    ("{0} of {1}" -f $eventargs.BytesReceived, $eventargs.TotalBytesToReceive) `
                    -PercentComplete $eventargs.ProgressPercentage    
            }

            Register-ObjectEvent $client DownloadFileCompleted -SourceIdentifier Finished
            $WebClient.DownloadFileAsync($URL, $LocalFile)

            # optionally wait, but you can break out and it will still write progress
            Wait-Event -SourceIdentifier Finished

        } 
        finally 
        { 
            $WebClient.dispose()
        }
    }
    End{}
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
    	Foreach-Object -Process { [void] $builder.Append($_.ToString("X2")) } -InputObject $hashBytes
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