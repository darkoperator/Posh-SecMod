$Global:sqliteconn = @()

function get-logdatestring
{
    (get-date).toString(‘yyyyMMddhhmm’)
}

function Connect-SQLite3 
{
	param ( [string]$DataBase)
    
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

		.EXAMPLE
			PS C:\> Get-Something 'One value' 32

		.INPUTS
			System.String,System.Int32

		.OUTPUTS
			System.String

		.NOTES
			Additional information about the function go here.

		.LINK
			about_functions_advanced

		.LINK
			about_comment_based_help

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

function New-IPv4Range
{
	param(
		[Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
				   $StartIP,
				   
		[Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
				   $EndIP		   
	)
	
    # created by Dr. Tobias Weltner, MVP PowerShell
    $ip1 = ([System.Net.IPAddress]$StartIP).GetAddressBytes()
    [Array]::Reverse($ip1)
    $ip1 = ([System.Net.IPAddress]($ip1 -join '.')).Address

    $ip2 = ([System.Net.IPAddress]$EndIP).GetAddressBytes()
    [Array]::Reverse($ip2)
    $ip2 = ([System.Net.IPAddress]($ip2 -join '.')).Address

    for ($x=$ip1; $x -le $ip2; $x++) {
        $ip = ([System.Net.IPAddress]$x).GetAddressBytes()
        [Array]::Reverse($ip)
        $ip -join '.'
    }
}

function Get-IPv4RangeFromCIDR {
    param(
		[Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
				   $strNetwork
    )
    # Extract the portions of the CIDR that will be needed
    $StrNetworkAddress = ($strNetwork.split("/"))[0]
    [int]$NetworkLength = ($strNetwork.split("/"))[1]
    $NetworkIP = ([System.Net.IPAddress]$StrNetworkAddress).GetAddressBytes()
    $IPLength = 32-$NetworkLength
    [Array]::Reverse($NetworkIP)
    $NumberOfIPs = ([System.Math]::Pow(2, $IPLength)) -1
    $NetworkIP = ([System.Net.IPAddress]($NetworkIP -join ".")).Address
    $StartIP = $NetworkIP +1
    $EndIP = $NetworkIP + $NumberOfIPs
    # We make sure they are of type Double before conversion
    If ($EndIP -isnot [double])
    {
        $EndIP = $EndIP -as [double]
    }
    If ($StartIP -isnot [double])
    {
        $StartIP = $StartIP -as [double]
    }
    # We turn the start IP and end IP in to strings so they can be used.
    $StartIP = ([System.Net.IPAddress]$StartIP).IPAddressToString
    $EndIP = ([System.Net.IPAddress]$EndIP).IPAddressToString
    New-IPRange $StartIP $EndIP
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Invoke-PingScan
{
    [CmdletBinding()]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$StartIP,

        # Param2 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [string]$EndIP,

        # Param3 help description
        [Parameter(
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [int]$TimeOut = 100
    )

    Begin
    {
    }
    Process
    {
        # Get list of IPs to ping
        $ips = New-IPv4Range $StartIP $EndIP
        $ip_num = $ips.count
        # Instansiate a ping object
        $ping = New-Object System.Net.NetworkInformation.Ping
        $count = 1
        $progress =0
		$results = @()
        foreach ($ip in $ips)
        {
          
          $results += $ping.Send($ip, $TimeOut)  | where {$_.Status -eq "Success"} | Select-Object Address 

          # Provide progress, specially usefull in large reports
          $record_progress = [int][Math]::Ceiling((($progress / $ip_num) * 100))
          Write-Progress -Activity "Ping Scan" -PercentComplete $record_progress -Status "Pinging hosts - $record_progress%" -Id 1;
          $progress++
        }
    }
    End
    {
		$results
    }
}

function Import-DNSReconXML
{
    <#
    .Synopsis
    Converts object properties in a DNSRecon XML output file in to objects.
    .DESCRIPTION
    The Import-DNSReconXML cmdlet creates objects from XML files that are generated by DNSRecon DNS Enumeration tool.
    .EXAMPLE
    Returns all records in the XML file
    .EXAMPLE
    Returns the objects for Service Records
    Import-DNSReconXML .\output.xml -Filter SRV
    .EXAMPLE
    Returns the objects for A, AAAA and PTR Records
    Import-DNSReconXML .\output.xml -Filter A,AAAA,PTR
    #>
    [CmdletBinding()]
    Param
    (
        # XML File generated by DNSRecon
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateScript({Test-Path $_})] 
        $XMLFile,

        # DNS RR Records to query for
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [ValidateSet("A","AAAA","NS","TXT","SPF","MX","SOA","SRV","PTR")] 
        $Filter
    )

    Begin
    {
        [Array]$dnsrecords = @()
        if ($Filter -eq $null)
        {
            $Filter = "A","AAAA","NS","TXT","SPF","MX","SOA","SRV","PTR"   
        }

    }
    Process
    {
        [xml]$dnsr = Get-Content $XMLFile
        # How many servers
        $record_count = $dnsr.records.record.Length
        # processed server count
        $i = 0;
        # Parse each record
        foreach ($record in $dnsr.records.record) {
            $record_progress = [int][Math]::Ceiling((($i / $record_count) * 100))
            Write-Progress -Activity "Processing XML" -PercentComplete $record_progress -Status "Processing records - $record_progress%" -Id 1;
            
            if ($Filter -contains $record.type) {

                # Check each of the record types
                switch -Regex ($record.type)
                {
                    # Parse SRV records
                    "SRV" 
                    {
                        $DNSRObject = New-Object PSObject 
                        $DNSRObject | add-member Noteproperty Type         $record.type
                        $DNSRObject | add-member Noteproperty Name         $record.name
                        $DNSRObject | add-member Noteproperty Target       $record.target
                        $DNSRObject | add-member Noteproperty Address      $record.address
                        $DNSRObject | add-member Noteproperty Port         $record.port
                        $DNSRObject | add-member Noteproperty ZoneTransfer $record.zone_server
                        $DNSRObject | add-member Noteproperty Text         $null
                        
                        $dnsrecords += $DNSRObject
                    }

                    # Parse NS records
                    "NS" 
                    {
                        $DNSRObject = New-Object PSObject 
                        $DNSRObject | add-member Noteproperty Type         $record.type
                        $DNSRObject | add-member Noteproperty Name         $record.target
                        $DNSRObject | add-member Noteproperty Target       $null
                        $DNSRObject | add-member Noteproperty Address      $record.address
                        $DNSRObject | add-member Noteproperty Port         $null
                        $DNSRObject | add-member Noteproperty ZoneTransfer $record.zone_server
                        $DNSRObject | add-member Noteproperty Text         $null
                   
                        $dnsrecords += $DNSRObject
                    }

                    # Parse AAA records
                    "AAAA|A|PTR"
                    {
                        $DNSRObject = New-Object PSObject 
                        $DNSRObject | add-member Noteproperty Type         $record.type
                        $DNSRObject | add-member Noteproperty Name         $record.name
                        $DNSRObject | add-member Noteproperty Target       $record.target
                        $DNSRObject | add-member Noteproperty Address      $record.address
                        $DNSRObject | add-member Noteproperty Port         $record.port
                        $DNSRObject | add-member Noteproperty ZoneTransfer $record.zone_server
                        $DNSRObject | add-member Noteproperty Text         $null

                        $dnsrecords += $DNSRObject
                    }

                    # Parse MX records
                    "MX"
                    {
                        $DNSRObject = New-Object PSObject 
                        $DNSRObject | add-member Noteproperty Type         $record.type
                        $DNSRObject | add-member Noteproperty Name         $record.exchange
                        $DNSRObject | add-member Noteproperty Target       $null
                        $DNSRObject | add-member Noteproperty Address      $record.address
                        $DNSRObject | add-member Noteproperty Port         $record.port
                        $DNSRObject | add-member Noteproperty ZoneTransfer $record.zone_server
                        $DNSRObject | add-member Noteproperty Text         $null

                        $dnsrecords += $DNSRObject
                    }

                    # Parse SOA records
                    "SOA" 
                    {
                        $DNSRObject = New-Object PSObject 
                        $DNSRObject | add-member Noteproperty Type         $record.type
                        $DNSRObject | add-member Noteproperty Name         $record.mname
                        $DNSRObject | add-member Noteproperty Target       $null
                        $DNSRObject | add-member Noteproperty Address      $record.address
                        $DNSRObject | add-member Noteproperty Port         $record.port
                        $DNSRObject | add-member Noteproperty ZoneTransfer $record.zone_server
                        $DNSRObject | add-member Noteproperty Text         $null

                        $dnsrecords += $DNSRObject
                    }
        
                    "TXT|SPF"
                    {
                        $DNSRObject = New-Object PSObject 
                        $DNSRObject | add-member Noteproperty Type         $record.type
                        $DNSRObject | add-member Noteproperty Name         $record.name
                        $DNSRObject | add-member Noteproperty Target       $record.target
                        $DNSRObject | add-member Noteproperty Address      $null
                        $DNSRObject | add-member Noteproperty Port         $null
                        $DNSRObject | add-member Noteproperty ZoneTransfer $record.zone_server
                        $DNSRObject | add-member Noteproperty Text         $record.text

                        $dnsrecords += $DNSRObject
                    }
                }
            }
            $i++
        }
    }
    End
    {
        $dnsrecords
    }
}

function Import-NessusReport
{
	<#
	.Synopsis
	   Converts object properties in a NessusV2 Report file in to objects
	.DESCRIPTION
	   The Import-NessusReport cmdlet creates objects from Nessus v2 files that are generated by the Nessus 4.x or 5.x scanner.
	.EXAMPLE
	   Return object with Profile Configuration info.
	   Import-NessusReport .\report.nessus -InfoType ProfileInfo
	.EXAMPLE
	   Returns objects for each of the hosts scanned with Properties and Report Items for each.
	   Import-NessusReport .\report.nessus
	.EXAMPLE
	   Looks for hosts for which a a Vulnerability was found that a Metasploit exploit exists and return the IP and Name of the Module.
	   Import-NessusReport .\repport.nessus | foreach {$_.reportitems} | where {$_.metasploit -ne $null} | foreach { "$($_.host) $($_.metasploitmodule)"}
	#>
    [CmdletBinding()]
    Param
    (
        # Nessus Version 2 report file
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateScript({Test-Path $_})] 
        $NessusFile,

        # Type of Information to return
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [ValidateSet("ProfileInfo","Vulnerabilities")] 
        $InfoType = "Vulnerabilities"
    )

    Begin
    {
        [xml]$nessus = Get-Content $NessusFile
    }
    Process
    {
        if ($InfoType -eq "Vulnerabilities")
        {
            # How many servers
            $record_count = $nessus.NessusClientData_v2.Report.ReportHost.Length
            # processed host count
            $i = 0;
            # Declare Array that will be returned with the objects
            $reported_hosts = @()
            # for each of the hosts reported
            $nessus.NessusClientData_v2.Report.ReportHost | foreach {
                # Declare variables for properties that will form the object
                $hproperties = @{}
                $host_properties = @{}
                $vulns = @()
                $hostip = $_.name
                # Gathering properties for each host
                $_.HostProperties.tag | foreach {$hproperties += @{($_.name -replace "-","_") = $_."#text"}}
    
                # Set the Host and Host Properties object properties
                $host_properties += @{Host = $hostip.Trim()}
                $host_properties += @{Host_Properties = New-Object PSObject -Property $hproperties}

                # Collect vulnerable information for each host
                $_.ReportItem | where {$_.pluginID -ne "0"} | foreach {
                    
                    $vuln_properties = New-Object PSObject
                    $vuln_properties | add-member Noteproperty  Host                  $hostip.Trim()
                    $vuln_properties | add-member Noteproperty  Port                  $_.Port
                    $vuln_properties | add-member Noteproperty  ServiceName           $_.svc_name
                    $vuln_properties | add-member Noteproperty  Severity              $_.severity
                    $vuln_properties | add-member Noteproperty  PluginID              $_.pluginID
                    $vuln_properties | add-member Noteproperty  PluginName            $_.pluginName
                    $vuln_properties | add-member Noteproperty  PluginFamily          $_.pluginFamily
                    $vuln_properties | add-member Noteproperty  RiskFactor            $_.risk_factor
                    $vuln_properties | add-member Noteproperty  Synopsis              $_.synopsis
                    $vuln_properties | add-member Noteproperty  Description           $_.description
                    $vuln_properties | add-member Noteproperty  Solution              $_.solution
                    $vuln_properties | add-member Noteproperty  PluginOutput          $_.plugin_output
                    $vuln_properties | add-member Noteproperty  SeeAlso               $_.see_also
                    $vuln_properties | add-member Noteproperty  CVE                   $_.cve
                    $vuln_properties | add-member Noteproperty  BID                   $_.bid
                    $vuln_properties | add-member Noteproperty  ExternaReference      $_.xref
                    $vuln_properties | add-member Noteproperty  PatchPublicationDate  $_.patch_publication_date
                    $vuln_properties | add-member Noteproperty  VulnPublicationDate   $_.vuln_publication_date
                    $vuln_properties | add-member Noteproperty  Exploitability        $_.exploitability_ease
                    $vuln_properties | add-member Noteproperty  ExploitAvailable      $_.exploit_available
                    $vuln_properties | add-member Noteproperty  CANVAS                $_.exploit_framework_canvas
                    $vuln_properties | add-member Noteproperty  Metasploit            $_.exploit_framework_metasploit
                    $vuln_properties | add-member Noteproperty  COREImpact            $_.exploit_framework_core
                    $vuln_properties | add-member Noteproperty  MetasploitModule      $_.metasploit_name
                    $vuln_properties | add-member Noteproperty  CANVASPackage         $_.canvas_package
                    $vuln_properties | add-member Noteproperty  CVSSVector            $_.cvss_vector
                    $vuln_properties | add-member Noteproperty  CVSSBase              $_.cvss_base_score
                    $vuln_properties | add-member Noteproperty  CVSSTemporal          $_.cvss_temporal_score
                    $vuln_properties | add-member Noteproperty  PluginType            $_.plugin_type
                    $vuln_properties | add-member Noteproperty  PluginVersion         $_.plugin_version
                    
                   
                    $vulns += $vuln_properties
                }
                $host_properties += @{ReportItems = $vulns}
    
                # Create each host object
                $reported_vuln = New-Object PSObject -Property $host_properties
                $reported_hosts += $reported_vuln

                # Provide progress, specially usefull in large reports
                $record_progress = [int][Math]::Ceiling((($i / $record_count) * 100))
                Write-Progress -Activity "Processing Vulnerability Report" -PercentComplete $record_progress -Status "Processing records - $record_progress%" -Id 1;
                $i++
            }
            $reported_hosts
        }
        else
        {
            $prefs = @()
            $ips_plugins =@()
            # Get Server Settings
            $nessus.NessusClientData_v2.Policy.Preferences.ServerPreferences.preference | % { $ServerSettings = @{} } { $ServerSettings += @{$_.name = $_.value} }
            
            
            # Policy Name
            $polname = $nessus.NessusClientData_v2.Policy.policyName
            
            # Get policy settings
            $prefobj = $nessus.NessusClientData_v2.Policy.Preferences.PluginsPreferences.ChildNodes
            foreach ($pref in $prefobj) 
            {
                $pref_property = @{}
                Get-Member -InputObject $pref -MemberType Property | foreach { $pref_property += @{$_.name = $pref.($_.name.trim()) }
                $prefs += New-Object PSObject -Property $pref_property
                }
            }
            
            # Get selected Plugin Families
            $nessus.NessusClientData_v2.Policy.FamilySelection.FamilyItem |% { $families = @{} } { $families += @{$_.familyname = $_.value} }

            # Individual Plugin Selection
            $ips = $nessus.NessusClientData_v2.Policy.IndividualPluginSelection.PluginItem 
            foreach ($plugin in $ips)
            {
                $plugin_property = @{}
                Get-Member -InputObject $plugin -MemberType Property | foreach { $plugin_property += @{$_.name = $plugin.($_.name.trim()) }
                $ips_plugins += New-Object PSObject -Property $plugin_property
                }
            }

        }
        $policyobj = New-Object PSObject
        $policyobj | add-member Noteproperty PolicyName                $polname
        $policyobj | add-member Noteproperty Preferences               $prefs
        $policyobj | add-member Noteproperty PluginFamilies            $families
        $policyobj | add-member Noteproperty IndividualPluginSelection $ips_plugins
        $policyobj | add-member Noteproperty ServerSettings            $ServerSettings
        $policyobj
    }
    End
    {
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
	   Confirm-IsAdmin
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
                   Position=0)]
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
	param([object]$items) 
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
Export-ModuleMember -Variable $sqliteconns
Export-ModuleMember -Function Get-FileHash
Export-ModuleMember -Function Invoke-SQLite3Query
Export-ModuleMember -Function Connect-SQLite3
Export-ModuleMember -Function Import-DNSReconXML
Export-ModuleMember -Function Import-NessusReport
Export-ModuleMember -Function Invoke-PingScan
Export-ModuleMember -Function Confirm-IsAdmin
Export-ModuleMember -Function New-Zip
Export-ModuleMember -Function Add-Zip
Export-ModuleMember -Function Get-Zip
Export-ModuleMember -Function Expand-Zip