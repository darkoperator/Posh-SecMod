
<#
.Synopsis
   Get a VirusTotal Report for a given IPv4 Address
.DESCRIPTION
   Get a VirusTotal Report for a given IPv4 Address that have been previously scanned.
.EXAMPLE
   Get-VirtusTotalIPReport -IPAddress 90.156.201.18 -APIKey $Key
.LINK
    http://www.darkoperator.com
    https://www.virustotal.com/en/documentation/public-api/
#>
function Get-VirusTotalIPReport
{
    [CmdletBinding()]
    Param
    (
        # IP Address to scan for.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$IPAddress,

        # VirusToral API Key.
        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    }
    Process
    {
        Try
        {
            $IPReport = Invoke-RestMethod -Uri $URI -method get -Body @{'ip'= $IPAddress; 'apikey'= $APIKey}
            $IPReport.pstypenames.insert(0,'VirusTotal.IP.Report')
            $IPReport
        }
        Catch [Net.WebException]
        {
            if ($Error[0].ToString() -like "*403*")
            {
                Write-Error "API key is not valid."
            }
            elseif ($Error[0].ToString() -like "*204*")
            {
                Write-Error "API key rate has been reached."
            }
        }
    }
    End
    {
    }
}

<#
.Synopsis
   Get a VirusTotal Report for a given Domain
.DESCRIPTION
   Get a VirusTotal Report for a given Domian that have been previously scanned.
.EXAMPLE
   Get-VirusTotalDomainReport -Domain '027.ru' -APIKey $Key
.LINK
    http://www.darkoperator.com
    https://www.virustotal.com/en/documentation/public-api/
#>
function Get-VirusTotalDomainReport
{
    [CmdletBinding()]
    Param
    (
        # Domain to scan.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$Domain,

        # VirusToral API Key.
        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/domain/report'
    }
    Process
    {
        Try
        {
            $DomainReport = Invoke-RestMethod -Uri $URI -method get -Body @{'domain'= $Domain; 'apikey'= $APIKey}
            $DomainReport.pstypenames.insert(0,'VirusTotal.Domain.Report')
            $DomainReport
        }
        Catch [Net.WebException]
        {
            if ($Error[0].ToString() -like "*403*")
            {
                Write-Error "API key is not valid."
            }
            elseif ($Error[0].ToString() -like "*204*")
            {
                Write-Error "API key rate has been reached."
            }
        }
    }
    End
    {
    }
}



<#
.Synopsis
   Get a VirusTotal Report for a given File
.DESCRIPTION
   Get a VirusTotal Report for a given File that have been previously scanned.
   A MD5, SHA1 or SHA2 Cryptpgraphic Hash can be provided or a ScanID for a File.
   Up to 4 file reporst can be retrieve at the same time.
.EXAMPLE
   Get-VirusTotalFileReport -Resource 99017f6eebbac24f351415dd410d522d -APIKey $Key
.LINK
    http://www.darkoperator.com
    https://www.virustotal.com/en/documentation/public-api/
#>
function Get-VirusTotalFileReport
{
    [CmdletBinding()]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum, File SHA256 Checksum or ScanID to query.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateCount(1,4)]
        [string[]]$Resource,

        # VirusToral API Key.
        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/report'
    }
    Process
    {
        $QueryResources =  $Resource -join ","

        Try
        {
            $ReportResult =Invoke-RestMethod -Uri $URI -method get -Body @{'resource'= $QueryResources; 'apikey'= $APIKey}
            foreach ($FileReport in $ReportResult)
            {
                $FileReport.pstypenames.insert(0,'VirusTotal.File.Report')
                $FileReport
            }
        }
        Catch [Net.WebException]
        {
            if ($Error[0].ToString() -like "*403*")
            {
                Write-Error "API key is not valid."
            }
            elseif ($Error[0].ToString() -like "*204*")
            {
                Write-Error "API key rate has been reached."
            }
        }
    }
    End
    {
    }
}

<#
.Synopsis
   Get a VirusTotal Report for a given URL
.DESCRIPTION
   Get a VirusTotal Report for a given URL that have been previously scanned.
   A URL or a ScanID for prevous scan. Up to 4 URL reporst can be retrieve at the same time.
.EXAMPLE
   Get-VirusTotalURLReport -Resource http://www.darkoperator.com -APIKey $Key
.LINK
    http://www.darkoperator.com
    https://www.virustotal.com/en/documentation/public-api/
#>
function Get-VirusTotalURLReport
{
    [CmdletBinding()]
    Param
    (
        # URL or ScanID to query.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateCount(1,4)]
        [string[]]$Resource,

        # VirusToral API Key.
        [Parameter(Mandatory=$true)]
        [string]$APIKey,

        # Automatically submit the URL for analysis if no report is found for it in VirusTotal.
        [Parameter(Mandatory=$false)]
        [switch]$Scan
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/url/report'
        if ($Scan)
        {
            $scanurl = 1
        }
        else
        {
            $scanurl = 0
        }
    }
    Process
    {
        $QueryResources =  $Resource -join ","

        Try
        {
            $ReportResult = Invoke-RestMethod -Uri $URI -method get -Body @{'resource'= $QueryResources; 'apikey'= $APIKey; 'scan'=$scanurl}
            foreach ($URLReport in $ReportResult)
            {
                $URLReport.pstypenames.insert(0,'VirusTotal.URL.Report')
                $URLReport
            }
        }
        Catch [Net.WebException]
        {
            if ($Error[0].ToString() -like "*403*")
            {
                Write-Error "API key is not valid."
            }
            elseif ($Error[0].ToString() -like "*204*")
            {
                Write-Error "API key rate has been reached."
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Submit a URL for scanning by VirusTotal
.DESCRIPTION
   Submit a URL for scanning by VirusTotal. Up to 4 URLcan be submitted at the same time.
.EXAMPLE
   Submit-VirusTotalURL -URL "http://www.darkoperator.com","http://gamil.com" -APIKey $Key
.LINK
    http://www.darkoperator.com
    https://www.virustotal.com/en/documentation/public-api/
#>
function Submit-VirusTotalURL
{
    [CmdletBinding()]
    Param
    (
        # URL or ScanID to query.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateCount(1,4)]
        [string[]]$URL,

        # VirusToral API Key.
        [Parameter(Mandatory=$true)]
        [string]$APIKey,

        # Automatically submit the URL for analysis if no report is found for it in VirusTotal.
        [Parameter(Mandatory=$false)]
        [switch]$Scan
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/url/scan'
        if ($Scan)
        {
            $scanurl = 1
        }
        else
        {
            $scanurl = 0
        }
    }
    Process
    {
        $URLList =  $URL -join "`n"

        Try
        {
            $SubmitedList = Invoke-RestMethod -Uri $URI -method Post -Body @{'url'= $URLList; 'apikey'= $APIKey}
            foreach($submited in $SubmitedList)
            {
                $submited.pstypenames.insert(0,'VirusTotal.URL.Submission')
                $submited
            }
        }
        Catch [Net.WebException]
        {
            if ($Error[0].ToString() -like "*403*")
            {
                Write-Error "API key is not valid."
            }
            elseif ($Error[0].ToString() -like "*204*")
            {
                Write-Error "API key rate has been reached."
            }
        }
    }
    End
    {
    }
}

