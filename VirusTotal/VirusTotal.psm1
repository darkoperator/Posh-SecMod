
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

<#
.Synopsis
   Submit a File for scanning by VirusTotal
.DESCRIPTION
   Submit a File for scanning by VirusTotal. File size is limited to 20MB.
.EXAMPLE
   Submit-VirusTotalFile -File C:\backdoor.dll -APIKey $Key
.LINK
    http://www.darkoperator.com
    https://www.virustotal.com/en/documentation/public-api/
#>
function Submit-VirusTotalFile
{
    [CmdletBinding()]
    Param
    (
        # URL or ScanID to query.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$File,

        # VirusToral API Key.
        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    Begin
    {
        $URI = "http://www.virustotal.com/vtapi/v2/file/scan"
    }
    Process
    {
        $fileinfo = Get-ItemProperty -Path $File

        # Check the file size
        if ($fileinfo.length -gt 64mb)
        {
            Write-Error "VirusTotal has a limit of 64MB per file submited" -ErrorAction Stop
        }
   
        $req = [System.Net.httpWebRequest][System.Net.WebRequest]::Create("http://www.virustotal.com/vtapi/v2/file/scan")
        $req.Headers = $headers
        $req.Method = "POST"
        $req.AllowWriteStreamBuffering = $true;
        $req.SendChunked = $false;
        $req.KeepAlive = $true;

        $headers = New-Object -TypeName System.Net.WebHeaderCollection

        # Prep the POST Headers for the message
        $headers.add("apikey",$apikey)
        $boundary = "----------------------------" + [DateTime]::Now.Ticks.ToString("x")
        $req.ContentType = "multipart/form-data; boundary=" + $boundary
        [byte[]]$boundarybytes = [System.Text.Encoding]::ASCII.GetBytes("`r`n--" + $boundary + "`r`n")
        [string]$formdataTemplate = "`r`n--" + $boundary + "`r`nContent-Disposition: form-data; name=`"{0}`";`r`n`r`n{1}"
        [string]$formitem = [string]::Format($formdataTemplate, "apikey", $apikey)
        [byte[]]$formitembytes = [System.Text.Encoding]::UTF8.GetBytes($formitem)
        [string]$headerTemplate = "Content-Disposition: form-data; name=`"{0}`"; filename=`"{1}`"`r`nContent-Type: application/octet-stream`r`n`r`n"
        [string]$header = [string]::Format($headerTemplate, "file", (get-item $file).name)
        [byte[]]$headerbytes = [System.Text.Encoding]::UTF8.GetBytes($header)
        [string]$footerTemplate = "Content-Disposition: form-data; name=`"Upload`"`r`n`r`nSubmit Query`r`n" + $boundary + "--"
        [byte[]]$footerBytes = [System.Text.Encoding]::UTF8.GetBytes($footerTemplate)


        # Read the file and format the message
        $stream = $req.GetRequestStream()
        $rdr = new-object System.IO.FileStream($fileinfo.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        [byte[]]$buffer = new-object byte[] $rdr.Length
        [int]$total = [int]$count = 0
        $stream.Write($formitembytes, 0, $formitembytes.Length)
        $stream.Write($boundarybytes, 0, $boundarybytes.Length)
        $stream.Write($headerbytes, 0,$headerbytes.Length)
        $count = $rdr.Read($buffer, 0, $buffer.Length)
        do{
            $stream.Write($buffer, 0, $count)
            $count = $rdr.Read($buffer, 0, $buffer.Length)
        }while ($count > 0)
        $stream.Write($boundarybytes, 0, $boundarybytes.Length)
        $stream.Write($footerBytes, 0, $footerBytes.Length)
        $stream.close()

        Try
        {
            # Upload the file
            $response = $req.GetResponse()

            # Read the response
            $respstream = $response.GetResponseStream()
            $sr = new-object System.IO.StreamReader $respstream
            $result = $sr.ReadToEnd()
            ConvertFrom-Json $result
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