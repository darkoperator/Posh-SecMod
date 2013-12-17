
<#
.Synopsis
   Get API Features for a given API Key
.DESCRIPTION
   Get API Features for a given API Key
.EXAMPLE
    Get-ShodanAPIInfo -APIKey $apikey


    unlocked_left : 99
    telnet        : True
    plan          : dev
    https         : True
    unlocked      : True
#>
function Get-ShodanAPIInfo
{
    [CmdletBinding()]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    Begin
    {
    }
    Process
    {
        Invoke-RestMethod -Method get -Uri 'http://www.shodanhq.com/api/info' -Body @{'key'=$APIKey}
    }
    End
    {
    }
}


<#
.Synopsis
   Search for Exploit Information using Shodan
.DESCRIPTION
   Search for Exploit Information using Shodan. The information is gathered from several sources.
   The sources that Shodan will search in are:
   - CVE Mitre
   - OSVDB Open Source Vulnerability Database
   - ExploitDB
   - Metasploit Framework

   Specific IDs can be use to narrow down a search:
    - Microsoft Buletin
    - Security Focus BID
    - CVE ID
    - OSVDB ID

.EXAMPLE
    $result = Search-ShodanExploit -Query "HPUX" -APIKey $apikey

    $result | Format-List


    matches : {@{name=HP-UX LPD Command Execution; source_link=www.exploit-db.com; source=Exploit DB; 
              link=http://www.exploit-db.com/exploits/16927; references=System.Object[]; id=16927; desc=}, 
              @{name=ex_stmkfont.sh; source_link=www.packetstormsecurity.org; source=Packet Storm; 
              link=/exploits/packetstorm/ex_stmkfont.sh; references=System.Object[]; id=ex_stmkfont.sh; desc=HPUX local 
              buffer overflow exploit for stmkfont which attempts to spawn a gid=bin shell. Tested on HPUX B11.11.}, 
              @{name=HP-UX FTPD Remote Buffer Overflow Exploit; source_link=www.exploit-db.com; source=Exploit DB; 
              link=http://www.exploit-db.com/exploits/212; references=System.Object[]; id=212; desc=}, @{name=HPUX execve 
              /bin/sh 58 bytes; source_link=www.exploit-db.com; source=Exploit DB; 
              link=http://www.exploit-db.com/exploits/13295; references=System.Object[]; id=13295; desc=}...}
    sources : {osvdb 272, cve 257, exploitdb 49, packetstorm 7...}
    total   : 586

   Search for HPUX Exploits

#>
function Search-ShodanExploit
{
    [CmdletBinding()]
    Param
    (
        # Text to query for.
        [Parameter(Mandatory=$false)]
        [string]$Query,
        
        # Sources to limit the seach.
        [Parameter(Mandatory=$false)]
        [Validateset('metasploit', 'cve', 'osvdb', 'exploitdb')]
        [string[]]$Sources,

        # CVE ID
        [Parameter(Mandatory=$false)]
        [string]$CVE,

        # OpenSource Vulnerability Databse ID
        [Parameter(Mandatory=$false)]
        [string]$OSVDB,

        # SecurityFocus BID Number
        [Parameter(Mandatory=$false)]
        [string]$BID,

        # Microsoft Buletin (MS012-020)
        [Parameter(Mandatory=$false)]
        [string]$MSB,

        # Shodan API Key
        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    Begin
    {
        $URI = 'http://www.shodanhq.com/api/search_exploits'

        if ($Sources)
        {
            $Query += " source:$($Sources -join ",")"
        }

        if ($CVE)
        {
            $Query += " cve:$($CVE.Trim())"
        }

        if ($OSVDB)
        {
            $Query += " osvdb:$($OSVDB.Trim())"
        }

        if ($BID)
        {
            $Query += " bid:$($BID.Trim())"
        }

        if ($MSB)
        {
            $Query += " msb:$($MSB.Trim())"
        }

    }
    Process
    {
        $result = Invoke-RestMethod -Uri $URI -Method Get -Body @{'q'= $Query;'key'= $APIKey}
        $result.pstypenames.insert(0,'Shodan.Exploit.Search')
        $result
    }
    End
    {
    }
}


<#
.Synopsis
   Get a specific count of results for a given query.
.DESCRIPTION
   Get a specific count of results for a given query not limited by the API Key.
.EXAMPLE
    Get-ShodanCount -Query "HPUX" -APIKey $apikey

    total
    -----
    1934
#>
function Get-ShodanCount
{
    [CmdletBinding()]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true)]
        [string]$Query,
        
        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    Begin
    {
        $URI = "http://www.shodanhq.com/api/count"
    }
    Process
    {
        $result = Invoke-RestMethod -Uri $URI -Method Get -Body @{'q'= $Query;'key'= $APIKey}
        $result.pstypenames.insert(0,'Shodan.Search.Count')
        $result
    }
    End
    {
    }
}


<#
.Synopsis
   Search for information on a given IP Address.
.DESCRIPTION
   Search for information on a given IP Address.
.EXAMPLE
    $info = Search-ShodanIP -IPAddress 173.194.67.26 -APIKey $apikey

    PS C:\> $info


    region_name   : CA
    ip            : 173.194.67.26
    area_code     : 650
    country_name  : United States
    hostnames     : {}
    postal_code   : 94043
    dma_code      : 807
    country_code  : US
    data          : {@{os=; ip=173.194.67.26; isp=Google; last_update=2013-04-16T10:21:33.307107; banner=220 mx.google.com 
                    ESMTP fb16si4179673wid.37 - gsmtp
                    ; hostnames=System.Object[]; link=generic tunnel or VPN; location=; timestamp=16.04.2013; org=Google; 
                    port=25; opts=}}
    city          : Mountain View
    longitude     : -122.0574
    country_code3 : USA
    latitude      : 37.41919999999999
    os            : 


    PS C:\> $info.data


    os          : 
    ip          : 173.194.67.26
    isp         : Google
    last_update : 2013-04-16T10:21:33.307107
    banner      : 220 mx.google.com ESMTP fb16si4179673wid.37 - gsmtp
              
    hostnames   : {173.194.67.26}
    link        : generic tunnel or VPN
    location    : @{city=Mountain View; region_name=CA; area_code=650; longitude=-122.0574; country_code3=USA; 
                  country_name=United States; postal_code=94043; dma_code=807; country_code=US; latitude=37.41919999999999}
    timestamp   : 16.04.2013
    org         : Google
    port        : 25
    opts        : 
#>
function Search-ShodanIP
{
    [CmdletBinding()]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true)]
        [string]$IPAddress,
        
        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    Begin
    {
        $URI = "http://www.shodanhq.com/api/host"
    }
    Process
    {
        $result = Invoke-RestMethod -Uri $URI -Method Get -Body @{'ip'= $IPAddress;'key'= $APIKey}
        $result.pstypenames.insert(0,'Shodan.Host.Info')
        $result
    }
    End
    {
    }
}


<#
.Synopsis
   Returns a breakdown of locations for a given search
.DESCRIPTION
   Returns a breakdown of locations for a given search query.
.EXAMPLE
   Search-ShodanLocation -Query openvms -APIKey $apikey | Format-List


    total     : 2268
    cities    : {@{count=58; name=Berlin}, @{count=48; name=Englewood}, @{count=44; name=Maribor}, @{count=43; 
                name=Victoria}...}
    countries : {@{count=1110; code=US; name=United States}, @{count=263; code=DE; name=Germany}, @{count=222; code=AU; 
                name=Australia}, @{count=123; code=CA; name=Canada}...}
#>
function Search-ShodanLocation
{
    [CmdletBinding()]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true)]
        [string]$Query,
        
        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    Begin
    {
        $URI = "http://www.shodanhq.com/api/locations"
    }
    Process
    {
        $result = Invoke-RestMethod -Uri $URI -Method Get -Body @{'q'= $Query;'key'= $APIKey}
        $result.pstypenames.insert(0,'Shodan.Query.Location')
        $result
    }
    End
    {
    }
}


<#
.Synopsis
   Search ExploitDB for exploits
.DESCRIPTION
   Searches ExploitDB for exploits. The search can be refined using additional paramters in addition
   to the Query parameter.
.EXAMPLE
    $edb = Search-ShodanExploitDB -Query warftpd -APIKey $apikey

    PS C:\> $edb.matches


    description : War-FTPD 1.65 Password Overflow
    author      : metasploit
    id          : 16706
    platform    : 
    date        : 03.07.2010
    cve         : 1999-0256
    type        : 
    port        : 0

    description : War-FTPD 1.65 Username Overflow
    author      : metasploit
    id          : 16724
    platform    : 
    date        : 03.07.2010
    cve         : 1999-0256
    type        : 
    port        : 0

    description : WAR-FTPD 1.65 (MKD/CD Requests) Denial of Service Vuln
    author      : opt!x hacker
    id          : 9496
    platform    : windows
    date        : 24.08.2009
    type        : dos
    port        : 0


#>
function Search-ShodanExploitDB
{
    [CmdletBinding()]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true)]
        [string]$Query,

        [ValidateSet('aix', 'asp', 'bsd', 'bsd/ppc', 'bsd/x86','bsdi/x86','cgi',
        'freebsd','freebsd/x86','freebsd/x86-64','generator','hardware', 'hp-ux', 
        'irix', 'jsp', 'linux', 'linux/amd64', 'linux/mips', 'linux/ppc', 'linux/sparc', 
        'linux/x86', 'linux/x86-64', 'minix', 'multiple', 'netbsd/x86', 'novell', 'openbsd', 
        'openbsd/x86', 'os-x/ppc', 'osx', 'php','plan9', 'qnx', 'sco', 'sco/x86', 
        'solaris', 'solaris/sparc', 'solaris/x86', 'tru64', 'ultrix', 'unix', 'unixware',
        'win32','win64','windows','arm','cfm')]
        [string]$Platform,

        # Param2 help description
        [ValidateSet('Local', 'Papers', 'Remote', 'Shellcode', 'WebApps', 'DoS')]
        [string]$Type,

        [Parameter(Mandatory=$false)]
        [int]$Port,

        [Parameter(Mandatory=$false)]
        [string]$Author,

        [Parameter(Mandatory=$false)]
        [string]$OSVDB,

        [Parameter(Mandatory=$false)]
        [string]$CVE,

        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    Begin
    {
       
       $URI = "http://www.shodanhq.com/api/exploitdb/search"
    }
    Process
    {
        $QueryParams = @{'q' = $Query; 'key'= $APIKey}
        if ($Platform)
        {
            $QueryParams.Add('platform',$Platform.ToLower())
        }

        if ($Port)
        {
            $QueryParams.add('port',$Port)
        }

        if ($Author)
        {
            $QueryParams.Add('author',"`"$($Author)`"")
        }

        if ($Type)
        {
            $QueryParams.add('type',$Type.ToLower())
        }

        if ($CVE)
        {
            $QueryParams.Add('cve', $CVE)
        }

        if ($OSVDB)
        {
            $QueryParams.Add('osvdb', $OSVDB)
        }

        $result = Invoke-RestMethod -Uri $URI -Method Get -Body $QueryParams
        $result.pstypenames.insert(0,'Shodan.ExploitDB.Search')
        $result
    }
    End
    {
    }
}


<#
.Synopsis
   Search Metasploit
.DESCRIPTION
   Searches Metasploit for modules that match a given query.
.EXAMPLE
    $msfres = Search-ShodanMSF -Query "RDP" -APIKey $apikey

    PS C:\> $msfres

    matches                                                                                                              total
    -------                                                                                                              -----
    {@{description=This module dumps MRU and connection data f...                                                            6



    PS C:\> $msfres.matches


    description : This module dumps MRU and connection data for RDP sessions
    rank        : normal
    platforms   : {Windows}
    references  : {}
    authors     : {Rob Fuller <mubix@hak5.org>}
    arch        : 
    name        : Windows Gather Terminal Server Client Connection Information Dumper
    alias       : 
    version     : 14774
    fullname    : post/windows/gather/enum_termserv
    type        : post
    privileged  : False

    description : This module enables the Remote Desktop Service. It provides the options to create
                                      a Account and configure such account to be a member of the Local Administrator and
                                      Remote Desktop Users group. It can also Fordward the targets 3389 Port.
    rank        : normal
    platforms   : {Windows}
    references  : {}
    authors     : {Carlos Perez <carlos_perez@darkoperator.com>}
    arch        : 
    name        : Microsoft Windows Enable Remote Desktop
    alias       : 
    version     : $Revision$
    fullname    : post/windows/manage/enable_rdp
    type        : post
    privileged  : False

    description : This module extracts saved passwords
                                          from mRemote. mRemote stores connections for
                                          RDP,VNC,SSH,Telnet,Rlogin and others. It saves
                                          the passwords in an encrypted format. The module
                                          will extract the connection info and decrypt
                                          the saved passwords.
    rank        : normal
    platforms   : {Windows}
    references  : {}
    authors     : {TheLightCosine <thelightcosine@gmail.com>, hdm <hdm@metasploit.com>, Rob Fuller <mubix@hak5.org>}
    arch        : 
    name        : Windows Gather mRemote Saved Password Extraction
    alias       : 
    version     : 12877
    fullname    : post/windows/gather/enum_mremote_pwds
    type        : post
    privileged  : False

    description : This module exploits the MS12-020 RDP vulnerability originally discovered and
                                  reported by Luigi Auriemma.  The flaw can be found in the way the T.125
                                  ConnectMCSPDU packet is handled in the maxChannelIDs field, which will result
                                  an invalid pointer being used, therefore causing a denial-of-service condition.
    rank        : normal
    platforms   : {}
    references  : {CVE 2012-0002, MSB MS12-020, URL http://www.privatepaste.com/ffe875e04a, URL 
                  http://pastie.org/private/4egcqt9nucxnsiksudy5dw...}
    authors     : {Luigi Auriemma, Daniel Godas-Lopez, Alex Ionescu, jduck <jduck@metasploit.com>...}
    arch        : 
    name        : MS12-020 Microsoft Remote Desktop Use-After-Free DoS
    alias       : 
    version     : 0
    fullname    : auxiliary/dos/windows/rdp/ms12_020_maxchannelids
    type        : auxiliary
    privileged  : False

    description : This module exploits a stack-based buffer overflow in the Cain & Abel v4.9.24
                                  and below. An attacker must send the file to victim, and the victim must open
                                  the specially crafted RDP file under Tools -> Remote Desktop Password Decoder.
    rank        : good
    platforms   : {Windows}
    references  : {CVE 2008-5405, OSVDB 50342, URL http://www.milw0rm.com/exploits/7329, BID 32543}
    authors     : {Trancek <trancek@yashira.org>}
    arch        : 
    name        : Cain & Abel <= v4.9.24 RDP Buffer Overflow
    alias       : 
    version     : 11127
    fullname    : exploit/windows/fileformat/cain_abel_4918_rdp
    type        : exploit
    privileged  : False

    description : This module extracts saved passwords from mRemote. mRemote stores
                                          connections for RDP, VNC, SSH, Telnet, rlogin and other protocols. It saves
                                          the passwords in an encrypted format. The module will extract the connection
                                          info and decrypt the saved passwords.
    rank        : normal
    platforms   : {Windows}
    references  : {}
    authors     : {TheLightCosine <thelightcosine@gmail.com>, hdm <hdm@metasploit.com>, Rob Fuller <mubix@hak5.org>}
    arch        : 
    name        : Windows Gather mRemote Saved Password Extraction
    alias       : 
    version     : 13512
    fullname    : post/windows/gather/credentials/mremote
    type        : post
    privileged  : False
#>
function Search-ShodanMSF
{
    [CmdletBinding()]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true)]
        [string]$Query,
        
        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    Begin
    {
        $URI = "http://www.shodanhq.com/api/msf/search"
    }
    Process
    {
        $result = Invoke-RestMethod -Uri $URI -Method Get -Body @{'q'= $Query;'key'= $APIKey}
        $result.pstypenames.insert(0,'Shodan.MSF.Search')
        $result
    }
    End
    {
    }
}


<#
.Synopsis
   Performs a Search of the Shodan Database
.DESCRIPTION
   Performs a Search of the Shodan Database. All filtering advanced parameters are available
   as options to make advancd searches and filtering simpler. Some filtering Options depend on 
   API license level. More information on filter use can be found at http://www.shodanhq.com/help/filters
.EXAMPLE
    (Search-Shodan -APIKey $apikey -Query "cisco" -City "Buenos Aires").matches | where {$_.data -like "*level_15_access*"} 

   Find all Cisco Routers in Buenos Aires that allow login via web with level 15 privilages
.LINK
    http://www.darkoperator.com
    http://www.shodanhq.com/help/filters
#>
function Search-Shodan
{
    [CmdletBinding()]

    Param
    (
        # Text to query for.
        [Parameter(Mandatory=$false)]
        [string]$Query,

        # Shodan API Key
        [Parameter(Mandatory=$true)]
        [string]$APIKey,
        #  Find devices located in the given city. It's best combined with the 'Country' filter to make sure you get the city in the country you want (city names are not always unique).
        [Parameter(Mandatory=$false)]
        [string]$City,

        # Narrow results down by country.
        [Parameter(Mandatory=$false)]
        [string]$Country,

        # Latitude and longitude.
        [Parameter(Mandatory=$false)]
        [string]$Geo,

        # Search for hosts that contain the value in their hostname.
        [Parameter(Mandatory=$false)]
        [string]$Hostname,
        
        # Limit the search results to a specific IP or subnet. It uses CIDR notation to designate the subnet range.
        [Parameter(Mandatory=$false)]
        [string]$Net,

        # Specific operating systems. Common possible values are: windows, linux and cisco.
        [Parameter(Mandatory=$false)]
        [string]$OS,

        # Port number  to narrow the search to specific services.
        [Parameter(Mandatory=$false)]
        [string]$Port,

        # Limit search for data that was collected before the given date in format day/month/year.
        [Parameter(Mandatory=$false)]
        [string]$Before,

        # Limit search for data that was collected after the given date in format day/month/year.
        [Parameter(Mandatory=$false)]
        [string]$After,

        # Search based on the SSL certificate version
        [Parameter(Mandatory=$false)]
        [Validateset('SSLv2', 'Original', 'SSLv3', 'TLSv1')]
        [string]$CertVersion,

        # Search based on the SSL certificate public key bit length
        [Parameter(Mandatory=$false)]
        [Validateset('ADH-AES128-SHA', 'ADH-AES256-SHA', 'ADH-DES-CBC-SHA', 'ADH-DES-CBC3-SHA', 'ADH-RC4-MD5',
        'AES128-SHA','AES256-SHA','DES-CBC-MD5','DES-CBC-SHA','DES-CBC3-MD5','DES-CBC3-SHA','DHE-DSS-AES128-SHA',
        'DHE-DSS-AES256-SHA','DHE-RSA-AES128-SHA','DHE-RSA-AES256-SHA','EDH-DSS-DES-CBC-SHA','EDH-DSS-DES-CBC3-SHA',
        'EDH-RSA-DES-CBC-SHA','EDH-RSA-DES-CBC3-SHA','EXP-ADH-DES-CBC-SHA','EXP-ADH-RC4-MD5','EXP-DES-CBC-SHA',
        'EXP-EDH-DSS-DES-CBC-SHA','EXP-EDH-RSA-DES-CBC-SHA','EXP-RC2-CBC-MD5','EXP-RC4-MD5','NULL-MD5','NULL-SHA',
        'RC2-CBC-MD5','RC4-MD5','RC4-SHA')]
        [string]$CipherName,

        # Accepted ciphers the server allows using the cipher bit length
        [Parameter(Mandatory=$false)]
        [Validateset(0, 40, 56, 128, 168, 256)]
        [int]$CipherBits,

        # Filter based on the accepted ciphers the server allows using the cipher protoco
        [Parameter(Mandatory=$false)]
        [Validateset('SSLv2','SSLv3', 'TLSv1')]
        [string]$CipherProtocol,

        # Information about the organisation that issued the SSL certificate.
        [Parameter(Mandatory=$false)]
        [string]$CertIssuer,

        # Information about the organisation receiving the SSL certificate.
        [Parameter(Mandatory=$false)]
        [string]$CertSubject,

        # Search based on the SSL certificate public key bit length.
        [Parameter(Mandatory=$false)]
        [int]$CertBits,

        # Page number of the search results
        [Parameter(Mandatory=$false)]
        [int]$Page = 1,

        # number of results to return
        [Parameter(Mandatory=$false)]
        [int]$Limit
    )
        

    Begin
    {
        $CertVersionList = @{
            'Original' = 0
            'SSLv2' = 1
            'SSLv3' = 2
            'TLSv1' = 3
        }

        if ($City)
        {
            $Query += " city:'$($City.Trim())'"   
        }

        if ($Country)
        {
            $Query += " country_name:$($Country.Trim())"   
        }

        if ($Geo)
        {
            $Query += " geo:$($Geo.Trim())"   
        }

        if ($Hostname)
        {
            $Query += " hostname:$($Hostname.Trim())"   
        }

        if ($Net)
        {
            $Query += " net:$($Net.Trim())"   
        }

        if ($OS)
        {
            $Query += " os:$($OS.Trim())"   
        }

        if ($Port)
        {
            $Query += " port:$($Port.Trim())"   
        }

        if ($Before)
        {
            $Query += " before:$($Before.Trim())"   
        }

        if ($After)
        {
            $Query += " after:$($After.Trim())"   
        }

        if ($CertVersion)
        {
            $Query += " cert_version:$($CertVersionList.get_item($CertVersion))"   
        }

        if ($CertBits)
        {
            $Query += " cert_bits:$($CertBits)"   
        }

        if ($CertIssuer)
        {
            $Query += " cert_issuer:'$($CertIssuer)'"   
        }

        if ($CertSubject)
        {
            $Query += " cert_subject:'$($CertSubject)'"   
        }

        if ($CipherName)
        {
            $Query += " cipher_name:'$($CipherName)'"   
        }

        if ($CipherBits)
        {
            $Query += " cipher_bits:'$($CipherBits)'"   
        }

        if ($CipherProtocol)
        {
            $Query += " cipher_protocol:'$($CipherProtocol)'"   
        }

        $URI = 'http://www.shodanhq.com/api/search'
    }
    Process
    {
        $Params = @{q = $Query; p = $Page; 'key'= $APIKey}
        if ($limit)
        {
            $Params.add('l',$Limit)
        }

        $result = Invoke-RestMethod -Uri $URI -Method Get -Body $Params
        $result.pstypenames.insert(0,'Shodan.General.Search')
        $result
    }
    End
    {
    }
}