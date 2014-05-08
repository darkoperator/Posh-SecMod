<#
.Synopsis
   Perform Whois Query
.DESCRIPTION
   Performs a Whois query for a given Domain.
.EXAMPLE
   Perfrom a whois query for google.com

   PS C:\> Get-Whois google.com

#>
function Get-Whois
{
    [CmdletBinding(DefaultParameterSetName="Domain")]
    
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ParameterSetName = "Domain",
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$Domain

        #[string]$IPAddress
    )

    Begin
    {
        # Need to generate hash from http://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xml,
        # http://www.iana.org/assignments/ipv6-address-space
        # http://www.iana.org/assignments/multicast-addresses
    }
    Process
    {
        if ($Domain)
        {
            [WebTools.Whois]::lookup($Domain, [WebTools.Whois+RecordType]::domain)
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Enumerates all mDNS records in the local subnet.
.DESCRIPTION
   Unsing mDNS the function qill query and resolve all mDNS records for
   devices advertising on the local subnet.
.EXAMPLE
   Shows only the A and AAAA Records for hosts in the local subnet

   Get-MDNSRecords | where recordtype -like "A*"

.EXAMPLE
   Show only HTTP servers in the local subnet

   Get-MDNSRecords | where name -like "*_http._tcp*"
#>
function Get-MDNSRecords
{
    [CmdletBinding()]
    param()
    $mdns = new-object -typename ARSoft.Tools.Net.Dns.MulticastDnsOneShotClient -ArgumentList 4
    $records = $mdns.Resolve("_services._dns-sd._udp.local",[ARSoft.Tools.Net.Dns.RecordType]::Any)
    $doms = @();
    $records| sort -Unique | foreach-object {
        $_.answerrecords| foreach {
            Write-Verbose $_.PointerDomainName
            $doms += $_.PointerDomainName
        }
    }
    $results = @()
    $doms | foreach-object {
        Write-Verbose "Resolving $($_)"
        $queryres = $mdns.Resolve($_,[ARSoft.Tools.Net.Dns.RecordType]::Ptr)
        $results += $queryres.answerrecords
        $results += $queryres.additionalrecords
        
    }
    $results | sort -Unique 
}



<#
.Synopsis
    Generates a IP Address Objects for IPv4 and IPv6 Ranges.
.DESCRIPTION
    Generates a IP Address Objects for IPv4 and IPv6 Ranges given a ranges in CIDR or
    range <StartIP>-<EndIP> format.
.EXAMPLE
    PS C:\> New-IPvRange -Range 192.168.1.1-192.168.1.5

    Generate a collection of IPv4 Object collection for the specified range.

.EXAMPLE
   New-IPRange -Range 192.168.1.1-192.168.1.50 | select -ExpandProperty ipaddresstostring

   Get a list of IPv4 Addresses in a given range as a list for use in another tool.
#>
function New-IPRange
{
    [CmdletBinding(DefaultParameterSetName="CIDR")]
    Param(
        [parameter(Mandatory=$true,
        ParameterSetName = "CIDR",
        Position=0)]
        [string]$CIDR,

        [parameter(Mandatory=$true,
        ParameterSetName = "Range",
        Position=0)]
        [string]$Range   
    )
    if($CIDR)
    {
        $IPPart,$MaskPart = $CIDR.Split("/")
        $AddressFamily = ([System.Net.IPAddress]::Parse($IPPart)).AddressFamily

        # Get the family type for the IP (IPv4 or IPv6)
        $subnetMaskObj = [IPHelper.IP.Subnetmask]::Parse($MaskPart, $AddressFamily)
        
        # Get the Network and Brodcast Addressed
        $StartIP = [IPHelper.IP.IPAddressAnalysis]::GetClasslessNetworkAddress($IPPart, $subnetMaskObj)
        $EndIP = [IPHelper.IP.IPAddressAnalysis]::GetClasslessBroadcastAddress($IPPart,$subnetMaskObj)
        
        # Ensure we do not list the Network and Brodcast Address
        $StartIP = [IPHelper.IP.IPAddressAnalysis]::Increase($StartIP)
        $EndIP = [IPHelper.IP.IPAddressAnalysis]::Decrease($EndIP)
        [IPHelper.IP.IPAddressAnalysis]::GetIPRange($StartIP, $EndIP)
    }
    elseif ($Range)
    {
        $StartIP, $EndIP = $range.split("-")
        [IPHelper.IP.IPAddressAnalysis]::GetIPRange($StartIP, $EndIP)
    }
}


<#
.Synopsis
    Generates a list of IPv4 IP Addresses given a Start and End IP.
.DESCRIPTION
    Generates a list of IPv4 IP Addresses given a Start and End IP.
.EXAMPLE
    Generating a list of IPs from CIDR

    Get-IPRange 192.168.1.0/24
    
.EXAMPLE
    Generating a list of IPs from Range

    Get-IPRange -Range 192.168.1.1-192.168.1.50
#>
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


<#
.Synopsis
    Generates a list of IPv4 IP Addresses given a CIDR.
.DESCRIPTION
    Generates a list of IPv4 IP Addresses given a CIDR.
.EXAMPLE
    Generating a list of IPs
    PS C:\> New-IPv4RangeFromCIDR -Network 192.168.1.0/29
    192.168.1.1
    192.168.1.2
    192.168.1.3
    192.168.1.4
    192.168.1.5
    192.168.1.6
    192.168.1.7
#>
function New-IPv4RangeFromCIDR 
{
    param(
		[Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
				   $Network
    )
    # Extract the portions of the CIDR that will be needed
    $StrNetworkAddress = ($Network.split("/"))[0]
    [int]$NetworkLength = ($Network.split("/"))[1]
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
    New-IPv4Range $StartIP $EndIP
}


<#
.Synopsis
   Performs a DNS Reverse Lookup of a given IPv4 IP Range.
.DESCRIPTION
   Performs a DNS Reverse Lookup of a given IPv4 IP Range.
.EXAMPLE
   Perfrom a threaded reverse lookup against a given CIDR

   PS C:\> Invoke-ReverseDNSLookup -CIDR 192.168.1.0/24

.EXAMPLE
   Perfrom a reverse lookup against a given range given the start and end IP Addresses

   PS C:\> Invoke-ReverseDNSLookup -Range 192.168.1.1-192.168.1.20
#>
function Invoke-ReverseDNSLookup
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ParameterSetName = "Range",
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$Range,

        [Parameter(Mandatory=$true,
                   ParameterSetName = "CIDR",
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$CIDR,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$MaxThreads=30,
        [Parameter(
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [int]$TimeOut = 200
    )

    Begin
    {
        # Manage if range is given
        if ($Range)
        {
            $rangeips = $Range.Split("-")
            $targets = New-IPv4Range -StartIP $rangeips[0] -EndIP $rangeips[1]
        }

        # Manage if CIDR is given
        if ($CIDR)
        {
            $targets = New-IPv4RangeFromCIDR -Network $CIDR
        }
    }
    Process
    {
        $RvlScripBlock = {
            param($ip)
            try {
            [System.Net.Dns]::GetHostEntry($ip)
            }
            catch {}
        }

        #Multithreading setup

        # create a pool of maxThread runspaces   
        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)   
        $pool.Open()
  
        $jobs = @()   
        $ps = @()   
        $wait = @()

        $i = 0

        # How many servers
        $record_count = $targets.Length

        #Loop through the endpoints starting a background job for each endpoint
        foreach ($ip in $targets)
        {
            Write-Verbose $ip
            # Show Progress
            $record_progress = [int][Math]::Ceiling((($i / $record_count) * 100))
            Write-Progress -Activity "Performing DNS Reverse Lookup Discovery" -PercentComplete $record_progress -Status "Reverse Lookup - $record_progress%" -Id 1;

            while ($($pool.GetAvailableRunspaces()) -le 0) 
            {
                Start-Sleep -milliseconds 500
            }
    
            # create a "powershell pipeline runner"   
            $ps += [powershell]::create()

            # assign our pool of 3 runspaces to use   
            $ps[$i].runspacepool = $pool

            # command to run
            [void]$ps[$i].AddScript($RvlScripBlock).AddParameter('ip', $ip)
            #[void]$ps[$i].AddParameter('ping', $ping)
    
            # start job
            $jobs += $ps[$i].BeginInvoke();
     
            # store wait handles for WaitForAll call   
            $wait += $jobs[$i].AsyncWaitHandle
    
            $i++
        }

        $waitTimeout = get-date

        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(get-date) - $waitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            } 
  
        # end async call   
        for ($y = 0; $y -lt $i; $y++) {     
  
            try 
            {   
                # complete async job   
                $ScanResults += $ps[$y].EndInvoke($jobs[$y])   
  
            } 
            catch 
            {   
       
                # oops-ee!   
                write-warning "error: $_"  
            }
    
            finally 
            {
                $ps[$y].Dispose()
            }    
        }

        $pool.Dispose()
    }

    end
    {
        $ScanResults
    }
}


<#
.Synopsis
   Performs a Ping Scan against a given range of IPv4 IP addresses.
.DESCRIPTION
   Performs a Ping Scan against a given range of IPv4 IP addresses by sending
   ICMP Echo Packets.
.EXAMPLE
   Perform Ping Scan against a given range in CIDR format

   PS C:\> Invoke-PingScan -CIDR 192.168.1.0/24 
.EXAMPLE
   Perform Ping Scan against a given range given the start and end IP Addresses

   PS C:\> Invoke-PingScan -Range 192.168.1.1-192.168.1.10
#>
function Invoke-PingScan
{
    [CmdletBinding()]
    Param
    (
        # IP Range to perform ping scan against.
        [Parameter(Mandatory=$true,
                   ParameterSetName = "Range",
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$Range,

        # IP CIDR to perform ping scan against.
        [Parameter(Mandatory=$true,
                   ParameterSetName = "CIDR",
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$CIDR,

        # Number of concurrent threads to execute
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [string]$MaxThreads=10,

        # Timeout in miliseconds for the ICMP Echo request.
        [Parameter(ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [int]$TimeOut = 200
    )

    Begin
    {
        # Manage if range is given
        if ($Range)
        {
            $rangeips = $Range.Split("-")
            $targets = New-IPv4Range -StartIP $rangeips[0] -EndIP $rangeips[1]
        }

        # Manage if CIDR is given
        if ($CIDR)
        {
            $targets = New-IPv4RangeFromCIDR -Network $CIDR
        }
    }
    Process
    {
        $PingScripBlock = {
            param($ip, $TimeOut)
            $ping = New-Object System.Net.NetworkInformation.Ping
            $result = $ping.Send($ip, $TimeOut)
            if ($result.Status -eq 'success')
            {
                new-object psobject -Property @{Address = $result.Address; Time = $result.RoundtripTime}
            }
        }

        #Multithreading setup

        # create a pool of maxThread runspaces   
        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)   
        $pool.Open()
  
        $jobs = @()   
        $ps = @()   
        $wait = @()

        $i = 0

        # How many servers
        $record_count = $targets.Length

        #Loop through the endpoints starting a background job for each endpoint
        foreach ($ip in $targets)
        {
            Write-Verbose $ip
            # Show Progress
            $record_progress = [int][Math]::Ceiling((($i / $record_count) * 100))
            Write-Progress -Activity "Performing Ping Discovery" -PercentComplete $record_progress -Status "Pinged Host - $record_progress%" -Id 1;

            while ($($pool.GetAvailableRunspaces()) -le 0) {
                Start-Sleep -milliseconds 500
            }
    
            # create a "powershell pipeline runner"   
            $ps += [powershell]::create()
   
            $ps[$i].runspacepool = $pool

            # command to run
            [void]$ps[$i].AddScript($PingScripBlock).AddParameter('ip', $ip).AddParameter('Timeout', $TimeOut)
    
            # start job
            $jobs += $ps[$i].BeginInvoke();
     
            # store wait handles for WaitForAll call   
            $wait += $jobs[$i].AsyncWaitHandle
    
            $i++
        }

        write-verbose "Waiting for scanning threads to finish..."

        $waitTimeout = get-date

        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(get-date) - $waitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            } 
  
        # end async call   
        for ($y = 0; $y -lt $i; $y++) {     
  
            try {   
                # complete async job   
                $ScanResults += $ps[$y].EndInvoke($jobs[$y])   
  
            } catch {
                write-warning "error: $_"  
            }
    
            finally {
                $ps[$y].Dispose()
            }    
        }

        $pool.Dispose()
    }

    end
    {
        $ScanResults
    }
}


<#
.Synopsis
   Performs full TCP Connection and UDP port scan.
.DESCRIPTION
   Performs full TCP Connection and UDP port scan against a given host 
   or range of IPv4 addresses.
.EXAMPLE
   Perform TCP Scan of known ports against a host
   
    PS C:\> Invoke-PortScan -Target 172.20.10.3 -Ports 22,135,139,445 -Type TCP

    Host                                                 Port State                        Type                        
    ----                                                 ---- -----                        ----                        
    172.20.10.3                                           135 Open                         TCP                         
    172.20.10.3                                           139 Open                         TCP                         
    172.20.10.3                                           445 Open                         TCP                         

#>
function Invoke-PortScan
{
    [CmdletBinding()]
   
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ParameterSetName = "SingleIP",
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [Alias("IPAddress,Host")]
        [string]$Target,

        [Parameter(Mandatory=$true,
                   ParameterSetName = "Range",
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$Range,

        [Parameter(Mandatory=$true,
                   ParameterSetName = "CIDR",
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$CIDR,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$false,
                   Position=1)]
        [int32[]]$Ports,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$false,
                   Position=2)]
        [ValidateSet("TCP", "UDP")]
        [String[]]$Type,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$false,
                   Position=3)]
        [ValidateSet("TCP", "UDP")]
        [int32]$Timeout=100


    )

    Begin
    {
        # Expand the needed address ranges
        if ($Range)
        {
            $rangeips = $Range.Split("-")
            $targets = New-IPv4Range -StartIP $rangeips[0] -EndIP $rangeips[1]
        }

        # Expnd CIDR
        if ($CIDR)
        {
            $targets = New-IPv4RangeFromCIDR -Network $CIDR
        }

        # Manage single target
        if ($Target)
        {
            $targets = @($Target)
        }
        
        # Set the default ports

    }
    Process
    {
        foreach ($t in $Type)
        {
            if ($t -eq "TCP")
            {
                foreach ($ip in $targets)
                {
                    foreach($p in $Ports)
                    {
                        try
                        {
                            $TcpSocket = new-object System.Net.Sockets.TcpClient
                            #$TcpSocket.client.ReceiveTimeout = $Timeout
                            # Connect to target host and port
                            $TcpSocket.Connect($ip, $p)
                            $ScanPortProps = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
                            $ScanPortProps.Add("Host",$ip)
                            $ScanPortProps.Add("Port",$p)
                            $ScanPortProps.Add("State","Open")
                            $ScanPortProps.Add("Type","TCP")
                            $scanport = New-Object psobject -Property $ScanPortProps

                            # Close Connection
                            $tcpsocket.Close()
                            $scanport
                        }
                        catch
                        { 
                            Write-Verbose "Port $p is closed"
                        }
                    }
                }
            }
            elseif ($t -eq "UDP")
            {
                foreach ($ip in $targets)
                {
                    foreach($p in $Ports)
                    {
                   
                        $UDPSocket = new-object System.Net.Sockets.UdpClient
                        $UDPSocket.client.ReceiveTimeout = $Timeout
                        $UDPSocket.Connect($ip,$p)

                        $data = New-Object System.Text.ASCIIEncoding
                        $byte = $data.GetBytes("$(Get-Date)")

                        #Send the data to the endpoint
                        [void] $UDPSocket.Send($byte,$byte.length)

                        #Create a listener to listen for response
                        $Endpoint = New-Object System.Net.IPEndPoint([system.net.ipaddress]::Any,0)

                        try 
                        {
                            #Attempt to receive a response indicating the port was open
                            $receivebytes = $UDPSocket.Receive([ref] $Endpoint)
                            [string] $returndata = $data.GetString($receivebytes)
                            $ScanPortProps = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
                            $ScanPortProps.Add("Host",$ip)
                            $ScanPortProps.Add("Port",$p)
                            $ScanPortProps.Add("State","Open")
                            $ScanPortProps.Add("Type","UDP")
                            $scanport = New-Object psobject -Property $ScanPortProps
                            $scanport
                        }
            
                        catch 
                        {
                            #Timeout or connection refused
                            Write-Verbose "Port $p is closed"
                        }

                        finally 
                        {
                            #Cleanup
                            $UDPSocket.Close()
                        }
  
                    }
                }
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Performs an ARP scan against a given range of IPv4 IP Addresses.
.DESCRIPTION
   Performs an ARP scan against a given range of IPv4 IP Addresses.
.EXAMPLE
   Invoke an ARP Scan against a range of IPs specified in CIDR Format

    PS C:\> Invoke-ARPScan -CIDR 172.20.10.1/24

    MAC                                                       Address                                                  
    ---                                                       -------                                                  
    14:10:9F:D5:1A:BF                                         172.20.10.2                                              
    00:0C:29:93:10:B5                                         172.20.10.3                                              
    00:0C:29:93:10:B5                                         172.20.10.15  
#>
function Invoke-ARPScan {

    param (
        [Parameter(Mandatory=$true,
                   ParameterSetName = "Range",
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$Range,

        [Parameter(Mandatory=$true,
                   ParameterSetName = "CIDR",
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$CIDR,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$MaxThreads=50
    )


    Begin 
    {
$sign = @"
using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

public static class NetUtils
{
    [System.Runtime.InteropServices.DllImport("iphlpapi.dll", ExactSpelling = true)]
    static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref int PhyAddrLen);

    public static string GetMacAddress(String addr)
    {
        try
                {                   
                    IPAddress IPaddr = IPAddress.Parse(addr);
                   
                    byte[] mac = new byte[6];
                    
                    int L = 6;
                    
                    SendARP(BitConverter.ToInt32(IPaddr.GetAddressBytes(), 0), 0, mac, ref L);
                    
                    String macAddr = BitConverter.ToString(mac, 0, L);
                    
                    return (macAddr.Replace('-',':'));
                }

                catch (Exception ex)
                {
                    return (ex.Message);              
                }
    }
}
"@
        try
        {
            Write-Verbose "Instanciating NetUtils"
            $IPHlp = Add-Type -TypeDefinition $sign -Language CSharp -PassThru
        }
        catch
        {
            Write-Verbose "NetUtils already instanciated"
        }

        # Manage if range is given
        if ($Range)
        {
            $rangeips = $Range.Split("-")
            $targets = New-IPv4Range -StartIP $rangeips[0] -EndIP $rangeips[1]
        }

        # Manage if CIDR is given
        if ($CIDR)
        {
            $targets = New-IPv4RangeFromCIDR -Network $CIDR
        }
    }
    Process 
    {


        $scancode = {
            param($IPAddress,$IPHlp)
            $result = $IPHlp::GetMacAddress($IPAddress)
            if ($result) {New-Object psobject -Property @{Address = $IPAddress; MAC = $result}}
        } # end ScanCode var

        $jobs = @()

    

        $start = get-date
        write-verbose "Begin Scanning at $start"

        #Multithreading setup

        # create a pool of maxThread runspaces   
        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)   
        $pool.Open()
  
        $jobs = @()   
        $ps = @()   
        $wait = @()

        $i = 0

        # How many servers
        $record_count = $targets.Length

        #Loop through the endpoints starting a background job for each endpoint
        foreach ($IPAddress in $targets)
        {
            # Show Progress
            $record_progress = [int][Math]::Ceiling((($i / $record_count) * 100))
            Write-Progress -Activity "Performing ARP Scan" -PercentComplete $record_progress -Status "Addresses Queried - $record_progress%" -Id 1;

            while ($($pool.GetAvailableRunspaces()) -le 0) 
            {
                Start-Sleep -milliseconds 500
            }
    
            # create a "powershell pipeline runner"
            $ps += [powershell]::create()

            # assign our pool of 3 runspaces to use   
            $ps[$i].runspacepool = $pool

            # command to run
            [void]$ps[$i].AddScript($scancode).AddParameter('IPaddress', $IPAddress).AddParameter('IPHlp', $IPHlp)
            #[void]$ps[$i].AddParameter()
    
            # start job
            $jobs += $ps[$i].BeginInvoke();
     
            # store wait handles for WaitForAll call   
            $wait += $jobs[$i].AsyncWaitHandle
    
            $i++
        }

        write-verbose "Waiting for scanning threads to finish..."

        $waitTimeout = get-date

        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(get-date) - $waitTimeout).totalSeconds) -gt 60) 
        {
                Start-Sleep -milliseconds 500
        } 
  
        # end async call   
        for ($y = 0; $y -lt $i; $y++) {     
  
            try 
            {   
                # complete async job   
                $ScanResults += $ps[$y].EndInvoke($jobs[$y])   
  
            } 
            catch 
            {   
       
                write-warning "error: $_"  
            }
    
            finally 
            {
                $ps[$y].Dispose()
            }    
        }

        $pool.Dispose()
    }

    end
    {
        $ScanResults
    }
}


<#
.Synopsis
   Enumerates the DNS Servers used by a system
.DESCRIPTION
   Enumerates the DNS Servers used by a system returning an IP Address .Net object for each.
.EXAMPLE
   C:\> Get-SystemDNSServer


    Address            : 16885952
    AddressFamily      : InterNetwork
    ScopeId            :
    IsIPv6Multicast    : False
    IsIPv6LinkLocal    : False
    IsIPv6SiteLocal    : False
    IsIPv6Teredo       : False
    IsIPv4MappedToIPv6 : False
    IPAddressToString  : 192.168.1.1
#>

function Get-SystemDNSServer
{
    $DNSServerAddresses = @()
    $interfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
    foreach($interface in $interfaces)
    {
        if($interface.OperationalStatus -eq "Up")
        {
            $DNSConfig = $interface.GetIPProperties().DnsAddresses
            if (!$DNSConfig.IsIPv6SiteLocal)
            {
                $DNSServerAddresses += $DNSConfig
            }
        }
    }
    $DNSServerAddresses
}


<#
.Synopsis
   Enumerates common DNS SRV Records for a given domain.
.DESCRIPTION
   Enumerates common DNS SRV Records for a given domain.
.EXAMPLE
   PS C:\> Invoke-EnumSRVRecords -Domain microsoft.com


    Type     : SRV
    Name     : _sip._tls.microsoft.com
    Port     : 443
    Priority : 0
    Target   : sip.microsoft.com.
    Address   : @{Name=sip.microsoft.com; Type=A; Address=65.55.30.130}

    Type     : SRV
    Name     : _sipfederationtls._tcp.microsoft.com
    Port     : 5061
    Priority : 0
    Target   : sipfed.microsoft.com.
    Address   : @{Name=sipfed.microsoft.com; Type=A; Address=65.55.30.130}

    Type     : SRV
    Name     : _xmpp-server._tcp.microsoft.com
    Port     : 5269
    Priority : 0
    Target   : sipdog3.microsoft.com.
    Address   : @{Name=sipdog3.microsoft.com; Type=A; Address=131.107.1.47}
#>

function Invoke-EnumSRVRecords
{
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [string]$NameServer,

        [Parameter(Mandatory = $false)]
        [int32]$TimeOut,

        [Parameter(Mandatory = $false)]
        [int32]$Retries
        )
    Begin 
    {
        
        # Records to test against
        $srv_rcds = @('_gc._tcp.', '_kerberos._tcp.', '_kerberos._udp.', '_ldap._tcp.',
        '_test._tcp.', '_sips._tcp.', '_sip._udp.', '_sip._tcp.', '_aix._tcp.',
        '_aix._tcp.', '_finger._tcp.', '_ftp._tcp.', '_http._tcp.', '_nntp._tcp.',
        '_telnet._tcp.', '_whois._tcp.', '_h323cs._tcp.', '_h323cs._udp.',
        '_h323be._tcp.', '_h323be._udp.', '_h323ls._tcp.', '_https._tcp.',
        '_h323ls._udp.', '_sipinternal._tcp.', '_sipinternaltls._tcp.',
        '_sip._tls.', '_sipfederationtls._tcp.', '_jabber._tcp.',
        '_xmpp-server._tcp.', '_xmpp-client._tcp.', '_imap.tcp.',
        '_certificates._tcp.', '_crls._tcp.', '_pgpkeys._tcp.',
        '_pgprevokations._tcp.', '_cmp._tcp.', '_svcp._tcp.', '_crl._tcp.',
        '_ocsp._tcp.', '_PKIXREP._tcp.', '_smtp._tcp.', '_hkp._tcp.',
        '_hkps._tcp.', '_jabber._udp.', '_xmpp-server._udp.', '_xmpp-client._udp.',
        '_jabber-client._tcp.', '_jabber-client._udp.', '_kerberos.tcp.dc._msdcs.',
        '_ldap._tcp.ForestDNSZones.', '_ldap._tcp.dc._msdcs.', '_ldap._tcp.pdc._msdcs.',
        '_ldap._tcp.gc._msdcs.', '_kerberos._tcp.dc._msdcs.', '_kpasswd._tcp.', '_kpasswd._udp.',
        '_imap._tcp.')

        $dnsopts = new-object JHSoftware.DnsClient+RequestOptions
        # Set the NS Server if one givem
        if ($nameserver)
        {
            try
            {
                # Check if what we got is an IP or a FQDN
                $IPObj = [Net.IPAddress]::Parse($nameserver)
                $IPCheck = [System.Net.IPAddress]::TryParse($nameserver,[ref]$IPObj)
                if ($IPCheck)
                {
                    $dns = [System.Net.IPAddress]$nameserver
                    $dnsopts.DnsServers += $dns
                }
                else
                {
                    Write-Error "$nameserver is not a valid IP Address"
                }
            }

            catch
            {
                $nsip = [Net.Dns]::GetHostAddresses($nameserver)[0]
                $dns = $nsip
                $dnsopts.DnsServers += $dns
            }
         }
         # Set the timeout
         if ($TimeOut)
         {
            $dnsopts.TimeOut = New-TimeSpan -Seconds $TimeOut
         }

         # Set Retries
         if ($Retries)
         {
            $dnsopts.RetryCount = $Retries
         }
         # Collection of records found
         $found = @()
    }
    
    Process
    {
        $i = 0
        $record_count = $srv_rcds.Length
        foreach($srv in  $srv_rcds)
            {
                $record_progress = [int][Math]::Ceiling((($i / $record_count) * 100))
                Write-Progress -Activity "Enumerating Common SRV Records" -PercentComplete $record_progress -Status "Records  - $record_progress%" -Id 1;
                $target = $srv+$domain

                try 
                {
                    $found += [JHSoftware.DnsClient]::Lookup($target,[JHSoftware.DnsClient+RecordType]::SRV,$dnsopts).AnswerRecords
                }
                catch
                {
                }
                $i++
            }
        foreach($recond in $found)
        {
            $data_info = $recond.Data.split(' ')
            New-Object psobject -Property ([ordered]@{Type=$recond.Type;
                Name =$recond.name;
                Port=$data_info[2];Priority=$data_info[1];
                Target=$data_info[3]
                Address = & {
                                if ($NameServer) 
                                {
                                    Resolve-HostRecord -Target $data_info[3] -NameServer $NameServer} 
                                else 
                                {
                                    Resolve-HostRecord -Target $data_info[3] 
                                }
                            } 
            })
        }
    }

}


<#
.Synopsis
   Resolve a given FQDN
.DESCRIPTION
   Resolves a given FQDN to its A, AAAA and CNAME record.
.EXAMPLE

   C:\> Resolve-HostRecord ipv6.google.com

    Name                                                   Type Address
    ----                                                   ---- -------
    ipv6.google.com                                       CNAME ipv6.l.google.com.
    ipv6.l.google.com                                      AAAA 2607:f8b0:4002:c02::93
#>

function Resolve-HostRecord
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $false)]
        [string]$NameServer,

        [Parameter(Mandatory = $false)]
        [int32]$TimeOut,

        [Parameter(Mandatory = $false)]
        [int32]$Retries
    )

    begin 
    {
        $dnsopts = new-object JHSoftware.DnsClient+RequestOptions
        # Set the NS Server if one givem
        if ($nameserver)
        {
            try
            {
                # Check if what we got is an IP or a FQDN
                $IPObj = [Net.IPAddress]::Parse($nameserver)
                $IPCheck = [System.Net.IPAddress]::TryParse($nameserver,[ref]$IPObj)
                if ($IPCheck)
                {
                    $dns = [System.Net.IPAddress]$nameserver
                    $dnsopts.DnsServers += $dns
                }
                else
                {
                    Write-Error "$nameserver is not a valid IP Address"
                }
            }

            catch
            {
                $nsip = [Net.Dns]::GetHostAddresses($nameserver)[0]
                $dns = $nsip
                $dnsopts.DnsServers += $dns
            }
         }
         # Set the timeout
         if ($TimeOut)
         {
            $dnsopts.TimeOut = New-TimeSpan -Seconds $TimeOut
         }

         # Set Retries
         if ($Retries)
         {
            $dnsopts.RetryCount = $Retries
         }
    }
    process
    {
        $ARecs = @()
        # Resolve A Record
        try 
        {
            $answer = [JHSoftware.DnsClient]::Lookup($target,[JHSoftware.DnsClient+RecordType]::A,$dnsopts).AnswerRecords
            foreach ($A in $answer)
            {
            $ARecs += Select-Object -InputObject $A -Property Name,Type,@{Name='Address';Expression={$A.Data}}
            }
        }
        catch {}
        try
        {
            # Resolve AAAA Recod
            $answer = [JHSoftware.DnsClient]::Lookup($target,[JHSoftware.DnsClient+RecordType]::AAAA,$dnsopts).AnswerRecords
            foreach ($AAAA in $answer)
            {
               $ARecs += Select-Object -InputObject $AAAA -Property Name,Type,@{Name='Address';Expression={$AAAA.Data}}
            }
        }
        catch {}
    }

    end
    {
        $ARecs
    }
}


<#
.Synopsis
   Query for specific DNS Records against a Nameserver
.DESCRIPTION
   Query for specific DNS Records against a Nameserver
.EXAMPLE
    C:\> Resolve-DNSRecord -Target microsoft.com -Type MX

    Name                                     Type                   TTL Data
    ----                                     ----                   --- ----
    microsoft.com                              MX                  1001 10 microsoft-com.m...

.EXAMPLE

    C:\> Resolve-DNSRecord -Target microsoft.com -Type NS

    Name                                     Type                   TTL Data
    ----                                     ----                   --- ----
    microsoft.com                              NS                 14893 ns1.msft.net.
    microsoft.com                              NS                 14893 ns2.msft.net.
    microsoft.com                              NS                 14893 ns3.msft.net.
    microsoft.com                              NS                 14893 ns4.msft.net.
    microsoft.com                              NS                 14893 ns5.msft.net.
#>

function Resolve-DNSRecord
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $false)]
        [string]$NameServer,

        [Parameter(Mandatory = $false)]
        [int32]$TimeOut,

        [Parameter(Mandatory = $false)]
        [int32]$Retries,
        
        [string]
        [ValidateSet('A','A6','AAAA','AFSDB','ANY','APL','ATMA','CERT','CNAME',
        'DHCID','DLV','DNAME','DNSKEY','DS','EID','GID','GPOS','HINFO',
        'HIP','IPSECKEY','ISDN','KEY','KX','LOC','MB','MD','MF','MG',
        'MINFO','MR','MX','NAPTR','NIMLOC','NS','NSAP','NSAPPTR','NSEC',
        'NSEC3','NSEC3PARAM','NULL','NXT','OPT','PTR','PX','RP','RRSIG',
        'RT','SRV','SINK','SIG','SOA','SPF','SSHFP','TA','TXT','UID',
        'UINFO','UNSPEC','WKS','X25')]
        $Type
    )

    begin
    {
        $dnsopts = new-object JHSoftware.DnsClient+RequestOptions
        # Set the NS Server if one givem
        if ($nameserver)
        {
            try
            {
                # Check if what we got is an IP or a FQDN
                $IPObj = [Net.IPAddress]::Parse($nameserver)
                $IPCheck = [System.Net.IPAddress]::TryParse($nameserver,[ref]$IPObj)
                if ($IPCheck)
                {
                    $dns = [System.Net.IPAddress]$nameserver
                    $dnsopts.DnsServers += $dns
                }
                else
                {
                    Write-Error "$nameserver is not a valid IP Address"
                }
            }

            catch
            {
                $nsip = [Net.Dns]::GetHostAddresses($nameserver)[0]
                $dns = $nsip
                $dnsopts.DnsServers += $dns
            }
         }
         # Set the timeout
         if ($TimeOut)
         {
            $dnsopts.TimeOut = New-TimeSpan -Seconds $TimeOut
         }

         # Set Retries
         if ($Retries)
         {
            $dnsopts.RetryCount = $Retries
         }
         
    }
    
    process
    {
        # Resolve A Record
        $answer = [JHSoftware.DnsClient]::Lookup($target,[JHSoftware.DnsClient+RecordType]::$Type,$dnsopts).AnswerRecords
        foreach ($A in $answer)
        {
           $A
        }
    }

    end
    {
    }
}


<#
.Synopsis
   Convert a string representation of an IPV4 IP to In-Addr-ARPA format.
.DESCRIPTION
   Convert a string representation of an IPV4 IP to In-Addr-ARPA format for performing PTR Lookups.
.EXAMPLE
    ConvertTo-InAddrARPA -IPAddress 192.168.1.10
    10.1.168.192.in-addr.arpa

#>
function ConvertTo-InAddrARPA
{
    [CmdletBinding()]
    [OutputType([String])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias("IP")] 
        $IPAddress
    )

    Begin
    {
    }
    Process
    {
        try
        {
            $IPObj = [System.Net.IPAddress]::Parse($IPAddress)
            $ipIpaddressSplit = $IPAddress.Split(".")
	        "$($ipIpaddressSplit.GetValue(3)).$($ipIpaddressSplit.GetValue(2)).$($ipIpaddressSplit.GetValue(1)).$($ipIpaddressSplit.GetValue(0)).in-addr.arpa"
        }
        catch 
        {
            Write-Host "Value provided is not an IP Address"
        }
    }
    End
    {
    }
}