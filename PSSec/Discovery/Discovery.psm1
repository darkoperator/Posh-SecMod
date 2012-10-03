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
        [string]$MaxThreads=50,
        [Parameter(
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [int]$TimeOut = 100
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
            $targets = Get-IPv4RangeFromCIDR -Network $CIDR
        }

        $PingScripBlock ={
            param($ip, $TimeOut, $ping)
            $result = $ping.Send($ip, $TimeOut)
            if ($result.status -eq "Success")
            {
                $result.Address
            }
        }

        # Instansiate a ping object
        $ping = New-Object System.Net.NetworkInformation.Ping
    }
    Process
    {
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
            Write-Progress -Activity "Performing Ping Discovery" -PercentComplete $record_progress -Status "Pinged Host - $record_progress%" -Id 1;

            while ($($pool.GetAvailableRunspaces()) -le 0) {
                Start-Sleep -milliseconds 500
            }
    
            # create a "powershell pipeline runner"   
            $ps += [powershell]::create()

            # assign our pool of 3 runspaces to use   
            $ps[$i].runspacepool = $pool

            # command to run
            [void]$ps[$i].AddScript($PingScripBlock).AddParameter('IPaddress', $IPAddress).AddParameter('Timeout', $TimeOut).AddParameter('ping', $ping)
            #[void]$ps[$i].AddParameter('ping', $ping)
    
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
       
                # oops-ee!   
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
   Performs full TCP Connection and UDP port scan.
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
            $targets = Get-IPv4RangeFromCIDR -Network $CIDR
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

                            $scanport = New-Object psobject -Property @{
                                              Host  = $ip
                                              Port  = $p
                                              State = "Open"
                                              Type  = "TCP"}

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
                
                            $scanport = New-Object psobject -Property @{
                                            Host  = $ip
                                            Port  = $p
                                            State = "Open"
                                            Type  = "UDP"}
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
            $targets = Get-IPv4RangeFromCIDR -Network $CIDR
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

            while ($($pool.GetAvailableRunspaces()) -le 0) {
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

        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(get-date) - $waitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            } 
  
        # end async call   
        for ($y = 0; $y -lt $i; $y++) {     
  
            try {   
                # complete async job   
                $ScanResults += $ps[$y].EndInvoke($jobs[$y])   
  
            } catch {   
       
                # oops-ee!   
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

