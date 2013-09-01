
<#
.Synopsis
  Imports an Nmap XML Scan Repot
.DESCRIPTION
   Imports an Nmap XML report and returns a collection of objects
   representing the scan information in the XML report.
.EXAMPLE
   Get Scan information

    PS C:\> Import-NmapXML -NmapXML $env:HOMEPATH\DEsktop\labscan.xml 


    NmapVersion      : 6.25
    Command          : nmap -p 1-65535 -T4 -A -v -Pn 192.168.10.1-200
    StartTime        : 4/12/2013 9:06:19 PM
    EndTime          : 4/12/2013 9:14:14 PM
    RunTime          : 
    ScanType         : syn
    ScanProtocol     : tcp
    NumberofServices : 65535
    Services         : 1-65535
    DebugLevel       : 0
    VerboseLevel     : 1
    Summary          : 
    ExitStatus       : 

.EXAMPLE
   Show IPv4 Addresses of hosts with port 139 TCP Open

    PS C:\> $nmaphosts = Import-NmapXML -NmapXML $env:HOMEPATH\DEsktop\labscan.xml -InfoType Hosts
    PS C:\> $nmaphosts | where {$_.opentcp -contains 139} | select ipv4address

    IPv4Address                                                                                                        
    -----------                                                                                                        
    192.168.10.2                                                                                                       
    192.168.10.10                                                                                                      
    192.168.10.12                                                                                                      
    192.168.10.13  

#>
function Import-NmapXML
{
    [CmdletBinding()]
    Param
    (
        # Nmap XML output file.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0,
                   ParameterSetName = "File")]
        [ValidateScript({Test-Path $_})] 
        $NmapXML,

        # XML Object containing Nmap XML information
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0,
                   ParameterSetName = "XMLDoc")]
        [xml]$InputObject,

        # Type of Information to return. Accepts ScanInfo and Hosts.
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [ValidateSet("ScanInfo","Hosts")] 
        $InfoType = "ScanInfo"
    )

    Begin
    {
    }
    Process
    {
        if ($NmapXML)
        {
            $file = Get-ChildItem $NmapXML
            [xml]$nmap = [System.IO.File]::ReadAllText($file.FullName)
        }
        else
        {
            [xml]$nmap = $InputObject
        }

        if ($InfoType -eq "ScanInfo")
        {
            # Format string for date
            $datefrmtstr = "ddd MMM dd HH:mm:ss yyyy"
            $scanstart = $nmap.nmaprun.startstr
            $scanend   = $nmap.nmaprun.runstats.finished.timestr
            

            $ScanInfoProperties = [ordered]@{
                NmapVersion      = $nmap.nmaprun.version
                Command          = $nmap.nmaprun.args
                StartTime        = [datetime]::ParseExact($scanstart,$datefrmtstr,$null)
                EndTime          = [datetime]::ParseExact($scanend,$datefrmtstr,$null)
                RunTime          = $nmap.nmaprun.runstats.finished.elapsed
                ScanType         = $nmap.nmaprun.scaninfo.type
                ScanProtocol     = $nmap.nmaprun.scaninfo.protocol
                NumberofServices = $nmap.nmaprun.scaninfo.numservices
                Services         = $nmap.nmaprun.scaninfo.services
                DebugLevel       = $nmap.nmaprun.debugging.level
                VerboseLevel     = $nmap.nmaprun.verbose.level
                Summary          = $nmap.nmaprun.runstats.finished.summary
                ExitStatus       = $nmap.nmaprun.runstats.finished.exit
            }
            [pscustomobject]$ScanInfoProperties
            
        }
        elseif ($InfoType -eq "Hosts")
        {
            # Returns epoch time so we need to tranform it
            $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0

            $discoveredhosts = $nmap.nmaprun.host | Where-Object {$_.status.state -eq "up"}
            foreach($dischost in $discoveredhosts)
            {
                # Set host addresses
                $macaddr  = $dischost.address | ForEach-Object {if($_.addrtype -eq "mac"){$_.addr}}
                $ipv4addr = $dischost.address | ForEach-Object {if($_.addrtype -eq "ipv4"){$_.addr}}
                $ipv6addr = $dischost.address | ForEach-Object {if($_.addrtype -eq "ipv6"){$_.addr}}

                # Hostsnames detected and type
                $hostnames = @()
                foreach($hostname in $dischost.hostnames.childnodes)
                {
                    $hostnmae_props = [ordered]@{
                        Name = $hostname.name
                        Type = $hostname.type
                    }
                    $hostnameobj = [pscustomobject]$hostnmae_props
                    $hostnameobj.pstypenames.insert(0,'Nmap.Host.Hostname')
                    $hostnames += $hostnameobj
                }

                # Traceroute information for the specific host
                $hops = @()
                foreach($hop in $dischost.trace.hop)
                {
                     $hopobj = [pscustomobject][ordered]@{
                        rtt       = $hop.rtt
                        ttl       = $hop.ttl
                        Host      = $hop.host
                        IPAddress = $hop.ipaddr
                    }
                    $hopobj.pstypenames.insert(0,'Nmap.Host.Trace.Hop')
                    $hops += $hopobj
                }
                
                $traceprop = [ordered]@{
                    Port     = $dischost.trace.port
                    Protocol = $dischost.trace.proto
                    Hops     = $hops
                }
                $traceobj = [pscustomobject]$traceprop
                $traceobj.pstypenames.insert(0,'Nmap.Host.Trace')

                # OS information on host
                $OSName   = $dischost.os.osmatch.name
                $Accuracy = $dischost.os.osmatch.accuracy
                $OSDBLine = $dischost.os.osmatch.line
                $osclass  = @()
                foreach($class in $dischost.os.osmatch.osclass){
                    $osclassobj = [pscustomobject][ordered]@{
                        Type          = $class.type
                        Vendor        = $class.vendor
                        OSFamily      = $class.osfamily
                        OSGeneration  = $class.osgen
                        Accuracy      = $class.accuracy
                    }
                    $osclassobj.pstypenames.insert(0,'Nmap.Host.OS.OSMatch.Class')
                    $osclass += $osclassobj
                }

                $portsused = @()
                foreach($portuse in $dischost.os.portused)
                {
                    $portusedobj = [pscustomobject]@{
                        State      = $portuse.state
                        PortNumber = $portuse.portid
                        Protocol   = $portuse.proto
                    }
                }

                # Port information for hosts
                $ports = @()
                $OpenTCP = @()
                $OpenUDP = @()
                foreach($port in $dischost.ports.port)
                {
                    # Port Scripts if any ran
                    $scripts = @()
                    if ($port.script)
                    {
                        foreach($script in $port.script)
                        {
                            $scripts += [pscustomobject][ordered]@{
                                ScriptName   = $script.id
                                ScriptOutput = $script.output
                            }
                        }
                    }

                    # port details

                    # Collect simple lists of open ports for easier parsing
                    if (($port.protocol -eq "tcp") -and ($port.state.state -eq "open"))
                    {
                        $OpenTCP += $port.portid
                    }

                    if (($port.protocol -eq "udp") -and ($port.state.state -eq "open"))
                    {
                        $OpenUDP += $port.portid
                    }

                    $portobj = [pscustomobject][ordered]@{
                        PortNumber = $port.portid
                        Protocol   = $port.protocol
                        PortState  = $port.state.state
                        Reason     = $port.state.reason
                        Scripts    = if ($scripts.count -gt 0){$scripts}else{$null}
                        Service = [pscustomobject][ordered]@{
                            ServiceName = $port.service.name
                            Product     = $port.service.product
                            OSType      = $port.service.ostype
                            Conf        = $port.service.conf
                            Extrainfo   = $port.service.extrainfo
                            Method      = $port.service.method
                            CPE         = $port.service.cpe
                            Tunnel      = $port.service.tunnel
                            RPCNumber   = $port.service.rpcnum
                            LowVersion  = $port.service.lowver
                            HighVersion = $port.service.highver
                            Hostname    = $port.service.hostname
                            ServiceFP   = $port.service.servicefp
                            DeviceType  = $port.service.devicetype
                        }
                    }
                    $portobj.pstypenames.insert(0,'Nmap.Host.Port')
                    $ports += $portobj
                }

                # Hosts scripts
                $hostscripts = @()
                $prescripts  = @()
                $postscripts = @()

                if ($dischost.hostscript)
                {
                    foreach($hostscript in $dischost.hostscript.script)
                    {
                        $hostscripts += [pscustomobject]@{
                            ScriptName   = $hostscript.id
                            ScriptOutput = $hostscript.output
                        }
                    }
                }

                if ($dischost.prescript)
                {
                    foreach($prescript in $dischost.prescript.script)
                    {
                        $prescripts += [pscustomobject]@{
                            ScriptName   = $prescript.id
                            ScriptOutput = $prescript.output
                        }
                    }
                }

                if ($dischost.postscript)
                {
                    foreach($postscript in $dischost.postscript.script)
                    {
                        $postscripts += [pscustomobject]@{
                            ScriptName   = $postscript.id
                            ScriptOutput = $postscript.output
                        }
                    }
                }

                $hostprops = [ordered]@{
                    ScanStartTime = $origin.AddSeconds($dischost.starttime).ToLocalTime()
                    ScanEndTime   = $origin.AddSeconds($dischost.endtime).ToLocalTime()
                    Status        = $dischost.status
                    MacAddress    = $macaddr
                    IPv4Address   = $ipv4addr
                    IPv6Address   = $ipv6addr
                    HostNames     = $hostnames
                    Smurf         = $dischost.smurf.responses
                    Distance      = $dischost.distance.value
                    Trace         = $traceobj
                    Ports         = $ports
                    OpenTCP       = $OpenTCP
                    OpenUDP       = $OpenUDP
                    HostScript    = $hostscripts
                    PreScript     = $prescripts
                    PostScript    = $postscripts
                    OSFingerprint = $osclass
                }
                [pscustomobject]$hostprops
            }
        }
    }
    End
    {
    }
}

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
function Import-DNSReconXML
{
    [CmdletBinding()]
    Param
    (
        # XML File generated by DNSRecon
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateScript({Test-Path $_})] 
        $XMLFile,

        # DNS RR Records to query for. Accpets A, AAAA, NS, TXT, SPF, MX, SOA, SRV and PTR
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

        $file = Get-ChildItem $XMLFile
        [xml]$dnsr = [System.IO.File]::ReadAllText($file.FullName)
    }
    Process
    {
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
                        $DNSRObject = New-Object PSObject -Property @{
                        Type         = $record.type
                        Name         = $record.name
                        Target       = $record.target
                        Address      = $record.address
                        Port         = $record.port
                        ZoneTransfer = $record.zone_server
                        Text         = $null
                        }
                        
                        $dnsrecords += $DNSRObject
                    }

                    # Parse NS records
                    "NS" 
                    {
                        $DNSRObject = New-Object PSObject -Property @{
                        Type         = $record.type
                        Name         = $record.target
                        Target       = $null
                        Address      = $record.address
                        Port         = $null
                        ZoneTransfer = $record.zone_server
                        Text         = $null
                        }
                   
                        $dnsrecords += $DNSRObject
                    }

                    # Parse AAAA, A and PTR records
                    "AAAA|A|PTR"
                    {
                        $DNSRObject = New-Object PSObject -Property @{
                        Type         = $record.type
                        Name         = $record.name
                        Target       = $record.target
                        Address      = $record.address
                        Port         = $record.port
                        ZoneTransfer = $record.zone_server
                        Text         = $null
                        }

                        $dnsrecords += $DNSRObject
                    }

                    # Parse MX records
                    "MX"
                    {
                        $DNSRObject = New-Object PSObject -Property @{
                        Type         = $record.type
                        Name         = $record.exchange
                        Target       = $null
                        Address      = $record.address
                        Port         = $record.port
                        ZoneTransfer = $record.zone_server
                        Text         = $null
                        }

                        $dnsrecords += $DNSRObject
                    }

                    # Parse SOA records
                    "SOA" 
                    {
                        $DNSRObject = New-Object PSObject -Property @{
                        Type         = $record.type
                        Name         = $record.mname
                        Target       = $null
                        Address      = $record.address
                        Port         = $record.port
                        ZoneTransfer = $record.zone_server
                        Text         = $null
                        }

                        $dnsrecords += $DNSRObject
                    }
        
                    "TXT|SPF"
                    {
                        $DNSRObject = New-Object PSObject -Property @{
                        Type         = $record.type
                        Name         = $record.mname
                        Target       = $record.target
                        Address      = $null
                        Port         = $null
                        ZoneTransfer = $record.zone_server
                        Text         = $record.text
                        }

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
