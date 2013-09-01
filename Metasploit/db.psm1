<#
.Synopsis
   Creates a new host in the Metasploit Database if not present.
.DESCRIPTION
   Creates a new host in the Metasploit Database if not present. If the host is already present
   it will update the information on the host entrie with any additional information given.

.EXAMPLE
   Set-MSFDBHost -Id 0 -IPAddress 192.168.1.100 | fl *


result      : success
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Set-MSFDBHost
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # IP Address of the host to add.
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$IPAddress,

        # Host name of the host.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$HostName,

        # State of the host ("Alive","Down","Unknown"). 
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Alive","Down","Unknown")]
        [string]$State,

        # General Name ame of the Operating System
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Linux", "Mac OS X","Microsoft Windows","FreeBSD","NetBSD","OpenBSD","VMware","Unknown")]
        [string]$OSName,

        # OS Flavor (XP, 7, 2008, ESXi).
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$OSFlavor,

        # Service Pack level of the OS (SP1, SP2)
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$OSSP,

        # OS Language ("English", "French", or "en-US")
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$OSLang,

        # Operating System Architecture.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("x86","x86_64","MIPS","MIPSBE","MIPSLE","PPC","SPARC","ARMLE","ARMBE")]
        [string]$Architecture,

        # MAC Address of the main interface to reach the host.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$MACAddress,

        # Comment
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Comment,

        # What is the purpose of the host.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Device", "Server","Client")]
        [string]$Purpose,

        # If it is a Virtual Machine what Hypervisor it is. 
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("VMWare", "QEMU", "Xen", "Hyper-V", "VirtualBox", "Parallels")]
        [string]$HyperVisor,

        # Database Workspace, if none Default will be use.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Workspace
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'
        if ($IPAddress)
        {
            $dbops.Add('host',$IPAddress)

        }

        if ($HostName)
        {
            $dbops.Add('name',$HostName)

        }

        if ($State)
        {
            $dbops.Add('state',$State.ToLower())
        }

        if ($OSName)
        {
            $dbops.Add('os_name',$OSName)
        }

        if ($OSFlavor)
        {
            $dbops.Add('os_flavor',$OSFlavor.ToLower())
        }

        if ($OSSP)
        {
            $dbops.Add('os_sp',$OSSP.ToLower())
        }

        if ($OSLang)
        {
            $dbops.Add('os_lang',$OSLang.ToLower())
        }

        if ($Architecture)
        {
            $dbops.Add('arch',$Architecture.ToLower())
        }

        if ($MACAddress)
        {
            $dbops.Add('mac',$MACAddress.ToLower())
        }

        if ($HyperVisor)
        {
            $dbops.Add('virtual_host',$MACAddress.ToLower())
        }

        if ($Info)
        {
            $dbops.Add('info',$Info)
        }

        if ($Purpose)
        {
            $dbops.Add('purpose',$Purpose.ToLower())
        }

        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }
       
        $request_reply = $MSession.Session.Execute("db.report_host", $dbops)

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.report_host", $dbops)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID",$Id)
                        $connectobj = New-Object -TypeName psobject -Property $request_reply
                        $connectobj.pstypenames[0] = "Metasploit.Action"
                        $connectobj 
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID",$Id)
                $connectobj = New-Object -TypeName psobject -Property $request_reply
                $connectobj.pstypenames[0] = "Metasploit.Action"
                $connectobj 
            }
        }
    }
}


<#
.Synopsis
   List Hosts in the Metasploit database.
.DESCRIPTION
   List Hosts in the Metasploit database.
.EXAMPLE
   Get-MSFDBHost -Id 0 -OnlyUp


created_at  : 1376481606
address     : 192.168.1.1
mac         : 
name        : 
state       : alive
os_name     : Unknown
os_flavor   : 
os_sp       : 
os_lang     : 
updated_at  : 1376481606
purpose     : device
info        : 
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Get-MSFDBHost
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # Metasploit session object
        [Parameter(Mandatory=$false)]
        [switch]$OnlyUp,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [int]$Limit,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Workspace
       
    )
    BEGIN 
    {
        # Epoch time 
        [datetime]$origin = '1970-01-01 00:00:00'
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'
        if ($OnlyAlive)
        {
            $dbops.Add('only_up',$true)

        }

        if ($Limit)
        {
            $dbops.Add('limit',$Limit)
        }

        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }
       
        $request_reply = $MSession.Session.Execute("db.hosts", $dbops)

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.hosts", $dbops)
                    if ($request_reply.ContainsKey('hosts'))
                    {
                        foreach ($dbhost in $request_reply['hosts'])
                        {
                            $hostprops = [ordered]@{}
                            $hostprops.Add("Address", $dbhost.address)
                            $hostprops.Add("Name", $dbhost.name)
                            $hostprops.Add("State", $dbhost.state)
                            $hostprops.Add("Mac", $dbhost.mac)
                            $hostprops.Add("OS_Name", $dbhost.os_name)
                            $hostprops.Add("OS_Flavor", $dbhost.os_flavor)
                            $hostprops.Add("OS_SP", $dbhost.so_sp)
                            $hostprops.Add("OS_Lang", $dbhost.os_lang)
                            $hostprops.Add("Info", $dbhost.info)
                            $hostprops.Add("Purpose", $dbhost.purpose)
                            $hostprops.Add("Updated", $origin.AddSeconds($dbhost.updated_at))
                            $hostprops.Add("Created", $origin.AddSeconds($dbhost.created_at))
                            $hostprops.Add("MSHost", $MSession.Host)
                            $hostprops.Add("MSSessionID", $MSession.Id)
                            $hostobj = New-Object -TypeName psobject -Property $hostprops
                            $hostobj.pstypenames[0] = "Metasploit.host"
                            $hostobj 
                        }
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('hosts'))
            {
                foreach ($dbhost in $request_reply['hosts'])
                {
                    $hostprops = [ordered]@{}
                    $hostprops.Add("Address", $dbhost.address)
                    $hostprops.Add("Name", $dbhost.name)
                    $hostprops.Add("State", $dbhost.state)
                    $hostprops.Add("Mac", $dbhost.mac)
                    $hostprops.Add("OS_Name", $dbhost.os_name)
                    $hostprops.Add("OS_Flavor", $dbhost.os_flavor)
                    $hostprops.Add("OS_SP", $dbhost.so_sp)
                    $hostprops.Add("OS_Lang", $dbhost.os_lang)
                    $hostprops.Add("Info", $dbhost.info)
                    $hostprops.Add("Purpose", $dbhost.purpose)
                    $hostprops.Add("Updated", $origin.AddSeconds($dbhost.updated_at))
                    $hostprops.Add("Created", $origin.AddSeconds($dbhost.created_at))
                    $hostprops.Add("MSHost", $MSession.Host)
                    $hostprops.Add("MSSessionID", $MSession.Id)
                    $consoleobj = New-Object -TypeName psobject -Property $hostprops
                    $consoleobj.pstypenames[0] = "Metasploit.host"
                    $consoleobj 
                }
            }
        }
    }
}


<#
.Synopsis
   Removes a host and all data related for that host from the Metasploit database. 
.DESCRIPTION
   Removes a host and all data related for that host from the Metasploit database. 
.EXAMPLE
   Remove-MSFDBHost -Id 0 -Address 192.168.1.103,192.168.1.104 | fl *


MSHost      : 192.168.1.104
MSSessionID : 0
deleted     : {192.168.1.103, 192.168.1.104}
#>
function Remove-MSFDBHost
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Workspace,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$Address
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'
        if ($Address)
        {
            $dbops.Add('addresses',$Address)

        }

        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }
       
        $request_reply = $MSession.Session.Execute("db.del_host", $dbops)

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.del_host", $dbops)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $deleteprops = [ordered]@{}
                        $deleteprops.add('MSHost', $MSession.Host)
                        $deleteprops.Add("MSSessionID", $Id)
                        $deletedrecs = @()
                        foreach ($prop in $request_reply.keys)
                        {
                            if ($prop -eq "deleted")
                            {
                                foreach ($record in $request_reply['deleted'] )
                                {
                                    $deletedrecs += $record
                                }
                                $deleteprops.add("deleted",$deletedrecs)
                            }
                        }
                        $connectobj = New-Object -TypeName psobject -Property $deleteprops
                        $connectobj.pstypenames[0] = "Metasploit.Removed.Hosts"
                        $connectobj 
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $deleteprops = [ordered]@{}
                $deleteprops.add('MSHost', $MSession.Host)
                $deleteprops.Add("MSSessionID", $Id)
                $deletedrecs = @()
                foreach ($prop in $request_reply.keys)
                {
                    if ($prop -eq "deleted")
                    {
                        foreach ($record in $request_reply['deleted'] )
                        {
                            $deletedrecs += $record
                        }
                        $deleteprops.add("deleted",$deletedrecs)
                    }
                }
                $connectobj = New-Object -TypeName psobject -Property $deleteprops
                $connectobj.pstypenames[0] = "Metasploit.Removed.Hosts"
                $connectobj 
            }
        }
    }
}


<#
.Synopsis
   List Services in the Metasploit database.
.DESCRIPTION
   List Services in the Metasploit database.
.EXAMPLE
    Get-MSFDBServcie -Id 0 -Ports 55553


host        : 192.168.1.102
created_at  : 1377197567
updated_at  : 1377197567
port        : 55553
proto       : tcp
state       : open
name        : metasploit
info        : 
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Get-MSFDBServcie
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,


        # Port list or range to filter
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Ports,

        # Filter services by protocol TCP or UDP
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        # Filter services by name
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Name,

        # Filter services by Address
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$Address,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [int]$Limit,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Workspace
       
    )
    BEGIN 
    {
        # Epoch time 
        [datetime]$origin = '1970-01-01 00:00:00'
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        # Parse filtering options
        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'

        if ($Ports)
        {
            $dbops.Add('ports', $Ports)
        }
       
        if ($Name)
        {
            $dbops.Add('names',$Name.ToLower())
        }

        if ($Protocol)
        {
            $dbops.Add('proto',$Protocol.ToLower())
        }

        if ($Address)
        {
            $dbops.Add('addresses', $Address)
        }

        if ($Limit)
        {
            $dbops.Add('limit',$Limit)
        }

        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }

        $request_reply = $MSession.Session.Execute("db.services", $dbops)

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.services", $dbops)
                    if ($request_reply.ContainsKey('services'))
                    {
                        foreach ($dbsrv in $request_reply['services'])
                        {
                            $srvprops = [ordered]@{}
                            $srvprops.Add("Host", $dbsrv.host)
                            $srvprops.Add("Port", $dbsrv.port)
                            $srvprops.Add("proto", $dbsrv.proto)
                            $srvprops.Add("Name", $dbsrv.name)
                            $srvprops.Add("State", $dbsrv.state)
                            $srvprops.Add("Info", $dbsrv.info)
                            $srvprops.Add("Updated", $origin.AddSeconds($dbsrv.updated_at))
                            $srvprops.Add("Created", $origin.AddSeconds($dbsrv.created_at))
                            $srvprops.Add("MSHost", $MSession.Host)
                            $srvprops.Add("MSSessionID", $MSession.Id)
                            $srvobj = New-Object -TypeName psobject -Property $srvprops
                            $srvobj.pstypenames[0] = "Metasploit.Service"
                            $srvobj 
                        }
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('services'))
            {
                foreach ($dbsrv in $request_reply['services'])
                {
                    $srvprops = [ordered]@{}
                    $srvprops.Add("Host", $dbsrv.host)
                    $srvprops.Add("Port", $dbsrv.port)
                    $srvprops.Add("proto", $dbsrv.proto)
                    $srvprops.Add("Name", $dbsrv.name)
                    $srvprops.Add("State", $dbsrv.state)
                    $srvprops.Add("Info", $dbsrv.info)
                    $srvprops.Add("Updated", $origin.AddSeconds($dbsrv.updated_at))
                    $srvprops.Add("Created", $origin.AddSeconds($dbsrv.created_at))
                    $srvprops.Add("MSHost", $MSession.Host)
                    $srvprops.Add("MSSessionID", $MSession.Id)
                    $srvobj = New-Object -TypeName psobject -Property $srvprops
                    $srvobj.pstypenames[0] = "Metasploit.Service"
                    $srvobj 
                }
            }
        }
    }
}


<#
.Synopsis
   Creates a new service in the Metasploit Database if not present.
.DESCRIPTION
   Creates a new service in the Metasploit Database if not present. If the host is already present
   it will update the information on the service entrie with any additional information given.
.EXAMPLE
   Set-MSFDBServcie -Id 0 -Port 8080 -Protocol TCP -IPAddress 192.168.1.1 -state Open | fl *


result      : success
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Set-MSFDBServcie
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,


        # Port list or range to filter
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Port,

        # Filter services by protocol TCP or UDP
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        # Filter services by name
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Name,

        # IPAddress to associate service with.
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$IPAddress,

        # IPAddress to associate service with.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Open', 'Close')]
        [string]$state,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Workspace
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        # Parse filtering options
        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'

        if ($Port)
        {
            $dbops.Add('port', $Port)
        }
       
        if ($Name)
        {
            $dbops.Add('name',$Name.ToLower())
        }

        if ($State)
        {
            $dbops.Add('state',$State.ToLower())
        }

        if ($Protocol)
        {
            $dbops.Add('proto',$Protocol.ToLower())
        }

        if ($IPAddress)
        {
            $dbops.Add('host', $IPAddress)
        }

        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }

        $request_reply = $MSession.Session.Execute("db.report_service", $dbops)
        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.report_service", $dbops)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $connectobj = New-Object -TypeName psobject -Property $request_reply
                        $connectobj.pstypenames[0] = "Metasploit.Action"
                        $connectobj 
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $Id)
                $connectobj = New-Object -TypeName psobject -Property $request_reply
                $connectobj.pstypenames[0] = "Metasploit.Action"
                $connectobj 
            }
        }
    }
}


<#
.Synopsis
   Deletes a service from the Metasploit database.
.DESCRIPTION
   Deletes a service from the database and associated vulns matching this port.
.EXAMPLE
    Remove-MSFDBServcie -Id 0 -Port 445 | fl *


MSHost      : 192.168.1.104
MSSessionID : 0
deleted     : {@{address=192.168.1.243; port=445; proto=tcp}, @{address=192.168.10.12; port=445; proto=tcp}, 
              @{address=192.168.10.3; port=445; proto=tcp}, @{address=192.168.1.183; port=445; proto=tcp}}
#>
function Remove-MSFDBServcie
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,


        # Port list or range to filter
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Port,

        # Filter services by name
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("sname")]
        [string]$Name,

        # IPAddress to associate service with.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("host")]
        [string]$IPAddress,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Workspace
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        # Parse filtering options
        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'

        if ($Port)
        {
            $dbops.Add('port', $Port)
        }
       
        if ($Name)
        {
            $dbops.Add('name',$Name.ToLower())
        }

        if ($State)
        {
            $dbops.Add('state',$State.ToLower())
        }

        if ($Protocol)
        {
            $dbops.Add('proto',$Protocol.ToLower())
        }

        if ($IPAddress)
        {
            $dbops.Add('host', $IPAddress)
        }

        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }

        $request_reply = $MSession.Session.Execute("db.del_service", $dbops)
        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.del_service", $dbops)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $deleteprops = [ordered]@{}
                        $deleteprops.add('MSHost', $MSession.Host)
                        $deleteprops.Add("MSSessionID", $Id)
                        $deletedrecs = @()
                        foreach ($prop in $request_reply.keys)
                        {
                            if ($prop -eq "deleted")
                            {
                                foreach ($record in $request_reply['deleted'] )
                                {
                                    $deletedrecs += New-Object -TypeName psobject -Property $record
                                }
                                $deleteprops.add("deleted",$deletedrecs)
                            }
                        }
                        $connectobj = New-Object -TypeName psobject -Property $deleteprops
                        $connectobj.pstypenames[0] = "Metasploit.Removed.Service"
                        $connectobj 
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $deleteprops = [ordered]@{}
                $deleteprops.add('MSHost', $MSession.Host)
                $deleteprops.Add("MSSessionID", $Id)
                $deletedrecs = @()
                foreach ($prop in $request_reply.keys)
                {
                    if ($prop -eq "deleted")
                    {
                        foreach ($record in $request_reply['deleted'] )
                        {
                            $deletedrecs += New-Object -TypeName psobject -Property $record
                        }
                        $deleteprops.add("deleted",$deletedrecs)
                    }
                }
                $connectobj = New-Object -TypeName psobject -Property $deleteprops
                $connectobj.pstypenames[0] = "Metasploit.Removed.Service"
                $connectobj 
            }
        }
    }
}


<#
.Synopsis
   Creates a new vulnerability relation in the Metasploit Database if not present.
.DESCRIPTION
   Creates a new vulnerability relation in the Metasploit Database if not present. If the vulnerability 
   is already present it will update the information on its entrie with any additional information given.
.EXAMPLE
   Set-MSFDBVuln -Id 0 -Port 22 -Protocol TCP -Name "SSH Pwn" -IPAddress 192.168.1.104 -References "CVE-2013-9999","BID99999" | fl *


result      : success
MSHost      : 192.168.1.104
MSSessionID : 0

PS C:\> Get-MSFDBVuln -Id 0 -Ports 22 -Address 192.168.1.104


port        : 22
proto       : tcp
time        : 1377221319
host        : 192.168.1.104
name        : ssh pwn
refs        : CVE-2013-9999,BID99999
MSHost      : 192.168.1.104
MSSessionID : 0


#>
function Set-MSFDBVuln
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # Network Port
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Port,

        # Network Protocol
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        # Vulnerability name.
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Name,

        # IPAddress to associate s
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$IPAddress,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Info,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$References,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Workspace
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        # Parse filtering options
        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'

        if ($Port)
        {
            $dbops.Add('port', $Port)
        }
       
        if ($Name)
        {
            $dbops.Add('name',$Name.ToLower())
        }

        if ($Info)
        {
            $dbops.Add('info',$Info)
        }

        if ($References)
        {
            $dbops.Add('refs',$References)
        }

        if ($Protocol)
        {
            $dbops.Add('proto',$Protocol.ToLower())
        }

        if ($IPAddress)
        {
            $dbops.Add('host', $IPAddress)
        }

        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }

        $request_reply = $MSession.Session.Execute("db.report_vuln", $dbops)
        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.report_vuln", $dbops)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $connectobj = New-Object -TypeName psobject -Property $request_reply
                        $connectobj.pstypenames[0] = "Metasploit.Action"
                        $connectobj 
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $Id)
                $connectobj = New-Object -TypeName psobject -Property $request_reply
                $connectobj.pstypenames[0] = "Metasploit.Action"
                $connectobj 
            }
        }
    }
}


<#
.Synopsis
   Enumerates specific vulnerabilities reported in the Metasploit database.
.DESCRIPTION
   Enumerates specific vulnerabilities reported in the Metasploit database. One can filter
   by several fields and limit the number of objects returned.
.EXAMPLE
    Get-MSFDBVuln -Id 0 -Ports 22 -Address 192.168.1.104


port        : 22
proto       : tcp
time        : 1377221319
host        : 192.168.1.104
name        : ssh pwn
refs        : CVE-2013-9999,BID99999
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Get-MSFDBVuln
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # Port list or range to filter
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Ports,

        # Filter services by protocol TCP or UDP
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        # Filter services by name
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Name,

        # Filter services by Address
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Address,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [int]$Limit,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Workspace
       
    )
    BEGIN 
    {
        # Epoch time 
        [datetime]$origin = '1970-01-01 00:00:00'
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        # Parse filtering options
        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'
        if ($OnlyAlive)
        {
            $dbops.Add('only_up',$true)

        }

        if ($Ports)
        {
            $dbops.Add('ports', $Ports)
        }
       
        if ($Name)
        {
            $dbops.Add('names',$Name.ToLower())
        }

        if ($Protocol)
        {
            $dbops.Add('proto',$Protocol.ToLower())
        }

        if ($Address)
        {
            $dbops.Add('addresses', $Address)
        }

        if ($Limit)
        {
            $dbops.Add('limit',$Limit)
        }

        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }

        $request_reply = $MSession.Session.Execute("db.vulns", $dbops)

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.vulns", $dbops)
                    if ($request_reply.ContainsKey('vulns'))
                    {
                        foreach ($vuln in $request_reply['vulns'])
                        {
                            $vulnops = [ordered]@{}
                            $vulnops.Add("Host", $vuln.host)
                            $vulnops.Add("Port", $vuln.port)
                            $vulnops.Add("proto", $vuln.proto)
                            $vulnops.Add("Name", $vuln.name)
                            $vulnops.Add("References", $vuln.refs)
                            $vulnops.Add("Time", $origin.AddSeconds($vuln.time))
                            $vulnops.Add("MSHost", $MSession.Host)
                            $vulnops.Add("MSSessionID", $MSession.Id)
                            $vulnobj = New-Object -TypeName psobject -Property $vulnops
                            $vulnobj.pstypenames[0] = "Metasploit.Vuln"
                            $vulnobj 
                        }
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('vulns'))
            {
                foreach ($vuln in $request_reply['vulns'])
                {
                    $vulnops = [ordered]@{}
                    $vulnops.Add("Host", $vuln.host)
                    $vulnops.Add("Port", $vuln.port)
                    $vulnops.Add("proto", $vuln.proto)
                    $vulnops.Add("Name", $vuln.name)
                    $vulnops.Add("References", $vuln.refs)
                    $vulnops.Add("Time", $origin.AddSeconds($vuln.time))
                    $vulnops.Add("MSHost", $MSession.Host)
                    $vulnops.Add("MSSessionID", $MSession.Id)
                    $vulnobj = New-Object -TypeName psobject -Property $vulnops
                    $vulnobj.pstypenames[0] = "Metasploit.Vuln"
                    $vulnobj 
                }
            }
        }
    }
}


<#
.Synopsis
   Removes a specified vulnerability from the Metasploit Database.
.DESCRIPTION
   Removes a specified vulnerability from the Metasploit Database.
#>
function Remove-MSFDBVuln
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # Network Port
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Port,

        # Network Protocol
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        # Vulnerability name.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Name,

        # IPAddress to associate s
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$IPAddress,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$References,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Workspace
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        # Parse filtering options
        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'

        if ($Port)
        {
            $dbops.Add('port', $Port)
        }
       
        if ($Name)
        {
            $dbops.Add('name',$Name)
        }


        if ($References)
        {
            $dbops.Add('refs',$References)
        }

        if ($Protocol)
        {
            $dbops.Add('proto',$Protocol.ToLower())
        }

        if ($IPAddress)
        {
            $dbops.Add('host', $IPAddress)
        }

        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }

        $request_reply = $MSession.Session.Execute("db.del_vuln", $dbops)
        $request_reply
        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.del_vuln", $dbops)
                    $request_reply
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $connectobj = New-Object -TypeName psobject -Property $request_reply
                        $connectobj.pstypenames[0] = "Metasploit.Action"
                        $connectobj 
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $Id)
                $connectobj = New-Object -TypeName psobject -Property $request_reply
                $connectobj.pstypenames[0] = "Metasploit.Action"
                $connectobj 
            }
        }
    }
}


<#
.Synopsis
   Gets notes stored in the Metasploit server Database
.DESCRIPTION
   Gets notes stored in the Metasploit server Database
.EXAMPLE
   Get-MSFDBNote -Id 0


time        : 1377313198
host        : 192.168.10.10
service     : 
type        : host.os.nessus_fingerprint
data        : {:os=>"Microsoft Windows Server 2012 Standard"}
MSHost      : 192.168.1.104
MSSessionID : 0

time        : 1377353992
host        : 192.168.1.104
service     : 
type        : javascript_fingerprint
data        : {:os_name=>"Mac OS X", :os_lang=>"en-US", :arch=>"x86"}
MSHost      : 192.168.1.104
MSSessionID : 0

time        : 1377354063
host        : 192.168.1.104
service     : 
type        : javascript_fingerprint
data        : {:os_name=>"Microsoft Windows", :os_flavor=>"8", :os_lang=>"en-US", :arch=>"x86"}
MSHost      : 192.168.1.104
MSSessionID : 0

time        : 1377793291
host        : 192.168.1.239
service     : 
type        : host.os.session_fingerprint
data        : {:name=>"WIN-VFAQ52MS90V", :os=>"Windows 7 (Build 7600).", :arch=>"x64 (Current Process is WOW64)"}
MSHost      : 192.168.1.104
MSSessionID : 0

time        : 1377313193
host        : 192.168.10.3
service     : 
type        : host.os.nessus_fingerprint
data        : {:os=>"Linux Kernel 2.6.32-358.0.1.el6.x86_64 on CentOS release 6.4 (Final)"}
MSHost      : 192.168.1.104
MSSessionID : 0

time        : 1377313194
host        : 192.168.10.2
service     : 
type        : host.os.nessus_fingerprint
data        : {:os=>"Microsoft Windows Server 2012 Standard"}
MSHost      : 192.168.1.104
MSSessionID : 0

time        : 1377313195
host        : 192.168.10.13
service     : 
type        : host.os.nessus_fingerprint
data        : {:os=>"Microsoft Windows Server 2008 R2 Enterprise Service Pack 1"}
MSHost      : 192.168.1.104
MSSessionID : 0

time        : 1377313197
host        : 192.168.10.12
service     : 
type        : host.os.nessus_fingerprint
data        : {:os=>"Microsoft Windows Server 2008 R2 Enterprise Service Pack 1"}
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Get-MSFDBNote
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # Port list or range to filter
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Ports,

        # Filter services by protocol TCP or UDP
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        # Filter services by name
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Name,

        # Filter services by Address
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Address,

        # Maximun number of results to pull from server
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [int]$Limit,

        # Workspace to execute query against
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Workspace,

        # Note ntype
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Type
       
    )
    BEGIN 
    {
        # Epoch time 
        [datetime]$origin = '1970-01-01 00:00:00'
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        # Parse filtering options
        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'
        if ($OnlyAlive)
        {
            $dbops.Add('only_up',$true)

        }

        if ($Ports)
        {
            $dbops.Add('ports', $Ports)
        }
       
        if ($Name)
        {
            $dbops.Add('names',$Name.ToLower())
        }

        if ($Protocol)
        {
            $dbops.Add('proto',$Protocol.ToLower())
        }

        if ($Address)
        {
            $dbops.Add('addresses', $Address)
        }

        if ($Limit)
        {
            $dbops.Add('limit',$Limit)
        }

        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }

        if ($Type)
        {
            $dbops.Add('ntype',$Type.ToLower())
        }

        $request_reply = $MSession.Session.Execute("db.notes", $dbops)

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.notes", $dbops)
                    if ($request_reply.ContainsKey('notes'))
                    {
                        foreach ($note in $request_reply['notes'])
                        {
                            $noteops = [ordered]@{}
                            $noteops.Add("Host", $note.host)
                            $noteops.Add("Service", $note.service)
                            $noteops.Add("Data", $note.data)
                            $noteops.Add("Type", $note.type)
                            $noteops.Add("Time", $origin.AddSeconds($note.time))
                            $noteops.Add("MSHost", $MSession.Host)
                            $noteops.Add("MSSessionID", $MSession.Id)
                            $notenobj = New-Object -TypeName psobject -Property $noteops
                            $notenobj.pstypenames[0] = "Metasploit.Note"
                            $notenobj 
                        }
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('notes'))
            {
                foreach ($note in $request_reply['notes'])
                {
                    $noteops = [ordered]@{}
                    $noteops.Add("Host", $note.host)
                    $noteops.Add("Service", $note.service)
                    $noteops.Add("Data", $note.data)
                    $noteops.Add("Type", $note.type)
                    $noteops.Add("Time", $origin.AddSeconds($note.time))
                    $noteops.Add("MSHost", $MSession.Host)
                    $noteops.Add("MSSessionID", $MSession.Id)
                    $notenobj = New-Object -TypeName psobject -Property $noteops
                    $notenobj.pstypenames[0] = "Metasploit.Note"
                    $notenobj 
                }
            }
        }
    }
}


<#
.Synopsis
   Creates or modifies a note in the Metasploit Database.
.DESCRIPTION
   Creates or modifies a note in the Metasploit Database.
.EXAMPLE
   Set-MSFDBNote -Id 0 -Data "This is my test note" -Type "Text" -Port 9999 -IPAddress 8.8.8.8 -Protocol TCP | fl *


result      : success
MSHost      : 192.168.1.104
MSSessionID : 0




PS C:\> Get-MSFDBNote -Id 0 -Ports 9999 -Address 8.8.8.8


time        : 1377917264
host        : 8.8.8.8
service     : 
type        : Text
data        : "This is my test note"
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Set-MSFDBNote
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # Note data for what the note is for.
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Data,

        # The type of note, e.g. smb_peer_os
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Type,

        # Port to associate the note to.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Port,

        # Protocol of service for the note, TCP or UDP
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        # IP Address of host to associate the note to.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$IPAddress,

        # what to do in case a similar Note exists
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Unique","Unique_Data", "Insert")]
        [string]$Update = "Insert",

        # Workspace to execute query against
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Workspace

        
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        # Parse filtering options
        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'

        if ($Port)
        {
            $dbops.Add('port', $Port)
        }
       
        if ($Data)
        {
            $dbops.Add('data',$Data)
        }

        if ($Protocol)
        {
            $dbops.Add('proto',$Protocol.ToLower())
        }

        if ($IPAddress)
        {
            $dbops.Add('host', $IPAddress)
        }

        if ($Type)
        {
            $dbops.Add('type',$Type)
        }

        if ($Update)
        {
            $dbops.Add('update',$Update.ToLower())
        }

        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }

        $request_reply = $MSession.Session.Execute("db.report_note", $dbops)

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.report_note", $dbops)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $connectobj = New-Object -TypeName psobject -Property $request_reply
                        $connectobj.pstypenames[0] = "Metasploit.Action"
                        $connectobj 
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $connectobj = New-Object -TypeName psobject -Property $request_reply
                $connectobj.pstypenames[0] = "Metasploit.Action"
                $connectobj 
            }
        }
    }
}


function Remove-MSFDBNote
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # The type of note, e.g. smb_peer_os
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Type,

        # Port associated with the note.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Port,

        # Protocol of service for the note, TCP or UDP
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        # IP Address of host in the database.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$IPAddress,


        # Workspace to execute query against
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Workspace
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        # Parse filtering options
        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'

        if ($Port)
        {
            $dbops.Add('port', $Port)
        }

        if ($Protocol)
        {
            $dbops.Add('proto',$Protocol.ToLower())
        }

        if ($IPAddress)
        {
            $dbops.Add('host', $IPAddress)
        }

        if ($Type)
        {
            $dbops.Add('ntype',$Type)
        }


        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }

        $request_reply = $MSession.Session.Execute("db.del_note", $dbops)
        $request_reply
        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.del_note", $dbops)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $deleteprops = [ordered]@{}
                        $deleteprops.add('MSHost', $MSession.Host)
                        $deleteprops.Add("MSSessionID", $Id)
                        $deletedrecs = @()
                        foreach ($prop in $request_reply.keys)
                        {
                            if ($prop -eq "deleted")
                            {
                                foreach ($record in $request_reply['deleted'] )
                                {
                                    $deletedrecs += New-Object -TypeName psobject -Property $record
                                }
                                $deleteprops.add("deleted",$deletedrecs)
                            }
                        }
                        $connectobj = New-Object -TypeName psobject -Property $deleteprops
                        $connectobj.pstypenames[0] = "Metasploit.Action"
                        $connectobj 
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $deleteprops = [ordered]@{}
                $deleteprops.add('MSHost', $MSession.Host)
                $deleteprops.Add("MSSessionID", $Id)
                $deletedrecs = @()
                foreach ($prop in $request_reply.keys)
                {
                    if ($prop -eq "deleted")
                    {
                        foreach ($record in $request_reply['deleted'] )
                        {
                            $deletedrecs += New-Object -TypeName psobject -Property $record
                        }
                        $deleteprops.add("deleted",$deletedrecs)
                    }
                }
                $connectobj = New-Object -TypeName psobject -Property $deleteprops
                $connectobj.pstypenames[0] = "Metasploit.Action"
                $connectobj 
            }
        }
    }
}


<#
.Synopsis
   Get a events recorded in the Metasploit Database.
.DESCRIPTION
   Get a events recorded in the Metasploit Database.
.EXAMPLE
   Get-MSFDBEvent -id 0 -Limit 10


created_at  : 1352342121
updated_at  : 1352342121
name        : ui_start
info        : {[revision, $Revision: 15713 $]}
MSHost      : 192.168.1.104
MSSessionID : 0

created_at  : 1352342121
updated_at  : 1352342121
name        : ui_command
info        : {[command, banner]}
MSHost      : 192.168.1.104
MSSessionID : 0

created_at  : 1352342282
updated_at  : 1352342282
name        : ui_command
info        : {[command, irb]}
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Get-MSFDBEvent
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # Maximun number of results to pull from server
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [int]$Limit,

        # Workspace to execute query against
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Workspace
       
    )
    BEGIN 
    {
        # Epoch time 
        [datetime]$origin = '1970-01-01 00:00:00'
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        # Parse filtering options
        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'
        
        if ($Limit)
        {
            $dbops.Add('limit',$Limit)
        }

        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }

        $request_reply = $MSession.Session.Execute("db.events", $dbops)

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.events", $dbops)
                    if ($request_reply.ContainsKey('events'))
                    {
                        foreach ($event in $request_reply['events'])
                        {
                            $eventprops = [ordered]@{}
                            $eventprops.Add("Name", $event.name)
                            $eventprops.Add("Info", $event.info)
                            $eventprops.Add("Updated", $origin.AddSeconds($event.updated_at))
                            $eventprops.Add("Created", $origin.AddSeconds($event.created_at))
                            $eventprops.Add("MSHost", $MSession.Host)
                            $eventprops.Add("MSSessionID", $MSession.Id)
                            $eventobj = New-Object -TypeName psobject -Property $eventprops
                            $eventobj.pstypenames[0] = "Metasploit.Event"
                            $eventobj 
                        }
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('events'))
            {
                foreach ($event in $request_reply['events'])
                {
                    $eventprops = [ordered]@{}
                    $eventprops.Add("Name", $event.name)
                    $eventprops.Add("Info", $event.info)
                    $eventprops.Add("Updated", $origin.AddSeconds($event.updated_at))
                    $eventprops.Add("Created", $origin.AddSeconds($event.created_at))
                    $eventprops.Add("MSHost", $MSession.Host)
                    $eventprops.Add("MSSessionID", $MSession.Id)
                    $eventobj = New-Object -TypeName psobject -Property $eventprops
                    $eventobj.pstypenames[0] = "Metasploit.Event"
                    $eventobj 
                }
            }
        }
    }
}


<#
.Synopsis
   Adds a credential in to the Metasploit database.
.DESCRIPTION
   Adds a credential obtained via bruteforce, exploit or post exploitation action 
   in to the Metasploit database.
.EXAMPLE
   Set-MSFDBCred -Id 0 -Port 22 -Username sdm -Password 123456 -Type Password -IPAddress 192.168.1.1 | fl *


result      : success
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Set-MSFDBCred
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # Network Port
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Port,

        # Username
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Username,

        # Cleartext password or Hash value
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Password,

        # Type of credential
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("SMB_Hash","Hash","Password","Password_RO" )]
        [string]$Type,

        # IPAddress to associate credential
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$IPAddress,

        # Password active
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [bool]$Active = $true,

        # Database workspace name
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Workspace,

        # Service name
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$ServiceName,

        # Data used to prove the account is actually active.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Proof,

        # The exploit database source ID.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$SourceID,

        # The type of the source of the credentiam (Vuln, Exploit, Cred)
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [string]$SourceType
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        # Parse filtering options
        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'

        if ($Port)
        {
            $dbops.Add('port', $Port)
        }
       
        if ($Username)
        {
            $dbops.Add('user',$Username)
        }

        if ($Password)
        {
            $dbops.Add('pass',$Password)
        }

        if ($Type)
        {
            $dbops.Add('ptype',$Type.ToLower())
        }

        if ($IPAddress)
        {
            $dbops.Add('host', $IPAddress)
        }

        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }

        if ($ServiceName)
        {
            $dbops.Add('sname', $ServiceName)
        }

        if ($Proof)
        {
            $dbops.Add('proof', $Proof)
        }

        if ($SourceID)
        {
            $dbops.Add('source_id', $Proof)
        }

        if ($SourceType)
        {
            $dbops.Add('source_type', $Proof)
        }


        $dbops.Add('active', $Active)

        $request_reply = $MSession.Session.Execute("db.report_cred", $dbops)
        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.report_cred", $dbops)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $connectobj = New-Object -TypeName psobject -Property $request_reply
                        $connectobj.pstypenames[0] = "Metasploit.Action"
                        $connectobj 
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $Id)
                $connectobj = New-Object -TypeName psobject -Property $request_reply
                $connectobj.pstypenames[0] = "Metasploit.Action"
                $connectobj 
            }
        }
    }
}


<#
.Synopsis
   Get credentials saved in the Metasploit Database.
.DESCRIPTION
   Get credentials saved in the Metasploit Database.
.EXAMPLE
   Get-MSFDBCred -Id 0


host        : 192.168.1.1
updated_at  : 1377351861
port        : 22
proto       : tcp
type        : password
user        : sdm
pass        : 123456
active      : True
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Get-MSFDBCred
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # Maximun number of results to pull from server
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [int]$Limit,

        # Workspace to execute query against
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [string]$Workspace
       
    )
    BEGIN 
    {
        # Epoch time 
        [datetime]$origin = '1970-01-01 00:00:00'
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        # Parse filtering options
        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'
        
        if ($Limit)
        {
            $dbops.Add('limit',$Limit)
        }

        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }

        $request_reply = $MSession.Session.Execute("db.creds", $dbops)

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.creds", $dbops)
                    if ($request_reply.ContainsKey('creds'))
                    {
                        foreach ($cred in $request_reply['creds'])
                        {
                            $cred.add('MSHost', $MSession.Host)
                            $cred.Add("MSSessionID", $MSession.Id)
                            $notenobj = New-Object -TypeName psobject -Property $cred
                            $notenobj.pstypenames[0] = "Metasploit.Cred"
                            $notenobj 
                        }
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('creds'))
            {
                foreach ($cred in $request_reply['creds'])
                {
                    $cred.add('MSHost', $MSession.Host)
                    $cred.Add("MSSessionID", $MSession.Id)
                    $notenobj = New-Object -TypeName psobject -Property $cred
                    $notenobj.pstypenames[0] = "Metasploit.Event"
                    $notenobj 
                }
            }
        }
    }
}


<#
.Synopsis
   Get loot entries in the Metasploit Database.
.DESCRIPTION
   Get loot entries in the Metasploit Database.
.EXAMPLE
   Get-MSFDBLoot -Id 0


host        : 192.168.10.10
ltype       : windows.hashes
ctype       : text/plain
created_at  : 1370909705
updated_at  : 1370909705
name        : DC01_hashes.txt
info        : Windows Hashes
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Get-MSFDBLoot
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # Maximun number of results to pull from server
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [int]$Limit,

        # Workspace to execute query against
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [string]$Workspace
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        # Parse filtering options
        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'
        
        if ($Limit)
        {
            $dbops.Add('limit',$Limit)
        }

        if ($Workspace)
        {
            $dbops.Add('workspace', $Workspace)
        }

        $request_reply = $MSession.Session.Execute("db.loots", $dbops)

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.loots", $dbops)
                    if ($request_reply.ContainsKey('loots'))
                    {
                        foreach ($loot in $request_reply['loots'])
                        {
                            $loot.add('MSHost', $MSession.Host)
                            $loot.Add("MSSessionID", $MSession.Id)
                            $notenobj = New-Object -TypeName psobject -Property $loot
                            $notenobj.pstypenames[0] = "Metasploit.Loot"
                            $notenobj 
                        }
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('loots'))
            {
                foreach ($loot in $request_reply['loots'])
                {
                    $loot.add('MSHost', $MSession.Host)
                    $loot.Add("MSSessionID", $MSession.Id)
                    $notenobj = New-Object -TypeName psobject -Property $loot
                    $notenobj.pstypenames[0] = "Metasploit.Loot"
                    $notenobj 
                }
            }
        }
    }
}


<#
.Synopsis
   Get the current database connection status for a Metasploit server.
.DESCRIPTION
   Get the current database connection status for a Metasploit server.
.EXAMPLE
   Get-MSFDBStatus -Id 0 | fl *


driver      : postgresql
db          : msf
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Get-MSFDBStatus
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        $request_reply = $MSession.Session.Execute("db.status")

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.status")
                    if ($request_reply.ContainsKey('driver'))
                    {
                        
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        if (!($request_reply.ContainsKey('db')))
                        {
                            $request_reply.add('db', "")
                        }
                        $dbstatobj = New-Object -TypeName psobject -Property $request_reply
                        $dbstatobj.pstypenames[0] = "Metasploit.DBStatus"
                        $dbstatobj 
                        
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('driver'))
            {
                        
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $MSession.Id)
                if (!($request_reply.ContainsKey('db')))
                {
                    $request_reply.add('db', "")
                }
                $dbstatobj = New-Object -TypeName psobject -Property $request_reply
                $dbstatobj.pstypenames[0] = "Metasploit.DBStatus"
                $dbstatobj 
                        
            }
        }
    }
}


<#
.Synopsis
   Coonect the Metasploit instance to an exiting PostgreSQl Database
.DESCRIPTION
   Coonect the Metasploit instance to an exiting PostgreSQl Database.
.EXAMPLE
    Connect-MSFDB -Id 0 -DBHost 127.0.0.1 -DatabaseName msf -Credentials (Get-Credential msf) | fl *


result      : success
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Connect-MSFDB
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # DB Port
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [int]$Port = 5432,

        # Database Hostname, FQDN or IP relative to the Metasploit server.
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$DBHost,

        # Database name
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$DatabaseName,

        # Credentials for connecting to the Database
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$Credentials

       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        # Parse connection options
        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'
        
        $dbops.Add('database',$DatabaseName)
        $dbops.Add('host', $DBHost)
        $dbops.Add('adapter','postgresql')
        $dbops.Add('username',$Credentials.GetNetworkCredential().UserName)
        $dbops.Add('password',$Credentials.GetNetworkCredential().Password)
        $dbops.Add('port',$Port)

        $request_reply = $MSession.Session.Execute("db.connect", $dbops)

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.connect", $dbops)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $connectobj = New-Object -TypeName psobject -Property $request_reply
                        $connectobj.pstypenames[0] = "Metasploit.Action"
                        $connectobj 
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $connectobj = New-Object -TypeName psobject -Property $request_reply
                $connectobj.pstypenames[0] = "Metasploit.Action"
                $connectobj 
            }
        }
    }
}


<#
.Synopsis
   Disconnects the Metasploit server database.
.DESCRIPTION
   Disconnects the Metasploit server database.
.EXAMPLE
   Disconnect-MSFDB -Id 0 |  fl


result      : success
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Disconnect-MSFDB
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        $request_reply = $MSession.Session.Execute("db.disconnect")

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.disconnect", $dbops)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $connectobj = New-Object -TypeName psobject -Property $request_reply
                        $connectobj.pstypenames[0] = "Metasploit.Action"
                        $connectobj 
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $connectobj = New-Object -TypeName psobject -Property $request_reply
                $connectobj.pstypenames[0] = "Metasploit.Action"
                $connectobj 
            }
        }
    }
}


<#
.Synopsis
   Get workspaces present on a Metaspoit serve.
.DESCRIPTION
   Get workspaces present on a Metaspoit serve.
.EXAMPLE
   Get-MSFDBWorspace -Id 0


name        : default
created_at  : 1352342111
updated_at  : 1352342111
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Get-MSFDBWorspace
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session
       
    )
    BEGIN 
    {
        # Epoch time 
        [datetime]$origin = '1970-01-01 00:00:00'
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        $request_reply = $MSession.Session.Execute("db.workspaces")

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.workspaces")
                    if ($request_reply.ContainsKey('workspaces'))
                    {
                        foreach ($workspace in $request_reply['workspaces'])
                        {
                            $wrkprops = [ordered]@{}
                            $wrkprops.Add("Name", $workspace.name)
                            $wrkprops.Add("Updated", $origin.AddSeconds($workspace.updated_at))
                            $wrkprops.Add("Created", $origin.AddSeconds($workspace.created_at))
                            $wrkprops.add('MSHost', $MSession.Host)
                            $wrkprops.Add("MSSessionID", $MSession.Id)
                            $wsobj = New-Object -TypeName psobject -Property $wrkprops
                            $wsobj.pstypenames[0] = "Metasploit.Workspace"
                            $wsobj 
                        }
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('workspaces'))
            {
                foreach ($workspace in $request_reply['workspaces'])
                {
                    $wrkprops = [ordered]@{}
                    $wrkprops.Add("Name", $workspace.name)
                    $wrkprops.Add("Updated", $origin.AddSeconds($workspace.updated_at))
                    $wrkprops.Add("Created", $origin.AddSeconds($workspace.created_at))
                    $wrkprops.add('MSHost', $MSession.Host)
                    $wrkprops.Add("MSSessionID", $MSession.Id)
                    $wsobj = New-Object -TypeName psobject -Property $wrkprops
                    $wsobj.pstypenames[0] = "Metasploit.Workspace"
                    $wsobj 
                }
            }
        }
    }
}


<#
.Synopsis
   Gets the current Workspace under which a Metasploit server is running under.
.DESCRIPTION
   Gets the current Workspace under which a Metasploit server is running under.
.EXAMPLE
   Get-MSFDBCurrentWorspace -Id 0 | fl *


workspace   : default
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Get-MSFDBCurrentWorspace
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        $request_reply = $MSession.Session.Execute("db.current_workspace")

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.current_workspace")
                    if ($request_reply.ContainsKey('workspace'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $wsobj = New-Object -TypeName psobject -Property $request_reply
                        $wsobj.pstypenames[0] = "Metasploit.Workspace"
                        $wsobj 
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('workspace'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $wsobj = New-Object -TypeName psobject -Property $request_reply
                $wsobj.pstypenames[0] = "Metasploit.Default.Workspace"
                $wsobj 
            }
        }
    }
}


<#
.Synopsis
   Creates a new workspace in the Metasploit server database.
.DESCRIPTION
   Creates a new workspace in the Metasploit server database.
.EXAMPLE
   New-MSFDBWorkspace -Id 0 -Workspace "Engagement4707" | fl *


result      : success
MSHost      : 192.168.1.104
MSSessionID : 0

#>
function New-MSFDBWorkspace
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # Workspace name
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session",
        Position=0)]
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index",
        Position=0)]
        [string]$Workspace
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        $request_reply = $MSession.Session.Execute('db.add_workspace', $Workspace)

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute('db.add_workspace', $Workspace)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $connectobj = New-Object -TypeName psobject -Property $request_reply
                        $connectobj.pstypenames[0] = "Metasploit.Action"
                        $connectobj 
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $connectobj = New-Object -TypeName psobject -Property $request_reply
                $connectobj.pstypenames[0] = "Metasploit.Action"
                $connectobj 
            }
        }
    }
}


<#
.Synopsis
   Deletes a workspace from the Metasploit database.
.DESCRIPTION
   Deletes a workspace from the Metasploit database.
.EXAMPLE
    Remove-MSFDBWorkspace -Id 0 -Workspace test2
result      : success
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Remove-MSFDBWorkspace
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # Workspace name
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session",
        Position=0)]
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index",
        Position=0)]
        [string]$Workspace
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        $request_reply = $MSession.Session.Execute('db.del_workspace', $Workspace)

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute('db.del_workspace', $Workspace)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $connectobj = New-Object -TypeName psobject -Property $request_reply
                        $connectobj.pstypenames[0] = "Metasploit.Action"
                        $connectobj 
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $connectobj = New-Object -TypeName psobject -Property $request_reply
                $connectobj.pstypenames[0] = "Metasploit.Action"
                $connectobj 
            }
        }
    }
}


<#
.Synopsis
   Changes de current working workspace on a Metasploit server database.
.DESCRIPTION
   Changes de current working workspace on a Metasploit server database.
.EXAMPLE
   Get-MSFDBCurrentWorspace -Id 0 | fl


workspace   : default
MSHost      : 192.168.1.104
MSSessionID : 0




PS C:\> Set-MSFDBWorkspace -Id 0 -Workspace "Engagement4707" | fl 


result      : success
MSHost      : 192.168.1.104
MSSessionID : 0




PS C:\> Get-MSFDBCurrentWorspace -Id 0 | fl


workspace   : Engagement4707
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Set-MSFDBWorkspace
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

        # Workspace name
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session",
        Position=0)]
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index",
        Position=0)]
        [string]$Workspace
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -in $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        $request_reply = $MSession.Session.Execute('db.set_workspace', $Workspace)

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute('db.set_workspace', $Workspace)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $connectobj = New-Object -TypeName psobject -Property $request_reply
                        $connectobj.pstypenames[0] = "Metasploit.Action"
                        $connectobj 
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $connectobj = New-Object -TypeName psobject -Property $request_reply
                $connectobj.pstypenames[0] = "Metasploit.Action"
                $connectobj 
            }
        }
    }
}


<#
.Synopsis
   Imports scan files and parses them in to the Metasploit Database.
.DESCRIPTION
   Imports scan files and parses them in to the Metasploit Database. File types are automatically detected.
   Currently supported file types include:
    Acunetix XML
    Amap Log
    Amap Log -m
    Appscan XML
    Burp Session XML
    Foundstone XML
    IP360 ASPL
    IP360 XML v3
    Microsoft Baseline Security Analyzer
    Nessus NBE
    Nessus XML (v1 and v2)
    NetSparker XML
    NeXpose Simple XML
    NeXpose XML Report
    Nmap XML
    OpenVAS Report
    Qualys Asset XML
    Qualys Scan XML
    Retina XML

.EXAMPLE
    Get-MSFDBHost -Id 0

PS C:\> Import-MSFDBData -Id 0 -File C:\Users\Carlos\Desktop\DevLabRepor.nessus

result      : success
MSHost      : 192.168.1.104
MSSessionID : 0                                                                                                                                                     0



PS C:\> Get-MSFDBHost -Id 0


created_at  : 1377957716
address     : 192.168.10.2
mac         : 00:0C:29:F9:CD:9D
name        : 192.168.10.2
state       : alive
os_name     : Microsoft Windows
os_flavor   : Server 2012 Standard
os_sp       : 
os_lang     : 
updated_at  : 1377957716
purpose     : server
info        : 
MSHost      : 192.168.1.104
MSSessionID : 0

created_at  : 1377957715
address     : 192.168.10.3
mac         : 00:0C:29:28:7A:F9
name        : nessus.darkoperator.com
state       : alive
os_name     : Linux
os_flavor   : 
os_sp       : 2.6.32-358
os_lang     : 
updated_at  : 1377957715
purpose     : device
info        : 
MSHost      : 192.168.1.104
MSSessionID : 0

created_at  : 1377957719
address     : 192.168.10.10
mac         : 00:0C:29:2E:1F:F1
name        : 192.168.10.10
state       : alive
os_name     : Microsoft Windows
os_flavor   : Server 2012 Standard
os_sp       : 
os_lang     : 
updated_at  : 1377957719
purpose     : server
info        : 
MSHost      : 192.168.1.104
MSSessionID : 0

created_at  : 1377957718
address     : 192.168.10.12
mac         : 00:0C:29:EB:DF:67
name        : 192.168.10.12
state       : alive
os_name     : Microsoft Windows
os_flavor   : 2008
os_sp       : SP1
os_lang     : 
updated_at  : 1377957718
purpose     : server
info        : 
MSHost      : 192.168.1.104
MSSessionID : 0

created_at  : 1377957716
address     : 192.168.10.13
mac         : 00:0C:29:02:EA:7B
name        : 192.168.10.13
state       : alive
os_name     : Microsoft Windows
os_flavor   : 2008
os_sp       : SP1
os_lang     : 
updated_at  : 1377957716
purpose     : server
info        : 
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Import-MSFDBData
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        [psobject]$Session,

         # Workspace to execute query against
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [string]$Workspace,

        # File with data to import
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
        [ValidateScript({Test-Path $_})]
        [string]$File

       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Id -ge 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.Id -eq $Id)
                {
                    $MSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Metasploit.Session")
        {
            if ($Global:MetasploitConn.Contains($Session))
            {
                $MSession = $Session
            }
            else
            {
                throw "The session object that was passed does not exists in `$Global:MetasploitConn"
            }
        }
        else 
        {
            throw "No Metasploit server session was provided"
        }

        if ($MSession -eq $null)
        {
            throw "Specified session was not found"
        }

        Write-Verbose "Reading file $($File)"
        $Data = Get-Content -Raw $File

        # Parse connection options
        $dbops = New-Object 'system.collections.generic.dictionary[string,object]'       
        $dbops.Add('data',$Data)
 

        $request_reply = $MSession.Session.Execute("db.import_data", $dbops)

        if ($request_reply.ContainsKey("error_code"))
        {
            Write-Verbose "An error was reported with code $($request_reply.error_code)"
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.URI
                $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
                if ($msfsess)
                {
                    Write-Verbose "Authentication successful."
                    # Select the correct session manager for the existing session
                    if ($MSession.Manager.GetType().tostring() -eq 'metasploitsharp.MetasploitManager')
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                    }
                    else
                    {
                        $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                    }

                    # Build the session object
                    $SessionProps.Add('Manager',$msfmng)
                    $SessionProps.Add('URI',$MSession.URI)
                    $SessionProps.add('Host',$MSession.host)
                    $SessionProps.add('Session',$msfsess)
                    $SessionProps.Add('Credentials',$MSession.Credentials)
                    $SessionProps.Add('Id', $MSession.Id)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)
                    
                    # Get again the Optios
                    $request_reply = $sessionobj.Session.Execute("db.import_data", $dbops)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $connectobj = New-Object -TypeName psobject -Property $request_reply
                        $connectobj.pstypenames[0] = "Metasploit.Action"
                        $connectobj 
                    }
                }
            }

            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $connectobj = New-Object -TypeName psobject -Property $request_reply
                $connectobj.pstypenames[0] = "Metasploit.Action"
                $connectobj 
            }
        }
    }
}