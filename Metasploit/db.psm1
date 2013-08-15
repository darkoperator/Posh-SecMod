

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
function Get-MetasploitDBHost
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session index
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [psobject]$Session,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index")]
        [switch]$OnlyUp,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [int]$Limit,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Workspace
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Index.Count -gt 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.index -in $Index)
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
                    $SessionProps.Add('Index', $MSession.index)
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
                            $dbhost.add('MSHost', $MSession.Host)
                            $consoleobj = New-Object -TypeName psobject -Property $dbhost
                            $consoleobj.pstypenames[0] = "Metasploit.host"
                            $consoleobj 
                        }
                    }
                }
            }
        }
        else
        {
            if ($request_reply.ContainsKey('hosts'))
            {
                foreach ($dbhost in $request_reply['hosts'])
                {
                    $dbhost.add('MSHost', $MSession.Host)
                    $consoleobj = New-Object -TypeName psobject -Property $dbhost
                    $consoleobj.pstypenames[0] = "Metasploit.host"
                    $consoleobj 
                }
            }
        }
    }
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
function Get-MetasploitDBServcie
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session index
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [psobject]$Session,

        # Metasploit session object
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [switch]$OnlyUp,

        # Port list or range to filter
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Ports,

        # Filter services by protocol TCP or UDP
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        # Filter services by name
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Name,

        # Filter services by Address
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Address,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [int]$Limit,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Workspace
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Index.Count -gt 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.index -in $Index)
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
                    $SessionProps.Add('Index', $MSession.index)
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
                        foreach ($dbhost in $request_reply['services'])
                        {
                            $dbhost.add('MSHost', $MSession.Host)
                            $consoleobj = New-Object -TypeName psobject -Property $dbhost
                            $consoleobj.pstypenames[0] = "Metasploit.Service"
                            $consoleobj 
                        }
                    }
                }
            }
        }
        else
        {
            if ($request_reply.ContainsKey('services'))
            {
                foreach ($dbhost in $request_reply['services'])
                {
                    $dbhost.add('MSHost', $MSession.Host)
                    $consoleobj = New-Object -TypeName psobject -Property $dbhost
                    $consoleobj.pstypenames[0] = "Metasploit.Service"
                    $consoleobj 
                }
            }
        }
    }
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
function Get-MetasploitDBVuln
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session index
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [psobject]$Session,

        # Port list or range to filter
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Ports,

        # Filter services by protocol TCP or UDP
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        # Filter services by name
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Name,

        # Filter services by Address
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Address,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [int]$Limit,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Workspace
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Index.Count -gt 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.index -in $Index)
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
                    $SessionProps.Add('Index', $MSession.index)
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
                            $vuln.add('MSHost', $MSession.Host)
                            $vulnobj = New-Object -TypeName psobject -Property $vuln
                            $vulnobj.pstypenames[0] = "Metasploit.Vuln"
                            $vulnobj 
                        }
                    }
                }
            }
        }
        else
        {
            if ($request_reply.ContainsKey('vulns'))
            {
                foreach ($vuln in $request_reply['vulns'])
                {
                    $vuln.add('MSHost', $MSession.Host)
                    $vulnobj = New-Object -TypeName psobject -Property $vuln
                    $vulnobj.pstypenames[0] = "Metasploit.Vuln"
                    $vulnobj 
                }
            }
        }
    }
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
function Get-MetasploitDBNote
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session index
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [psobject]$Session,

        # Port list or range to filter
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Ports,

        # Filter services by protocol TCP or UDP
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        # Filter services by name
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Name,

        # Filter services by Address
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Address,

        # Maximun number of results to pull from server
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [int]$Limit,

        # Workspace to execute query against
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Workspace,

        # Note ntype
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Type
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Index.Count -gt 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.index -in $Index)
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
                    $SessionProps.Add('Index', $MSession.index)
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
                            $note.add('MSHost', $MSession.Host)
                            $notenobj = New-Object -TypeName psobject -Property $note
                            $notenobj.pstypenames[0] = "Metasploit.Note"
                            $notenobj 
                        }
                    }
                }
            }
        }
        else
        {
            if ($request_reply.ContainsKey('notes'))
            {
                foreach ($note in $request_reply['notes'])
                {
                    $note.add('MSHost', $MSession.Host)
                    $notenobj = New-Object -TypeName psobject -Property $note
                    $notenobj.pstypenames[0] = "Metasploit.Note"
                    $notenobj 
                }
            }
        }
    }
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
function Get-MetasploitDBEvent
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session index
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [psobject]$Session,

        # Maximun number of results to pull from server
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [int]$Limit,

        # Workspace to execute query against
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Workspace
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Index.Count -gt 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.index -in $Index)
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
                    $SessionProps.Add('Index', $MSession.index)
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
                            $event.add('MSHost', $MSession.Host)
                            $notenobj = New-Object -TypeName psobject -Property $event
                            $notenobj.pstypenames[0] = "Metasploit.Event"
                            $notenobj 
                        }
                    }
                }
            }
        }
        else
        {
            if ($request_reply.ContainsKey('events'))
            {
                foreach ($event in $request_reply['events'])
                {
                    $event.add('MSHost', $MSession.Host)
                    $notenobj = New-Object -TypeName psobject -Property $event
                    $notenobj.pstypenames[0] = "Metasploit.Event"
                    $notenobj 
                }
            }
        }
    }
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
function Get-MetasploitDBCred
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session index
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [psobject]$Session,

        # Maximun number of results to pull from server
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [int]$Limit,

        # Workspace to execute query against
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Workspace
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Index.Count -gt 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.index -in $Index)
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
                    $SessionProps.Add('Index', $MSession.index)
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
                            $notenobj = New-Object -TypeName psobject -Property $cred
                            $notenobj.pstypenames[0] = "Metasploit.Cred"
                            $notenobj 
                        }
                    }
                }
            }
        }
        else
        {
            if ($request_reply.ContainsKey('creds'))
            {
                foreach ($cred in $request_reply['creds'])
                {
                    $cred.add('MSHost', $MSession.Host)
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-MetasploitDBLoot
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session index
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [psobject]$Session,

        # Maximun number of results to pull from server
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [int]$Limit,

        # Workspace to execute query against
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [string]$Workspace
       
    )
    BEGIN 
    {
        
        
    }
    PROCESS 
    {    
        if ($Index.Count -gt 0)
        {
            foreach($conn in $Global:MetasploitConn)
            {
                if ($conn.index -in $Index)
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
                    $SessionProps.Add('Index', $MSession.index)
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
                            $notenobj = New-Object -TypeName psobject -Property $loot
                            $notenobj.pstypenames[0] = "Metasploit.Loot"
                            $notenobj 
                        }
                    }
                }
            }
        }
        else
        {
            if ($request_reply.ContainsKey('loots'))
            {
                foreach ($loot in $request_reply['loots'])
                {
                    $loot.add('MSHost', $MSession.Host)
                    $notenobj = New-Object -TypeName psobject -Property $loot
                    $notenobj.pstypenames[0] = "Metasploit.Loot"
                    $notenobj 
                }
            }
        }
    }
}