

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
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [switch]$OnlyUp,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [int]$Limit,

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
                            $dbhost.add('MSHost', $MSession.Host)
                            $dbhost.Add("MSSessionID", $MSession.Id)
                            $consoleobj = New-Object -TypeName psobject -Property $dbhost
                            $consoleobj.pstypenames[0] = "Metasploit.host"
                            $consoleobj 
                        }
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        else
        {
            if ($request_reply.ContainsKey('hosts'))
            {
                foreach ($dbhost in $request_reply['hosts'])
                {
                    $dbhost.add('MSHost', $MSession.Host)
                    $dbhost.Add("MSSessionID", $MSession.Id)
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

        # Metasploit session object
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [switch]$OnlyUp,

        # Port list or range to filter
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [string]$Ports,

        # Filter services by protocol TCP or UDP
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        # Filter services by name
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [string]$Name,

        # Filter services by Address
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [string]$Address,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [int]$Limit,

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
                        foreach ($dbhost in $request_reply['services'])
                        {
                            $dbhost.add('MSHost', $MSession.Host)
                            $dbhost.Add("MSSessionID", $MSession.Id)
                            $consoleobj = New-Object -TypeName psobject -Property $dbhost
                            $consoleobj.pstypenames[0] = "Metasploit.Service"
                            $consoleobj 
                        }
                    }
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        else
        {
            if ($request_reply.ContainsKey('services'))
            {
                foreach ($dbhost in $request_reply['services'])
                {
                    $dbhost.add('MSHost', $MSession.Host)
                    $dbhost.Add("MSSessionID", $MSession.Id)
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
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [string]$Ports,

        # Filter services by protocol TCP or UDP
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        # Filter services by name
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [string]$Name,

        # Filter services by Address
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [string]$Address,

        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [int]$Limit,

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
                            $vuln.Add('MSHost', $MSession.Host)
                            $vuln.Add("MSSessionID", $MSession.Id)
                            $vulnobj = New-Object -TypeName psobject -Property $vuln
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
        else
        {
            if ($request_reply.ContainsKey('vulns'))
            {
                foreach ($vuln in $request_reply['vulns'])
                {
                    $vuln.add('MSHost', $MSession.Host)
                    $vuln.Add("MSSessionID", $MSession.Id)
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
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [string]$Ports,

        # Filter services by protocol TCP or UDP
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        # Filter services by name
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [string]$Name,

        # Filter services by Address
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [string]$Address,

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
        [string]$Workspace,

        # Note ntype
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [string]$Type
       
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
                            $note.add('MSHost', $MSession.Host)
                            $note.Add("MSSessionID", $MSession.Id)
                            $notenobj = New-Object -TypeName psobject -Property $note
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
        else
        {
            if ($request_reply.ContainsKey('notes'))
            {
                foreach ($note in $request_reply['notes'])
                {
                    $note.add('MSHost', $MSession.Host)
                    $note.Add("MSSessionID", $MSession.Id)
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
                            $event.add('MSHost', $MSession.Host)
                            $event.Add("MSSessionID", $MSession.Id)
                            $notenobj = New-Object -TypeName psobject -Property $event
                            $notenobj.pstypenames[0] = "Metasploit.Event"
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
        else
        {
            if ($request_reply.ContainsKey('events'))
            {
                foreach ($event in $request_reply['events'])
                {
                    $event.add('MSHost', $MSession.Host)
                    $event.Add("MSSessionID", $MSession.Id)
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [int]$Port = 5432,

        # Database Host
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [string]$DBHost,

        # Database name
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
                            $workspace.add('MSHost', $MSession.Host)
                            $workspace.Add("MSSessionID", $MSession.Id)
                            $wsobj = New-Object -TypeName psobject -Property $workspace
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
        else
        {
            if ($request_reply.ContainsKey('workspaces'))
            {
                foreach ($workspace in $request_reply['workspaces'])
                {
                    $workspace.add('MSHost', $MSession.Host)
                    $workspace.Add("MSSessionID", $MSession.Id)
                    $wsobj = New-Object -TypeName psobject -Property $workspace
                    $wsobj.pstypenames[0] = "Metasploit.Workspace"
                    $wsobj 
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
        else
        {
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
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