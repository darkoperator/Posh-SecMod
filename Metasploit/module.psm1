
<#
.Synopsis
   Gets the module count for each type on a Metasploit server.
.DESCRIPTION
   Gets the module count for each type on a Metasploit server.
.EXAMPLE
   Get-MSFModuleStats -Id 0


exploits    : 1167
auxiliary   : 641
post        : 185
encoders    : 30
nops        : 8
payloads    : 312
MSHost      : 192.168.1.104
MSSessionID : 0

#>
function Get-MSFModuleStats
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
        
        $request_reply = $MSession.Manager.GetCoreModuleStats()

        if ($request_reply.ContainsKey("error_code"))
        {
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

                    # Get again the information
                    $request_reply = $sessionobj.Manager.GetCoreModuleStats()
                    if ($request_reply.ContainsKey('post'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $consoleobj = New-Object -TypeName psobject -Property $request_reply
                        $consoleobj.pstypenames[0] = "Metasploit.Module.Stats"
                        $consoleobj   
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
            if ($request_reply.ContainsKey('post'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $consoleobj = New-Object -TypeName psobject -Property $request_reply
                $consoleobj.pstypenames[0] = "Metasploit.Module.Stats"
                $consoleobj   
            }
        }
    }
}


<#
.Synopsis
   Reloads all modules in a Metasploit server.
.DESCRIPTION
   Reloads all modules in a Metasploit server and returns the new module count per type.
.EXAMPLE
   Invoke-MSFModuleReload -Id 0


exploits    : 1167
auxiliary   : 641
post        : 185
encoders    : 30
nops        : 8
payloads    : 312
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Invoke-MSFModuleReload
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
        
        $request_reply = $MSession.Manager.ReloadCoreModules()

        if ($request_reply.ContainsKey("error_code"))
        {
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

                    # Get again the information
                    $request_reply = $sessionobj.Manager.ReloadCoreModules()
                    if ($request_reply.ContainsKey('post'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $consoleobj = New-Object -TypeName psobject -Property $request_reply
                        $consoleobj.pstypenames[0] = "Metasploit.Module.Stats"
                        $consoleobj   
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
            if ($request_reply.ContainsKey('post'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $consoleobj = New-Object -TypeName psobject -Property $request_reply
                $consoleobj.pstypenames[0] = "Metasploit.Module.Stats"
                $consoleobj   
            }
        }
    }
}


<#
.Synopsis
   Retrieves the name of all Auxiliary Modules in a Metasploit server.
.DESCRIPTION
   Retrieves the name of all Auxiliary Modules in a Metasploit server.
.EXAMPLE
   Get-MSFAuxiliaryModule -Id 0 | where {$_.name -like "*ipmi*"} | fl *


MSHost      : 192.168.1.104
Name        : scanner/ipmi/ipmi_version
MSSessionID : 0

MSHost      : 192.168.1.104
Name        : scanner/ipmi/ipmi_dumphashes
MSSessionID : 0

MSHost      : 192.168.1.104
Name        : scanner/ipmi/ipmi_cipher_zero
MSSessionID : 0
#>
function Get-MSFAuxiliaryModule
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
        
        $request_reply = $MSession.Manager.GetAuxiliaryModules()

        if ($request_reply.ContainsKey("error_code"))
        {
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

                    # Get again the information
                    $request_reply = $sessionobj.Manager.GetAuxiliaryModules()
                    if ($request_reply.ContainsKey('modules'))
                    {
                        foreach ($module in $request_reply['modules'])
                        {
                            $moduleprops = @{}
                            $moduleprops.add('MSHost', $MSession.Host)
                            $moduleprops.Add('Name', $module)
                            $moduleprops.Add("MSSessionID", $MSession.Id)
                            $consoleobj = New-Object -TypeName psobject -Property $moduleprops
                            $consoleobj.pstypenames[0] = "Metasploit.Module.auxiliary"
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
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('modules'))
            {
                foreach ($module in $request_reply['modules'])
                {
                    $moduleprops = @{}
                    $moduleprops.add('MSHost', $MSession.Host)
                    $moduleprops.Add('Name', $module)
                    $moduleprops.Add("MSSessionID", $MSession.Id)
                    $consoleobj = New-Object -TypeName psobject -Property $moduleprops
                    $consoleobj.pstypenames[0] = "Metasploit.Module.auxiliary"
                    $consoleobj
                }   
            }
        }
    }
}


<#
.Synopsis
   Retrieves the name of all Post  Modules in a Metasploit server.
.DESCRIPTION
   Retrieves the name of all Post  Modules in a Metasploit server.
#>
function Get-MSFPostModule
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
        
        $request_reply = $MSession.Manager.GetPostModules()

        if ($request_reply.ContainsKey("error_code"))
        {
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

                    # Get again the information
                    $request_reply = $sessionobj.Manager.GetPostModules()
                    if ($request_reply.ContainsKey('modules'))
                    {
                        foreach ($module in $request_reply['modules'])
                        {
                            $moduleprops = @{}
                            $moduleprops.add('MSHost', $MSession.Host)
                            $moduleprops.Add('Name', $module)
                            $moduleprops.Add("MSSessionID", $MSession.Id)
                            $consoleobj = New-Object -TypeName psobject -Property $moduleprops
                            $consoleobj.pstypenames[0] = "Metasploit.Module.post"
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
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('modules'))
            {
                foreach ($module in $request_reply['modules'])
                {
                    $moduleprops = @{}
                    $moduleprops.add('MSHost', $MSession.Host)
                    $moduleprops.Add('Name', $module)
                    $moduleprops.Add("MSSessionID", $MSession.Id)
                    $consoleobj = New-Object -TypeName psobject -Property $moduleprops
                    $consoleobj.pstypenames[0] = "Metasploit.Module.post"
                    $consoleobj
                }   
            }
        }
    }
}


<#
.Synopsis
   Retrieves the name of all Exploit  Modules in a Metasploit server.
.DESCRIPTION
   Retrieves the name of all Exploit  Modules in a Metasploit server.
#>
function Get-MSFExploitModule
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
        
        $request_reply = $MSession.Manager.GetExploitModules()

        if ($request_reply.ContainsKey("error_code"))
        {
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

                    # Get again the information
                    $request_reply = $sessionobj.Manager.GetExploitModules()
                    if ($request_reply.ContainsKey('modules'))
                    {
                        foreach ($module in $request_reply['modules'])
                        {
                            $moduleprops = @{}
                            $moduleprops.add('MSHost', $MSession.Host)
                            $moduleprops.Add('Name', $module)
                            $moduleprops.Add("MSSessionID", $MSession.Id)
                            $consoleobj = New-Object -TypeName psobject -Property $moduleprops
                            $consoleobj.pstypenames[0] = "Metasploit.Module.exploit"
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
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.ContainsKey('modules'))
            {
                foreach ($module in $request_reply['modules'])
                {
                    $moduleprops = @{}
                    $moduleprops.add('MSHost', $MSession.Host)
                    $moduleprops.Add('Name', $module)
                    $moduleprops.Add("MSSessionID", $MSession.Id)
                    $consoleobj = New-Object -TypeName psobject -Property $moduleprops
                    $consoleobj.pstypenames[0] = "Metasploit.Module.exploit"
                    $consoleobj
                }   
            }
        }
    }
}

<#
.Synopsis
   Retrieves the name of all Payload  Modules in a Metasploit server.
.DESCRIPTION
   Retrieves the name of all Payload  Modules in a Metasploit server.
#>
function Get-MSFPayloadModule
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
        
        $request_reply = $MSession.Manager.GetPayloads()

        if ($request_reply.ContainsKey("error_code"))
        {
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

                    # Get again the information
                    $request_reply = $sessionobj.Manager.GetPayloads()
                    if ($request_reply.ContainsKey('modules'))
                    {
                        foreach ($module in $request_reply['modules'])
                        {
                            $moduleprops = @{}
                            $moduleprops.add('MSHost', $MSession.Host)
                            $moduleprops.Add('Name', $module)
                            $moduleprops.Add("MSSessionID", $MSession.Id)
                            $consoleobj = New-Object -TypeName psobject -Property $moduleprops
                            $consoleobj.pstypenames[0] = "Metasploit.Module.payload"
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
            if ($request_reply.ContainsKey('modules'))
            {
                foreach ($module in $request_reply['modules'])
                {
                    $moduleprops = @{}
                    $moduleprops.add('MSHost', $MSession.Host)
                    $moduleprops.Add('Name', $module)
                    $moduleprops.Add("MSSessionID", $MSession.Id)
                    $consoleobj = New-Object -TypeName psobject -Property $moduleprops
                    $consoleobj.pstypenames[0] = "Metasploit.Module.payload"
                    $consoleobj
                }   
            }
        }
    }
}

<#
.Synopsis
   Retrieves the name of all Nop  Modules in a Metasploit server.
.DESCRIPTION
   Retrieves the name of all Nop  Modules in a Metasploit server.
#>
function Get-MSFNOPS
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
        
        $request_reply = $MSession.Manager.GetNops()

        if ($request_reply.ContainsKey("error_code"))
        {
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

                    # Get again the information
                    $request_reply = $sessionobj.Manager.GetNops()
                    if ($request_reply.ContainsKey('modules'))
                    {
                        foreach ($module in $request_reply['modules'])
                        {
                            $moduleprops = @{}
                            $moduleprops.add('MSHost', $MSession.Host)
                            $moduleprops.Add('Name', $module)
                            $moduleprops.Add("MSSessionID", $MSession.Id)
                            $consoleobj = New-Object -TypeName psobject -Property $moduleprops
                            $consoleobj.pstypenames[0] = "Metasploit.Module.NOP"
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
            if ($request_reply.ContainsKey('modules'))
            {
                foreach ($module in $request_reply['modules'])
                {
                    $moduleprops = @{}
                    $moduleprops.add('MSHost', $MSession.Host)
                    $moduleprops.Add('Name', $module)
                    $moduleprops.Add("MSSessionID", $MSession.Id)
                    $consoleobj = New-Object -TypeName psobject -Property $moduleprops
                    $consoleobj.pstypenames[0] = "Metasploit.Module.NOP"
                    $consoleobj
                }   
            }
        }
    }
}

<#
.Synopsis
   Gets information about a specic module in a Metasploit server.
.DESCRIPTION
   Gets information about a specic module in a Metasploit server.
.EXAMPLE
   Get-MSFModuleInfo -Id 0 -Name scanner/ipmi/ipmi_version -Type auxiliary | fl *


name        : IPMI Information Discovery
description : Discover host information through IPMI Channel Auth probes
license     : Metasploit Framework License (BSD)
filepath    : /usr/local/share/metasploit-framework/modules/auxiliary/scanner/ipmi/ipmi_version.rb
rank        : 300
references  : {URL http://fish2.com/ipmi/}
authors     : {Dan Farmer <zen@fish2.com>, hdm <hdm@metasploit.com>}
actions     : {}
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Get-MSFModuleInfo
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

        # Module name
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
        [string]$Name,

        # Module Type
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipelineByPropertyName=$true,
        Position=2)]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        ValueFromPipelineByPropertyName=$true,
        Position=2)]
        [ValidateSet('post','auxiliary','exploit', 'payload')]
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
        
        Write-Verbose "Getting information for module $name of type $type."
        $request_reply = $MSession.Manager.GetModuleInformation($Type.ToLower(),$Name)

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

                    # Get again the information
                    $request_reply = $sessionobj.Manager.GetModuleInformation($Type.ToLower(),$Name)
                    if ($request_reply.ContainsKey('name'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $consoleobj = New-Object -TypeName psobject -Property $request_reply
                        $consoleobj.pstypenames[0] = "Metasploit.Module.Info"
                        $consoleobj 
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
            if ($request_reply.ContainsKey('name'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $consoleobj = New-Object -TypeName psobject -Property $request_reply
                $consoleobj.pstypenames[0] = "Metasploit.Module.Info"
                $consoleobj
            }
        }
    }
}


<#
.Synopsis
   Identify compatible payloads for a specific exploit on a Metasploit server.
.DESCRIPTION
   Identify compatible payloads for a specific exploit on a Metasploit server.
.EXAMPLE
    Get-MSFExploitCompatiblePayloads -Id 0 -Name aix/rpc_cmsd_opcode21  | fl *


MSHost      : 192.168.1.104
Name        : aix/ppc/shell_bind_tcp
MSSessionID : 0

MSHost      : 192.168.1.104
Name        : aix/ppc/shell_reverse_tcp
MSSessionID : 0

MSHost      : 192.168.1.104
Name        : generic/custom
MSSessionID : 0

MSHost      : 192.168.1.104
Name        : generic/shell_bind_tcp
MSSessionID : 0

MSHost      : 192.168.1.104
Name        : generic/shell_reverse_tcp
MSSessionID : 0

#>
function Get-MSFExploitCompatiblePayloads
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

        # Exploit Module name
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
        [string]$Name
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
        
        $request_reply = $MSession.Manager.GetModuleCompatiblePayloads($Name)

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

                    # Get again the information
                    $request_reply = $sessionobj.Manager.GetModuleCompatiblePayloads($Name)
                    $request_reply
                    if ($request_reply.ContainsKey('payloads'))
                    {
                        foreach ($payload in $request_reply['payloads'])
                        {
                            $moduleprops = @{}
                            $moduleprops.add('MSHost', $MSession.Host)
                            $moduleprops.Add('Name', $payload)
                            $moduleprops.Add("MSSessionID", $MSession.Id)
                            $consoleobj = New-Object -TypeName psobject -Property $moduleprops
                            $consoleobj.pstypenames[0] = "Metasploit.Module.payload"
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
            if ($request_reply.ContainsKey('payloads'))
            {
                foreach ($payload in $request_reply['payloads'])
                {
                    $moduleprops = @{}
                    $moduleprops.add('MSHost', $MSession.Host)
                    $moduleprops.Add('Name', $payload)
                    $moduleprops.Add("MSSessionID", $MSession.Id)
                    $consoleobj = New-Object -TypeName psobject -Property $moduleprops
                    $consoleobj.pstypenames[0] = "Metasploit.Module.payload"
                    $consoleobj
                }  
            }
        }
    }
}


<#
.Synopsis
   Get all options and details for a specific module on a Metasploit server.
.DESCRIPTION
   Get all options and details for a specific module on a Metasploit server.
.EXAMPLE
   Get-MSFModuleOptions -Id 0 -Name windows/meterpreter/reverse_tcp -Type payload -Verbose
VERBOSE: Getting information for module windows/meterpreter/reverse_tcp of type payload.


WORKSPACE                  : {[type, string], [required, False], [advanced, True], [evasion, False]...}
VERBOSE                    : {[type, bool], [required, False], [advanced, True], [evasion, False]...}
LHOST                      : {[type, address], [required, True], [advanced, False], [evasion, False]...}
LPORT                      : {[type, port], [required, True], [advanced, False], [evasion, False]...}
ReverseConnectRetries      : {[type, integer], [required, True], [advanced, True], [evasion, False]...}
ReverseListenerBindAddress : {[type, address], [required, False], [advanced, True], [evasion, False]...}
ReverseListenerComm        : {[type, string], [required, False], [advanced, True], [evasion, False]...}
ReverseAllowProxy          : {[type, bool], [required, True], [advanced, True], [evasion, False]...}
EnableStageEncoding        : {[type, bool], [required, False], [advanced, True], [evasion, False]...}
StageEncoder               : {[type, string], [required, False], [advanced, True], [evasion, False]...}
PrependMigrate             : {[type, bool], [required, True], [advanced, True], [evasion, False]...}
PrependMigrateProc         : {[type, string], [required, False], [advanced, True], [evasion, False]...}
EXITFUNC                   : {[type, raw], [required, True], [advanced, False], [evasion, False]...}
AutoLoadStdapi             : {[type, bool], [required, True], [advanced, True], [evasion, False]...}
InitialAutoRunScript       : {[type, string], [required, False], [advanced, True], [evasion, False]...}
AutoRunScript              : {[type, string], [required, False], [advanced, True], [evasion, False]...}
AutoSystemInfo             : {[type, bool], [required, True], [advanced, True], [evasion, False]...}
EnableUnicodeEncoding      : {[type, bool], [required, True], [advanced, True], [evasion, False]...}
MSHost                     : 192.168.1.104
MSSessionID                : 0
#>
function Get-MSFModuleOptions
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

        # Module name
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
        [string]$Name,

        # Module Type
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipelineByPropertyName=$true,
        Position=2)]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        ValueFromPipelineByPropertyName=$true,
        Position=2)]
        [ValidateSet('post','auxiliary','exploit', 'payload')]
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
        
        Write-Verbose "Getting information for module $name of type $type."
        $request_reply = $MSession.Manager.GetModuleOptions($Type.ToLower(),$Name)

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
                    $request_reply = $sessionobj.Manager.GetModuleOptions($Type.ToLower(),$Name)
                    $request_reply
                    if ($request_reply.ContainsKey('WORKSPACE'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $consoleobj = New-Object -TypeName psobject -Property $request_reply
                        $consoleobj.pstypenames[0] = "Metasploit.Module.Option"
                        $consoleobj 
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
            if ($request_reply.ContainsKey('WORKSPACE'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $consoleobj = New-Object -TypeName psobject -Property $request_reply
                $consoleobj.pstypenames[0] = "Metasploit.Module.Option"
                $consoleobj
            }
        }
    }
}


<#
.Synopsis
   Enumerates what sessions on a Metasploit server are compatible with a give Post Module
.DESCRIPTION
   Enumerates what sessions on a Metasploit server are compatible with a give Post Module
.EXAMPLE
   Get-MSFCompatibleSession -Id 0 -Name "multi/general/execute" | fl *


MSHost      : 192.168.1.104
Session     : 1
MSSessionID : 0

MSHost      : 192.168.1.104
Session     : 2
MSSessionID : 0
#>
function Get-MSFPostCompatibleSession
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

        # Post Module Name
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
        [string]$Name
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
        
        $request_reply = $MSession.Manager.GetModuleCompatibleSessions($Name)
       
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

                    # Get again the information
                    $request_reply = $sessionobj.Manager.GetModuleCompatibleSessions($Name)
                    
                    if ($request_reply.ContainsKey('sessions'))
                    {
                        foreach ($sessionidx in $request_reply['sessions'])
                        {
                            $moduleprops = @{}
                            $moduleprops.add('MSHost', $MSession.Host)
                            $moduleprops.Add("MSSessionID", $MSession.Id)
                            $moduleprops.Add("Session", $sessionidx)
                            $consoleobj = New-Object -TypeName psobject -Property $moduleprops
                            $consoleobj.pstypenames[0] = "Metasploit.Module.Session"
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
            if ($request_reply.ContainsKey('sessions'))
            {
                foreach ($sessionidx in $request_reply['sessions'])
                {
                    $moduleprops = @{}
                    $moduleprops.add('MSHost', $MSession.Host)
                    $moduleprops.Add("MSSessionID", $MSession.Id)
                    $moduleprops.Add("Session", $sessionidx)
                    $consoleobj = New-Object -TypeName psobject -Property $moduleprops
                    $consoleobj.pstypenames[0] = "Metasploit.Module.Session"
                    $consoleobj
                }  
            }
        }
    }
}


<#
.Synopsis
   Invoke a specific module on a Metasploit server.
.DESCRIPTION
   Invoke a specific module on a Metasploit server.
.EXAMPLE
   Invoke-MSFModule -Id 0 -Type exploit -Name "multi/handler" -Options @{"PAYLOAD"="windows/meterpreter/reverse_tcp"; "LHOST"="192.168.1.104";"LPORT"=8080 } -Verbose 
VERBOSE: Getting information for module multi/handler of type exploit.


job_id      : 4
uuid        : 9mo0x0ql
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Invoke-MSFModule
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

        # Module name
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
        [string]$Name,

        # Module Type
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=2)]
        [ValidateSet('post','auxiliary','exploit', 'payload')]
        [string]$Type,

        # Module Options
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipelineByPropertyName=$true,
        Position=3)]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        ValueFromPipelineByPropertyName=$true,
        Position=3)]
        [hashtable]$Options
       
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

        $ops = New-Object 'system.collections.generic.dictionary[string,object]'
        foreach ($opt in $Options.Keys)
        {
            $ops.Add($opt,$Options[$opt])
        }
        
        Write-Verbose "Getting information for module $name of type $type."
        $request_reply = $MSession.Manager.ExecuteModule($Type.ToLower(),$Name, $ops)
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
                    $request_reply = $sessionobj.Manager.ExecuteModule($Type.ToLower(),$Name, $ops)
                    if ($request_reply.ContainsKey('job_id'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $consoleobj = New-Object -TypeName psobject -Property $request_reply
                        $consoleobj.pstypenames[0] = "Metasploit.Job"
                        $consoleobj 
                    }
                    else
                    {
                        Write-error "Module failed to execute, ensure name and options are correct."
                        return
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
            if ($request_reply.ContainsKey('job_id'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $consoleobj = New-Object -TypeName psobject -Property $request_reply
                $consoleobj.pstypenames[0] = "Metasploit.Job"
                $consoleobj
            }
            else
            {
                Write-error "Module failed to execute, ensure name and options are correct."
            }
        }
    }
}
