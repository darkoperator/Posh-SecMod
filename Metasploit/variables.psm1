# Variables
#########################################################################################

#region Variables

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
function Set-MetasploitGlobalVariable
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

        # Variable name
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        Position=1)]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=1)]
        [string]$Name,

        # Variable Value
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        Position=2)]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=2)]
        [string]$Value

       
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
        
        $request_reply = $MSession.Manager.SetCoreGlobalVariable($Name,$Value)

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
                    $SessionProps.Add('Index', $MSession.index)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)

                    # Get again the information
                    $request_reply = $sessionobj.Manager.SetCoreGlobalVariable($Name,$Value)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $consoleobj = New-Object -TypeName psobject -Property $request_reply
                        $consoleobj.pstypenames[0] = "Metasploit.Action"
                        $consoleobj   
                    }
                }
            }
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $consoleobj = New-Object -TypeName psobject -Property $request_reply
                $consoleobj.pstypenames[0] = "Metasploit.Action"
                $consoleobj   
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
function Remove-MetasploitGlobalVariable
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

        # Variable name
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        Position=1)]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=1)]
        [string]$Name
       
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
        
        $request_reply = $MSession.Manager.UnsetCoreGlobalVariable($Name)

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
                    $SessionProps.Add('Index', $MSession.index)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)

                    # Get again the information
                    $request_reply = $sessionobj.Manager.UnsetCoreGlobalVariable($Name)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $consoleobj = New-Object -TypeName psobject -Property $request_reply
                        $consoleobj.pstypenames[0] = "Metasploit.Action"
                        $consoleobj   
                    }
                }
            }
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $consoleobj = New-Object -TypeName psobject -Property $request_reply
                $consoleobj.pstypenames[0] = "Metasploit.Action"
                $consoleobj   
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
function Save-MetasploitConfig
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
        [psobject]$Session
       
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
        
        $request_reply = $MSession.Manager.SaveCore()

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
                    $SessionProps.Add('Index', $MSession.index)
                    $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                    $sessionobj.pstypenames[0] = "Metasploit.Session"

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)

                    # Get again the information
                    $request_reply = $sessionobj.Manager.SaveCore()
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $consoleobj = New-Object -TypeName psobject -Property $request_reply
                        $consoleobj.pstypenames[0] = "Metasploit.Action"
                        $consoleobj   
                    }
                }
            }
        }
        else
        {
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $consoleobj = New-Object -TypeName psobject -Property $request_reply
                $consoleobj.pstypenames[0] = "Metasploit.Action"
                $consoleobj   
            }
        }
    }
}

#endregion