if (!(Test-Path variable:Global:MetasploitConn ))
{
    $Global:MetasploitConn = New-Object System.Collections.ArrayList
}

# Session
#########################################################################################

#region Session

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
function New-MSFServerSession
{
    [CmdletBinding()]
    Param
    (
        # Metasploit Server FQDN or IP.
        [Parameter(Mandatory=$true,
        Position=0)]
        [string[]]$ComputerName,

        # Credentials for connecting to the Metasploit RPC Server
        [Parameter(Mandatory=$true,
        Position=1)]
        [Management.Automation.PSCredential]$Credentials,

        # Port of the Metasploit RPC server.
        [Parameter(Mandatory=$false,
        Position=2)]
        [Int32]$Port = 3790,

        # Version of API to use depending on target server.
        [validateset('Pro','Framework')]
        [string]$Version = "Framework",

        # Specify a existing permanent token to use.
        [Parameter(Mandatory=$false)]
        [ValidateScript({ $_.Length -eq 32})]
        [string]$Token
    )

    Begin
    {
    }
    Process
    {
        foreach ($Computer in $ComputerName)
        {
            $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
            $sessparams   = $Credentials.GetNetworkCredential().UserName,$Credentials.GetNetworkCredential().Password,"https://$($ComputerName):$($Port)/api/1.1"
            $msfsess = New-Object metasploitsharp.MetasploitSession -ArgumentList $sessparams
            if ($msfsess)
            {
                if ($Version -eq 'Framework')
                {
                    $msfmng = New-Object metasploitsharp.MetasploitManager -ArgumentList $msfsess
                }
                else
                {
                    $msfmng = New-Object metasploitsharp.MetasploitProManager -ArgumentList $msfsess
                }

                $SessionProps.Add('Manager',$msfmng)
                $SessionProps.Add('URI',"https://$($ComputerName):$($Port)/api/1.1")
                $SessionProps.add('Host', $computer)
                $SessionProps.Add('Credentials',$Credentials)
                $SessionProps.add('Session',$msfsess)
                $SessionIndex = $Global:MetasploitConn.Count
                $SessionProps.Add('Index', $SessionIndex)
                $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                $sessionobj.pstypenames[0] = "Metasploit.Session"
                if ($Token)
                {
                    Write-Verbose "A permanent token was specified."
                    $tokens = $msfsess.Execute("auth.token_list")
                    Write-Verbose "Checking if token is valid."
                    if ($tokens.ContainsKey('tokens'))
                    {
                        foreach ($tkn in $tokens['tokens'])
                        {
                            if ($Token -eq $tkn)
                            {
                                Write-Verbose "Token has been verified, setting token to session."
                                $sessionobj.Session.Token = $Token
                            }
                        }
                    }
                }
                [void]$Global:MetasploitConn.Add($sessionobj) 

                $sessionobj
            }
        }
    }
    End
    {
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
function Get-MSFServerSession
{
    [CmdletBinding()]
    param(

        # Metasploit session index.
        [Parameter(Mandatory=$false,
        Position=0)]
        [Int32[]] $Index
    )

    Begin{}
    Process
    {
        if ($Index.Count -gt 0)
        {
            foreach($i in $Index)
            {
                foreach($Connection in $Global:MetasploitConn)
                {
                    if ($Connection.Index -eq $i)
                    {
                        $Connection
                    }
                }
            }
        }
        else
        {
            # Return all database connections.
            $return_sessions = @()
            foreach($s in $Global:MetasploitConn){$return_sessions += $s}
            $return_sessions
        }
    }
    End{}
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
function Remove-MSFServerSession
{
    [CmdletBinding()]
    param(

        # Metasploit session index.
        [Parameter(Mandatory=$false,
        Position=0)]
        [Int32[]] $Index
    )

    Begin{}
    Process
    {
        $connections = $Global:MetasploitConn
        $toremove = @()
        if ($Index.Count -gt 0)
        {
            foreach($i in $Index)
            {
                
                foreach($Connection in $connections)
                {
                    if ($Connection.Index -eq $i)
                    {
                        Write-Verbose "Disposing of connection"
                        $Connection.Manager.Dispose()
                        Write-Verbose "Removing session from `$Global:MetasploitConn"
                        $toremove += $Connection
                        
                    }
                }
            }

            foreach ($conn in $toremove)
            {
                $Global:MetasploitConn.Remove($conn)
            }
        }
    }
    End{}
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
function Get-MSFCoreInfo 
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
        
        $request_reply = $MSession.Manager.GetCoreVersionInformation()

        if ($request_reply.ContainsKey("error_code"))
        {
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.host
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
                    $request_reply = $sessionobj.Manager.GetCoreVersionInformation()
                    $request_reply.add('MSHost', $MSession.Host)

                    $versionobj = New-Object -TypeName psobject -Property $request_reply
                    $versionobj.pstypenames[0] = "Metasploit.VersionInfo"
                    $versionobj
                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        else
        {
            $request_reply.add('MSHost', $MSession.Host)
            $versionobj = New-Object -TypeName psobject -Property $request_reply
            $versionobj.pstypenames[0] = "Metasploit.VersionInfo"
            $versionobj
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
function Get-MSFAuthToken 
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
        
        $request_reply = $MSession.Session.Execute("auth.token_list")

        if ($request_reply.ContainsKey("error_code"))
        {
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.host
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
                    $request_reply = $sessionobj.Session.Execute("auth.token_list")
                    foreach ($tkn in $request_reply['tokens'])
                    {
                        $tokenprops = @{}
                        $tokenprops.add('MSHost', $MSession.Host)
                        $tokenprops.add('Token', $tkn)
                        $tokenobj = New-Object -TypeName psobject -Property $tokenprops
                        $tokenobj.pstypenames[0] = "Metasploit.Token"
                        $tokenobj
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
            foreach ($tkn in $request_reply['tokens'])
            {
                $tokenprops = @{}
                $tokenprops.add('MSHost', $MSession.Host)
                $tokenprops.add('Token', $tkn)
                $tokenobj = New-Object -TypeName psobject -Property $tokenprops
                $tokenobj.pstypenames[0] = "Metasploit.Token"
                $tokenobj
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
function New-MSFAuthToken 
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


        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [switch]$SetSession

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
        
        $request_reply = $MSession.Session.Execute("auth.token_generate")

        if ($request_reply.ContainsKey("error_code"))
        {
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.host
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
                    $request_reply = $sessionobj.Session.Execute("auth.token_generate")
                    if ($request_reply.containskey('token'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $tokenobj = New-Object -TypeName psobject -Property $request_reply
                        $tokenobj.pstypenames[0] = "Metasploit.Token"
                        $tokenobj
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
            if ($request_reply.containskey('token'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $tokenobj = New-Object -TypeName psobject -Property $request_reply
                $tokenobj.pstypenames[0] = "Metasploit.Token"
                $tokenobj
            }
        }

        if ($SetSession)
        {
            $tempsession = $MSession
            $Global:MetasploitConn.Remove($MSession)
            Write-Verbose "Setting session at index $($MSession.index) to token $($tokenobj.Token)."
            $tempsession.session.token = $tokenobj.Token
            [void]$Global:MetasploitConn.add($tempsession)
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
function Remove-MSFAuthToken 
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

        # Existing token to remove.
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index")]
        [ValidateScript({ $_.Length -eq 32})]
        [string]$Token

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
        
        if ($MSession.session.token -eq $Token)
        {
            Write-Error "You are tying to remove the same token in use by the session." -ErrorAction Stop
        }
        $request_reply = $MSession.Session.Execute("auth.token_remove", $Token)

        if ($request_reply.ContainsKey("error_code"))
        {
            if ($request_reply.error_code -eq 401)
            {
                write-verbose "The session has expired, Re-authenticating"

                $SessionProps = New-Object System.Collections.Specialized.OrderedDictionary
                $sessparams   = $MSession.Credentials.GetNetworkCredential().UserName,$MSession.Credentials.GetNetworkCredential().Password,$MSession.host
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
                    $request_reply = $sessionobj.Session.Execute("auth.token_remove", $Token)
                    
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $actionobj = New-Object -TypeName psobject -Property $request_reply
                        $actionobj.pstypenames[0] = "Metasploit.Action"
                        $actionobj 
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
                $actionobj = New-Object -TypeName psobject -Property $request_reply
                $actionobj.pstypenames[0] = "Metasploit.Action"
                $actionobj 
            }
        }
    }
}

#endregion

