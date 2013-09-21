if (!(Test-Path variable:Global:MetasploitConn ))
{
    $Global:MetasploitConn = New-Object System.Collections.ArrayList
}


<#
.Synopsis
   Create a new Metasploit Server Session to a given MSFRPCD Server.
.DESCRIPTION
   Create a new Metasploit Server Session to a given MSFRPCD Server. The Metasploit server
   can be a Framework server running msfrpcd or the commercial version of Metasploit from
   Rapid7. Authentication can be done with Username and Password or using an existing permanent
   token.
.EXAMPLE
    New-MSFServerSession -ComputerName 192.168.1.104 -Port 55553 -Credentials (Get-Credential msf)


Manager     : metasploitsharp.MetasploitManager
URI         : https://192.168.1.104:55553/api/1.1
Host        : 192.168.1.104
Credentials : System.Management.Automation.PSCredential
Session     : metasploitsharp.MetasploitSession
Id          : 1

.EXAMPLE
   New-MSFServerSession -ComputerName 192.168.1.104 -Port 55553 -Token TEMP2996258342382165380499920035


Manager     : metasploitsharp.MetasploitManager
URI         : https://192.168.1.104:55553/api/1.1
Host        : 192.168.1.104
Credentials : 
Session     : metasploitsharp.MetasploitSession
Id          : 0
#>
function New-MSFServerSession
{
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param
    (
        # Metasploit Server FQDN or IP.
        [Parameter(Mandatory=$true,
        Position=0)]
        [Parameter(ParameterSetName = "Credential")]
        [Parameter(ParameterSetName = "Token")]
        [string[]]$ComputerName,

        # Credentials for connecting to the Metasploit RPC Server
        [Parameter(Mandatory=$true,
        Position=1,
        ParameterSetName = "Credential")]
        [Management.Automation.PSCredential]$Credentials,

        # Port of the Metasploit RPC server. Use 55553 for Framework and 3790 for commercial versions.
        [Parameter(Mandatory=$false,
        Position=2)]
        [Int32]$Port = 55553,

        # Version of API to use depending on target server.
        [validateset('Pro','Framework')]
        [string]$Version = "Framework",

        [validateset('Pro','Framework')]
        [switch]$DisableSSL,

        # Specify a existing permanent token to use.
        [Parameter(Mandatory=$false, ParameterSetName = "Token")]
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
            if ($DisableSSL)
            {
                $proto = "http"
            }
            else
            {
                $proto = "https"
            }
            switch ($PSCmdlet.ParameterSetName)
            {
                'Credential' 
                {
                    $sessparams   = $Credentials.GetNetworkCredential().UserName,$Credentials.GetNetworkCredential().Password,"$($proto)://$($ComputerName):$($Port)/api/1.1"
                }
                
                'Token' 
                {
                    $sessparams   = $Token,"$($proto)://$($ComputerName):$($Port)/api/1.1"
                }
                Default {}
            }

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
                $SessionProps.Add('Id', $SessionIndex)
                $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                $sessionobj.pstypenames[0] = "Metasploit.Session"
                
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
   Sets on a existing MSF Server Session a Authentication Token.
.DESCRIPTION
   Sets on a existing MSF Server Session a existing authentication token is already present on the server
   or has been generated wit New-MSFAuthToken function.
.EXAMPLE
    $Global:MetasploitConn[1].Session

Token                                                                                                                                                                                                                                    
-----                                                                                                                                                                                                                                    
TEMPJ69aGNgFEMURvkl9Z1IjwjrDSL7b                                                                                                                                                                                                         



C:\PS> Set-MSFAuthToken -Id 1 -Token TEMP2996258342382165380499920035 -Verbose
VERBOSE: The session has expired, Re-authenticating
VERBOSE: Authentication successful.
VERBOSE: Updating session with new authentication token


Manager     : metasploitsharp.MetasploitManager
URI         : https://192.168.1.104:55553/api/1.1
Host        : 192.168.1.104
Session     : metasploitsharp.MetasploitSession
Credentials : System.Management.Automation.PSCredential
Id          : 1




C:\PS> $Global:MetasploitConn[1].Session

Token                                                                                                                                                                                                                                    
-----                                                                                                                                                                                                                                    
TEMP2996258342382165380499920035
#>
function Set-MSFAuthToken
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
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


        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [string]$Token
    )

    Begin
    {
    }
    Process
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

        $request_reply = $MSession.Manager.ListConsoles()

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
                    $sessionobj.session.token = $Token
                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)

                    # Now that the object has been updated return it
                    $sessionobj

                }
            }
            else
            {
                Write-Error -Message "$($request_reply.error_message)"
            }
        }
        else
        {
            $MSession.session.token = $Token
            # Update the session with the new information
            Write-Verbose "Updating session with new authentication token"
            [void]$Global:MetasploitConn.Remove($MSession)
            [void]$Global:MetasploitConn.Add($MSession)
        }
           
    }
    End
    {
    }
}


<#
.Synopsis
   Retrives a specified Metasploit server session or all sessions.
.DESCRIPTION
   Retrives a specified Metasploit server session or list of sessions given the Id for each session from
   the variable $Global:MetasploitConn if none is specified it retrieves all sessions.
.EXAMPLE
     Get-MSFServerSession


Manager     : metasploitsharp.MetasploitManager
URI         : https://192.168.1.104:55553/api/1.1
Host        : 192.168.1.104
Credentials : 
Session     : metasploitsharp.MetasploitSession
Id          : 0

Manager     : metasploitsharp.MetasploitManager
URI         : https://192.168.1.104:55553/api/1.1
Host        : 192.168.1.104
Session     : metasploitsharp.MetasploitSession
Credentials : System.Management.Automation.PSCredential
Id          : 1
   
#>
function Get-MSFServerSession
{
    [CmdletBinding()]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$false,
        ParameterSetName = "Index",
        Position=0)]
        [Alias("Index")]
        [int32[]]$Id = @()
    )

    Begin{}
    Process
    {
        if ($Index.Count -gt 0)
        {
            foreach($i in $Id)
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
   Removes an existing Metasploit server session.
.DESCRIPTION
   Removes an existing Metasploit server session give the session Id by unloging the user removing
   the temporary Token if it was created with one and removes the session from $Global:MetasploitConn.
.EXAMPLE
   Remove-MSFServerSession -Id 1 -Verbose
VERBOSE: Removing server session 1
VERBOSE: Disposing of connection
VERBOSE: Removing session from $Global:MetasploitConn
#>
function Remove-MSFServerSession
{
    [CmdletBinding()]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        Position=0,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32[]]$Id = @()
    )

    Begin{}
    Process
    {
        $connections = $Global:MetasploitConn
        $toremove = @()
        
        if ($Id.Count -gt 0)
        {
            
            foreach($i in $Id)
            {
                Write-Verbose "Removing server session $($i)"
                
                foreach($Connection in $connections)
                {
                    if ($Connection.Id -eq $i)
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
   Get the Core Version information for a given Metasploit session
.DESCRIPTION
   Get the Core Version information for a given Metasploit session. Gets the Metasploit version,
   Ruby version and API version being used.
.EXAMPLE
    Get-MSFCoreInfo -Id 0 


version     : 4.8.0-dev
ruby        : 1.9.3 x86_64-darwin12.4.0 2013-06-27
api         : 1.0
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Get-MSFCoreInfo 
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

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
        
        $request_reply = $MSession.Manager.GetCoreVersionInformation()

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
                    $request_reply = $sessionobj.Manager.GetCoreVersionInformation()
                    $request_reply.add('MSHost', $MSession.Host)
                    $request_reply.add('MSSessionID', $Id)
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
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            $request_reply.add('MSHost', $MSession.Host)
            $request_reply.add('MSSessionID', $Id)
            $versionobj = New-Object -TypeName psobject -Property $request_reply
            $versionobj.pstypenames[0] = "Metasploit.VersionInfo"
            $versionobj
        }
    }
}


<#
.Synopsis
   Gets existing Authentication Token for a given Metasploit session.
.DESCRIPTION
   Gets existing Authentication Token from memory or the database for a given Metasploit session.
.EXAMPLE
    Get-MSFAuthToken -Id 0 | fl *


Token       : TEMP2996258342382165380499920035
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Get-MSFAuthToken 
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

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
        
        $request_reply = $MSession.Session.Execute("auth.token_list")

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
                    $request_reply = $sessionobj.Session.Execute("auth.token_list")
                    foreach ($tkn in $request_reply['tokens'])
                    {
                        $tokenprops = @{}
                        $tokenprops.add('MSHost', $MSession.Host)
                        $tokenprops.add('MSSessionID', $Id)
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
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            foreach ($tkn in $request_reply['tokens'])
            {
                $tokenprops = @{}
                $tokenprops.add('MSHost', $MSession.Host)
                $tokenprops.add('MSSessionID', $Id)
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
   Genetates a new permanent Metasploit authentication token.
.DESCRIPTION
   Genetates a new permanent Metasploit authentication token and if a database is 
   connected it saves the token to the database.
.EXAMPLE
   New-MSFAuthToken -Id 0 


result      : success
token       : TEMP5453191165387926134603279826
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function New-MSFAuthToken 
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id.
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object.
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [psobject]$Session,

        # Set the newly created token to the Metasploit session.
        [Parameter(Mandatory=$false)]
        [switch]$SetSession

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
        
        $request_reply = $MSession.Session.Execute("auth.token_generate")

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
                    $request_reply = $sessionobj.Session.Execute("auth.token_generate")
                    if ($request_reply.containskey('token'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.add('MSSessionID', $Id)
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
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($request_reply.containskey('token'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.add('MSSessionID', $Id)
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
   Removes a known Metasploit Authentication Token from a Metasploit session.
.DESCRIPTION
   Removes a known Metasploit Authentication Token from a Metasploit session.
.EXAMPLE
   Remove-MSFAuthToken -Id 0 -Token TEMP5453191165387926134603279826 | fl *


result      : success
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Remove-MSFAuthToken 
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
    param(

        # Metasploit session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("Index","MSSessionID")]
        [int32]$Id,

        # Metasploit session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [psobject]$Session,

        # Existing token to remove.
        [Parameter(Mandatory=$true)]
        [ValidateScript({ $_.Length -eq 32})]
        [string]$Token

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
                    $request_reply = $sessionobj.Session.Execute("auth.token_remove", $Token)
                    
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.add('MSSessionID', $Id)
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
                $request_reply.add('MSSessionID', $Id)
                $actionobj = New-Object -TypeName psobject -Property $request_reply
                $actionobj.pstypenames[0] = "Metasploit.Action"
                $actionobj 
            }
        }
    }
}




<#
.Synopsis
   Enumerates all current Metasploit server threads.
.DESCRIPTION
   Enumerates all current Metasploit server threads including detailed information on each one of them.
#>
function Get-MSFThread
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
        
        $reply = $MSession.Session.Execute("core.thread_list")

        if ($reply.ContainsKey("error_code"))
        {
            if ($reply.error_code -eq 401)
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
                    $reply = $sessionobj.Session.Execute("core.thread_list")
                    if ($reply)
                    {
                        foreach ($ThreadID in $reply.Keys)
                        {
                            $Threadprops = [ordered]@{}
                            $Threadprops.Add("ThreadID",$ThreadID)
                            foreach ($singleprop in $reply[$ThreadID])
                            {
                                foreach ($prop in $singleprop.keys)
                                {
                                    $Threadprops.Add($prop,$singleprop[$prop])
                                }
                            }
                            $Threadprops.Add("MSSessionID",$sessionobj.Id)
                            $Threadobj = New-Object -TypeName psobject -Property $Threadprops
                            $Threadobj.pstypenames[0] = "Metasploit.Thread"
                            $Threadobj
                        }
                    }
                    else
                    {
                        Write-Verbose "No session where found"
                    }
                }
            }
            else
            {
                Write-Error -Message "$($reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($reply)
            {
                foreach ($SessionID in $reply.Keys)
                {
                    $Threadprops = [ordered]@{}
                    $Threadprops.Add("ThreadID",$ThreadID)
                    foreach ($singleprop in $reply[$ThreadID])
                    {
                        foreach ($prop in $singleprop.keys)
                        {
                            $Threadprops.Add($prop,$singleprop[$prop])
                        }
                    }
                    $Threadprops.Add("MSSessionID",$Id)
                    $Threadobj = New-Object -TypeName psobject -Property $Threadprops
                    $Threadobj.pstypenames[0] = "Metasploit.Thread"
                    $Threadobj
                }
            }
            else
            {
                Write-Verbose "No session where found"
            }
        }
    }
}


<#
.Synopsis
   Terminates a current thread in the Metasploit server.
.DESCRIPTION
   Terminates a current thread in the Metasploit server given the ThreadID.
#>
function Remove-MSFThread
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

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
        [Int]$ThreadId
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
        
        $reply = $MSession.Session.Execute("core.thread_list")
        if ($reply.ContainsKey("error_code"))
        {
            if ($reply.error_code -eq 401)
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
                    $reply = $sessionobj.Session.Execute("core.thread_list")
                    $present = $false
                    foreach ($currentthread in $reply.keys)
                    {
                        if ($currentthread -eq $ThreadId)
                        {
                            $present = $true
                        }
                    }
                    if (!($present))
                    {
                        Write-Warning "A thread with ID $($ThreadId) is not present."
                        return
                    }

                    
                    $request_reply = $sessionobj.Session.Execute("core.thread_kill", $ThreadId)
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
                Write-Error -Message "$($reply.error_message)"
            }
        }
        elseif ($request_reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            $present = $false
            foreach ($currentthread in $reply.keys)
            {
                if ($currentthread -eq $ThreadId)
                {
                    $present = $true
                }
            }
            if (!($present))
            {
                Write-Warning "A thread with ID $($ThreadId) is not present."
                return
            }

            $request_reply = $MSession.Session.Execute("core.thread_kill", $ThreadId)
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