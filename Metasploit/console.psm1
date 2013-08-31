
<#
.Synopsis
   Gets active consoles on a Metasploit server.
.DESCRIPTION
   Gets active consoles on a Metasploit server.
.EXAMPLE
    Get-MSFConsole -Id 0


Propmpt     : msf > 
Busy        : False
MSHost      : 192.168.1.104
ConsoleId   : 0
MSSessionID : 0
#>
function Get-MSFConsole
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

                    # Update the session with the new information
                    Write-Verbose "Updating session with new authentication token"
                    [void]$Global:MetasploitConn.Remove($MSession)
                    [void]$Global:MetasploitConn.Add($sessionobj)

                    # Get again the information
                    $request_reply = $sessionobj.Manager.ListConsoles()
                    if ($request_reply.ContainsKey('consoles'))
                    {
                        foreach ($console in $request_reply['consoles'])
                        {
                            $consoleprops = @{}
                            $consoleprops.add('MSHost', $MSession.Host)
                            $consoleprops.Add('Propmpt', $console.prompt)
                            $consoleprops.Add('ConsoleId', $console.id)
                            $consoleprops.Add('Busy', $console.busy)
                            $consoleprops.Add("MSSessionID", $MSession.Id)
                            $consoleobj = New-Object -TypeName psobject -Property $consoleprops
                            $consoleobj.pstypenames[0] = "Metasploit.Console"
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
            if ($request_reply.ContainsKey('consoles'))
            {
                foreach ($console in $request_reply['consoles'])
                {
                    $consoleprops = @{}
                    $consoleprops.add('MSHost', $MSession.Host)
                    $consoleprops.Add('Propmpt', $console.prompt)
                    $consoleprops.Add('ConsoleId', $console.id)
                    $consoleprops.Add('Busy', $console.busy)
                    $consoleprops.Add("MSSessionID", $MSession.Id)
                    $consoleobj = New-Object -TypeName psobject -Property $consoleprops
                    $consoleobj.pstypenames[0] = "Metasploit.Console"
                    $consoleobj   
                }
            }
        }
    }
}


<#
.Synopsis
   Creates a new console on a Metasploit server.
.DESCRIPTION
   Creates a new console on a Metasploit server.
.EXAMPLE
   New-MSFConsole -Id 0 | fl 


Propmpt     : msf > 
Busy        : False
MSHost      : 192.168.1.104
ConsoleId   : 0
MSSessionID : 0
#>
function New-MSFConsole
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
        
        $request_reply = $MSession.Manager.CreateConsole()

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
                    $request_reply = $sessionobj.Manager.CreateConsole()
                    if ($request_reply.ContainsKey('id'))
                    {
                        $consoleprops = @{}
                        $consoleprops.add('MSHost', $MSession.Host)
                        $consoleprops.Add('Propmpt', $request_reply.prompt)
                        $consoleprops.Add('ConsoleId', $request_reply.id)
                        $consoleprops.Add('Busy', $request_reply.busy)
                        $consoleprops.Add("MSSessionID", $MSession.Id)
                        $consoleobj = New-Object -TypeName psobject -Property $consoleprops
                        $consoleobj.pstypenames[0] = "Metasploit.Console"
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
            if ($request_reply.ContainsKey('id'))
            {
                $consoleprops = @{}
                $consoleprops.add('MSHost', $MSession.Host)
                $consoleprops.Add('Propmpt', $request_reply.prompt)
                $consoleprops.Add('ConsoleId', $request_reply.id)
                $consoleprops.Add('Busy', $request_reply.busy)
                $consoleprops.Add("MSSessionID", $MSession.Id)
                $consoleobj = New-Object -TypeName psobject -Property $consoleprops
                $consoleobj.pstypenames[0] = "Metasploit.Console"
                $consoleobj   
            }
        }
    }
}


<#
.Synopsis
   Removes an active console from a Metasploit server.
.DESCRIPTION
   Removes an active console from a Metasploit server.
.EXAMPLE
   Remove-MSFConsole -Id 0 -ConsoleId 1 | fl


result      : success
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Remove-MSFConsole
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

        # Console Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int]$ConsoleId
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
        Write-Verbose "Checking existing consoles"
       
        $current_consoles = Get-MSFConsole -Session $MSession 
        
        if ($current_consoles)
        {
            $present = $false
            foreach ($con in $current_consoles)
            {
                if ($con.ConsoleId -eq $ConsoleId)
                {
                    $present = $true
                }
            }
            if (!($present))
            {
                Write-Warning "A console with ID $($ConsoleId) is not present."
                return
            }
        }
        else
        {
            Write-Warning "There are no consoles to interact with."
            return
        }

        $request_reply = $MSession.Manager.DestroyConsole($Id)

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
                    $request_reply = $sessionobj.Manager.DestroyConsole($Id)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $pluginobj = New-Object -TypeName psobject -Property $request_reply
                        $pluginobj.pstypenames[0] = "Metasploit.Console.Destroy"
                        $pluginobj
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
                $pluginobj = New-Object -TypeName psobject -Property $request_reply
                $pluginobj.pstypenames[0] = "Metasploit.Console.Destroy"
                $pluginobj
            }
        }
    }
}


<#
.Synopsis
   Writes text to a selected Metasploir console.
.DESCRIPTION
   Writes text to a selected Metasploir console.
.EXAMPLE
   Write-MSFConsole -Id 0 -ConsoleId 0 -Text "version`n" | fl *


wrote       : 8
MSHost      : 192.168.1.104
Command     : 
MSSessionID : 0
#>
function Write-MSFConsole
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

        # Console Id
        [Parameter(Mandatory=$true,
        Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int]$ConsoleId,

        # Console Id
        [Parameter(Mandatory=$true,
        Position=2,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Text
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

        $current_consoles = Get-MSFConsole -Session $MSession 
        
        if ($current_consoles)
        {
            $present = $false
            foreach ($con in $current_consoles)
            {
                if ($con.consoleid -eq $ConsoleId)
                {
                    $present = $true
                }
            }
            if (!($present))
            {
                Write-Warning "A console with ID $($ConsoleId) is not present."
                return
            }
        }
        else
        {
            Write-Warning "There are no consoles to interact with."
            return
        }
        
        Write-Verbose "Writing text to the console."
        $request_reply = $MSession.Manager.WriteToConsole($ConsoleId, $Text)

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
                    $request_reply = $sessionobj.Manager.WriteToConsole($ConsoleId, $Text)
                    if ($request_reply.ContainsKey('wrote'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.add('Command', $Command)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $writeobj = New-Object -TypeName psobject -Property $request_reply
                        $writeobj.pstypenames[0] = "Metasploit.Console.Write"
                        $writeobj
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
            if ($request_reply.ContainsKey('wrote'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.add('Command', $Command.TrimEnd())
                $request_reply.Add("MSSessionID", $MSession.Id)
                $writeobj = New-Object -TypeName psobject -Property $request_reply
                $writeobj.pstypenames[0] = "Metasploit.Console.write"
                $writeobj
            }
        }
    }
}


<#
.Synopsis
   Invokes a console command on a specific console on the Metasploit server.
.DESCRIPTION
   Invokes a console command on a specific console on the Metasploit server.
.EXAMPLE
   Invoke-MSFConsoleCommand -Id 0 -ConsoleId 0 -Command "jobs" | fl *


wrote       : 5
MSHost      : 192.168.1.104
Command     : jobs
              
MSSessionID : 0




PS C:\> Read-MSFConsole -Id 0 -ConsoleId 0


data        : Framework: 4.8.0-dev
              Console  : 4.8.0-dev.15168
              
              Jobs
              ====
              
                Id  Name
                --  ----
                1   Exploit: multi/handler
                2   Exploit: multi/handler
              
              
prompt      : msf > 
busy        : False
MSHost      : 192.168.1.104
MSSessionID : 0

#>
function Invoke-MSFConsoleCommand
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

        # Console Id
        [Parameter(Mandatory=$true,
        Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int]$ConsoleId,

        # Console Id
        [Parameter(Mandatory=$true,
        Position=2,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Command
    )
    BEGIN 
    {
        $Command = $Command + "`n"
        
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

        $current_consoles = Get-MSFConsole -Session $MSession 
        
        if ($current_consoles)
        {
            $present = $false
            foreach ($con in $current_consoles)
            {
                if ($con.consoleid -eq $ConsoleId)
                {
                    $present = $true
                }
            }
            if (!($present))
            {
                Write-Warning "A console with ID $($ConsoleId) is not present."
                return
            }
        }
        else
        {
            Write-Warning "There are no consoles to interact with."
            return
        }
        
        Write-Verbose "Executing command $command"
        $request_reply = $MSession.Manager.WriteToConsole($ConsoleId, $Command)

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
                    $request_reply = $sessionobj.Manager.WriteToConsole($ConsoleId, $Command)
                    if ($request_reply.ContainsKey('wrote'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.add('Command', $Command)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $writeobj = New-Object -TypeName psobject -Property $request_reply
                        $writeobj.pstypenames[0] = "Metasploit.Console.Write"
                        $writeobj
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
            if ($request_reply.ContainsKey('wrote'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.add('Command', $Command)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $writeobj = New-Object -TypeName psobject -Property $request_reply
                $writeobj.pstypenames[0] = "Metasploit.Console.write"
                $writeobj
            }
        }
    }
}


<#
.Synopsis
   Reads the current data in the buffer of a console on a Metasploit server.
.DESCRIPTION
   Reads the current data in the buffer of a console on a Metasploit server.
.EXAMPLE
   Write-MSFConsole -Id 0 -ConsoleId 0 -Text "version`n" | fl *


wrote       : 8
MSHost      : 192.168.1.104
Command     : 
MSSessionID : 0




PS C:\> Read-MSFConsole -Id 0 -ConsoleId 0


data        : Framework: 4.8.0-dev
              Console  : 4.8.0-dev.15168
              
prompt      : msf > 
busy        : False
MSHost      : 192.168.1.104
MSSessionID : 0

#>
function Read-MSFConsole
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

        # Console Id
        [Parameter(Mandatory=$true,
        Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int]$ConsoleId
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

        $current_consoles = Get-MSFConsole -Session $MSession 

        if ($current_consoles)
        {
            $present = $false
            foreach ($con in $current_consoles)
            {
                if ($con.ConsoleId -eq $ConsoleId)
                {
                    $present = $true
                }
            }
            if (!($present))
            {
                Write-Warning "A console with ID $($ConsoleId) is not present."
                return
            }
        }
        else
        {
            Write-Warning "There are no consoles to interact with."
            return
        }
        
        $request_reply = $MSession.Manager.ReadConsole($ConsoleId)

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
                    $request_reply = $sessionobj.Manager.ReadConsole($ConsoleId)
                    if ($request_reply.ContainsKey('data'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $writeobj = New-Object -TypeName psobject -Property $request_reply
                        $writeobj.pstypenames[0] = "Metasploit.Console.Write"
                        $writeobj
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
            if ($request_reply.ContainsKey('data'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $writeobj = New-Object -TypeName psobject -Property $request_reply
                $writeobj.pstypenames[0] = "Metasploit.Console.write"
                $writeobj
            }
        }
    }
}
