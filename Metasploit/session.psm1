
<#
.Synopsis
   Enumerate sessions present from Shell and/or Meterpreter on a Metasploit server.
.DESCRIPTION
   Enumerate sessions present from Shell and/or Meterpreter on a Metasploit server. Provides full details
   on the session including the Exploit ID and Session ID that can be used when referencing Event and Credentials.
.EXAMPLE
   Get-MSFSession -Id 0


tunnel_peer  : 192.168.10.12:65352
MSSessionID  : 0
session_port : 65352
type         : meterpreter
tunnel_local : 192.168.1.104:4444
exploit_uuid : kjlmsgbt
username     : carlos
desc         : Meterpreter
uuid         : e2l2na8g
workspace    : 
via_payload  : payload/windows/meterpreter/reverse_tcp
target_host  : 
platform     : x86/win32
routes       : 
info         : ACMELABS\administrator @ DC02
SessionID    : 1
via_exploit  : exploit/multi/handler
session_host : 192.168.10.12
#>
function Get-MSFSession
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
        
        $reply = $MSession.Session.Execute("session.list")

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
                    $reply = $sessionobj.Session.Execute("session.list")
                    if ($reply)
                    {
                        foreach ($SessionID in $reply.Keys)
                        {
                            $sessionprops = @{}
                            $sessionprops.Add("SessionID",$SessionID)
                            $sessionprops.Add("MSSessionID",$sessionobj.Id)
                            foreach ($singleprop in $reply[$SessionID])
                            {
                                foreach ($prop in $singleprop.keys)
                                {
                                    $sessionprops.Add($prop,$singleprop[$prop])
                                }
                            }
                            $sessionobj = New-Object -TypeName psobject -Property $sessionprops
                            $sessionobj.pstypenames[0] = "Metasploit.Session"
                            $sessionobj
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
        elseif ($reply.ContainsKey("error_message"))
        {
            Write-Error -Message "$($request_reply.error_message)"
        }
        else
        {
            if ($reply)
            {
                foreach ($SessionID in $reply.Keys)
                {
                    $sessionprops = @{}
                    $sessionprops.Add("SessionID",$SessionID)
                    $sessionprops.Add("MSSessionID",$MSession.Id)
                    foreach ($singleprop in $reply[$SessionID])
                    {
                        foreach ($prop in $singleprop.keys)
                        {
                            $sessionprops.Add($prop,$singleprop[$prop])
                        }
                    }
                    $sessionobj = New-Object -TypeName psobject -Property $sessionprops
                    $sessionobj.pstypenames[0] = "Metasploit.Session"
                    $sessionobj
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
   Write text to a Meterpreter interactive console.
.DESCRIPTION
   Write text to a Meterpreter interactive console.
.EXAMPLE
   Write-MSFMeterpreterConsole -Index 0 -SessionId 1 -Text "sysinfo`n" | fl *
   

result    : success
MSHost    : 192.168.1.104
SessionId : 1
Command   : sysinfo

#>
function Write-MSFMeterpreterConsole
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

        # Meterpreter Session Id
        [Parameter(Mandatory=$true,
        Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int]$SessionId,

        # Console command
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
            throw "Specified session was not found."
        }
        Write-Verbose "Checking if Session ID $($SessionId) exists in the current server session."
        $current_sessions = Get-MSFSession -Session $MSession
        if ($current_sessions)
        {
            $found = $false
            foreach ($sess in $current_sessions)
            {
                if ($sess.SessionID -eq $SessionId)
                {
                    Write-Verbose "Specified session is present."
                    Write-Verbose "Checking session type."
                    if ($sess.type -eq "meterpreter")
                    {
                        $found = $true
                    }
                    else
                    {
                        Write-Error "This is not a Meterpreter session" -ErrorAction Stop
                    }
                }
            }
            if (!($found))
            {
                Write-Warning "Sepcified session was not found."
                return
            }
        }
        else
        {
            Write-Warning "No sessions where found."
            return
        }
        Write-Verbose "Writing to the console `"$Text `""
        $request_reply = $MSession.Session.Execute("session.meterpreter_write",$SessionId,$Text)

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
                    $request_reply = $sessionobj.Session.Execute("session.meterpreter_write",$SessionId,$Text)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.add('SessionId', $SessionId)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $request_reply.add('Text', $Text)
                        $writeobj = New-Object -TypeName psobject -Property $request_reply
                        $writeobj.pstypenames[0] = "Metasploit.MeterpreterConsole.Write"
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
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.add('SessionId', $SessionId)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $request_reply.add('Text', $Text)
                $writeobj = New-Object -TypeName psobject -Property $request_reply
                $writeobj.pstypenames[0] = "Metasploit.MeterpreterConsole.Write"
                $writeobj
            }
        }
    }
}


<#
.Synopsis
   Read the current data in the buffer for an interactive Meterpreter interactice console.
.DESCRIPTION
   Read the current data in the buffer for an interactive Meterpreter interactice console.
.EXAMPLE
   Read-MSFMeterpreterConsole -Id 0 -SessionId 1 | fl *


data      : Computer        : WIN2K3VMTEST
            OS              : Windows .NET Server (Build 3790, Service Pack 2).
            Architecture    : x86
            System Language : en_US
            Meterpreter     : x86/win32
            
MSHost    : 192.168.1.104
SessionId : 1
#>
function Read-MSFMeterpreterConsole
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

        # Meterpreter Session Id
        [Parameter(Mandatory=$true,
        Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int]$SessionId
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
        
        Write-Verbose "Checking if Session ID $($SessionId) exists in the current server session."
        $current_sessions = Get-MSFSession -Session $MSession
        if ($current_sessions)
        {
            $found = $false
            foreach ($sess in $current_sessions)
            {
                if ($sess.SessionID -eq $SessionId)
                {
                    Write-Verbose "Specified session is present."
                    Write-Verbose "Checking session type."
                    if ($sess.type -eq "meterpreter")
                    {
                        $found = $true
                    }
                    else
                    {
                        Write-Error "This is not a Meterpreter session" -ErrorAction Stop
                    }
                }
            }
            if (!($found))
            {
                Write-Warning "Sepcified session was not found."
                return
            }
        }
        else
        {
            Write-Warning "No sessions where found."
            return
        }

        $request_reply = $MSession.Session.Execute("session.meterpreter_read",$SessionId)

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
                    $request_reply = $sessionobj.Session.Execute("session.meterpreter_read",$SessionId)
                    if ($request_reply.ContainsKey('data'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.add('SessionId', $SessionId)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $writeobj = New-Object -TypeName psobject -Property $request_reply
                        $writeobj.pstypenames[0] = "Metasploit.MeterpreterConsole.Data"
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
            if ($request_reply.ContainsKey('data'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.add('SessionId', $SessionId)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $writeobj = New-Object -TypeName psobject -Property $request_reply
                $writeobj.pstypenames[0] = "Metasploit.MeterpreterConsole.Data"
                $writeobj
            }
        }
    }
}


<#
.Synopsis
   Finds compatible post modules for a given session on a Metasploit server.
.DESCRIPTION
   Finds compatible post modules for a given session on a Metasploit server.
.EXAMPLE
   Get-MSFSessionCompatPostModules -Id 0 -SessionId 2

Name                                                                                                                 MSHost                                                                                                              
----                                                                                                                 ------                                                                                                                                                                                                                   
post/multi/manage/system_session                                                                                     192.168.1.104                                                                                                       
post/multi/manage/sudo                                                                                               192.168.1.104                                                                                                       
post/multi/manage/multi_post                                                                                         192.168.1.104                                                                                                       
post/multi/general/execute                                                                                           192.168.1.104                                                                                                       
post/multi/general/close                                                                                             192.168.1.104                                                                                                       
post/multi/gather/thunderbird_creds                                                                                  192.168.1.104                                                                                                       
post/multi/gather/ssh_creds                                                                                          192.168.1.104                                                                                                       
post/multi/gather/skype_enum                                                                                         192.168.1.104                                                                                                       
post/multi/gather/ping_sweep                                                                                         192.168.1.104                                                                                                       
post/multi/gather/pidgin_cred                                                                                        192.168.1.104                                                                                                       
post/multi/gather/pgpass_creds                                                                                       192.168.1.104                                                                                                       
post/multi/gather/netrc_creds                                                                                        192.168.1.104                                                                                                       
post/multi/gather/multi_command                                                                                      192.168.1.104                                                                                                       
post/multi/gather/gpg_creds                                                                                          192.168.1.104                                                                                                       
post/multi/gather/firefox_creds                                                                                      192.168.1.104                                                                                                       
post/multi/gather/find_vmx                                                                                           192.168.1.104                                                                                                       
post/multi/gather/filezilla_client_cred                                                                              192.168.1.104                                                                                                       
post/multi/gather/fetchmailrc_creds                                                                                  192.168.1.104                                                                                                       
post/multi/gather/env                                                                                                192.168.1.104                                                                                                       
post/multi/gather/enum_vbox                                                                                          192.168.1.104                                                                                                       
post/multi/gather/dns_srv_lookup                                                                                     192.168.1.104                                                                                                       
post/multi/gather/dns_reverse_lookup                                                                                 192.168.1.104                                                                                                       
post/multi/gather/dns_bruteforce                                                                                     192.168.1.104                                                                                                       
post/multi/gather/apple_ios_backup                                                                                   192.168.1.104                                                                                                       
post/multi/escalate/metasploit_pcaplog                                                                               192.168.1.104                                                                                                       
post/linux/manage/download_exec                                                                                      192.168.1.104                                                                                                       
post/linux/gather/pptpd_chap_secrets                                                                                 192.168.1.104                                                                                                       
post/linux/gather/mount_cifs_creds                                                                                   192.168.1.104                                                                                                       
post/linux/gather/hashdump                                                                                           192.168.1.104                                                                                                       
post/linux/gather/enum_xchat                                                                                         192.168.1.104                                                                                                       
post/linux/gather/enum_users_history                                                                                 192.168.1.104                                                                                                       
post/linux/gather/enum_system                                                                                        192.168.1.104                                                                                                       
post/linux/gather/enum_protections                                                                                   192.168.1.104                                                                                                       
post/linux/gather/enum_network                                                                                       192.168.1.104                                                                                                       
post/linux/gather/enum_configs                                                                                       192.168.1.104                                                                                                       
post/linux/gather/checkvm                                                                                            192.168.1.104                                                                                                       

#>
function Get-MSFSessionCompatPostModules
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

        # Session Id
        [Parameter(Mandatory=$true,
        Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int]$SessionId
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
        
        Write-Verbose "Checking if Session ID $($SessionId) exists in the current server session."
        $current_sessions = Get-MSFSession -Session $MSession
        if ($current_sessions)
        {
            $found = $false
            foreach ($sess in $current_sessions)
            {
                if ($sess.SessionID -eq $SessionId)
                {
                    $found = $true
                    Write-Verbose "Specified session is present."
                }
            }
            if (!($found))
            {
                Write-Warning "Sepcified session was not found."
                return
            }
        }
        else
        {
            Write-Warning "No sessions where found."
            return
        }

        $request_reply = $MSession.Session.Execute("session.compatible_modules",$SessionId)

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
                    $request_reply = $sessionobj.Session.Execute("session.compatible_modules",$SessionId)
                    if ($request_reply.ContainsKey('modules'))
                    {
                        foreach ($module in $request_reply['modules'])
                        {
                            $moduleprops = @{}
                            $moduleprops.add('MSHost', $MSession.Host)
                            $moduleprops.Add('Name', $module)
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
   Invokes a console command on a Meterpreter Session on a Metasploit server.
.DESCRIPTION
   Invokes a console command on a Meterpreter Session on a Metasploit server given the session Id.
.EXAMPLE
   Invoke-MSFMMeterpreterCommand -Id 0 -SessionId 1 -Command "getuid" | fl *


result    : success
MSHost    : 192.168.1.104
SessionId : 1
Command   : getuid
#>
function Invoke-MSFMeterpreterCommand
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

        # Meterpreter Session Id
        [Parameter(Mandatory=$true,
        Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int]$SessionId,

        # Console command
        [Parameter(Mandatory=$true,
        Position=2,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Command
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
        
        Write-Verbose "Checking if Session ID $($SessionId) exists in the current server session."
        $current_sessions = Get-MSFSession -Session $MSession
        if ($current_sessions)
        {
            $found = $false
            foreach ($sess in $current_sessions)
            {
                if ($sess.SessionID -eq $SessionId)
                {
                    Write-Verbose "Specified session is present."
                    Write-Verbose "Checking session type."
                    if ($sess.type -eq "meterpreter")
                    {
                        $found = $true
                    }
                    else
                    {
                        Write-Error "This is not a Meterpreter session" -ErrorAction Stop
                    }
                }
            }
            if (!($found))
            {
                Write-Warning "Sepcified session was not found."
                return
            }
        }
        else
        {
            Write-Warning "No sessions where found."
            return
        }

        Write-Verbose "Executing command $command"
        $request_reply = $MSession.Session.Execute("session.meterpreter_run_single",$SessionId,$Command)

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
                    $request_reply = $sessionobj.Session.Execute("session.meterpreter_run_single",$SessionId,$Command)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.add('SessionId', $SessionId)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $request_reply.add('Command', $Command)
                        $writeobj = New-Object -TypeName psobject -Property $request_reply
                        $writeobj.pstypenames[0] = "Metasploit.MeterpreterConsole.Write"
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
            if ($request_reply.ContainsKey('result'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.add('SessionId', $SessionId)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $request_reply.add('Command', $Command)
                $writeobj = New-Object -TypeName psobject -Property $request_reply
                $writeobj.pstypenames[0] = "Metasploit.MeterpreterConsole.Write"
                $writeobj
            }
        }
    }
}


<#
.Synopsis
   Writes text to a specified session on a Metasploit server.
.DESCRIPTION
   Writes text to a specified session on a Metasploit server given its session Id.
.EXAMPLE
   Write-MSFShellConsole -Id 0 -SessionId 2 -Text "ping -c 2 127.0.0.1`n" | fl *


write_count : 20
MSHost      : 192.168.1.104
SessionId   : 2
Command     : ping -c 2 127.0.0.1
#>
function Write-MSFShellConsole
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

        # Shell Session Id
        [Parameter(Mandatory=$true,
        Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int]$SessionId,

        # Console command
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
        
        Write-Verbose "Checking if Session ID $($SessionId) exists in the current server session."
        $current_sessions = Get-MSFSession -Session $MSession
        if ($current_sessions)
        {
            $found = $false
            foreach ($sess in $current_sessions)
            {
                if ($sess.SessionID -eq $SessionId)
                {
                    Write-Verbose "Specified session is present."
                    Write-Verbose "Checking session type."
                    if ($sess.type -eq "shell")
                    {
                        $found = $true
                    }
                    else
                    {
                        Write-Error "This is not a Meterpreter session" -ErrorAction Stop
                    }
                }
            }
            if (!($found))
            {
                Write-Warning "Sepcified session was not found."
                return
            }
        }
        else
        {
            Write-Warning "No sessions where found."
            return
        }

        Write-Verbose "Writing to session `"$Text`""
        $request_reply = $MSession.Session.Execute("session.shell_write",$SessionId,$Text)

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
                    $request_reply = $sessionobj.Session.Execute("session.shell_write",$SessionId,$Text)

                    if ($request_reply.ContainsKey('write_count'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.add('SessionId', $SessionId)
                        $request_reply.Add("MSSessionID",$MSession.Id)
                        $request_reply.add('Text', $Text)
                        $writeobj = New-Object -TypeName psobject -Property $request_reply
                        $writeobj.pstypenames[0] = "Metasploit.ShellConsole.Write"
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
            if ($request_reply.ContainsKey('write_count'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.add('SessionId', $SessionId)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $request_reply.add('Text', $Text)
                $writeobj = New-Object -TypeName psobject -Property $request_reply
                $writeobj.pstypenames[0] = "Metasploit.ShellConsole.Write"
                $writeobj
            }
        }
    }
}


<#
.Synopsis
   Reads the output generated in a Metasploit Shell Session.
.DESCRIPTION
   Reads the output generated by a command or a shell write in a Metasploit Shell Session given the Session Id.
.EXAMPLE
   Read-MSFShellConsole -Id 0 -SessionId 2 | fl *


seq       : 16
data      : PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
            64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.082 ms
            64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.057 ms
            
            --- 127.0.0.1 ping statistics ---
            2 packets transmitted, 2 received, 0% packet loss, time 1000ms
            rtt min/avg/max/mdev = 0.057/0.069/0.082/0.015 ms
            PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
            64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.094 ms
            64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.058 ms
            
            --- 127.0.0.1 ping statistics ---
            2 packets transmitted, 2 received, 0% packet loss, time 1000ms
            rtt min/avg/max/mdev = 0.058/0.076/0.094/0.018 ms
            
MSHost    : 192.168.1.104
SessionId : 2
Command   : 

#>
function Read-MSFShellConsole
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

        # Shell Session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int]$SessionId,

        # Shell buffer position
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Session")]
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        ParameterSetName = "Index")]
        [int]$Position
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
        
        Write-Verbose "Checking if Session ID $($SessionId) exists in the current server session."
        $current_sessions = Get-MSFSession -Session $MSession
        if ($current_sessions)
        {
            $found = $false
            foreach ($sess in $current_sessions)
            {
                if ($sess.SessionID -eq $SessionId)
                {
                    Write-Verbose "Specified session is present."
                    Write-Verbose "Checking session type."
                    if ($sess.type -eq "shell")
                    {
                        $found = $true
                    }
                    else
                    {
                        Write-Error "This is not a Meterpreter session" -ErrorAction Stop
                    }
                }
            }
            if (!($found))
            {
                Write-Warning "Sepcified session was not found."
                return
            }
        }
        else
        {
            Write-Warning "No sessions where found."
            return
        }

        Write-Verbose "Executing command $command"
        $request_reply = $MSession.Session.Execute("session.shell_read",$SessionId,$Position)

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
                    $request_reply = $sessionobj.Session.Execute("session.shell_read",$SessionId,$Position)
                    if ($request_reply.ContainsKey('data'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $request_reply.add('SessionId', $SessionId)
                        $request_reply.Add("MSSessionID", $MSession.Id)
                        $request_reply.add('Command', $Command)
                        $writeobj = New-Object -TypeName psobject -Property $request_reply
                        $writeobj.pstypenames[0] = "Metasploit.ShellConsole.Data"
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
            if ($request_reply.ContainsKey('data'))
            {
                $request_reply.add('MSHost', $MSession.Host)
                $request_reply.add('SessionId', $SessionId)
                $request_reply.Add("MSSessionID", $MSession.Id)
                $request_reply.add('Command', $Command)
                $writeobj = New-Object -TypeName psobject -Property $request_reply
                $writeobj.pstypenames[0] = "Metasploit.ShellConsole.Data"
                $writeobj
            }
        }
    }
}


<#
.Synopsis
   Terminate a specific session connected to a Metasploit server.
.DESCRIPTION
   Terminate a specific session connected to a Metasploit server given the Session Id number.
#>
function Remove-MSFSession
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

        # Session Id
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=1,
        ValueFromPipelineByPropertyName=$true)]
        [int]$SessionId
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
        
        Write-Verbose "Checking if Session ID $($SessionId) exists in the current server session."
        $current_sessions = Get-MSFSession -Session $MSession
        if ($current_sessions)
        {
            $found = $false
            foreach ($sess in $current_sessions)
            {
                if ($sess.SessionID -eq $SessionId)
                {
                    $found = $true
                    Write-Verbose "Specified session is present."
                }
            }
            if (!($found))
            {
                Write-Warning "Sepcified session was not found."
                return
            }
        }
        else
        {
            Write-Warning "No sessions where found."
            return
        }

        $request_reply = $MSession.Session.Execute("session.stop",$SessionId)

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
                    $request_reply = $sessionobj.Session.Execute("session.stop",$SessionId)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
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
                $connectobj = New-Object -TypeName psobject -Property $request_reply
                $connectobj.pstypenames[0] = "Metasploit.Action"
                $connectobj 
            }
        }
    }
}
