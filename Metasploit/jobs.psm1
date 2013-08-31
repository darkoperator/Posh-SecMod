<#
.Synopsis
   Enumerates current jobs running on a Metasploit server.
.DESCRIPTION
   Enumerates current jobs running on a Metasploit server.
.EXAMPLE
   Get-MSFJob -Id 0 | fl *


JobId       : 1
Name        : Exploit: multi/handler
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Get-MSFJob
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
                    Write-Verbose "Using session $($conn.id)"
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
        Write-Verbose "Enumerating list of hosts."
        $request_reply = $MSession.Session.Execute("job.list")
        if (!($request_reply))
        {
            Write-Warning "No Jobs where found."
            return
        }

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
                    $request_reply = $sessionobj.Session.Execute("job.list")
                    if ($request_reply)
                    {
                        foreach ($job in $request_reply.keys)
                        {
                            $jobprops = [ordered]@{}
                            $jobprops.add("JobId", $job)
                            $jobprops.add("Name", $request_reply[$job])
                            $jobprops.add('MSHost', $MSession.Host)
                            $jobprops.Add("MSSessionID", $MSession.Id)
                            $jobobj = New-Object -TypeName psobject -Property $jobprops
                            $jobobj.pstypenames[0] = "Metasploit.Job"
                            $jobobj   
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
            if ($request_reply)
            {
                foreach ($job in $request_reply.keys)
                {
                    
                    $jobprops = [ordered]@{}
                    $jobprops.add("JobId", $job)
                    $jobprops.add("Name", $request_reply[$job])
                    $jobprops.add('MSHost', $MSession.Host)
                    $jobprops.Add("MSSessionID", $MSession.Id)
                    $jobobj = New-Object -TypeName psobject -Property $jobprops
                    $jobobj.pstypenames[0] = "Metasploit.Job"
                    $jobobj    
                }
            }
            else
            {
                Write-Warning "No Jobs where found"
            }
        }
    }
}

<#
.Synopsis
   Gets more detailed information about a running jon on a Metasploit server.
.DESCRIPTION
   Gets more detailed information about a running jon on a Metasploit server. 
   It will also get all the Datastore parameters used to launch the module running 
   as a job.
.EXAMPLE
   Get-MSFJobInfo -Id 0 -JobId 1


JobId       : 1
Name        : Exploit: multi/handler
StartTime   : 8/24/2013 5:25:15 PM
Datastore   : @{VERBOSE=False; WfsDelay=0; EnableContextEncoding=False; DisablePayloadHandler=False; ExitOnSession=True; 
              ListenerTimeout=0; LPORT=8080; LHOST=192.168.1.104; PAYLOAD=windows/meterpreter/reverse_tcp; ReverseConnectRetries=5; 
              ReverseAllowProxy=False; EnableStageEncoding=False; PrependMigrate=False; EXITFUNC=process; AutoLoadStdapi=True; 
              InitialAutoRunScript=; AutoRunScript=; AutoSystemInfo=True; EnableUnicodeEncoding=True; TARGET=0}
MSHost      : 192.168.1.104
MSSessionID : 0
#>
function Get-MSFJobInfo
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
        [Int]$JobId
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
        
        $current_jobs = Get-MSFJob -Session $MSession
        if ($current_jobs)
        {
            $found = $true
            foreach ($cjob in $current_jobs)
            {
                if ($cjob.JobId -eq $JobId)
                {
                    $found = $false
                }
            }
            if ($found)
            {
                Write-Warning "Job Id $($JobId) does not exist in server session $($MSession.Id)."
                return
            }
        }
        else
        {
            Write-Warning "No jobs where found for the server session."
            return
        }
        $request_reply = $MSession.Session.Execute("job.info", $JobId)

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
                    $request_reply = $sessionobj.Session.Execute("job.info", $JobId)
                    if ($request_reply)
                    {
                        $jobprops = [ordered]@{}
                        $jobprops.add("JobId", $request_reply.jid)
                        $jobprops.add("Name", $request_reply.name)
                        $jobprops.add("StartTime", $origin.AddSeconds($request_reply.start_time))
                        $jobprops.add("Datastore", (New-Object -TypeName psobject -Property $request_reply.datastore))
                        $jobprops.add('MSHost', $MSession.Host)
                        $jobprops.Add("MSSessionID", $MSession.Id)
                        $jobobj = New-Object -TypeName psobject -Property $jobprops
                        $jobobj.pstypenames[0] = "Metasploit.Job"
                        $jobobj   
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
            if ($request_reply)
            {  
                $jobprops = [ordered]@{}
                $jobprops.add("JobId", $request_reply.jid)
                $jobprops.add("Name", $request_reply.name)
                $jobprops.add("StartTime", $origin.AddSeconds($request_reply.start_time))
                $jobprops.add("Datastore", (New-Object -TypeName psobject -Property $request_reply.datastore))
                $jobprops.add('MSHost', $MSession.Host)
                $jobprops.Add("MSSessionID", $MSession.Id)
                $jobobj = New-Object -TypeName psobject -Property $jobprops
                $jobobj.pstypenames[0] = "Metasploit.Job"
                $jobobj    
            }
        }
    }
}


<#
.Synopsis
   Stops and removes a running job on a Metasploit server.
.DESCRIPTION
   Stops and removes a running job on a Metasploit server.
#>
function Remove-MSFJob
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
        [Int]$JobId
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
        
        $request_reply = $MSession.Session.Execute("job.stop", $JobId)

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
                    $request_reply = $sessionobj.Session.Execute("job.stop", $JobId)
                    if ($request_reply.ContainsKey('result'))
                    {
                        $request_reply.add('MSHost', $MSession.Host)
                        $jobprops.Add("MSSessionID", $MSession.Id)
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
                $jobprops.Add("MSSessionID", $MSession.Id)
                $connectobj = New-Object -TypeName psobject -Property $request_reply
                $connectobj.pstypenames[0] = "Metasploit.Action"
                $connectobj 
            }
        }
    }
}