if (!(Test-Path variable:Global:NessusConn ))
{
    $Global:NessusConn = New-Object System.Collections.ArrayList
}
 

##################################
#     Nessus Session Cmdlets     #
##################################


<#
.Synopsis
   Creates a session to a Nessus 5.x Server
.DESCRIPTION
   Create a session to a given Nessus 5.x Server.
.EXAMPLE
    New-NessusSession -ComputerName 192.168.10.3 -Credentials (Get-Credential) -IgnoreSSL
    cmdlet Get-Credential at command pipeline position 1
    Supply values for the following parameters:


    User             : carlos
    IsAdmin          : True
    Index            : 0
    SessionState     : Nessus.Data.NessusManagerSession
    SessionManager   : Nessus.Data.NessusManager
    IdleTimeout      : 30
    ScannerBootTime  : 4/10/2013 10:25:52 AM
    PluginSet        : 201302261815
    LoaddedPluginSet : 201302261815
    ServerUUID       : fd14bd4c-27bc-7c35-0308-876409e7758d0b0d82169800a061
    Token            : 421969f30a6887aa52af709f21c84b344e413dd3cd0e7eee
    MSP              : True
    ServerHost       : 192.168.10.3

#>

function New-NessusSession
{
    [CmdletBinding()]
    Param
    (
        # Nessus Server FQDN or IP.
        [Parameter(Mandatory=$true,
        Position=0)]
        [string[]]$ComputerName,

        # Credentials for connecting to the Nessus Server
        [Parameter(Mandatory=$true,
        Position=1)]
        [Management.Automation.PSCredential]$Credentials,

        # Port of the Nessus server.
        [Parameter(Mandatory=$false,
        Position=2)]
        [Int32]$Port = 8834,

        # Check on the user cotext for the certificate CA
        [switch]$UseUserContext,

        # Ignore SSL certificate validation errors
        [switch]$IgnoreSSL

        )

    Begin
    {

       
    }
    Process
    {
        foreach($comp in $ComputerName)
        {
            # Make sure that we trust the certificate
            $ConnectString = "https://$comp`:$port"
            $WebRequest = [Net.WebRequest]::Create($ConnectString)
            
            # Random number for sequence request
            $rand = New-Object System.Random
                    
            
       
            if (!$IgnoreSSL)
            {
                # set default proxy settings
                $proxy = [System.Net.WebRequest]::GetSystemWebProxy()
                $proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
                $WebRequest.Proxy = $Proxy

                $status = $true

                $WebRequest.Timeout = 3000
                $WebRequest.AllowAutoRedirect = $true
                Write-Verbose "Checking if SSL Certificate is valid."
                [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                ## SSL Checking di
                try {$Response = $WebRequest.GetResponse()}
                catch {}

                if ($WebRequest.ServicePoint.Certificate -ne $null) 
                {
                    Write-Verbose "Was able to pull certificate information from host."
                    $Cert = [Security.Cryptography.X509Certificates.X509Certificate2]$WebRequest.ServicePoint.Certificate.Handle
                    try {$SAN = ($Cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.17"}).Format(0) -split ", "}
                    catch {$SAN = $null}
                    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain -ArgumentList (!$UseUserContext)
                    [void]$chain.ChainPolicy.ApplicationPolicy.Add("1.3.6.1.5.5.7.3.1")
                    $Status = $chain.Build($Cert)
                    [string[]]$ErrorInformation = $chain.ChainStatus | ForEach-Object {$_.Status}
                    $chain.Reset()
                    [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
                    $certinfo = New-Object PKI.Web.WebSSL -Property @{
                        Certificate = $WebRequest.ServicePoint.Certificate;
                        Issuer = $WebRequest.ServicePoint.Certificate.Issuer;
                        Subject = $WebRequest.ServicePoint.Certificate.Subject;
                        SubjectAlternativeNames = $SAN;
                        CertificateIsValid = $Status;
                        ErrorInformation = $ErrorInformation

                    }
                    
                } 
                if (!$Status)
                {
                    Write-Verbose "Certificate is not valid!"
                    Write-Warning "Certificate is not valid and returned errors: $($ErrorInformation)"
                    $certinfo

                    $answer2cert = Read-Host "Do you wish to continue? (Y/N)"
                    if ($answer2cert -eq "n")
                    {
                        return
                    }
                }
            }    

            # Since we where able to connect we load the assemblies to use the Nessus-Sharp lib.
            $NessusSession = New-Object Nessus.Data.NessusManagerSession -ArgumentList "https",$comp,$port
            write-verbose "Session object was created successfuly"
            $NessusSessionManager = New-Object Nessus.Data.NessusManager -ArgumentList $NessusSession
            write-verbose "Session Manager Objects was created successfuly"


            # Log to server using the provided credentials
            write-verbose "Logging in to the server."
            $log_status = $NessusSessionManager.Login(
                $Credentials.GetNetworkCredential().UserName, 
                $Credentials.GetNetworkCredential().Password,
                $rand.next(),
                [ref]$true)
            
            # Proceed if we where able to connect.
            if ($log_status.reply.status -eq "OK")
            {
                Write-Verbose "Successfully loged on to server."
                $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
                # Get current index
                $SessionIndex = $Global:nessusconn.Count
                Write-Verbose "Adding connection as index $($SessionIndex)"
                # Create hash with properties for custom objec
                $sessobj = New-Object -TypeName Nessus.Server.Session
                $sessobj.Index = $SessionIndex
                $sessobj.SessionState = $NessusSession
                $sessobj.SessionManager = $NessusSessionManager
                $sessobj.PluginSet = $log_status.reply.contents.loaded_plugin_set
                $sessobj.LoaddedPluginSet = $log_status.reply.contents.loaded_plugin_set
                $sessobj.IdleTimeout = $log_status.reply.contents.idle_timeout
                $sessobj.ScannerBootTime = $origin.AddSeconds($log_status.reply.contents.scanner_boottime).ToLocalTime()
                $sessobj.MSP = $log_status.reply.contents.msp
                $sessobj.ServerUUID = $log_status.reply.contents.server_uuid
                $sessobj.Token = $log_status.reply.contents.token
                $sessobj.ServerHost = $comp
            
                # Add object to global variable holding the sessions.
                [void]$Global:nessusconn.Add($sessobj)

                # Return Object
                $sessobj
            
            }
            else 
            {
                # if we can not connect throw an exception
                throw "Connection to $($comp) at $($Port) with User $($Credentials.GetNetworkCredential().UserName) Failed"
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Closes one or more Nessus sessions
.DESCRIPTION
    The Remove-NessusSession cmdlet closes Nessus sessions in the current session. It does not stops 
    any scans that are running in the Nessus Server. Specific Sessions can be closed given the session
    Index.
.EXAMPLE
   Disconnecting session with Index 0

   PS C:\> Remove-NessusSession -Index 0

#>

function Remove-NessusSession
{
    [CmdletBinding()]
    param(

        # Nessus session index
        [Parameter(Mandatory=$true,
        Position=0,
        ParameterSetName = "Index")]
        [int32[]]$Index,

        # Nessus Session Object
        [Parameter(Mandatory=$true,
        Position=0,
        ParameterSetName = "Session",
        ValueFromPipeline=$True)]
        [Nessus.Server.Session]$Session
    )
    BEGIN {
        
    }
    PROCESS {
        if ($Index.Length -gt 0)
        {
            foreach($conn in $Global:nessusconn)
            {
                if ($conn.index -in $Index)
                {
                    $NSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Nessus.Server.Session")
        {
                $NSession = $Session
        }
        else 
        {
            throw "No Nessus.Server.Session was provided"
        }

        if ($NSession) 
        {
            Write-Verbose "Removing session with Index of $($NSession.index)"
            try
            {
                $NSession.SessionManager.Logout() | Out-Null
                $Global:nessusconn.Remove($NSession)
            }
            catch 
            {
                $Global:nessusconn.Remove($NSession)
            }
            Write-Verbose "Session removed."
            $true
        }
    }

    END {}
}


<#
.Synopsis
    Gets the Nessus sessions on local and remote computers.

.DESCRIPTION
   Without parameters, Get-NessusSession gets all sessions that were created in the current session.
    
    Use the Index parameter to select from among the sessions that Get-PSSession returns.

.EXAMPLE
   Get all sessions available

    PS C:\> Get-NessusSession


    User             : carlos
    IsAdmin          : True
    Index            : 0
    SessionState     : Nessus.Data.NessusManagerSession
    SessionManager   : Nessus.Data.NessusManager
    IdleTimeout      : 30
    ScannerBootTime  : 4/10/2013 10:25:52 AM
    PluginSet        : 201302261815
    LoaddedPluginSet : 201302261815
    ServerUUID       : fd14bd4c-27bc-7c35-0308-876409e7758d0b0d82169800a061
    Token            : 421969f30a6887aa52af709f21c84b344e413dd3cd0e7eee
    MSP              : True
    ServerHost       : 192.168.10.3

#>

function Get-NessusSession
{
    [CmdletBinding()]
    param(

        # Nessus session index.
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
                foreach($Connection in $Global:nessusconn)
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
            foreach($s in $Global:nessusconn){$return_sessions += $s}
            $return_sessions
        }
    }
    End{}
}


<#
.Synopsis
   Gets Nessus Server Session Feed Information
.DESCRIPTION
   Gets the feed information for the server that correspond to a local or
   remote Nessus session. Session must be specified by Index or Nessus Server
   Session Object.
.EXAMPLE
   Gets the feed information for a specific session.

    PS C:\> Get-NessusServerFeedInfo -Index 0

    Feed             : ProFeed
    ServerVersion    : 5.2.0
    WebServerVersion : 4.0.29
    MSP              : False
    Expiration       : 9/19/2013 4:00:00 AM
    ServerHost       : 192.168.10.3

#>

function Get-NessusServerFeedInfo 
{
    [CmdletBinding()]
    param(

        # Nessus session index
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

        # Nessus session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [Nessus.Server.Session]$Session
    )
    BEGIN {
        
    }
    PROCESS {    
        if ($Index.Count -gt 0)
        {
            foreach($conn in $Global:nessusconn)
            {
                if ($conn.index -in $Index)
                {
                    $NSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Nessus.Server.Session")
        {
                $NSession = $Session
        }
        else {
            throw "No Nessus.Server.Session was provided"
        }
        Try {
            $request_reply = $NSession.SessionManager.GetFeedInformation().reply
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $NSession.SessionManager.Login(
                $NSession.SessionState.Username, 
                $NSession.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionManager.GetFeedInformation().reply
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }
            
        }
    
        # Check that we got the proper response
        if ($request_reply.status -eq "OK"){
            # Returns epoch time so we need to tranform it
            $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
            Write-Verbose -Message "We got an OK reply from the session."
            $feedinfoobj = New-Object -TypeName Nessus.Server.FeedInfo
            
            $feedinfoobj.Feed             = $request_reply.contents.feed
            $feedinfoobj.ServerVersion    = $request_reply.contents.server_version
            $feedinfoobj.WebServerVersion = $request_reply.contents.web_server_version
            $feedinfoobj.MSP              = &{if($request_reply.contents.msp -like "TRUE"){$true}else{$false}}
            $feedinfoobj.Expiration       = $origin.AddSeconds($request_reply.contents.expiration)
            $feedinfoobj.ServerHost       = $NSession.ServerHost
            
            # Retun the feed object
            $feedinfoobj
        }
        else {
            $request_reply
        }
    }
}


<#
.Synopsis
    Get the server load for a local or remote Nessus session
.DESCRIPTION
    Get the server load for a local or remote Nessus session. The session
    can be specified by Index or by passing a Nessus Session Object.
.EXAMPLE
    Get a specific Nessus Session server load

    PS C:\> Get-NessusServerLoad -Index 0


    ServerHost      : 192.168.10.3
    Platform        : LINUX
    ScanCount       : 0
    SessionCount    : 1
    HostCount       : 0
    TCPSessionCount : 0
    LoadAverage     : 0.00
#>
   
function Get-NessusServerLoad 
{
    [CmdletBinding()]
    param(

        # Nessus session index
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

        # Nessus session object
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [Nessus.Server.Session]$Session
    )
    BEGIN {
        # Random number for sequence request
        $rand = New-Object System.Random
        # Options for XMLRPC request
        $ops = @{
            seq = $rand.Next()
        }
    }
    PROCESS {    
        if ($Index.Count -gt 0)
        {
            foreach($conn in $Global:nessusconn)
            {
                if ($conn.index -in $Index)
                {
                    $NSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Nessus.Server.Session")
        {
                $NSession = $Session
        }
        else {
            throw "No Nessus.Server.Session was provided"
        }
        Try {
            $request_reply = $NSession.SessionState.ExecuteCommand("/server/load", $ops)
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $NSession.SessionManager.Login(
                $NSession.SessionState.Username, 
                $NSession.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionState.ExecuteCommand("/server/load", $ops)
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }
            
        }
    
        # Check that we got the proper response
        if ($request_reply.reply.status -eq "OK"){
            Write-Verbose -Message "We got an OK reply from the session."
            $load_props = [ordered]@{
                ServerHost      = $NSession.ServerHost
                Platform        = $request_reply.reply.contents.platform
                ScanCount       = $request_reply.reply.contents.load.num_scans
                SessionCount    = $request_reply.reply.contents.load.num_sessions
                HostCount       = $request_reply.reply.contents.load.num_hosts
                TCPSessionCount = $request_reply.reply.contents.load.num_tcp_sessions
                LoadAverage     = $request_reply.reply.contents.load.loadavg
            }
            $srvload = [pscustomobject]$load_props
            $srvload.pstypenames.insert(0,'Nessus.Server.Load')
            $srvload
        }
        else {
            $request_reply
        }
    }
}


<#
.Synopsis
   Initiates a Nessus Feed Update for a Local or Remote Nessus Session
.DESCRIPTION
   Initiates a Nessus Feed Update for a Local or Remote Nessus Session given
   a Nessus session index or Nessus Session Object.
.EXAMPLE
   Have a specific Nessus server for a given session inititate a Feed Update.

   PS C:\> Start-NessusServerFeedUpdate -Index 0 -Verbose
#>

function Start-NessusServerFeedUpdate
{
    [CmdletBinding()]
    param(
        # Nessus session index
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

        # Nessus session onject
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [Nessus.Server.Session]$Session
    )
    BEGIN {
        # Random number for sequence request
        $rand = New-Object System.Random
        # Options for XMLRPC request
        $ops = @{
            seq = $rand.Next()
        }
    }
    PROCESS {    
        if ($Index.Count -gt 0)
        {
            foreach($conn in $Global:nessusconn)
            {
                if ($conn.index -in $Index)
                {
                    $NSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Nessus.Server.Session")
        {
                $NSession = $Session
        }
        else {
            throw "No Nessus.Server.Session was provided"
        }
        
        # Make sure we are admin since it is required for this command
        if (!$NSession.SessionState.IsAdministrator)
        {
            throw "Session does not have Administrative privelages."
        }

        Try {
            $request_reply = $NSession.SessionState.ExecuteCommand("/server/update", $ops)
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $NSession.SessionManager.Login(
                $NSession.SessionState.Username, 
                $NSession.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK")
            {
                $request_reply = $NSession.SessionState.ExecuteCommand("/server/update", $ops)
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }
            
        }
    
        # Check that we got the proper response
        if ($request_reply.reply.status -eq "OK")
        {
            Write-Verbose -Message "We got an OK reply from the session."
            if ($request_reply.reply.contents.update -eq "OK")
            {
                Write-Verbose "Plugin Feed Update initiated."
            }
        }
    }
}


<#
.Synopsis
   Gets a local or remote Nessus Server session Advanced Settings
.DESCRIPTION
   Gets a local or remote Nessus Server session Advanced Settings given either
   a Nessus Server Session Index or a Nessus Server Session Object.
.EXAMPLE
   Get a given Nessus Server session advanced settings

    PS C:\> Get-NessusServerAdvancesSettings -Index 0


    allow_post_scan_editing          : yes
    auto_enable_dependencies         : yes
    auto_update                      : yes
    auto_update_delay                : 24
    cgi_path                         : /cgi-bin:/scripts
    checks_read_timeout              : 5
    disable_ntp                      : no
    disable_xmlrpc                   : no
    dumpfile                         : /opt/nessus/var/nessus/logs/nessusd.dump
    global.max_hosts                 : 125
    global.max_scans                 : 0
    global.max_web_users             : 1024
    listen_address                   : 0.0.0.0
    listen_port                      : 1241
    log_whole_attack                 : no
    logfile                          : /opt/nessus/var/nessus/logs/nessusd.messages
    max_checks                       : 5
    max_hosts                        : 30
    nasl_log_type                    : normal
    nasl_no_signature_check          : no
    non_simult_ports                 : 139, 445, 3389
    optimize_test                    : yes
    plugin_upload                    : yes
    plugins_timeout                  : 320
    port_range                       : default
    purge_plugin_db                  : no
    qdb_mem_usage                    : high
    reduce_connections_on_congestion : no
    report_crashes                   : yes
    rules                            : /opt/nessus/etc/nessus/nessusd.rules
    safe_checks                      : yes
    silent_dependencies              : yes
    slice_network_addresses          : no
    ssl_cipher_list                  : strong
    stop_scan_on_disconnect          : no
    stop_scan_on_hang                : no
    throttle_scan                    : yes
    use_kernel_congestion_detection  : no
    www_logfile                      : /opt/nessus/var/nessus/logs/www_server.log
    xmlrpc_idle_session_timeout      : 30
    xmlrpc_listen_port               : 8834
#>

function Get-NessusServerAdvancesSettings
{
    [CmdletBinding()]
    param(

        # Nessus server session index.
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

        # Nessus Server Session Object.
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [Nessus.Server.Session]$Session
    )
    BEGIN {
        # Random number for sequence request
        $rand = New-Object System.Random
        # Options for XMLRPC request
        $ops = @{
            seq = $rand.Next()
        }
    }
    PROCESS {    
        if ($Index.Count -gt 0)
        {
            foreach($conn in $Global:nessusconn)
            {
                if ($conn.index -in $Index)
                {
                    $NSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Nessus.Server.Session")
        {
                $NSession = $Session
        }
        else {
            throw "No Nessus.Server.Session was provided"
        }

        # Make sure we are admin since it is required for this command
        if (!$NSession.SessionState.IsAdministrator)
        {
            throw "Session does not have Administrative privelages."
        }


        Try {
            $request_reply = $NSession.SessionState.ExecuteCommand("/server/preferences/list", $ops)
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $NSession.SessionManager.Login(
                $NSession.SessionState.Username, 
                $NSession.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionState.ExecuteCommand("/server/preferences/list", $ops)
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }
            
        }
    
        # Check that we got the proper response
        if ($request_reply.reply.status -eq "OK"){
            Write-Verbose -Message "We got an OK reply from the session."
            $prefs = $request_reply.reply.contents.ServerPreferences.preference
            $prefopts = [ordered]@{}
            foreach($pref in $prefs)
            {
                $prefopts.add($pref.name,$pref.value)
            }
            $srvprefs = [pscustomobject]$prefopts
            $srvprefs.pstypenames.insert(0,'Nessus.Server.Settings.Advanced')
            $srvprefs
        }
    }
}


<#
.Synopsis
   Gets a Nessus Server local or remote session general configuration settings
.DESCRIPTION
   Gets a Nessus Server local or remote session general configuration settings. These
   settings are used by the Nessus Server for the proxy configuration for updating the
   Nessus Feed. To retive the configuretion a Nessus Server Session Index or Session Object
   must be specified.
.EXAMPLE
   Get a Nessus Server General Settings for a given session

    PS C:\> Get-NessusServerGeneralSettings -Index 0


    proxy          : 
    proxy_port     : 
    proxy_username : 
    proxy_password : 
    user_agent     : 
    custom_host    : 
#>

function Get-NessusServerGeneralSettings
{
    [CmdletBinding()]
    param(
        # Nessus server session index.
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

        # Nessus Server Session Object.
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [Nessus.Server.Session]$Session
    )
    BEGIN {
        # Random number for sequence request
        $rand = New-Object System.Random
        # Options for XMLRPC request
        $ops = @{
            seq = $rand.Next()
        }
    }
    PROCESS {    
        if ($Index.Count -gt 0)
        {
            foreach($conn in $Global:nessusconn)
            {
                if ($conn.index -in $Index)
                {
                    $NSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Nessus.Server.Session")
        {
                $NSession = $Session
        }
        else {
            throw "No Nessus.Server.Session was provided"
        }

        # Make sure we are admin since it is required for this command
        if (!$NSession.SessionState.IsAdministrator)
        {
            throw "Session does not have Administrative privelages."
        }


        Try {
            $request_reply = $NSession.SessionState.ExecuteCommand("/server/securesettings/list", $ops)
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $NSession.SessionManager.Login(
                $NSession.SessionState.Username, 
                $NSession.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionState.ExecuteCommand("/server/securesettings/list", $ops)
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }
            
        }
    
        # Check that we got the proper response
        if ($request_reply.reply.status -eq "OK"){
            Write-Verbose -Message "We got an OK reply from the session."
            $prefs = $request_reply.reply.contents.SecureSettings.ProxySettings.childnodes
            $prefopts = [ordered]@{}
            foreach($pref in $prefs)
            {
                $prefopts.add($pref.name,$pref.value)
            }
            $srvprefs = [pscustomobject]$prefopts
            $srvprefs.pstypenames.insert(0,'Nessus.Server.Settings.General')
            $srvprefs
        }
    }
}


<#
.Synopsis
   Gets a Nessus Server local or remote session Mobile configuration settings
.DESCRIPTION
   Gets a Nessus Server local or remote session mobile configuration settings. These
   settings are used by the Nessus Server to connect to mobile management solutions so
   as to identify vulnerable mobile devices. To retive the configuretion a Nessus 
   Server Session Index or Session Object
   must be specified.
.EXAMPLE
   Get a list of all the mobile settings for a given Nessus Server Session

    PS C:\> Get-NessusServerMobileSettings -Index 0 | fl


    Platform : Apple Profile Manager API Settings
    Name     : Apple Profile Manager server 
    PValue   : 
    SValue   : 

    Platform : Apple Profile Manager API Settings
    Name     : Apple Profile Manager port 
    PValue   : 443
    SValue   : 

    Platform : Apple Profile Manager API Settings
    Name     : Apple Profile Manager username 
    PValue   : 
    SValue   : 

    Platform : Apple Profile Manager API Settings
    Name     : Apple Profile Manager password 
    PValue   : 
    SValue   : 

    Platform : Apple Profile Manager API Settings
    Name     : SSL 
    PValue   : yes
    SValue   : 

    Platform : Apple Profile Manager API Settings
    Name     : Verify SSL Certificate 
    PValue   : no
    SValue   : 

    Platform : Apple Profile Manager API Settings
    Name     : Force Device Updates 
    PValue   : yes
    SValue   : 

    Platform : Apple Profile Manager API Settings
    Name     : Device Update Timeout (Minutes) 
    PValue   : 5
    SValue   : 

    Platform : ADSI Settings
    Name     : Domain Controller 
    PValue   : 
    SValue   : 192.168.10.10

    Platform : ADSI Settings
    Name     : Domain 
    PValue   : 
    SValue   : acmelabs.com

    Platform : ADSI Settings
    Name     : Domain Username 
    PValue   : 
    SValue   : administrator

    Platform : ADSI Settings
    Name     : Domain Password 
    PValue   : 
    SValue   : *********
#>

function Get-NessusServerMobileSettings
{
    [CmdletBinding()]
    param(
        # Nessus server session index.
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

        # Nessus Server Session Object.
        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$true,
        Position=0)]
        [Nessus.Server.Session]$Session
    )
    BEGIN {
        # Random number for sequence request
        $rand = New-Object System.Random
        # Options for XMLRPC request
        $ops = @{
            seq = $rand.Next()
        }
    }
    PROCESS {    
        if ($Index.Count -gt 0)
        {
            foreach($conn in $Global:nessusconn)
            {
                if ($conn.index -in $Index)
                {
                    $NSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Nessus.Server.Session")
        {
                $NSession = $Session
        }
        else {
            throw "No Nessus.Server.Session was provided"
        }

        # Make sure we are admin since it is required for this command
        if (!$NSession.SessionState.IsAdministrator)
        {
            throw "Session does not have Administrative privelages."
        }


        Try {
            $request_reply = $NSession.SessionState.ExecuteCommand("/mobile/settings/list", $ops)
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $NSession.SessionManager.Login(
                $NSession.SessionState.Username, 
                $NSession.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionState.ExecuteCommand("/mobile/settings/list", $ops)
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }
            
        }
    
        # Check that we got the proper response
        if ($request_reply.reply.status -eq "OK")
        {
            Write-Verbose -Message "We got an OK reply from the session."
            $platforms = $request_reply.reply.contents.settings.setting
            foreach ($platform in $platforms)
            {
                foreach($pref in $platform.values)
                {
                    $prefopts = [ordered]@{}
                    $prefopts.add('Platform',$pref.plugin_name)
                    $prefopts.add('Name',$pref.name.Substring(0,$pref.name.Length-1))
                    $prefopts.add('PValue',$pref.pvalues)
                    $prefopts.add('SValue',$pref.svalue)
                    $srvprefs = [pscustomobject]$prefopts
                    $srvprefs.pstypenames.insert(0,'Nessus.Server.Settings.Mobile')
                    $srvprefs
                }
                
            }
        }
    }
}

###############################
#     Nessus User Cmdlets     #
###############################


<#
.Synopsis
   Gets the Nessus Users on local and remote computers.
.DESCRIPTION
   Gets a list of the Nessus sessions on local and remote computers.
   Retrives information like last time the user logged on and f it is
   an administrator or not.
.EXAMPLE
    Gets a list of users from a specif Nessus Server Session.
   
    PS C:\> Get-NessusUsers -Index 0


    ServerHost  : 192.168.10.3
    Name        : carlos
    IsAdmin     : True
    LastLogging : 4/10/2013 4:38:22 PM
    Session     : Nessus.Server.Session

#>

function Get-NessusUsers 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,
        Position=0,
        ParameterSetName = "Index")]
        [int32[]]$Index,

        [Parameter(Mandatory=$true,
        Position=0,
        ParameterSetName = "Session",
        ValueFromPipeline=$True)]
        [Nessus.Server.Session]$Session
    )
    BEGIN {}
    PROCESS
    {
        if ($Index.Count -gt 0)
        {
            foreach($conn in $Global:nessusconn)
            {
                if ($conn.index -in $Index)
                {
                    $NSession = $conn
                }
            }
        }
        elseif ($Session -ne $null -and $Session.pstypenames[0] -eq "Nessus.Server.Session")
        {
                $NSession = $Session
        }
        else 
        {
            throw "No Nessus.Server.Session was provided"
        }
        
        # Make sure we are admin since it is required for this command
        if (!$NSession.SessionState.IsAdministrator)
        {
            throw "Session does not have Administrative privelages."
        }

        # Retrieve the Nessus users from a session.
        Try 
        {
            $request_reply = $NSession.SessionManager.ListUsers().reply
        }
        Catch [Net.WebException] 
        {   
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $NSession.SessionManager.Login(
                $NSession.SessionState.Username, 
                $NSession.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK")
            {
                $request_reply = $NSession.SessionManager.ListUsers().reply
            }
            else
            {
                throw "Session expired could not Re-Authenticate"
            }
        }

        # Check that we got the proper response
        if ($request_reply.status -eq "OK")
        {
            # Returns epoch time so we need to tranform it
            $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
            Write-Verbose -Message "We got an OK reply from the session."
            $request_reply.contents.users.user | ForEach-Object {
                $userobj = New-Object -TypeName Nessus.Server.User
                $userobj.Name        = $_.name
                $userobj.IsAdmin     = &{if($_.admin -like "TRUE"){$true}else{$false}}
                $userobj.LastLogging = $origin.AddSeconds($_.lastlogin).ToLocalTime()
                $userobj.session     = $NSession
                $userobj
            }
        }
    }
}


<#
.Synopsis
   Creates a new Nessus Users on local and remote computers.
.DESCRIPTION
   Long description
.EXAMPLE
   Creates a new Nessus Users on local and remote computers. A PSCredential
   Object with the username and the password of the user to create on the Nessus
   Server. The user can be made in to an administrator of the Nessus Server when
   the switch parameter IsAdmin is specified.
.EXAMPLE
   Create a regular user name auditor1

    PS C:\> New-NessusUser -Index 0 -Credentials (Get-Credential)
    cmdlet Get-Credential at command pipeline position 1
    Supply values for the following parameters:


    ServerHost  : 192.168.10.3
    Name        : auditor1
    IsAdmin     : False
    LastLogging : 1/1/0001 12:00:00 AM
    Session     : Nessus.Server.Session


.EXAMPLE
   Create a user with Administrator privilages named admin1

    PS C:\> New-NessusUser -Index 0 -Credentials (Get-Credential) -IsAdmin
    cmdlet Get-Credential at command pipeline position 1
    Supply values for the following parameters:


    ServerHost  : 192.168.10.3
    Name        : admin1
    IsAdmin     : True
    LastLogging : 1/1/0001 12:00:00 AM
    Session     : Nessus.Server.Session
#>

function New-NessusUser
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index")]
        [int32[]]$Index,

        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$True)]
        [Nessus.Server.Session]$Session, 

        [Parameter(Mandatory=$true,
        ParameterSetName = "Index")]
        [Parameter(ParameterSetName = "Session")]
        [Management.Automation.PSCredential]$Credentials,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [Parameter(ParameterSetName = "Session")]
        [switch]$IsAdmin
     )
    BEGIN {
        
    }
    PROCESS{
        
        # Process the session information
        if ($Index.Length -gt 0)
        {
            foreach($conn in $Global:nessusconn)
            {
                if ($conn.index -in $Index)
                {
                    $NSession = $conn
                }
            }
        }
        elseif ($Session -ne $null)
        {
                $NSession = $Session
        }

        # Throw exception if session not found
        if ($NSession -eq $null){
            throw "The specified session does not exist"
        }
        
        # Make sure we are admin since it is required for this command
        if (!$NSession.SessionState.IsAdministrator)
        {
            throw "Session does not have Administrative privelages."
        }

        Try {
            $reply = $NSession.SessionManager.AddUser($Credentials.GetNetworkCredential().UserName,
                                                            $Credentials.GetNetworkCredential().Password, 
                                                            $IsAdmin)
        }
        Catch {
            # Catch if it is that the session timedout
            if ($Error[0].Exception -like "*403*Forbidden.") {
                $reply = $NSession.SessionManager.AddUser($Credentials.GetNetworkCredential().UserName,
                                                            $Credentials.GetNetworkCredential().Password, 
                                                            $IsAdmin)
            }
        }

        # We can get more than one reply when creating a user
        if ($reply.count -gt 1){
            $request_reply = $reply[0]
        }
        else{
            $request_reply = $reply
        }

        # Check that we got the proper response
        if ($request_reply.reply.status -eq "OK"){
           
            Write-Verbose -Message "We got an OK reply from the session."
            $userobj = New-Object Nessus.Server.User
            
            $userobj.Name        = $request_reply.reply.contents.user.name
            $userobj.IsAdmin     = &{if($request_reply.reply.contents.user.admin -like "TRUE"){$true}else{$false}}
            $userobj.Session     = $NSession
            
            $userobj
        }
        else{

            throw $request_reply.reply.contents
        }
        
    }
}


<#
.Synopsis
   Removes a Nessus Users on local and remote computers.
.DESCRIPTION
   Removes a Nessus Users on local and remote computers, the username
   of the user that needs to be removed from a specified Nessus Session. 
.EXAMPLE
   Example of how to use this cmdlet

    PS C:\> Remove-NessusUser -Index 0 -UserName auditor1

    PS C:\> Get-NessusUsers -Index 0


    ServerHost  : 192.168.10.3
    Name        : carlos
    IsAdmin     : True
    LastLogging : 4/10/2013 4:38:22 PM
    Session     : Nessus.Server.Session

    ServerHost  : 192.168.10.3
    Name        : admin1
    IsAdmin     : True
    LastLogging : 12/31/1969 8:00:00 PM
    Session     : Nessus.Server.Session
#>

function Remove-NessusUser
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,
        Position=0,
        ParameterSetName = "Index")]
        [int32[]]$Index,

        [Parameter(Mandatory=$true,
        Position=0,
        ParameterSetName = "Session",
        ValueFromPipeline=$True)]
        [Nessus.Server.Session]$Session, 

        [Parameter(Mandatory=$true,
        Position=1,
        ParameterSetName = "Index")]
        [Parameter(ParameterSetName = "Session")]
        [string]$UserName
     )
    BEGIN {
        
    }
    PROCESS{
        # Process the session information
        if ($Index.Length -gt 0)
        {
            foreach($conn in $Global:nessusconn)
            {
                if ($conn.index -in $Index)
                {
                    $NSession = $conn
                }
            }
        }
        elseif ($Session -ne $null)
        {
                $NSession = $Session
        }

        # Throw exception if session not found
        if ($NSession -eq $null){
            throw "The specified session does not exist"
        }

        # Make sure we are admin since it is required for this command
        if (!$NSession.SessionState.IsAdministrator)
        {
            throw "Session does not have Administrative privelages."
        }

        Try {
            $reply = $NSession.SessionManager.DeleteUser($UserName)
        }
        Catch {
            # Catch if it is that the session timedout
            if ($Error[0].Exception -like "*403*Forbidden.") {
                $reply = $NSession.SessionManager.DeleteUser($UserName)
            }
        }

        # We can get more than one reply when creating a user
        if ($reply.count -gt 1){
            $request_reply = $reply[0]
        }
        else{
            $request_reply = $reply
        }

        # Check that we got the proper response
        if ($request_reply.reply.status -eq "OK"){
            Write-Verbose "User $($userName) has been removed."
            $true
            
        }
        else{

            throw $request_reply.reply.contents
        }
        
    }
}


<#
.Synopsis
   Updates a Nessus User Password on local and remote computers.
.DESCRIPTION
   Updates a Nessus User Passord on local and remote computers. A PSCredential
   Object with the username and new password for the user that needs to be updated
   must be provided. Users can update their own password, to update other users
   passwords the user used for the Nessus Session must be one with adminostrator
   privilages.
.EXAMPLE
    Updates the password for the Admin1 user.

    PS C:\> Update-NessusUserPassword -Index 0 -Credentials (Get-Credential)
    cmdlet Get-Credential at command pipeline position 1
    Supply values for the following parameters:


    ServerHost  : 192.168.10.3
    Name        : admin1
    IsAdmin     : True
    LastLogging : 1/1/0001 12:00:00 AM
    Session     : Nessus.Server.Session
#>

function Update-NessusUserPassword
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index")]
        [int32[]]$Index,

        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        ValueFromPipeline=$True)]
        [Nessus.Server.Session]$Session, 

        [Parameter(Mandatory=$true,
        ParameterSetName = "Index")]
        [Parameter(ParameterSetName = "Session")]
        [Management.Automation.PSCredential]$Credentials
     )
    BEGIN {
        
    }
    PROCESS{
        
        # Process the session information
        if ($Index.Length -gt 0)
        {
            foreach($conn in $Global:nessusconn)
            {
                if ($conn.index -in $Index)
                {
                    $NSession = $conn
                }
            }
        }
        elseif ($Session -ne $null)
        {
                $NSession = $Session
        }

        # Throw exception if session not found
        if ($NSession -eq $null){
            throw "The specified session does not exist"
        }

        Try {
            $reply = $NSession.SessionManager.ChangeUserPassword($Credentials.GetNetworkCredential().UserName,
                                                            $Credentials.GetNetworkCredential().Password)
        }
        Catch {
            # Catch if it is that the session timedout
            if ($Error[0].Exception -like "*403*Forbidden.") {
                $reply = $NSession.SessionManager.ChangeUserPassword($Credentials.GetNetworkCredential().UserName,
                                                            $Credentials.GetNetworkCredential().Password)
            }
        }

        # We can get more than one reply when creating a user
        if ($reply.count -gt 1){
            $request_reply = $reply[0]
        }
        else{
            $request_reply = $reply
        }

        # Check that we got the proper response
        if ($request_reply.reply.status -eq "OK"){
            Write-Verbose -Message "We got an OK reply from the session."
            $userobj = New-Object Nessus.Server.User
            
            $userobj.Name        = $request_reply.reply.contents.user.name
            $userobj.IsAdmin     = &{if($request_reply.reply.contents.user.admin -like "TRUE"){$true}else{$false}}
            $userobj.Session     = $NSession
            
            $userobj
        }
        else{

            throw $request_reply.reply.contents
        }
        
    }
}
