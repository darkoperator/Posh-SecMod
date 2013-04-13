
$Global:nessusconn = New-Object System.Collections.ArrayList
 

##################################
#     Nessus Session Cmdlets     #
##################################


<#
.Synopsis
   Creates a session to a Nessus 5.x Server
.DESCRIPTION
   Create a session to a given Nessus 5.x Server.
.EXAMPLE
   Connect to a given Nessus 5.x server ignoring SSL certificate validation

    PS C:\> New-NessusSession -ComputerName 192.168.10.3 -Credentials (Get-Credential) -IgnoreSSL
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

                $WebRequest.Timeout = 3000
                $WebRequest.AllowAutoRedirect = $true
                Write-Verbose "Checking if SSL Certificate is valid."
                #[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
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
                    Write-warning "Certificate is not valid and returned errors: $($ErrorInformation)"
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
                $NSession.SessionManager.Logout()
                $Global:nessusconn.Remove($NSession)
            }
            catch 
            {
                $Global:nessusconn.Remove($NSession)
            }
            Write-Verbose "Session removed."
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

#################################
#     Nessus Policy Cmdlets     #
#################################


<#
.Synopsis
   Shows the Policies available of a Nessus Server Session.
.DESCRIPTION
   Shows the Policies available of a Nessus Server Session.
.EXAMPLE
   Shows the policies available for a specific Nessus Server Session.

    PS C:\> Show-NessusPolicy -Index 0

    PolicyID                     PolicyName                   PolicyOwner                  Visibility                  
    --------                     ----------                   -----------                  ----------                  
    -4                           Internal Network Scan        Tenable Policy Distributi... shared                      
    -3                           Web App Tests                Tenable Policy Distributi... shared                      
    -2                           Prepare for PCI-DSS audit... Tenable Policy Distributi... shared                      
    -1                           External Network Scan        Tenable Policy Distributi... shared                                        
    1                            Mobile Devices Audit         carlos                       private                     



    PS C:\> Show-NessusPolicy -Index 0 -PolicyID 1

    PolicyID                     PolicyName                   PolicyOwner                  Visibility                  
    --------                     ----------                   -----------                  ----------                  
    1                            Mobile Devices Audit         carlos                       private     
#>

function Show-NessusPolicy
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

        [Parameter(Mandatory=$false,
        Position=1,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [int]$PolicyID

    )
    Begin {
        
    }
    Process {
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

        Try {
            $request_reply = $NSession.SessionManager.ListPolicies().reply
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionManager.ListPolicies().reply
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }
            
        }
        # Check that we got the proper response
        if ($request_reply.status -eq "OK"){
            Write-Verbose -Message "We got an OK reply from the session."

            # Return all policies if none is specified by name
            if ($PolicyID -eq 0){
                Write-Verbose "No individual policy was requested."
                foreach ($policy in $request_reply.contents.policies.policy){
                    $policy_proprties = [ordered]@{
                        PolicyID = $policy.policyID
                        PolicyName = $policy.policyName
                        PolicyOwner = $policy.policyOwner
                        Visibility = $policy.visibility
                        #PolisySettings = $policy.policyContents
                    }
                    $policyobj = [PSCustomObject]$policy_proprties
                    $policyobj.pstypenames.insert(0,'Nessus.Server.Policy')
                    $policyobj
                }
            }
            else{
                Write-Verbose "Lokking for policy with ID of $($PolicyID)"
                foreach ($policy in $request_reply.contents.policies.policy) {
                    if ($policy.policyID -eq $PolicyID){
                        $policy_proprties = [ordered]@{
                            PolicyID = $policy.policyID
                            PolicyName = $policy.policyName
                            PolicyOwner = $policy.policyOwner
                            Visibility = $policy.visibility
                            #PolicySettings = $policy.policyContents
                        }
                        $policyobj = [PSCustomObject]$policy_proprties
                        $policyobj.pstypenames.insert(0,'Nessus.Server.Policy')
                        $policyobj
                    }
                }
            }
        }
    }
}



<#
.Synopsis
   Removes a Nessus Policy for a given Nessus Server Session
.DESCRIPTION
   Removes a Nessus Policy for a given Nessus Server Session given it PolicyID.
.EXAMPLE
    Removes Policy with ID 3
   
    PS C:\> Remove-NessusPolicy -Index 0 -PolicyID 0 -Verbose
    VERBOSE: Policy with ID 0 was successfully removed
#>

function Remove-NessusPolicy
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
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [int]$PolicyID
    )
    Begin {
        # Random number for sequence request
        $rand = New-Object System.Random
        # Options for XMLRPC request
        $ops = @{
            seq = $rand.Next()
            "policy_id" = $PolicyID
        }
    }
    Process {
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

        Try {
            $request_reply = $NSession.SessionState.ExecuteCommand("/policy/delete", $ops)
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionState.ExecuteCommand("/policy/delete", $ops)
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }
            
        }
        # Check that we got the proper response
        if ($request_reply.reply.status -eq "OK")
        {
            Write-Verbose "Policy with ID $($PolicyID) was successfully removed"
            $true
        }
        else
        {
            throw $request_reply.reply.contents
        }
    }
}



<#
.Synopsis
   Gets a Specifc Nessus Policy as a XML Object of a Nessus Server Session
.DESCRIPTION
   Gets a Specifc Nessus Policy as a XML Object of a Nessus Server Session
.EXAMPLE
    Retrives a specific Policy in to a variable and uses the Save method of the XML Object
    to save the policy tot he users Desktop.

    PS C:\> Show-NessusPolicy -Index 0 -PolicyID 1

    PolicyID                     PolicyName                   PolicyOwner                  Visibility                  
    --------                     ----------                   -----------                  ----------                  
    1                            Mobile Devices Audit         carlos                       private                     


    PS C:\> $MobilePolicy = Get-NessusPolicyXML -Index 0 -PolicyID 1 

    PS C:\> $MobilePolicy.Save("$env:HOMEPATH\Desktop\mobilepolicy.xml")

.Example

    Retrives a Nessus Policy for a given policy in to a variable and retrives from the policy
    the list of plugin families enabled.

    PS C:\> $MobilePolicy = Get-NessusPolicyXML -Index 0 -PolicyID 1 

    PS C:\> $MobilePolicy.NessusClientData_v2.policy.policyContents.FamilySelection.FamilyItem

    FamilyName                                                Status                                                   
    ----------                                                ------                                                   
    MacOS X Local Security Checks                             disabled                                                 
    DNS                                                       disabled                                                 
    Gain a shell remotely                                     disabled                                                 
    Solaris Local Security Checks                             disabled                                                 
    Port scanners                                             disabled                                                 
    Web Servers                                               disabled                                                 
    SMTP problems                                             disabled                                                 
    Service detection                                         disabled                                                 
    CGI abuses : XSS                                          disabled                                                 
    Mandriva Local Security Checks                            disabled                                                 
    Databases                                                 disabled                                                 
    Debian Local Security Checks                              disabled                                                 
    Denial of Service                                         disabled                                                 
    Default Unix Accounts                                     disabled                                                 
    Settings                                                  disabled                                                 
    HP-UX Local Security Checks                               disabled                                                 
    Backdoors                                                 disabled                                                 
    VMware ESX Local Security Checks                          disabled                                                 
    SCADA                                                     disabled                                                 
    General                                                   disabled                                                 
    Red Hat Local Security Checks                             disabled                                                 
    FreeBSD Local Security Checks                             disabled                                                 
    CGI abuses                                                disabled                                                 
    Windows : User management                                 disabled                                                 
    Netware                                                   disabled                                                 
    Peer-To-Peer File Sharing                                 disabled                                                 
    Slackware Local Security Checks                           disabled                                                 
    SNMP                                                      disabled                                                 
    Fedora Local Security Checks                              disabled                                                 
    Gentoo Local Security Checks                              disabled                                                 
    Ubuntu Local Security Checks                              disabled                                                 
    Misc.                                                     disabled                                                 
    FTP                                                       disabled                                                 
    Firewalls                                                 disabled                                                 
    Windows : Microsoft Bulletins                             disabled                                                 
    Junos Local Security Checks                               disabled                                                 
    Mobile Devices                                            enabled                                                  
    Windows                                                   disabled                                                 
    Policy Compliance                                         disabled                                                 
    SuSE Local Security Checks                                disabled                                                 
    RPC                                                       disabled                                                 
    CentOS Local Security Checks                              disabled                                                 
    CISCO                                                     disabled                                                 
    Scientific Linux Local Security Checks                    disabled                                                 
    AIX Local Security Checks                                 disabled                                                 
#>

function Get-NessusPolicyXML
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
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [int]$PolicyID
    )
    Begin {
        # Random number for sequence request
        $rand = New-Object System.Random
        # Options for XMLRPC request
        $ops = @{
            seq = $rand.Next()
            "policy_id" = $PolicyID
        }
    }
    Process {
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

        Try {
            $request_reply = $NSession.SessionState.ExecuteCommand("/policy/download", $ops)
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionState.ExecuteCommand("/policy/download", $ops)
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }
            
        }
        
        # Check that we got the proper response
        # in the case of a download a reply means it failed
        if ($request_reply.reply){
            throw $request_reply.reply.contents
        }
        else
        {
            $request_reply
        }
    }
}


<#
.Synopsis
   Create a copy of a given Nessus Policy
.DESCRIPTION
   Create a copy of a given Nessus Policy. When a copy is made the text
   "Copy of " is appended to the name of the original policy to be used
   as the name of the new policy.
.EXAMPLE
    Creates a copy of a policy.

    PS C:\> Copy-NessusPolicy -Index 0 -PolicyID 1 

    PolicyID                     PolicyName                   PolicyOwner                  Visibility                  
    --------                     ----------                   -----------                  ----------                  
    3                            Copy of Mobile Devices Audit carlos                       private
#>

function Copy-NessusPolicy
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
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [int]$PolicyID
    )
    Begin {
        # Random number for sequence request
        $rand = New-Object System.Random
        # Options for XMLRPC request
        $ops = @{
            seq = $rand.Next()
            "policy_id" = $PolicyID
        }
    }
    Process {
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

        Try {
            $request_reply = $NSession.SessionState.ExecuteCommand("/policy/copy", $ops)
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionState.ExecuteCommand("/policy/copy", $ops)
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }
            
        }
        # Check that we got the proper response
        if ($request_reply.reply.status -eq "OK")
        {
            $new_pol = $request_reply.reply.contents.policy
            $policy_proprties = [ordered]@{
                PolicyID = $new_pol.policyID
                PolicyName = $new_pol.policyName
                PolicyOwner = $new_pol.policyOwner
                Visibility = $new_pol.visibility
                }
            $policyobj = [PSCustomObject]$policy_proprties
            $policyobj.pstypenames.insert(0,'Nessus.Server.Policy')
            $policyobj
        }
        else
        {
            throw $request_reply.reply.contents
        }
    }
}

####################################
#     Nessus Reporting Cmdlets     #
####################################


<#
.Synopsis
   Gets Report Information from a Nessus Server
.DESCRIPTION
   Gets a list of reports information objects for each report on a server.
   The Objects returns have methods to get a reports XML and Report Items.
.EXAMPLE
   Get information on all reports available on a Nessus Server

   PS C:\> Get-NessusReports -Index 0 


    ServerHost : 192.168.10.3
    ReportID   : b2e60535-3d4c-4d1b-b883-3ae8eef7e312a8af5e186f93aea7
    ReportName : Scan QA Lab
    Status     : completed
    KB         : True
    AuditTrail : True
    Date       : 4/11/2013 4:44:12 AM
    Session    : Nessus.Server.Session

    ServerHost : 192.168.10.3
    ReportID   : 908185a5-19cc-e2e4-6073-2134043611b99e3d5fcf060ec31e
    ReportName : Scan Dev Lab
    Status     : completed
    KB         : True
    AuditTrail : True
    Date       : 4/11/2013 4:26:13 AM
    Session    : Nessus.Server.Session

    ServerHost : 192.168.10.3
    ReportID   : 86a1eb58-e79a-5077-3fc0-af2d6d55d900c32ca8d0af510d7d
    ReportName : Scan QA Lab
    Status     : completed
    KB         : True
    AuditTrail : True
    Date       : 4/11/2013 4:17:54 AM
    Session    : Nessus.Server.Session

.EXAMPLE
   List the properties and ScriptMethods available for the objects returned

   PS C:\> Get-NessusReports -Index 0 | gm


   TypeName: Nessus.Server.ReportInfo

    Name           MemberType   Definition                              
    ----           ----------   ----------                              
    Equals         Method       bool Equals(System.Object obj)          
    GetHashCode    Method       int GetHashCode()                       
    GetType        Method       type GetType()                          
    ToString       Method       string ToString()                       
    AuditTrail     Property     bool AuditTrail {get;set;}              
    Date           Property     datetime Date {get;set;}                
    KB             Property     bool KB {get;set;}                      
    ReportID       Property     string ReportID {get;set;}              
    ReportName     Property     string ReportName {get;set;}            
    ServerHost     Property     string ServerHost {get;}                
    Session        Property     Nessus.Server.Session Session {get;set;}
    Status         Property     string Status {get;set;}                
    GetReportItems ScriptMethod System.Object GetReportItems();         
    GetXML         ScriptMethod System.Object GetXML(); 
#>

function Get-NessusReports
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,
        Position=0,
        ParameterSetName = "Index")]
        [int32[]]$Index,

        [Parameter(Mandatory=$true,
        ParameterSetName = "Session",
        Position=0,
        ValueFromPipeline=$True)]
        [Nessus.Server.Session]$Session,

        [Parameter(Mandatory=$false,
        Position=1,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        $ReportName

    )
    Begin {
        
    }
    Process 
    {
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

        try 
        {
            $request_reply = $NSession.SessionManager.ListReports().reply
        }
        Catch [Net.WebException] 
        {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK")
            {
                $request_reply = $NSession.SessionManager.ListReports().reply
            }
            else
            {
                throw "Session expired could not Re-Authenticate"
            }
            
        }

        # Check that we got the proper response
        if ($request_reply.status -eq "OK"){
            # Returns epoch time so we need to tranform it
            $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
            Write-Verbose -Message "We got an OK reply from the session."
            if ($request_reply.contents.reports.report) {
                # Return all policies if none is specified by name
                if ($ReportName -eq $null){
                    foreach ($report in $request_reply.contents.reports.report){
                        # Get info on report to make sure it has a KB and Audit Trail
                        $hasaudit = $NSession.SessionManager.ReportHasAudit($report.name).reply.contents.hasAuditTrail
                        $hasKB = $NSession.SessionManager.ReportHasKB($report.name).reply.contents.hasKB
                        
                        # Build Report object
                        $reportobj = New-Object Nessus.Server.ReportInfo
                        $reportobj.ReportID   = $report.name
                        $reportobj.ReportName = $report.readableName
                        $reportobj.Status     = $report.status
                        $reportobj.KB         = &{if ($hasKB -eq "TRUE"){$true}else{$false}}
                        $reportobj.AuditTrail = &{if ($hasaudit -eq "TRUE"){$true}else{$false}}
                        $reportobj.Date       = $origin.AddSeconds($report.timestamp).ToLocalTime()
                        $reportobj.Session    = $NSession
                        Add-Member -InputObject $reportobj -MemberType ScriptMethod GetXML {
                                                            Get-NessusV2ReportXML -session $this.session -ReportID $this.ReportID
                                                            }
                        Add-Member -InputObject $reportobj -MemberType ScriptMethod GetReportItems {
                                                            Get-NessusReportItemsL -session $this.session -ReportID $this.ReportID
                                                            }
                        $reportobj

                    }
                }
                else{
                    foreach ($report in $request_reply.contents.reports.report) {
                        if ($report.readableName -eq $ReportName){
                            # Build Report object
                            $reportobj = New-Object Nessus.Server.ReportInfo
                            $reportobj.ReportID   = $report.name
                            $reportobj.ReportName = $report.readableName
                            $reportobj.Status     = $report.status
                            $reportobj.KB         = &{if ($hasKB -eq "TRUE"){$true}else{$false}}
                            $reportobj.AuditTrail = &{if ($hasaudit -eq "TRUE"){$true}else{$false}}
                            $reportobj.Date       = $origin.AddSeconds($report.timestamp).ToLocalTime()
                            $reportobj.Session    = $NSession
                            # Method for getting the Nessusv2 XML
                            Add-Member -InputObject $reportobj -MemberType ScriptMethod GetXML {
                                                                Get-NessusV2ReportXML -session $this.session -ReportID $this.ReportID
                                                                }
                            Add-Member -InputObject $reportobj -MemberType ScriptMethod GetReportItems {
                                                                Get-NessusReportItemsL -session $this.session -ReportID $this.ReportID
                                                                }
                            $reportobj
                        }
                    }
                }
            }
            else {
                Write-Warning "No reports where found."
            }
        }
    }
}


<#
.Synopsis
   Gets Nessus Report as a XML Object in Nessus v2 Format
.DESCRIPTION
   Gets Nessus Report as a XML Object in Nessus v2 Format that can be manipulated and used.
.EXAMPLE
    Saves report as a .Nessus file

    PS C:\> $nessusreport = Get-NessusV2ReportXML -Index 0 -ReportID 908185a5-19cc-e2e4-6073-2134043611b99e3d5fcf060ec31e

    PS C:\> $nessusreport.Save("$env:HOMEPATH\Desktop\DevLabRepor.nessus")

.EXAMPLE
    Pull from XML object the list of hosts in the report

    PS C:\> $nessusreport = Get-NessusV2ReportXML -Index 0 -ReportID 908185a5-19cc-e2e4-6073-2134043611b99e3d5fcf060ec31e


    PS C:\> $nessusreport.NessusClientData_v2.Report.ReportHost

    name                                   HostProperties                         ReportItem                           
    ----                                   --------------                         ----------                           
    192.168.10.3                           HostProperties                         {ReportItem, ReportItem, ReportIte...
    192.168.10.2                           HostProperties                         {ReportItem, ReportItem, ReportIte...
    192.168.10.13                          HostProperties                         {ReportItem, ReportItem, ReportIte...
    192.168.10.12                          HostProperties                         {ReportItem, ReportItem, ReportIte...
    192.168.10.10                          HostProperties                         {ReportItem, ReportItem, ReportIte...
#>

function Get-NessusV2ReportXML
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
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        $ReportID

    )
    BEGIN 
    {
    }
    PROCESS 
    {
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

        try {
            $request_reply = $NSession.SessionManager.GetNessusV2Report($ReportID)
        }
        Catch [Net.WebException] {
           if ($_.exception -match ".*403.*") {
                write-verbose "The session has expired, Re-authenticating"
                $reauth = $ns.SessionManager.Login(
                    $ns.SessionState.Username, 
                    $ns.SessionState.Password, 
                    [ref]$true)
                if ($reauth.reply.status -eq "OK"){
                    $request_reply = $NSession.SessionManager.GetNessusV2Report($ReportID)
                }
                else{
                    throw "Session expired could not Re-Authenticate"
                }
            }
            elseif ($_.exception -match ".*404.*") {
                throw "A report with that ID was not found on Nessus Server"
            } 
        }

        # Check if scan still running
        $report_reply = $NSession.SessionManager.ListReports().reply
        foreach ($report in $report_reply.contents.reports.report){
            if (($report.name -eq $ReportID) -and ($report.status -ne "completed")) {
                Write-Warning "The report has not finished running, it has a status of $($report.status)"
            }
         }
        $request_reply}
    END {}
}


<#
.Synopsis
   Gets a Summary of Vulnerabities Found in a Nessus Report
.DESCRIPTION
   Gets a vulnerability count by risk level for each host in a given Nessus Report
.EXAMPLE
   Get host summary from report

    PS C:\> Get-NessusReportHostSummary -Index 0 -ReportID 908185a5-19cc-e2e4-6073-2134043611b99e3d5fcf060ec31e


    Hostname : 192.168.10.10
    Info     : 61
    Low      : 0
    Medium   : 3
    High     : 0
    Critical : 0

    Hostname : 192.168.10.12
    Info     : 61
    Low      : 1
    Medium   : 4
    High     : 1
    Critical : 1

    Hostname : 192.168.10.13
    Info     : 113
    Low      : 1
    Medium   : 10
    High     : 0
    Critical : 0

    Hostname : 192.168.10.2
    Info     : 43
    Low      : 0
    Medium   : 1
    High     : 0
    Critical : 0

    Hostname : 192.168.10.3
    Info     : 44
    Low      : 0
    Medium   : 2
    High     : 0
    Critical : 0
#>

function Get-NessusReportHostSummary
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
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        $ReportID

    )
    BEGIN 
    {
    }
    PROCESS 
    {
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

        try {
            $request_reply = $NSession.SessionManager.GetReportHosts($ReportID)
        }
        Catch [Net.WebException] {
           if ($_.exception -match ".*403.*") {
                write-verbose "The session has expired, Re-authenticating"
                $reauth = $ns.SessionManager.Login(
                    $ns.SessionState.Username, 
                    $ns.SessionState.Password, 
                    [ref]$true)
                if ($reauth.reply.status -eq "OK"){
                    $request_reply = $NSession.SessionManager.GetReportHosts($ReportID)
                }
                else{
                    throw "Session expired could not Re-Authenticate"
                }
            }
            elseif ($_.exception -match ".*404.*") {
                throw "A report with that ID was not found on Nessus Server"
            } 
        }
        $severity = @{"0"="Info";"1"="Low";"2"="Medium";"3"="High";"4"="Critical"}   
        if ($request_reply.reply.status -eq "OK"){     
            foreach($host in $request_reply.reply.contents.hostlist.host){
                $host_props = [ordered]@{}
                $host_props.add("Hostname",$host.hostname)
                foreach($vulncount in $host.severityCount.ChildNodes)
                {
                    $host_props.add($severity[$vulncount.severityLevel], $vulncount.count)
                }
                [pscustomobject]$host_props
            }
        }
    }
}


<#
.Synopsis
   Gets all Hosts in a Report with Host Information and Report Items for each
.DESCRIPTION
   Gets all Hosts in a Report with Host Information and Report Items for each
.EXAMPLE
   Get detailed information for all hosts in a report

    PS C:\> Get-NessusReportHostsDetailed -Index 0 -ReportID 908185a5-19cc-e2e4-6073-2134043611b99e3d5fcf060ec31e

    Host                                   Host_Properties                        ReportItems                          
    ----                                   ---------------                        -----------                          
    192.168.10.3                           @{system_type=general-purpose; nets... {@{Host=192.168.10.3; Port=0; Serv...
    192.168.10.2                           @{operating_system=Microsoft Window... {@{Host=192.168.10.2; Port=0; Serv...
    192.168.10.13                          @{operating_system=Microsoft Window... {@{Host=192.168.10.13; Port=0; Ser...
    192.168.10.12                          @{operating_system=Microsoft Window... {@{Host=192.168.10.12; Port=0; Ser...
    192.168.10.10                          @{operating_system=Microsoft Window... {@{Host=192.168.10.10; Port=0; Ser...

.EXAMPLE
   Gets Properties for a specific hots

    PS C:\> $hosts = Get-NessusReportHostsDetailed -Index 0 -ReportID 908185a5-19cc-e2e4-6073-2134043611b99e3d5fcf060ec31e 

    PS C:\> $hosts | where {$_.host -eq "192.168.10.2"} | select -ExpandProperty host_properties


    operating_system : Microsoft Windows Server 2012 Standard
    traceroute_hop_0 : 192.168.10.2
    HOST_START       : Thu Apr 11 04:19:01 2013
    netbios_name     : WIN2K01
    host_ip          : 192.168.10.2
    mac_address      : 00:0c:29:f9:cd:9d
    system_type      : general-purpose
    HOST_END         : Thu Apr 11 04:25:08 2013
#>

function Get-NessusReportHostsDetailed
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
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        $ReportID

    )
    BEGIN 
    {
    }
    PROCESS 
    {
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

        try {
            $request_reply = $NSession.SessionManager.GetNessusV2Report($ReportID)
        }
        Catch [Net.WebException] {
           if ($_.exception -match ".*403.*") {
                write-verbose "The session has expired, Re-authenticating"
                $reauth = $ns.SessionManager.Login(
                    $ns.SessionState.Username, 
                    $ns.SessionState.Password, 
                    [ref]$true)
                if ($reauth.reply.status -eq "OK"){
                    $request_reply = $NSession.SessionManager.GetNessusV2Report($ReportID)
                }
                else{
                    throw "Session expired could not Re-Authenticate"
                }
            }
            elseif ($_.exception -match ".*404.*") {
                throw "A report with that ID was not found on Nessus Server"
            } 
        }

        # Check if scan still running
        $report_reply = $NSession.SessionManager.ListReports().reply
        foreach ($report in $report_reply.contents.reports.report){
            if (($report.name -eq $ReportID) -and ($report.status -ne "completed")) {
                Write-Warning "The report has not finished running, it has a status of $($report.status)"
            }
         }
        $nessus = $request_reply
        # Serveriry Hash to use
        $severity = @{"0"="Info";"1"="Low";"2"="Medium";"3"="High";"4"="Critical"}
        # How many servers
        $record_count = $nessus.NessusClientData_v2.Report.ReportHost.Length
        # processed host count
        $i = 0;
        # Declare Array that will be returned with the objects
        $reported_hosts = @()
        # for each of the hosts reported
        foreach ($reporthost in $nessus.NessusClientData_v2.Report.ReportHost) {
            # Declare variables for properties that will form the object
            $hproperties = @{}
            $host_properties = @{}
            $vulns = @()
            $hostip = $reporthost.name
            # Gathering properties for each host
            foreach($hostproperty in $reporthost.HostProperties.tag) 
            {
                $hproperties += @{($hostproperty.name -replace "-","_") = $hostproperty."#text"}
            }
    
            # Set the Host and Host Properties object properties
            $host_properties += @{Host = $hostip.Trim()}
            $host_properties += @{Host_Properties = [pscustomobject]$hproperties}

            # Collect vulnerable information for each host
            foreach ($reportitem in ($reporthost.ReportItem | where {$_.pluginID -ne "0"})) {
                    
                $vuln_properties = [pscustomobject]@{
                Host                 = $hostip.Trim()
                Port                 = $reportitem.Port
                ServiceName          = $reportitem.svc_name
                Severity             = $severity[$reportitem.severity]
                PluginID             = $reportitem.pluginID
                PluginName           = $reportitem.pluginName
                PluginFamily         = $reportitem.pluginFamily
                RiskFactor           = $reportitem.risk_factor
                Synopsis             = $reportitem.synopsis
                Description          = $reportitem.description
                Solution             = $reportitem.solution
                PluginOutput         = $reportitem.plugin_output
                SeeAlso              = $reportitem.see_also
                CVE                  = $reportitem.cve
                BID                  = $reportitem.bid
                ExternaReference     = $reportitem.xref
                PatchPublicationDate = $reportitem.patch_publication_date
                VulnPublicationDate  = $reportitem.vuln_publication_date
                Exploitability       = $reportitem.exploitability_ease
                ExploitAvailable     = $reportitem.exploit_available
                CANVAS               = $reportitem.exploit_framework_canvas
                Metasploit           = $reportitem.exploit_framework_metasploit
                COREImpact           = $reportitem.exploit_framework_core
                MetasploitModule     = $reportitem.metasploit_name
                CANVASPackage        = $reportitem.canvas_package
                CVSSVector           = $reportitem.cvss_vector
                CVSSBase             = $reportitem.cvss_base_score
                CVSSTemporal         = $reportitem.cvss_temporal_score
                PluginType           = $reportitem.plugin_type
                PluginVersion        = $reportitem.plugin_version
                }
                    
                   
                $vulns += $vuln_properties
            }
            $host_properties += @{ReportItems = $vulns}
    
            # Create each host object
            $reported_vuln =  [pscustomobject]$host_properties
            $reported_hosts += $reported_vuln

            # Provide progress, specially usefull in large reports
            if ($record_count -gt 1)
            {
                $record_progress = [int][Math]::Ceiling((($i / $record_count) * 100))
                Write-Progress -Activity "Processing Vulnerability Report" -PercentComplete $record_progress -Status "Processing records - $record_progress%" -Id 1;
                $i++
            }
        }
        $reported_hosts
        }
    END {}
}


<#
.Synopsis
   Gets Report Items for a Specified Report
.DESCRIPTION
   Allows to pull report items from a specific Nessus Report. It allows to filter
   per host and severity level(Info, Low, Medium, High and Critical).
.EXAMPLE
   Get Report Items for a specifc hosts with a level of medium

   PS C:\> Get-NessusReportItems -Index 0 -ReportID 908185a5-19cc-e2e4-6073-2134043611b99e3d5fcf060ec31e -HostFilter 192.168.10.2 -SeverityFilter medium


    Host                 : 192.168.10.2
    Port                 : 445
    ServiceName          : cifs
    Severity             : Medium
    PluginID             : 57608
    PluginName           : SMB Signing Disabled
    PluginFamily         : Misc.
    RiskFactor           : Medium
    Synopsis             : Signing is disabled on the remote SMB server.
    Description          : Signing is disabled on the remote SMB server.  This can allow man-in-the-middle attacks 
                           against the SMB server.
    Solution             : Enforce message signing in the host's configuration.  On Windows, this is found in the 
                           Local Security Policy.  On Samba, the setting is called 'server signing'.  See the 'see 
                           also' links for further details.
    PluginOutput         : 
    SeeAlso              : http://support.microsoft.com/kb/887429
                           http://www.nessus.org/u?74b80723
                           http://www.samba.org/samba/docs/man/manpages-3/smb.conf.5.html
    CVE                  : 
    BID                  : 
    ExternaReference     : 
    PatchPublicationDate : 
    VulnPublicationDate  : 2012/01/17
    Exploitability       : 
    ExploitAvailable     : 
    CANVAS               : 
    Metasploit           : 
    COREImpact           : 
    MetasploitModule     : 
    CANVASPackage        : 
    CVSSVector           : CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N
    CVSSBase             : 5.0
    CVSSTemporal         : 
    PluginType           : remote
    PluginVersion        : 
#>
l
function Get-NessusReportItems
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

        # Report to query
        [Parameter(Mandatory=$true,
        Position=1,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        $ReportID,

        # Filter by host providing a collection of Host IP Addresses to filter on.
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string[]]$HostFilter,

        # Filter by one ore more severity level. Levels:Info, Low, Medium, High and Critical
        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [ValidateSet("Info","Low","Medium","High","Critical")]
        [string[]]$SeverityFilter = @("Info","Low","Medium","High","Critical")
    )
    BEGIN 
    {
    }
    PROCESS 
    {
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

        try {
            $request_reply = $NSession.SessionManager.GetNessusV2Report($ReportID)
        }
        Catch [Net.WebException] {
           if ($_.exception -match ".*403.*") {
                write-verbose "The session has expired, Re-authenticating"
                $reauth = $ns.SessionManager.Login(
                    $ns.SessionState.Username, 
                    $ns.SessionState.Password, 
                    [ref]$true)
                if ($reauth.reply.status -eq "OK"){
                    $request_reply = $NSession.SessionManager.GetNessusV2Report($ReportID)
                }
                else{
                    throw "Session expired could not Re-Authenticate"
                }
            }
            elseif ($_.exception -match ".*404.*") {
                throw "A report with that ID was not found on Nessus Server"
            } 
        }

        # Check if scan still running
        $report_reply = $NSession.SessionManager.ListReports().reply
        foreach ($report in $report_reply.contents.reports.report){
            if (($report.name -eq $ReportID) -and ($report.status -ne "completed")) {
                Write-Warning "The report has not finished running, it has a status of $($report.status)"
            }
         }
        $nessus = $request_reply
        # Serveriry Hash to use
        $severity = @{"0"="Info";"1"="Low";"2"="Medium";"3"="High";"4"="Critical"}
        # How many servers
        $record_count = $nessus.NessusClientData_v2.Report.ReportHost.Length
        # processed host count
        $i = 0;
        # Declare Array that will be returned with the objects
        $reported_hosts = @()
        # for each of the hosts reported
        foreach ($reporthost in $nessus.NessusClientData_v2.Report.ReportHost) {
            # Declare variables for properties that will form the object
            $hostip = $reporthost.name

            # Collect vulnerable information for each host
            foreach ($reportitem in ($reporthost.ReportItem)) 
            {
                if ($HostFilter.Count -eq 0 -or $hostip -in $HostFilter)
                {   
                    if ($severity[$reportitem.severity] -notin $SeverityFilter) {continue}
                    [pscustomobject]@{
                    Host                 = $hostip.Trim()
                    Port                 = $reportitem.Port
                    ServiceName          = $reportitem.svc_name
                    Severity             = $severity[$reportitem.severity]
                    PluginID             = $reportitem.pluginID
                    PluginName           = $reportitem.pluginName
                    PluginFamily         = $reportitem.pluginFamily
                    RiskFactor           = $reportitem.risk_factor
                    Synopsis             = $reportitem.synopsis
                    Description          = $reportitem.description
                    Solution             = $reportitem.solution
                    PluginOutput         = $reportitem.plugin_output
                    SeeAlso              = $reportitem.see_also
                    CVE                  = $reportitem.cve
                    BID                  = $reportitem.bid
                    ExternaReference     = $reportitem.xref
                    PatchPublicationDate = $reportitem.patch_publication_date
                    VulnPublicationDate  = $reportitem.vuln_publication_date
                    Exploitability       = $reportitem.exploitability_ease
                    ExploitAvailable     = $reportitem.exploit_available
                    CANVAS               = $reportitem.exploit_framework_canvas
                    Metasploit           = $reportitem.exploit_framework_metasploit
                    COREImpact           = $reportitem.exploit_framework_core
                    MetasploitModule     = $reportitem.metasploit_name
                    CANVASPackage        = $reportitem.canvas_package
                    CVSSVector           = $reportitem.cvss_vector
                    CVSSBase             = $reportitem.cvss_base_score
                    CVSSTemporal         = $reportitem.cvss_temporal_score
                    PluginType           = $reportitem.plugin_type
                    PluginVersion        = $reportitem.plugin_version
                    }
                }
            }
            
    
            # Provide progress, specially usefull in large reports
            if ($record_count -gt 1)
            {
                $record_progress = [int][Math]::Ceiling((($i / $record_count) * 100))
                Write-Progress -Activity "Processing Vulnerability Report" -PercentComplete $record_progress -Status "Processing records - $record_progress%" -Id 1;
                $i++
            }
        }
       
        }
    END {}
}


<#
.Synopsis
   Gets Count and Basic Information per Vulnerability
.DESCRIPTION
   Gets Count and Basic Information per Vulnerability for a Nessus Report in
   a Nessus Server. The information includes PluginID, PluginName, Severity, 
   PluginFamily and Count.
.EXAMPLE
   Get vulnerability summary from report

   PS C:\> Get-NessusReportVulnSummary -Index 0 -ReportID b2e60535-3d4c-4d1b-b883-3ae8eef7e312a8af5e186f93aea7


    PluginID     : 10107
    PluginName   : HTTP Server Type and Version
    PluginFamily : Web Servers
    Count        : 1
    Severity     : Info

    PluginID     : 10147
    PluginName   : Nessus Server Detection
    PluginFamily : Service detection
    Count        : 1
    Severity     : Info

    PluginID     : 10150
    PluginName   : Windows NetBIOS / SMB Remote Host Information Disclosure
    PluginFamily : Windows
    Count        : 4
    Severity     : Info

    PluginID     : 10267
    PluginName   : SSH Server Type and Version Information
    PluginFamily : Service detection
    Count        : 1
    Severity     : Info

    PluginID     : 10736
    PluginName   : DCE Services Enumeration
    PluginFamily : Windows
    Count        : 49
    Severity     : Info

    PluginID     : 10881
    PluginName   : SSH Protocol Versions Supported
    PluginFamily : General
    Count        : 1
    Severity     : Info

    PluginID     : 11011
    PluginName   : Microsoft Windows SMB Service Detection
    PluginFamily : Windows
    Count        : 8
    Severity     : Info

    PluginID     : 12053
    PluginName   : Host Fully Qualified Domain Name (FQDN) Resolution
    PluginFamily : General
    Count        : 1
    Severity     : Info

    PluginID     : 14272
    PluginName   : netstat portscanner (SSH)
    PluginFamily : Port scanners
    Count        : 3
    Severity     : Info

    PluginID     : 56984
    PluginName   : SSL / TLS Versions Supported
    PluginFamily : General
    Count        : 1
    Severity     : Info

    PluginID     : 58651
    PluginName   : Netstat Active Connections
    PluginFamily : Misc.
    Count        : 1
    Severity     : Info

    PluginID     : 64582
    PluginName   : Netstat Connection Information
    PluginFamily : General
    Count        : 1
    Severity     : Info
#>

function Get-NessusReportVulnSummary
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
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        $ReportID

    )
    BEGIN 
    {
        # Random number for sequence request
        $rand = New-Object System.Random
        # Options for XMLRPC request
        $opts = @{
            seq = $rand.Next()
            report = $ReportID
        }
    }
    PROCESS 
    {
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

        try {
            Write-Verbose "getting summary for report $($ReportID)"
            $request_reply = $NSession.SessionState.ExecuteCommand("/report2/vulnerabilities", $opts)
            
        }
        Catch [Net.WebException] {
           if ($_.exception -match ".*403.*") {
                write-verbose "The session has expired, Re-authenticating"
                $reauth = $ns.SessionManager.Login(
                    $ns.SessionState.Username, 
                    $ns.SessionState.Password, 
                    [ref]$true)
                if ($reauth.reply.status -eq "OK"){
                    $request_reply = $NSession.SessionState.ExecuteCommand("/report2/vulnerabilities", $opts)
                }
                else{
                    throw "Session expired could not Re-Authenticate"
                }
            }
            elseif ($_.exception -match ".*404.*") {
                throw "A report with that ID was not found on Nessus Server"
            } 
        }
        $severity = @{"0"="Info";"1"="Low";"2"="Medium";"3"="High";"4"="Critical"}
        if ($request_reply.reply.status -eq "OK"){
            Write-Verbose "We got OK on request." 
            foreach($vuln in $request_reply.reply.contents.vulnList.vulnerability)
            {
                $vuln_props = [ordered]@{
                    PluginID     = $vuln.plugin_id
                    PluginName   = $vuln.plugin_name
                    PluginFamily = $vuln.plugin_family
                    Count        = $vuln.count
                    Severity     = $severity[$vuln.severity]
                }
                $vulnsum = [pscustomobject]$vuln_props
                $vulnsum.pstypenames.insert(0,'Nessus.Server.VulnSumaryItem')
                $vulnsum
            }
        }
    }
}


<#
.Synopsis
   Gets the Audit Trail for a Specic Nessus Plugin and Host
.DESCRIPTION
   Gets the audit trail for the execution of a specific Nessus Plugin against a host
   on a Report stored on a Nessus Server.
.EXAMPLE
   Gets the audit trail for plugin 53521 when it executed against host 192.168.10.12

   PS C:\> Get-NessusReportPluginAudit -Index 0 -ReportID "d2e6b6e0-1eb1-de50-5216-34c1f8b9db0dae7dbaa3a704c053" -Host "192.168.10.12" -PluginID 53521 | fl
 
 
    Host     : 192.168.10.12
    PluginID : 53521
    ExitCode : 0
    Reason   : fedora_2011-5495.nasl was not launched because the key Host/local_checks_enabled is missing
#>

function Get-NessusReportPluginAudit
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
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string]$ReportID,

        [Parameter(Mandatory=$true,
        Position=2,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string]$Host,

        [Parameter(Mandatory=$true,
        Position=3,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [int]$PluginID
    )
    BEGIN 
    {
    }
    PROCESS 
    {
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

        try {
            $request_reply = $NSession.SessionManager.GetAuditTrail($ReportID, $host, $PluginID)
        }
        Catch [Net.WebException] {
           if ($_.exception -match ".*403.*") {
                write-verbose "The session has expired, Re-authenticating"
                $reauth = $ns.SessionManager.Login(
                    $ns.SessionState.Username, 
                    $ns.SessionState.Password, 
                    [ref]$true)
                if ($reauth.reply.status -eq "OK"){
                    $request_reply = $NSession.SessionManager.GetAuditTrail($ReportID, $host, $PluginID)
                }
                else{
                    throw "Session expired could not Re-Authenticate"
                }
            }
            elseif ($_.exception -match ".*404.*") {
                throw "A report with that ID was not found on Nessus Server"
            } 
        }

        # Check if scan still running
        $report_reply = $NSession.SessionManager.ListReports().reply
        foreach ($report in $report_reply.contents.reports.report){
            if (($report.name -eq $ReportID) -and ($report.status -ne "completed")) {
                Write-Warning "The report has not finished running, it has a status of $($report.status)"
            }
         }
        if ($request_reply.reply.contents.audit_trail)
        {
            $trail = $request_reply.reply.contents.audit_trail.trail
            $trail_props = @{
                Host = $trail.hostname
                PluginID = $trail.plugin_id
                ExitCode = $trail.exit_code
                Reason = $trail.reason
            }
            $trailobj = [pscustomobject]$trail_props
            $trailobj.pstypenames.insert(0,'Nessus.Server.AuditTrail')
            $trailobj
        }
        else
        {
            Write-Warning "Audit Trail for $($PluginID) for $($Host) was not found."
        }
        }
    END {}
}


<#
.Synopsis
	Imports a Nessus v2 Report file and returns the results as objects.
.DESCRIPTION
	The Import-NessusReport cmdlet creates objects from Nessus v2 files that are generated by the Nessus 4.x or 5.x scanner.
.EXAMPLE
	Return object with report configuration and general information.
	
    Import-NessusReport .\report.nessus -InfoType ReportInfo
.EXAMPLE
	Returns objects for each of the hosts scanned with Properties and Report Items for each.
	
    Import-NessusReport .\report.nessus
.EXAMPLE
	Looks for hosts for which a a Vulnerability was found that a Metasploit exploit exists and return the IP and Name of the Module.
	
    Import-NessusReport .\repport.nessus | foreach {$_.reportitems} | where {$_.metasploit -ne $null} | foreach { "$($_.host) $($_.metasploitmodule)"}
#>
function Import-NessusV2Report
{
    [CmdletBinding()]
    Param
    (
        # Nessus Version 2 report file
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0,
                   ParameterSetName = "File")]
        [ValidateScript({Test-Path $_})] 
        $NessusFile,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0,
                   ParameterSetName = "XMLDoc")]
        [xml]$InputObject,

        # Type of Information to return
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [ValidateSet("Config", "Vulnerabilities", "EnabledPlugins", "FamilySelection", "ReportInfo", "PluginPreferences")] 
        $InfoType = "Vulnerabilities"
    )

    Begin
    {
        if ($NessusFile)
        {
            $file = Get-ChildItem $NessusFile
            [xml]$nessus = [System.IO.File]::ReadAllText($file.FullName)
        }
        else
        {
            [xml]$nessus = $InputObject
        }
    }
    Process
    {
        if ($InfoType -eq "Vulnerabilities")
        {
            # How many servers
            $record_count = $nessus.NessusClientData_v2.Report.ReportHost.Length
            # processed host count
            $i = 0;
            # Declare Array that will be returned with the objects
            $reported_hosts = @()
            # for each of the hosts reported
            foreach ($reporthost in $nessus.NessusClientData_v2.Report.ReportHost) {
                # Declare variables for properties that will form the object
                $hproperties = @{}
                $host_properties = @{}
                $vulns = @()
                $hostip = $reporthost.name
                # Gathering properties for each host
                foreach($hostproperty in $reporthost.HostProperties.tag) 
                {
                    $hproperties += @{($hostproperty.name -replace "-","_") = $hostproperty."#text"}
                }
    
                # Set the Host and Host Properties object properties
                $host_properties += @{Host = $hostip.Trim()}
                $host_properties += @{Host_Properties = [pscustomobject]$hproperties}

                # Collect vulnerable information for each host
                foreach ($reportitem in ($reporthost.ReportItem | where {$_.pluginID -ne "0"})) {
                    
                    $vuln_properties = @{
                    Host                 = $hostip.Trim()
                    Port                 = $reportitem.Port
                    ServiceName          = $reportitem.svc_name
                    Severity             = $reportitem.severity
                    PluginID             = $reportitem.pluginID
                    PluginName           = $reportitem.pluginName
                    PluginFamily         = $reportitem.pluginFamily
                    RiskFactor           = $reportitem.risk_factor
                    Synopsis             = $reportitem.synopsis
                    Description          = $reportitem.description
                    Solution             = $reportitem.solution
                    PluginOutput         = $reportitem.plugin_output
                    SeeAlso              = $reportitem.see_also
                    CVE                  = $reportitem.cve
                    BID                  = $reportitem.bid
                    ExternaReference     = $reportitem.xref
                    PatchPublicationDate = $reportitem.patch_publication_date
                    VulnPublicationDate  = $reportitem.vuln_publication_date
                    Exploitability       = $reportitem.exploitability_ease
                    ExploitAvailable     = $reportitem.exploit_available
                    CANVAS               = $reportitem.exploit_framework_canvas
                    Metasploit           = $reportitem.exploit_framework_metasploit
                    COREImpact           = $reportitem.exploit_framework_core
                    MetasploitModule     = $reportitem.metasploit_name
                    CANVASPackage        = $reportitem.canvas_package
                    CVSSVector           = $reportitem.cvss_vector
                    CVSSBase             = $reportitem.cvss_base_score
                    CVSSTemporal         = $reportitem.cvss_temporal_score
                    PluginType           = $reportitem.plugin_type
                    PluginVersion        = $reportitem.plugin_version
                    }
                    
                   
                    $vulns += [pscustomobject]$vuln_properties
                }
                $host_properties += @{ReportItems = $vulns}
    
                # Create each host object
                $reported_vuln = New-Object PSObject -Property $host_properties
                $reported_hosts += $reported_vuln

                # Provide progress, specially usefull in large reports
                if ($record_count -gt 1)
                {
                    $record_progress = [int][Math]::Ceiling((($i / $record_count) * 100))
                    Write-Progress -Activity "Processing Vulnerability Report" -PercentComplete $record_progress -Status "Processing records - $record_progress%" -Id 1;
                    $i++
                }
            }
            $reported_hosts
        }
        elseif ($InfoType -eq "Config")
        {
            $prefs = @()
            $ips_plugins =@()
            # Get Server Settings
            $ServerSettings = @{}
            Write-Verbose "Processing server settings."
            foreach ($serverpref in ($nessus.NessusClientData_v2.Policy.Preferences.ServerPreferences.preference))
            { 
               $ServerSettings.Add($serverpref.name,$serverpref.value) 
            }
            [pscustomobject]$ServerSettings
        }
        elseif ($InfoType -eq "EnabledPlugins")
        {
            $plugins = $nessus.NessusClientData_v2.Policy.IndividualPluginSelection.PluginItem
            foreach($plugin in $plugins)
            {
                [pscustomobject]@{
                PluginId   = $plugin.PluginId
                PluginName = $plugin.PluginName
                Family     = $plugin.Family
                }   
            }
        }
        elseif ($InfoType -eq "FamilySelection")
        {
            $families = $nessus.NessusClientData_v2.Policy.FamilySelection.FamilyItem
            foreach($family in $families)
            {
                [pscustomobject]@{
                    Name   = $family.FamilyName
                    Status = $family.Status
                }
            }

        }
        elseif ($InfoType -eq "PluginPreferences")
        {
            $pluginprefs = $nessus.NessusClientData_v2.Policy.Preferences.PluginsPreferences.ChildNodes
            foreach($pref in $pluginprefs)
            {
                [pscustomobject]@{
                    PluginID        = $pref.pluginId
                    PluginName      = $pref.pluginName
                    FullName        = $pref.fullName
                    PreferenceName  = $pref.preferenceName
                    PreferenceType  = $pref.preferenceType
                    PreferenceValue = $pref.preferenceValues
                    SelectedValue   = $pref.selectedValue
                }
            }
        }
        elseif ($InfoType -eq "PolicyInfo")
        {
            # Variables for collections
            $SelectedPlugins    = @()
            $SelectedFamiles    = @()
            $PlugingPreferences = @()

            # Selected individual plugins
            Write-Verbose "Parsing individual family selection"
            $plugins = $nessus.NessusClientData_v2.Policy.IndividualPluginSelection.PluginItem
            foreach($plugin in $plugins)
            {
                $SelectedPlugins += [pscustomobject]@{
                    PluginId   = $plugin.PluginId
                    PluginName = $plugin.PluginName
                    Family     = $plugin.Family
                }   
            }

            # Familiy selection
            Write-Verbose "Parsing plugin family selection"
            $families = $nessus.NessusClientData_v2.Policy.FamilySelection.FamilyItem
            foreach($family in $families)
            {
                $SelectedFamiles += [pscustomobject]@{
                    Name   = $family.FamilyName
                    Status = $family.Status
                }
            }

            # Get Server Settings
            $ServerSettings = @{}
            Write-Verbose "Parsing server settings."
            foreach ($serverpref in ($nessus.NessusClientData_v2.Policy.Preferences.ServerPreferences.preference))
            { 
               $ServerSettings.Add($serverpref.name,$serverpref.value) 
            }

            # PluginPreferences
            Write-Verbose "Parsing plugin preferences."
            $pluginprefs = $nessus.NessusClientData_v2.Policy.Preferences.PluginsPreferences.ChildNodes
            foreach($pref in $pluginprefs)
            {
                $PlugingPreferences += [pscustomobject]@{
                    PluginID        = $pref.pluginId
                    PluginName      = $pref.pluginName
                    FullName        = $pref.fullName
                    PreferenceName  = $pref.preferenceName
                    PreferenceType  = $pref.preferenceType
                    PreferenceValue = $pref.preferenceValues
                    SelectedValue   = $pref.selectedValue
                }
            }

            # Return Object
            [pscustomobject]@{
                ReportName                = $nessus.NessusClientData_v2.Report.name
                PolicyName                = $nessus.NessusClientData_v2.Policy.policyName
                Comment                   = $nessus.NessusClientData_v2.Policy.policyComments
                Preferences               = [pscustomobject]$ServerSettings
                IndividualPluginSelection = $SelectedPlugins
                FamilySelecttion          = $SelectedFamiles
                PluginPreferences         = $PlugingPreferences
            }
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Pulls a Host KB from a Nessus Report in a Nessus Server
.DESCRIPTION
   Pulls a Host KB from a Nessus Report in a Nessus Server. The KB
   contains the trace for the execution of the plugins against the
   specified host.
.EXAMPLE
    Get the KB for a specific host in a Nessus Report

    PS C:\> $ReportID = "b2e60535-3d4c-4d1b-b883-3ae8eef7e312a8af5e186f93aea7"

    PS C:\> $ScannedHost = "192.168.10.3"

    PS C:\> $KB = Get-NessusReportHostKB -Index 0 -ReportID $ReportID -ReportHost $ScannedHost 
#>

function Get-NessusReportHostKB
{
    [CmdletBinding()]
    Param
    (
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
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        $ReportID,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string]$ReportHost

        )

    Begin
    {
    
       
    }
    Process
    {
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

        try {
            $request_reply = $NSession.SessionManager.ReportHasKB($ReportID)
        }
        Catch [Net.WebException] {
           if ($_.exception -match ".*403.*") {
                write-verbose "The session has expired, Re-authenticating"
                $reauth = $ns.SessionManager.Login(
                    $ns.SessionState.Username, 
                    $ns.SessionState.Password, 
                    [ref]$true)
                if ($reauth.reply.status -eq "OK"){
                    $request_reply = $NSession.SessionManager.ReportHasKB($ReportID)
                }
                else{
                    throw "Session expired could not Re-Authenticate"
                }
            }
            elseif ($_.exception -match ".*404.*") {
                throw "A report with that ID was not found on Nessus Server"
            } 
        }

        # Lets make sure that the report has KB
        if ($request_reply.reply.contents.hasKB -eq "TRUE")
        {
            # Disable SSL Checking for the PowerShell Session
            [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} 
            $webClient = New-Object System.Net.WebClient
            $nessusserver = $NSession.ServerHost
            $token = $NSession.SessionState.Token
            $webClient.DownloadString("https://$($nessusserver):8834/report/kb?report=$($ReportID)&hostname=$($ReportHost)&token=$($token)")

        }
        else
        {
            Write-Error "Report $ReportID dos not have a KB."
        }
    }
    End
    {
    }
}

################################
#     Nessus Scan Cmdlets      #
################################


<#
.Synopsis
   Shows Current Nessus Vulnerability Scans
.DESCRIPTION
   Shows current Nessus Vulnerability Scans that are running on a Nessus Server.
.EXAMPLE
    Shows running vulnerability scans on a Nessus Server

    PS C:\> Show-NessusScans -Index 0


    ScanID   : 908185a5-19cc-e2e4-6073-2134043611b99e3d5fcf060ec31e
    ScanName : Scan Dev Lab
    Owner    : carlos
    Status   : running
    Date     : 4/11/2013 4:19:01 AM
#>

function Show-NessusScans
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

        [Parameter(Mandatory=$false,
        Position=1,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        $ScanName

    )
    Begin {
        
    }
    Process {

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

        try {
            $request_reply = $NSession.SessionManager.ListScans().reply
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionManager.ListScans().reply
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

            if ($request_reply.contents.scans.scanlist.scan -ne $null) {
                # Return all scans if none is specified by name
                if ($ScantName -eq $null){
                    foreach ($scan in $request_reply.contents.scans.scanlist.scan){
                        $scan_proprties = [ordered]@{
                            ScanID   = $scan.uuid
                            ScanName = $scan.readableName
                            Owner    = $scan.owner
                            Status   = $scan.status
                            Date     = $origin.AddSeconds($scan.start_time).ToLocalTime()
                        }
                        $scanpropobj = [PSCustomObject]$scan_proprties
                        $scanpropobj.pstypenames.insert(0,'Nessus.Server.Scan')
                        $scanpropobj
                    }
                }
                else{
                    foreach ($scan in $request_reply.contents.scans.scanlist.scan) {
                        if ($scan.readableName -eq $ScanName){
                                $scan_proprties = [ordered]@{
                                ScanID   = $scan.uuid
                                ScanName = $scan.readableName
                                Owner    = $scan.owner
                                Status   = $scan.status
                                Date     = $origin.AddSeconds($scan.start_time).ToLocalTime()
                            }
                            $scanpropobj = [PSCustomObject]$scan_proprties
                            $scanpropobj.pstypenames.insert(0,'Nessus.Server.Scan')
                            $scanpropobj
                        }
                    }
                }
            }
            else {
                Write-Warning "No scans are running at this moment."
            }
        }
    }
}


<#
.Synopsis
   Invokes a Nessus Vulnerability Scan
.DESCRIPTION
   Launches a Vulnerability Scan against a specified set of targets using an existing policy.
.EXAMPLE
   Invoke a Nessus Vulnerability Scan using Policy with ID 4 against an IP Range
   and names the san "Scan Dev Lab"

    PS C:\> Invoke-NessusScan -Index 0 -PolicyID -4 -Targets "192.168.10.1-192.168.10.200" -Name "Scan QA Lab" 


    ScanID   : 86a1eb58-e79a-5077-3fc0-af2d6d55d900c32ca8d0af510d7d
    ScanName : Scan QA Lab
    Owner    : carlos
    Status   : running
    Date     : 4/11/2013 4:11:11 AM
#>

function Invoke-NessusScan
{
    [CmdletBinding()]
    param(
        # Nessus Session Index
        [Parameter(Mandatory=$true,
        Position=0,
        ParameterSetName = "Index")]
        [int32[]]$Index,

        # Nessus Session Object
        [Parameter(Mandatory=$true,
        Position=0,
        ParameterSetName = "Session",
        ValueFromPipeline=$True)]
        [Nessus.Server.Session]$Session,

        # PolicyID for the policy to use for the scan 
        [Parameter(Mandatory=$true,
        Position=1,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [int]$PolicyID,

        # Targets to execute scan against
        [Parameter(Mandatory=$true,
        Position=2,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string[]]$Targets,

        # Name for the Scan
        [Parameter(Mandatory=$true,
        Position=3,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string]$Name
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
        elseif ($Session -ne $null)
        {
                $NSession = $Session
        }

        $targetlist = $Targets -join ' '

        try {
            $request_reply = $NSession.SessionManager.CreateScan(
                $targetlist,$PolicyID,$Name).reply
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionManager.CreateScan(
                    $targetlist,$PolicyID,$Name).reply
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }   
        }

        if ($request_reply.status -eq "OK"){
            # Returns epoch time so we need to tranform it
            $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
            Write-Verbose -Message "We got an OK reply from the session."
            # Get the UUID of the report to look for it in the Scan list
            $created_uuid = $request_reply.contents.scan.uuid
            # Search for the recently created report
            foreach ($scan in $NSession.SessionManager.ListScans().reply.contents.scans.scanlist.scan) {
                if ($scan.uuid -eq $created_uuid){
                        $scan_proprties = [ordered]@{
                        ScanID   = $scan.uuid
                        ScanName = $scan.readableName
                        Owner    = $scan.owner
                        Status   = $scan.status
                        Date     = $origin.AddSeconds($scan.start_time).ToLocalTime()
                    }
                    $scanpropobj = [PSCustomObject]$scan_proprties
                    $scanpropobj.pstypenames.insert(0,'Nessus.Server.Scan')
                    $scanpropobj
                }
            }
        }
        else {
            throw $request_reply.contents
        }
    }
}


<#
.Synopsis
   Stops a Running Nessus Scan
.DESCRIPTION
   Stops a running Nessus scan given its ID
.EXAMPLE
   Stoppping a running Nessus Vulnerability Scan

    PS C:\> Stop-NessusScan -Index 0 -ScanID b2e60535-3d4c-4d1b-b883-3ae8eef7e312a8af5e186f93aea7


    ScanID   : b2e60535-3d4c-4d1b-b883-3ae8eef7e312a8af5e186f93aea7
    ScanName : Scan QA Lab
    Owner    : carlos
    Status   : stopping
    Date     : 4/11/2013 4:43:47 AM
#>

function Stop-NessusScan
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

        [Parameter(Mandatory=$false,
        Position=1,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        $ScanID

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
        elseif ($Session -ne $null)
        {
                $NSession = $Session
        }

        try {
            $request_reply = $NSession.SessionManager.StopScan(
                $ScanID).reply
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionManager.StopScan(
                    $ScanID).reply
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }   
        }

        if ($request_reply.status -eq "OK" -and $request_reply.contents){
            # Returns epoch time so we need to tranform it
            $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
            Write-Verbose -Message "We got an OK reply from the session."
            # Get the UUID of the report to look for it in the Scan list
            $created_uuid = $request_reply.contents.scan.uuid
            # Search for the recently created report
            foreach ($scan in $NSession.SessionManager.ListScans().reply.contents.scans.scanlist.scan) {
                if ($scan.uuid -eq $created_uuid){
                        $scan_proprties = [ordered]@{
                        ScanID   = $scan.uuid
                        ScanName = $scan.readableName
                        Owner    = $scan.owner
                        Status   = $scan.status
                        Date     = $origin.AddSeconds($scan.start_time).ToLocalTime()
                    }
                    $scanpropobj = [PSCustomObject]$scan_proprties
                    $scanpropobj.pstypenames.insert(0,'Nessus.Server.Scan')
                    $scanpropobj
                }
            }
        }
        elseif(($request_reply.status -eq "OK") -and (!($request_reply.contents))) {
            throw "ScanID not found"
        }
        else {
            throw $request_reply.contents
        }
    }
    END {}

}


<#
.Synopsis
   Resumes a Suspended Nessus Vulnerability Scans
.DESCRIPTION
   Resumes a paused Nessus Vulnerability scan on a given server.
.EXAMPLE
   Resumming a Nessus Vulnerability scan that was paused given its ScanID

    PS C:\> Resume-NessusScan -Index 0 -ScanID 908185a5-19cc-e2e4-6073-2134043611b99e3d5fcf060ec31e


    ScanID   : 908185a5-19cc-e2e4-6073-2134043611b99e3d5fcf060ec31e
    ScanName : Scan Dev Lab
    Owner    : carlos
    Status   : resuming
    Date     : 4/11/2013 4:19:01 AM
#>

function Resume-NessusScan
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

        [Parameter(Mandatory=$false,
        Position=1,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        $ScanID

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
        elseif ($Session -ne $null)
        {
                $NSession = $Session
        }

        try {
            $request_reply = $NSession.SessionManager.ResumeScan(
                $ScanID).reply
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionManager.ResumeScan(
                    $ScanID).reply
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }   
        }

        if ($request_reply.status -eq "OK" -and $request_reply.contents){
            # Returns epoch time so we need to tranform it
            $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
            Write-Verbose -Message "We got an OK reply from the session."
            # Get the UUID of the report to look for it in the Scan list
            $created_uuid = $request_reply.contents.scan.uuid
            # Search for the recently created report
            foreach ($scan in $NSession.SessionManager.ListScans().reply.contents.scans.scanlist.scan) {
                if ($scan.uuid -eq $created_uuid){
                        $scan_proprties = [ordered]@{
                        ScanID   = $scan.uuid
                        ScanName = $scan.readableName
                        Owner    = $scan.owner
                        Status   = $scan.status
                        Date     = $origin.AddSeconds($scan.start_time).ToLocalTime()
                    }
                    $scanpropobj = [PSCustomObject]$scan_proprties
                    $scanpropobj.pstypenames.insert(0,'Nessus.Server.Scan')
                    $scanpropobj
                }
            }
        }
        elseif(($request_reply.status -eq "OK") -and (!($request_reply.contents))) {
            throw "ScanID not found"
        }
        else {
            throw $request_reply.contents
        }
    }
    END {}

}


<#
.Synopsis
   Suspends a Running Nessus Vulnerability Scan
.DESCRIPTION
   Suspends a running Nessus Vulnerability San on a Nessus Server given its ScanID.
.EXAMPLE
   Sustending a Nessus scan given its ScanID

    PS C:\> Suspend-NessusScan -Index 0 -ScanID 908185a5-19cc-e2e4-6073-2134043611b99e3d5fcf060ec31e


    ScanID   : 908185a5-19cc-e2e4-6073-2134043611b99e3d5fcf060ec31e
    ScanName : Scan Dev Lab
    Owner    : carlos
    Status   : paused
    Date     : 4/11/2013 4:19:01 AM
#>

function Suspend-NessusScan
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

        [Parameter(Mandatory=$false,
        Position=1,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        $ScanID

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
        elseif ($Session -ne $null)
        {
                $NSession = $Session
        }

        try {
            $request_reply = $NSession.SessionManager.PauseScan(
                $ScanID).reply
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionManager.PauseScan(
                    $ScanID).reply
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }   
        }

        if ($request_reply.status -eq "OK" -and $request_reply.contents){
            # Returns epoch time so we need to tranform it
            $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
            Write-Verbose -Message "We got an OK reply from the session."
            # Get the UUID of the report to look for it in the Scan list
            $created_uuid = $request_reply.contents.scan.uuid
            # Search for the recently created report
            foreach ($scan in $NSession.SessionManager.ListScans().reply.contents.scans.scanlist.scan) {
                if ($scan.uuid -eq $created_uuid){
                        $scan_proprties = [ordered]@{
                        ScanID   = $scan.uuid
                        ScanName = $scan.readableName
                        Owner    = $scan.owner
                        Status   = $scan.status
                        Date     = $origin.AddSeconds($scan.start_time).ToLocalTime()
                    }
                    $scanpropobj = [PSCustomObject]$scan_proprties
                    $scanpropobj.pstypenames.insert(0,'Nessus.Server.Scan')
                    $scanpropobj
                }
            }
        }
        elseif(($request_reply.status -eq "OK") -and (!($request_reply.contents))) {
            throw "ScanID not found"
        }
        else {
            throw $request_reply.contents
        }
    }
    END {}
}

########################################
#     Nessus Scan Template Cmdlets     #
########################################



<#
.Synopsis
   Shoow Nessus Scan Templates Available
.DESCRIPTION
   Shows scan templates available on a Nessus Server.
.EXAMPLE
   List Scan Templates availabe on a Nessus Session.

   
    PS C:\> Show-NessusScanTemplate -Index 0


    TemplateID : template-7e833a7b-ddc7-78a2-8e8c-a9e1105f4fa720181ca11c9ad9be
    PolicyID   : 4
    PolicyName : Full Scan
    Name       : Lab Full Unauthenticated Scan
    Owner      : carlos
    Targets    : 192.168.10.1-192.168.10.254
#>

function Show-NessusScanTemplate
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
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        $TemplateID

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
        elseif ($Session -ne $null)
        {
                $NSession = $Session
        }

        try {
            $request_reply = $NSession.SessionManager.ListTemplates().reply
            $templates = $request_reply.contents.templates.templateList.template
            $policies = $request_reply.contents.policies.policies.policy
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionManager.ListTemplates().reply
                $templates = $request_reply.contents.templates.templateList.template
                $policies = $request_reply.contents.policies.policies.policy
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }   
        }

        foreach ($template in $templates){
            if ($TemplateID){
                if ($template.name -eq $TemplateID) {
                    $template_properties = [ordered]@{
                        TemplateID = $template.name
                        PolicyID    = $template.policy_id
                        PolicyName  = &{foreach($pol in $policies){
                                        if ($pol.policyID -eq $template.policy_id) {
                                            $pol.policyName
                                        }
                                       }}
                        Name        = $template.readableName
                        Owner       = $template.owner
                        Targets     = $template.target
                    }
                    $templateobj = [PSCustomObject]$template_properties
                    $templateobj.pstypenames.insert(0,'Nessus.Server.ScanTemplate')
                    $templateobj
                }
            }
            else{
                Write-Verbose "Processing Template $($template.name)"
                $template_properties = [ordered]@{
                    TemplateID = $template.name
                    PolicyID    = $template.policy_id
                    PolicyName  = &{foreach($pol in $policies){
                                    if ($pol.policyID -eq $template.policy_id) {
                                        $pol.policyName
                                    }
                                   }}
                    Name        = $template.readableName
                    Owner       = $template.owner
                    Targets     = $template.target
                }
                $templateobj = [PSCustomObject]$template_properties
                $templateobj.pstypenames.insert(0,'Nessus.Server.ScanTemplate')
                $templateobj
            }
        }
    }
    END{}
}


<#
.Synopsis
   Launch a Nessus Vulnerability Scan from Nessus Scan Template
.DESCRIPTION
   Launch a Nessus Vulnerability Scan from Nessus Scan Template. The scan will have as name the name of the template.
.EXAMPLE
   Launch vulnerability scan based on the scan template selected

    PS C:\> Invoke-NessusScanTemplate -Index 0 -TemplateID template-7e833a7b-ddc7-78a2-8e8c-a9e1105f4fa720181ca11c9ad9be


    ScanID   : beb54ae5-ddd5-4700-3e85-d0241ade948354bf668ec4c5c319
    ScanName : Lab Full Unauthenticated Scan
    Owner    : carlos
    Status   : running
    Date     : 4/11/2013 6:32:39 AM

#>

function Invoke-NessusScanTemplate
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
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string]$TemplateID
    )

    BEGIN 
    {
    }

    PROCESS 
    {
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


        try 
        {
            $request_reply = $NSession.SessionManager.LaunchScanTemplate($TemplateID).reply
        }
        Catch [Net.WebException] 
        {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK")
            {
                $request_reply = $NSession.SessionManager.LaunchScanTemplate($TemplateID).reply
            }
            else
            {
                throw "Session expired could not Re-Authenticate"
            }   
        }
        if ($request_reply.status -eq "OK")
        {
            # Returns epoch time so we need to tranform it
            $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
            Write-Verbose -Message "We got an OK reply from the session."
            # Get the UUID of the report to look for it in the Scan list
            $created_uuid = $request_reply.contents.scan.uuid
            # Search for the recently created report
            foreach ($scan in $NSession.SessionManager.ListScans().reply.contents.scans.scanlist.scan) {
                if ($scan.uuid -eq $created_uuid)
                {
                        $scan_proprties = [ordered]@{
                        ScanID   = $scan.uuid
                        ScanName = $scan.readableName
                        Owner    = $scan.owner
                        Status   = $scan.status
                        Date     = $origin.AddSeconds($scan.start_time).ToLocalTime()
                    }
                    $scanpropobj = [PSCustomObject]$scan_proprties
                    $scanpropobj.pstypenames.insert(0,'Nessus.Server.Scan')
                    $scanpropobj
                }
            }
        }
        else 
        {
            throw $request_reply.contents
        }

    }
}


<#
.Synopsis
   Create a Nessus Scan Template
.DESCRIPTION
   Creates a Nessus Scan Template given then name, policy and targets.
.EXAMPLE
    Create a Scan Template named "Lab Full Unauthenticated Scan" with an IP Range for targets.

    PS C:\> New-NessusScanTemplate -Index 0 -TemplateName "Lab Full Unauthenticated Scan" -PolicyID 4 -Targets "192.168.10.1-192.168.10.254"


    TemplateID : template-e2f1ad52-beaa-7202-9bed-576c19cf0a9bd87efb466030f92f
    PolicyID   : 4
    PolicyName : 
    Name       : Lab Full Unauthenticated Scan
    Owner      : carlos
    Targets    : 192.168.10.1-192.168.10.254
#>

function New-NessusScanTemplate
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,
        Position=0,
        ParameterSetName = "Index")]
        [int[]]$Index,

        [Parameter(Mandatory=$true,
        Position=0,
        ParameterSetName = "Session",
        ValueFromPipeline=$True)]
        [Nessus.Server.Session]$Session,

        [Parameter(Mandatory=$true,
        Position=1,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string]$TemplateName,

        [Parameter(Mandatory=$true,
        Position=2,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string]$Targets,

        [Parameter(Mandatory=$true,
        Position=3,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [int]$PolicyID
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
        elseif ($Session -ne $null)
        {
                $NSession = $Session
        }

        $target = $Targets -join " "

        try {
            $request_reply = $NSession.SessionManager.CreateScanTemplate($TemplateName, $PolicyID, $Target).reply
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionManager.CreateScanTemplate($TemplateName, $PolicyID, $Target).reply
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }   
        }
        if ($request_reply.status -eq "OK"){
            Write-Verbose -Message "We got an OK reply from the session."
            $template = $request_reply.contents.template
            $template_properties = [ordered]@{
                    TemplateID = $template.name
                    PolicyID    = $template.policy_id
                    PolicyName  = ''
                    Name        = $template.readableName
                    Owner       = $template.owner
                    Targets     = $template.target
                }
                $templateobj = [PSCustomObject]$template_properties
                $templateobj.pstypenames.insert(0,'Nessus.Server.ScanTemplate')
                $templateobj
        }
        else {
            throw $request_reply.contents
        }
    
    }
    END {}
    
}



<#
.Synopsis
  Removes a Nessus Scan Template from a Nessus Server
.DESCRIPTION
   Removes a Scan Template from a Nessus Server given its Template ID.
.EXAMPLE
    Removes a Scan Template given its TemplateID
    
    PS C:\> Remove-NessusScanTemplate -Index 0 -TemplateID template-7e833a7b-ddc7-78a2-8e8c-a9e1105f4fa720181ca11c9ad9be
    True
#>

function Remove-NessusScanTemplate
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
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string]$TemplateID
    )
    
     BEGIN 
     {
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

        try 
        {
            $request_reply = $NSession.SessionManager.ListTemplates().reply
            $templates = $request_reply.contents.templates.templateList.template
            $policies = $request_reply.contents.policies.policies.policy
        }
        Catch [Net.WebException] 
        {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK")
            {
                $request_reply = $NSession.SessionManager.ListTemplates().reply
                $templates = $request_reply.contents.templates.templateList.template
                $policies = $request_reply.contents.policies.policies.policy
            }
            else
            {
                throw "Session expired could not Re-Authenticate"
            }   
        }
    }
    PROCESS 
    {
        Write-Verbose "Checking if Templete with ID $($TemplateID) exists before attempting to delete."
        $template_found = $false
        foreach($template in $templates) {
            if ($template.name -eq $TemplateID){
                Write-Verbose "Template was found"
                $template_found = $true
            }
        }
        if ($template_found) 
        {
            $delete_reply = $NSession.SessionManager.DeleteScanTemplate($TemplateID).reply
            if ($delete_reply.status -eq "OK"){
                write-verbose "Template deleted successfuly"
                $true
            }
            else 
            {
                throw $delete_reply.reply.contents
            }
        }
        else 
        {
            throw "A template with ID $($TemplateID) was not found on the server"
        }
    }
    END
    {}
}



<#
.Synopsis
   Updates Configuration of a Nessus Scan Template
.DESCRIPTION
   Modifies the Name, Targets, or PolicyID for a given Nessus Scan Template on a Nessus Server.
.EXAMPLE
   Changes the target list on an existing Nessus Scan Template
 
   PS C:\> $TemplateID = "template-e2f1ad52-beaa-7202-9bed-576c19cf0a9bd87efb466030f92f"
   PS C:\> Updat-NessusScanTemplate -Index 0 -TemplateID $TemplateID -Targets "192.168.10.1-192.168.10.254",192.168.1.1-192.168.1.254"


    TemplateID : template-e2f1ad52-beaa-7202-9bed-576c19cf0a9bd87efb466030f92f
    PolicyID   : 4
    PolicyName : 
    Name       : Lab Full Unauthenticated Scan
    Owner      : carlos
    Targets    : 192.168.10.1-192.168.10.254;192.168.1.1-192.168.1.254
#>

function Update-NessusScanTemplate
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
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string]$TemplateID,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [int]$PolicyID,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string[]]$Targets,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string]$Name
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
        elseif ($Session -ne $null)
        {
                $NSession = $Session
        }

        # Check if at least one value was given for change.
        Write-Verbose "Checking if a value was given for change."
        if (($Targets -gt 0) -or ($PolicyID) -or ($Name))
        {
            try 
            {
                # Collect current Scan Template on the given session.
                Write-Verbose "Collecting Scan Templates on the given session to check for presence"
                $request_reply = $NSession.SessionManager.ListTemplates().reply
                $templates = $request_reply.contents.templates.templateList.template
                $policies = $request_reply.contents.policies.policies.policy
            }
            Catch [Net.WebException] 
            {
                # If the session timedout we will try to re-authenticate if not raise error.
                write-verbose "The session has expired, Re-authenticating"
                $reauth = $ns.SessionManager.Login(
                    $ns.SessionState.Username, 
                    $ns.SessionState.Password, 
                    [ref]$true)
                if ($reauth.reply.status -eq "OK")
                {
                    # If we where able to re-authenticate we will collec the necesarry info.
                    $request_reply = $NSession.SessionManager.ListTemplates().reply
                    $templates = $request_reply.contents.templates.templateList.template
                    $policies = $request_reply.contents.policies.policies.policy
                }
                else
                {
                    throw "Session expired could not Re-Authenticate"
                }   
            }
        }
        else 
        {
            # If no value for changing is given we will throw an exception.
            throw "No value for change was given"
        }
        Write-Verbose "Checking if Templete with ID $($TemplateID) exists before attempting to Update."
        $template_found = $false
        $template_to_update = $null

        foreach($template in $templates) 
        {
            if ($template.name -eq $TemplateID)
            {
                Write-Verbose "Template was found"
                $template_to_update = $template
                $template_found = $true
            }
        }
        if ($template_found) 
        {
            # Process Name
            if ($Name) 
            {
                Write-Verbose "Will be changing name to $($name)"
                $Name2update = $name
            }
            else
            {
                $Name2update = $template_to_update.readableName
            }

            # Process Policy ID
            if ($PolicyID)
            {
                Write-Verbose "Will be changing PolicyID to $($PolicyID)"
                $policy2update = $PolicyID
            }
            else 
            {
                $policy2update = $template.policy_id
            }

            # Process Targets
            if ($Targets.Count -gt 0)
            {
                Write-Verbose "Will be changing targets"
                $targets2update = $Targets -join ' '
            }
            else 
            {
                $targets2update = $template.target
            }

            $update_reply = $NSession.SessionManager.EditScanTemplate($TemplateID, 
                                $Name2update, 
                                $policy2update,
                                $targets2update).reply
 
            if ($update_reply.status -eq "OK")
            {
                write-verbose "Template updated successfuly"
                $updated_template = $update_reply.contents.template
                tmp
                $template_properties = [ordered]@{
                    TemplateID  = $updated_template.name
                    PolicyID    = $updated_template.policy_id
                    PolicyName  = ''
                    Name        = $updated_template.readableName
                    Owner       = $updated_template.owner
                    Targets     = $updated_template.target
                }
                $templateobj = [PSCustomObject]$template_properties
                $templateobj.pstypenames.insert(0,'Nessus.Server.ScanTemplate')
                $templateobj
            }
            else 
            {
                throw $update_reply.reply.contents
            }
        }
        else 
        {
            throw "A template with ID $($TemplateID) was not found on the server"
        }

    }
}

<# function New-NessusScheduledScanTemplate
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
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string]$TemplateID,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [int]$PolicyID,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string[]]$Targets,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string]$Name,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [validateset("Africa/Abidjan","Africa/Accra","Africa/Addis_Ababa","Africa/Algiers","Africa/Asmara","Africa/Asmera","Africa/Bamako","Africa/Bangui",
        "Africa/Banjul","Africa/Bissau","Africa/Blantyre","Africa/Brazzaville","Africa/Bujumbura","Africa/Cairo","Africa/Casablanca","Africa/Ceuta","Africa/Conakry",
        "Africa/Dakar","Africa/Dar_es_Salaam","Africa/Djibouti","Africa/Douala","Africa/El_Aaiun","Africa/Freetown","Africa/Gaborone","Africa/Harare","Africa/Johannesburg",
        "Africa/Juba","Africa/Kampala","Africa/Khartoum","Africa/Kigali","Africa/Kinshasa","Africa/Lagos","Africa/Libreville","Africa/Lome","Africa/Luanda","Africa/Lubumbashi",
        "Africa/Lusaka","Africa/Malabo","Africa/Maputo","Africa/Maseru","Africa/Mbabane","Africa/Mogadishu","Africa/Monrovia","Africa/Nairobi","Africa/Ndjamena","Africa/Niamey",
        "Africa/Nouakchott","Africa/Ouagadougou","Africa/Porto-Novo","Africa/Sao_Tome","Africa/Timbuktu","Africa/Tripoli","Africa/Tunis","Africa/Windhoek","America/Adak",
        "America/Anchorage","America/Anguilla","America/Antigua","America/Araguaina","America/Argentina/Buenos_Aires","America/Argentina/Catamarca","America/Argentina/ComodRivadavia"
        ,"America/Argentina/Cordoba","America/Argentina/Jujuy","America/Argentina/La_Rioja","America/Argentina/Mendoza","America/Argentina/Rio_Gallegos","America/Argentina/Salta",
        "America/Argentina/San_Juan","America/Argentina/San_Luis","America/Argentina/Tucuman","America/Argentina/Ushuaia","America/Aruba","America/Asuncion","America/Atikokan",
        "America/Atka","America/Bahia","America/Bahia_Banderas","America/Barbados","America/Belem","America/Belize","America/Blanc-Sablon","America/Boa_Vista","America/Bogota",
        "America/Boise","America/Buenos_Aires","America/Cambridge_Bay","America/Campo_Grande","America/Cancun","America/Caracas","America/Catamarca","America/Cayenne","America/Cayman",
        "America/Chicago","America/Chihuahua","America/Coral_Harbour","America/Cordoba","America/Costa_Rica","America/Creston","America/Cuiaba","America/Curacao","America/Danmarkshavn",
        "America/Dawson","America/Dawson_Creek","America/Denver","America/Detroit","America/Dominica","America/Edmonton","America/Eirunepe","America/El_Salvador","America/Ensenada",
        "America/Fort_Wayne","America/Fortaleza","America/Glace_Bay","America/Godthab","America/Goose_Bay","America/Grand_Turk","America/Grenada","America/Guadeloupe","America/Guatemala",
        "America/Guayaquil","America/Guyana","America/Halifax","America/Havana","America/Hermosillo","America/Indiana/Indianapolis","America/Indiana/Knox","America/Indiana/Marengo",
        "America/Indiana/Petersburg","America/Indiana/Tell_City","America/Indiana/Vevay","America/Indiana/Vincennes","America/Indiana/Winamac","America/Indianapolis","America/Inuvik",
        "America/Iqaluit","America/Jamaica","America/Jujuy","America/Juneau","America/Kentucky/Louisville","America/Kentucky/Monticello","America/Knox_IN","America/Kralendijk",
        "America/La_Paz","America/Lima","America/Los_Angeles","America/Louisville","America/Lower_Princes","America/Maceio","America/Managua","America/Manaus","America/Marigot",
        "America/Martinique","America/Matamoros","America/Mazatlan","America/Mendoza","America/Menominee","America/Merida","America/Metlakatla","America/Mexico_City","America/Miquelon",
        "America/Moncton","America/Monterrey","America/Montevideo","America/Montreal","America/Montserrat","America/Nassau","America/New_York","America/Nipigon","America/Nome",
        "America/Noronha","America/North_Dakota/Beulah","America/North_Dakota/Center","America/North_Dakota/New_Salem","America/Ojinaga","America/Panama","America/Pangnirtung",
        "America/Paramaribo","America/Phoenix","America/Port-au-Prince","America/Port_of_Spain","America/Porto_Acre","America/Porto_Velho","America/Puerto_Rico","America/Rainy_River",
        "America/Rankin_Inlet","America/Recife","America/Regina","America/Resolute","America/Rio_Branco","America/Rosario","America/Santa_Isabel","America/Santarem","America/Santiago",
        "America/Santo_Domingo","America/Sao_Paulo","America/Scoresbysund","America/Shiprock","America/Sitka","America/St_Barthelemy","America/St_Johns","America/St_Kitts",
        "America/St_Lucia","America/St_Thomas","America/St_Vincent","America/Swift_Current","America/Tegucigalpa","America/Thule","America/Thunder_Bay","America/Tijuana",
        "America/Toronto","America/Tortola","America/Vancouver","America/Virgin","America/Whitehorse","America/Winnipeg","America/Yakutat","America/Yellowknife","Antarctica/Casey",
        "Antarctica/Davis","Antarctica/DumontDUrville","Antarctica/Macquarie","Antarctica/Mawson","Antarctica/McMurdo","Antarctica/Palmer","Antarctica/Rothera","Antarctica/South_Pole",
        "Antarctica/Syowa","Antarctica/Vostok","Arctic/Longyearbyen","Asia/Aden","Asia/Almaty","Asia/Amman","Asia/Anadyr","Asia/Aqtau","Asia/Aqtobe","Asia/Ashgabat","Asia/Ashkhabad",
        "Asia/Baghdad","Asia/Bahrain","Asia/Baku","Asia/Bangkok","Asia/Beirut","Asia/Bishkek","Asia/Brunei","Asia/Calcutta","Asia/Choibalsan","Asia/Chongqing","Asia/Chungking",
        "Asia/Colombo","Asia/Dacca","Asia/Damascus","Asia/Dhaka","Asia/Dili","Asia/Dubai","Asia/Dushanbe","Asia/Gaza","Asia/Harbin","Asia/Hebron","Asia/Ho_Chi_Minh","Asia/Hong_Kong",
        "Asia/Hovd","Asia/Irkutsk","Asia/Istanbul","Asia/Jakarta","Asia/Jayapura","Asia/Jerusalem","Asia/Kabul","Asia/Kamchatka","Asia/Karachi","Asia/Kashgar","Asia/Kathmandu",
        "Asia/Katmandu","Asia/Kolkata","Asia/Krasnoyarsk","Asia/Kuala_Lumpur","Asia/Kuching","Asia/Kuwait","Asia/Macao","Asia/Macau","Asia/Magadan","Asia/Makassar","Asia/Manila",
        "Asia/Muscat","Asia/Nicosia","Asia/Novokuznetsk","Asia/Novosibirsk","Asia/Omsk","Asia/Oral","Asia/Phnom_Penh","Asia/Pontianak","Asia/Pyongyang","Asia/Qatar","Asia/Qyzylorda",
        "Asia/Rangoon","Asia/Riyadh","Asia/Riyadh87","Asia/Riyadh88","Asia/Riyadh89","Asia/Saigon","Asia/Sakhalin","Asia/Samarkand","Asia/Seoul","Asia/Shanghai","Asia/Singapore",
        "Asia/Taipei","Asia/Tashkent","Asia/Tbilisi","Asia/Tehran","Asia/Tel_Aviv","Asia/Thimbu","Asia/Thimphu","Asia/Tokyo","Asia/Ujung_Pandang","Asia/Ulaanbaatar","Asia/Ulan_Bator",
        "Asia/Urumqi","Asia/Vientiane","Asia/Vladivostok","Asia/Yakutsk","Asia/Yekaterinburg","Asia/Yerevan","Atlantic/Azores","Atlantic/Bermuda","Atlantic/Canary","Atlantic/Cape_Verde",
        "Atlantic/Faeroe","Atlantic/Faroe","Atlantic/Jan_Mayen","Atlantic/Madeira","Atlantic/Reykjavik","Atlantic/South_Georgia","Atlantic/St_Helena","Atlantic/Stanley","Australia/ACT",
        "Australia/Adelaide","Australia/Brisbane","Australia/Broken_Hill","Australia/Canberra","Australia/Currie","Australia/Darwin","Australia/Eucla","Australia/Hobart","Australia/LHI",
        "Australia/Lindeman","Australia/Lord_Howe","Australia/Melbourne","Australia/NSW","Australia/North","Australia/Perth","Australia/Queensland","Australia/South","Australia/Sydney",
        "Australia/Tasmania","Australia/Victoria","Australia/West","Australia/Yancowinna","Brazil/Acre","Brazil/DeNoronha","Brazil/East","Brazil/West","CET","CST6CDT","Canada/Atlantic",
        "Canada/Central","Canada/East-Saskatchewan","Canada/Eastern","Canada/Mountain","Canada/Newfoundland","Canada/Pacific","Canada/Saskatchewan","Canada/Yukon","Chile/Continental",
        "Chile/EasterIsland","Cuba","EET","EST","EST5EDT","Egypt","Eire","Etc/GMT","Etc/GMT+0","Etc/GMT+1","Etc/GMT+10","Etc/GMT+11","Etc/GMT+12","Etc/GMT+2","Etc/GMT+3","Etc/GMT+4",
        "Etc/GMT+5","Etc/GMT+6","Etc/GMT+7","Etc/GMT+8","Etc/GMT+9","Etc/GMT-0","Etc/GMT-1","Etc/GMT-10","Etc/GMT-11","Etc/GMT-12","Etc/GMT-13","Etc/GMT-14","Etc/GMT-2","Etc/GMT-3",
        "Etc/GMT-4","Etc/GMT-5","Etc/GMT-6","Etc/GMT-7","Etc/GMT-8","Etc/GMT-9","Etc/GMT0","Etc/Greenwich","Etc/UCT","Etc/UTC","Etc/Universal","Etc/Zulu","Europe/Amsterdam","Europe/Andorra",
        "Europe/Athens","Europe/Belfast","Europe/Belgrade","Europe/Berlin","Europe/Bratislava","Europe/Brussels","Europe/Bucharest","Europe/Budapest","Europe/Chisinau","Europe/Copenhagen",
        "Europe/Dublin","Europe/Gibraltar","Europe/Guernsey","Europe/Helsinki","Europe/Isle_of_Man","Europe/Istanbul","Europe/Jersey","Europe/Kaliningrad","Europe/Kiev","Europe/Lisbon",
        "Europe/Ljubljana","Europe/London","Europe/Luxembourg","Europe/Madrid","Europe/Malta","Europe/Mariehamn","Europe/Minsk","Europe/Monaco","Europe/Moscow","Europe/Nicosia","Europe/Oslo",
        "Europe/Paris","Europe/Podgorica","Europe/Prague","Europe/Riga","Europe/Rome","Europe/Samara","Europe/San_Marino","Europe/Sarajevo","Europe/Simferopol","Europe/Skopje","Europe/Sofia",
        "Europe/Stockholm","Europe/Tallinn","Europe/Tirane","Europe/Tiraspol","Europe/Uzhgorod","Europe/Vaduz","Europe/Vatican","Europe/Vienna","Europe/Vilnius","Europe/Volgograd","Europe/Warsaw",
        "Europe/Zagreb","Europe/Zaporozhye","Europe/Zurich","GB","GB-Eire","GMT","GMT+0","GMT-0","GMT0","Greenwich","HST","Hongkong","Iceland","Indian/Antananarivo","Indian/Chagos","Indian/Christmas",
        "Indian/Cocos","Indian/Comoro","Indian/Kerguelen","Indian/Mahe","Indian/Maldives","Indian/Mauritius","Indian/Mayotte","Indian/Reunion","Iran","Israel","Jamaica","Japan","Kwajalein","Libya",
        "MET","MST","MST7MDT","Mexico/BajaNorte","Mexico/BajaSur","Mexico/General","Mideast/Riyadh87","Mideast/Riyadh88","Mideast/Riyadh89","NZ","NZ-CHAT","Navajo","PRC","PST8PDT","Pacific/Apia",
        "Pacific/Auckland","Pacific/Chatham","Pacific/Chuuk","Pacific/Easter","Pacific/Efate","Pacific/Enderbury","Pacific/Fakaofo","Pacific/Fiji","Pacific/Funafuti","Pacific/Galapagos",
        "Pacific/Gambier","Pacific/Guadalcanal","Pacific/Guam","Pacific/Honolulu","Pacific/Johnston","Pacific/Kiritimati","Pacific/Kosrae","Pacific/Kwajalein","Pacific/Majuro","Pacific/Marquesas",
        "Pacific/Midway","Pacific/Nauru","Pacific/Niue","Pacific/Norfolk","Pacific/Noumea","Pacific/Pago_Pago","Pacific/Palau","Pacific/Pitcairn","Pacific/Pohnpei","Pacific/Ponape",
        "Pacific/Port_Moresby","Pacific/Rarotonga","Pacific/Saipan","Pacific/Samoa","Pacific/Tahiti","Pacific/Tarawa","Pacific/Tongatapu","Pacific/Truk","Pacific/Wake","Pacific/Wallis",
        "Pacific/Yap","Poland","Portugal","ROC","ROK","Singapore","Turkey","UCT","US/Alaska","US/Aleutian","US/Arizona","US/Central","US/East-Indiana","US/Eastern","US/Hawaii","US/Indiana-Starke",
        "US/Michigan","US/Mountain","US/Pacific","US/Pacific-New","US/Samoa","UTC","Universal","W-SU","WET","Zulu")]
        $TimeZone

    )
} #>
