
$Global:nessusconn = New-Object System.Collections.ArrayList
 

##################################
#     Nessus Session Cmdlets     #
##################################

#  .ExternalHelp posh-nessus.Help.xml
function New-NessusSession
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
        Position=0)]
        [string[]]$ComputerName,

        [Parameter(Mandatory=$true,
        Position=1)]
        [Management.Automation.PSCredential]$Credentials,

        [Parameter(Mandatory=$false,
        Position=2)]
        [Int32]$Port = 8834,

        # Check on the user cotext for the certificate CA
        [switch]$UseUserContext,

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

                if ($WebRequest.ServicePoint.Certificate -ne $null) {
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
            if ($log_status.reply.status -eq "OK"){
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
            else {
                # if we can not connect throw an exception
                throw "Connection to $($comp) at $($Port) with User $($Credentials.GetNetworkCredential().UserName) Failed"
            }
        }
    }
    End
    {
    }
}

#  .ExternalHelp posh-nessus.Help.xml
function Remove-NessusSession
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

#  .ExternalHelp posh-nessus.Help.xml
function Get-NessusSession
{
    [CmdletBinding()]
    param(
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

#  .ExternalHelp posh-nessus.Help.xml
function Get-NessusServerFeedInfo 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

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

#  .ExternalHelp posh-nessus.Help.xml
function Get-NessusServerLoad 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

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

#  .ExternalHelp posh-nessus.Help.xml
function Start-NessusServerFeedUpdate
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

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
            $request_reply = $NSession.SessionState.ExecuteCommand("/server/update", $opts)
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $NSession.SessionManager.Login(
                $NSession.SessionState.Username, 
                $NSession.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK")
            {
                $request_reply = $NSession.SessionState.ExecuteCommand("/server/update", $opts)
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

#  .ExternalHelp posh-nessus.Help.xml
function Get-NessusServerAdvancesSettings
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

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

#  .ExternalHelp posh-nessus.Help.xml
function Get-NessusServerGeneralSettings
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

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

#  .ExternalHelp posh-nessus.Help.xml
function Get-NessusServerMobileSettings
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,
        ParameterSetName = "Index",
        Position=0)]
        [int32[]]$Index = @(),

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

###############################
#     Nessus User Cmdlets     #
###############################

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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
            
        }
        else{

            throw $request_reply.reply.contents
        }
        
    }
}

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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
        }
        else
        {
            throw $request_reply.reply.contents
        }
    }
}

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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

        [Parameter(Mandatory=$true,
        Position=1,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        $ReportID,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string[]]$HostFilter,

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

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
function Import-NessusV2Report
{
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

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
function Invoke-NessusScan
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
        [int]$PolicyID,

        [Parameter(Mandatory=$true,
        Position=2,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [string[]]$Targets,

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

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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


        try {
            $request_reply = $NSession.SessionManager.LaunchScanTemplate($TemplateID).reply
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionManager.LaunchScanTemplate($TemplateID).reply
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

#  .ExternalHelp posh-nessus.Help.xml
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

#  .ExternalHelp posh-nessus.Help.xml
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
    
     BEGIN {
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
    }
    PROCESS {
        Write-Verbose "Checking if Templete with ID $($TemplateID) exists before attempting to delete."
        $template_found = $false
        foreach($template in $templates) {
            if ($template.name -eq $TemplateID){
                Write-Verbose "Template was found"
                $template_found = $true
            }
        }
        if ($template_found) {
            $delete_reply = $NSession.SessionManager.DeleteScanTemplate($TemplateID).reply
            if ($delete_reply.status -eq "OK"){
                write-verbose "Template deleted successfuly"
            }
            else {
                throw $delete_reply.reply.contents
            }
        }
        else {
            throw "A template with ID $($TemplateID) was not found on the server"
        }
    }
    END{}
}

#  .ExternalHelp posh-nessus.Help.xml
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
        if (($Targets -gt 0) -or ($PolicyID) -or ($Name)){
            try {
                # Collect current Scan Template on the given session.
                Write-Verbose "Collecting Scan Templates on the given session to check for presence"
                $request_reply = $NSession.SessionManager.ListTemplates().reply
                $templates = $request_reply.contents.templates.templateList.template
                $policies = $request_reply.contents.policies.policies.policy
            }
            Catch [Net.WebException] {
                # If the session timedout we will try to re-authenticate if not raise error.
                write-verbose "The session has expired, Re-authenticating"
                $reauth = $ns.SessionManager.Login(
                    $ns.SessionState.Username, 
                    $ns.SessionState.Password, 
                    [ref]$true)
                if ($reauth.reply.status -eq "OK"){
                    # If we where able to re-authenticate we will collec the necesarry info.
                    $request_reply = $NSession.SessionManager.ListTemplates().reply
                    $templates = $request_reply.contents.templates.templateList.template
                    $policies = $request_reply.contents.policies.policies.policy
                }
                else{
                    throw "Session expired could not Re-Authenticate"
                }   
            }
        }
        else {
            # If no value for changing is given we will throw an exception.
            throw "No value for change was given"
        }
        Write-Verbose "Checking if Templete with ID $($TemplateID) exists before attempting to Update."
        $template_found = $false
        $template_to_update = $null

        foreach($template in $templates) {
            if ($template.name -eq $TemplateID){
                Write-Verbose "Template was found"
                $template_to_update = $template
                $template_found = $true
            }
        }
        if ($template_found) {
            # Process Name
            if ($Name) {
                Write-Verbose "Will be changing name to $($name)"
                $Name2update = $name
            }
            else{
                $Name2update = $template_to_update.readableName
            }

            # Process Policy ID
            if ($PolicyID){
                Write-Verbose "Will be changing PolicyID to $($PolicyID)"
                $policy2update = $PolicyID
            }
            else {
                $policy2update = $template.policy_id
            }

            # Process Targets
            if ($Targets.Count -gt 0){
                Write-Verbose "Will be changing targets"
                $targets2update = $Targets -join ' '
            }
            else {
                $targets2update = $template.target
            }

            $update_reply = $NSession.SessionManager.EditScanTemplate($TemplateID, 
                                $Name2update, 
                                $policy2update,
                                $targets2update).reply
 
            if ($update_reply.status -eq "OK"){
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
            else {
                throw $update_reply.reply.contents
            }
        }
        else {
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
