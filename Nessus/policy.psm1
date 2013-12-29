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
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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


function Get-NessusPolicyPluginFamilies
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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
            #add token to options
            $ops.Add("token",$NSession.token)
            $request_reply = $NSession.SessionState.ExecuteCommand("/policy/list/families", $ops)
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK"){
                $request_reply = $NSession.SessionState.ExecuteCommand("/policy/list/families", $ops)
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }
            
        }
        
        $families = $request_reply.reply.contents.policyfamilies.family
        foreach ($family in $families)
        {
            $family_proprties = [ordered]@{
                Name = $family.name
                ID = $family.id
                PluginCount = $family.plugin_count
                Status = $family.status
            }
            $familyobj = [PSCustomObject]$family_proprties
            $familyobj.pstypenames.insert(0,'Nessus.Server.Policyfamily')
            $familyobj
        }
    }
}


function Publish-NessusPolicy
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [ValidateScript({Test-Path $_})]
        [string]$File
    )
    Begin {
        # Random number for sequence request
        $rand = New-Object System.Random
        
        $FileProps = Get-ItemProperty $File
        $FullPath = $FileProps.FullName
        $FileName = $FileProps.Name

        # Options for XMLRPC request
        $ops = @{
            seq  = $rand.Next()
            file = $FileName 
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
            #add token to options
            $ops.Add("token",$NSession.token)
            $request_reply = $NSession.SessionState.upload("/file/upload", $FullPath)
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK")
            {
                $request_reply = $NSession.SessionState.upload("/file/upload", $FullPath)
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }

            
            
        }
            
        if ($request_reply.reply.status -eq "OK")
        {
            $import_reply = $NSession.SessionState.executecommand("/file/policy/import",$ops)
            if ($import_reply.reply.status -eq "OK")
            {
                return $true
            }
            else
            {
                return $false
            }
        }
    }
}  


function Update-NessusPolicyGeneralSettings
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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

        [Parameter(Mandatory=$false)]
        [Parameter(ParameterSetName = "Index")]
        [Parameter(ParameterSetName = "Session")]
        [string]$Name,

        [Parameter(Mandatory=$false)]
        [Parameter(ParameterSetName = "Index")]
        [Parameter(ParameterSetName = "Session")]
        [string]$Description,

        [Parameter(Mandatory=$false)]
        [Parameter(ParameterSetName = "Index")]
        [Parameter(ParameterSetName = "Session")]
        [ValidateSet("Private","Shared")]
        [string]$Visibility
    )
    Begin {
        # Random number for sequence request
        $rand = New-Object System.Random
        # Options for XMLRPC request
        $ops = @{
            seq = $rand.Next()
            "policy_id" = $PolicyID
        }
        if ($Name)
        {
            $ops.add("general.Basic.0", $Name.Replace(" ",'+'))
        }

        if ($Description)
        {
            $ops.add("general.Basic.2", $Description)
        }

        if ($Visibility)
        {
            switch ($Visibility)
            {
                "Private" {$ops.add("general.Basic.1", "private")}
                "Shared"  {$ops.add("general.Basic.1", "shared")}
            }
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
            #add token to options
            $ops.Add("token",$NSession.token)
            $request_reply = $NSession.SessionState.ExecuteCommand("/policy/update", $ops)
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK")
            {
                $request_reply = $NSession.SessionState.ExecuteCommand("/policy/update", $ops)
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }
            
        }

        $policy = $request_reply.reply.contents.metadata
            
        $policy_proprties = [ordered]@{
            Name = $policy.name
            PolicyID = $policy.id
            Visibility = $policy.visibility
            Owner = $policy.owner
        }
        $Policyobj = [PSCustomObject]$policy_proprties
        $Policyobj.pstypenames.insert(0,'Nessus.Server.Policy')
        $Policyobj
            
    }
}


function Update-NessusPolicyFamily
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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

        [Parameter(Mandatory=$false)]
        [Parameter(ParameterSetName = "Index")]
        [Parameter(ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Individual")]
        [validateset('AIX Local Security Checks',
        'AIX_Local_Security_Checks',
        'Backdoors',
        'CGI_abuses',
        'CGI_abuses_XSS',
        'CISCO',
        'CentOS_Local_Security_Checks',
        'DNS',
        'Databases',
        'Debian_Local_Security_Checks',
        'Default_Unix_Accounts',
        'Denial_of_Service',
        'FTP',
        'Fedora_Local_Security_Checks',
        'Firewalls',
        'FreeBSD_Local_Security_Checks',
        'Gain_a_shell_remotely',
        'General',
        'Gentoo_Local_Security_Checks',
        'HP-UX_Local_Security_Checks',
        'Junos_Local_Security_Checks',
        'MacOS_X_Local_Security_Checks',
        'Mandriva_Local_Security_Checks',
        'Misc.',
        'Mobile_Devices',
        'Netware',
        'Peer-To-Peer_File_Sharing',
        'Policy_Compliance',
        'RPC',
        'Red_Hat_Local_Security_Checks',
        'SCADA',
        'SMTP_problems',
        'SNMP',
        'Scientific_Linux_Local_Security_Checks',
        'Service_detection',
        'Settings',
        'Slackware_Local_Security_Checks',
        'Solaris_Local_Security_Checks',
        'SuSE_Local_Security_Checks',
        'Ubuntu_Local_Security_Checks',
        'VMware_ESX_Local_Security_Checks',
        'Web_Servers',
        'Windows',
        'Windows_Microsoft_Bulletins',
        'Windows_User_management')]
        [string]$Name,

        [Parameter(Mandatory=$false)]
        [Parameter(ParameterSetName = "Index")]
        [Parameter(ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Individual")]
        [ValidateSet("Enabled","Disabled")]
        [string]$Status,

        [Parameter(Mandatory=$false)]
        [Parameter(ParameterSetName = "Index")]
        [Parameter(ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "enableallplugs")]
        [Switch]$EnableAll,

        [Parameter(Mandatory=$false)]
        [Parameter(ParameterSetName = "Index")]
        [Parameter(ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "disableallplugs")]
        [Switch]$DisableAll
    )
    Begin 
    {
        
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


        # Sadly I have to hardcode them, Families and IDs for 4/15/13
        $FamilyHash = @{
            'AIX_Local_Security_Checks'='9aedd4dcccf909d4912a2f8113cffa43'
            'Backdoors'='6b480fc3bed84db55fce1e140c7b6b99'
            'CGI_abuses'='07948b8ff59e8dda0b01012f70f00327'
            'CGI_abuses_:_XSS'='61e021375865ee20d8f9e2562510b86f'
            'CISCO'='2e9d0015563e8f6c3614c219c759934c'
            'CentOS_Local_Security_Checks'='8f8213e8b86855939d5beea715ce3045'
            'DNS'='ed5f2bdecbd4bd349d09412d1ff6a6fb'
            'Databases'='ea2ef9b0d095bf991f4973633b485340'
            'Debian_Local_Security_Checks'='74562d71b087df9eabd0c21f99b132cc'
            'Default_Unix_Accounts'='98229c13ca0419b92d92c2af6ae65a55'
            'Denial_of_Service'='711d051a7c0db70ca108b804aa5319ac'
            'FTP'='c728a49363c9a93a43a7e7f232b5a54a'
            'Fedora_Local_Security_Checks'='be931514784f88df80712740ad2723e7'
            'Firewalls'='fd6d703cd1a0c15485615c97ae2fc355'
            'FreeBSD_Local_Security_Checks'='fe45aa727b58c1249bf04cfb7b4e6ae0'
            'Gain_a_shell_remotely'='55e5f61d4983f1c14216d056f7a03453'
            'General'='0db377921f4ce762c62526131097968f'
            'Gentoo_Local_Security_Checks'='cf18d881f0f76f23f322ed3f861d3616'
            'HP-UX_Local_Security_Checks'='f537a8c4c2a2ecce05af223984a006fc'
            'Junos_Local_Security_Checks'='f44fb98241ad612bdd34e6e796e60393'
            'MacOS_X_Local_Security_Checks'='9415f91090c2218ae67dd519ff399983'
            'Mandriva_Local_Security_Checks'='526837706681051344a466f9e51ac982'
            'Misc.'='f988dc6e0b4d047c838adcca890ea132'
            'Mobile_Devices'='b5aaa8de40d02294ba91f817a863ad9f'
            'Netware'='e7f18ad43e1a8ae73a65410ff262f6d9'
            'Peer-To-Peer_File_Sharing'='65e7b23b67bc8b3328746b8164139fda'
            'Policy_Compliance'='3c97e5be2c0439a7a7a8c5afdbb4ccce'
            'RPC'='6defe438c8cba7575d04f8a4e24467ad'
            'Red_Hat_Local_Security_Checks'='b46559ea68ec9a13474c3a7776817cfd'
            'SCADA'='8ebe43fc79c5288888cac7b7106b0045'
            'SMTP_problems'='f1e6d897f0494b2ac2149594a462ae12'
            'SNMP'='305af65222ed3fff91f5c8bcdfe17162'
            'Scientific_Linux_Local_Security_Checks'='b3a4d461a1383c8ba9fa401b58d29827'
            'Service_detection'='a3d3c73c01505d0383b007174b5bb5ac'
            'Settings'='f4f70727dc34561dfde1a3c529b6205c'
            'Slackware_Local_Security_Checks'='43a3ec56ec636b53af6d97a47899295c'
            'Solaris_Local_Security_Checks'='be2073bfad5e624acf0f878f09eda795'
            'SuSE_Local_Security_Checks'='71a40666da62ba38d22539c8277870c7'
            'Ubuntu_Local_Security_Checks'='c9b7d00377a789a14c9bb9dab6c7168c'
            'VMware_ESX_Local_Security_Checks'='ba996e5e98af86fd5a9f58bf52eea4bb'
            'Web_Servers'='07a0416e4de2a26a0531240b230d9eca'
            'Windows'='aea23489ce3aa9b6406ebb28e0cda430'
            'Windows_:_Microsoft_Bulletins'='c9898bc973bfffca5119f1a3bfa73a8d'
            'Windows_:_User_management'='bc1f6ae08a99ba29bc641b28fd6a94db'
        }

        # Random number for sequence request
        $rand = New-Object System.Random
        # Options for XMLRPC request
        $ops = @{
            seq = $rand.Next()
            "policy_id" = $PolicyID
            json = 1
        }
        
        if (($Name -ne "") -and ($Status))
        {
            Write-Verbose "Updating Family $Name to be $dtatus"
            
            $famid = $FamilyHash."$Name"
            $famkey = "family." + $famid
            Write-Verbose "The Family ID is $famid"
            switch ($Status)
            {
                "Enabled"  {$ops.add($famkey, "enabled")}
                "Disabled" {$ops.add($famkey, "disabled")}
            }
        }

        if ($EnableAll)
        {
            Write-Verbose "Enabling all families"
            $FamilyHash.GetEnumerator() | foreach {
                $famid = $FamilyHash."$($_.name)"
                $famkey = "family." + $famid
                $ops.add($famkey, "enabled")
            }

        }

        if ($DisableAll)
        {
            Write-Verbose "Enabling all families"
            $FamilyHash.GetEnumerator() | foreach {
                $famid = $FamilyHash."$($_.name)"
                $famkey = "family." + $famid
                $ops.add($famkey, "disabled")
            }

        }
        Try {
            #add token to options
            $ops.Add("token",$NSession.token)
            $request_reply = $NSession.SessionState.ExecuteCommand("/policy/update", $ops)
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK")
            {
                $request_reply = $NSession.SessionState.ExecuteCommand("/policy/update", $ops)
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }
            
        }
        
        $policy = $request_reply.reply.contents.metadata
            
        $policy_proprties = [ordered]@{
            Name = $policy.name
            PolicyID = $policy.id
            Visibility = $policy.visibility
            Owner = $policy.owner
        }
        $Policyobj = [PSCustomObject]$policy_proprties
        $Policyobj.pstypenames.insert(0,'Nessus.Server.Policy')
        $Policyobj
    }
}


function New-NessusPolicy
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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

        [Parameter(Mandatory=$false)]
        [Parameter(ParameterSetName = "Index")]
        [Parameter(ParameterSetName = "Session")]
        [string]$Name,

        [Parameter(Mandatory=$false)]
        [Parameter(ParameterSetName = "Index")]
        [Parameter(ParameterSetName = "Session")]
        [string]$Description,

        [Parameter(Mandatory=$false)]
        [Parameter(ParameterSetName = "Index")]
        [Parameter(ParameterSetName = "Session")]
        [ValidateSet("Private","Shared")]
        [string]$Visibility
    )
    Begin {
        # Random number for sequence request
        $rand = New-Object System.Random
        # Options for XMLRPC request
        $ops = @{
            seq = $rand.Next()
            "policy_id" = 0
        }
        if ($Name)
        {
            $ops.add("general.Basic.0", $Name.Replace(" ",'+'))
        }

        if ($Description)
        {
            $ops.add("general.Basic.2", $Description)
        }

        if ($Visibility)
        {
            switch ($Visibility)
            {
                "Private" {$ops.add("general.Basic.1", "private")}
                "Shared"  {$ops.add("general.Basic.1", "shared")}
            }
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
            #add token to options
            $ops.Add("token",$NSession.token)
            $request_reply = $NSession.SessionState.ExecuteCommand("/policy/update", $ops)
        }
        Catch [Net.WebException] {
           
            write-verbose "The session has expired, Re-authenticating"
            $reauth = $ns.SessionManager.Login(
                $ns.SessionState.Username, 
                $ns.SessionState.Password, 
                [ref]$true)
            if ($reauth.reply.status -eq "OK")
            {
                $request_reply = $NSession.SessionState.ExecuteCommand("/policy/update", $ops)
            }
            else{
                throw "Session expired could not Re-Authenticate"
            }
            
        }
            
        $policy = $request_reply.reply.contents.metadata
            
        $policy_proprties = [ordered]@{
            Name = $policy.name
            PolicyID = $policy.id
            Visibility = $policy.visibility
            Owner = $policy.owner
        }
        $Policyobj = [PSCustomObject]$policy_proprties
        $Policyobj.pstypenames.insert(0,'Nessus.Server.Policy')
        $Policyobj

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
    Copy-NessusPolicy -Index 0 -PolicyID 1 

    PolicyID                     PolicyName                   PolicyOwner                  Visibility                  
    --------                     ----------                   -----------                  ----------                  
    3                            Copy of Mobile Devices Audit carlos                       private

    Creates a copy of a policy.
#>
function Copy-NessusPolicy
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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

<#
.Synopsis
   Sets on a given policy the Windows Credential to Try
.DESCRIPTION
   Sets on a given policy the Windows credentials to try for those plugins
   that use Windows credentials to perform authenticated checks. Up to 4
   credential combination can be set. The NTLMv2 and Password type will apply
   to all credentials. Text password, LM Hash or NTML Hash can be used to 
   authenticate with Windows hosts.
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Set-NessusPolicyWindowsCredential
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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

        # Numeric ID of the Policy to update.
        [Parameter(Mandatory=$false,
        Position=1,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [int]$PolicyID,

        # A index value from 0 to 3 for the credentials. Nessus can have up to 4 credentials to try.
        [Parameter(Mandatory=$true,
        Position=2)]
        [ValidateRange(0,3)] 
        $UserIndex,

        # Credential object with credentials that will be set.
        [Parameter(Mandatory=$true,
        Position=3)]
        [Management.Automation.PSCredential]$Credential,

        # Sets if NTLMv2 will be used to transmit the credentials.
        [Parameter(Mandatory=$false,
        Position=4)]
        [switch]$NTLMv2 = $true,

        # Sets if Kerberos will be used for authentication.
        [Parameter(Mandatory=$false,
        Position=4)]
        [switch]$KerberosOnly = $true,


        # Type of password format, text password, LM Hash or NTML Hash.
        [Parameter(Mandatory=$false,
        Position=6)]
        [ValidateSet("Password","NTLMHash","LMHash")]
        [String]$PasswordType = "Password"

    )

    Begin
    {
        # Random number for sequence request
        $rand = New-Object System.Random

        # Options for XMLRPC request
        $opt = @{ 
            seq  = $rand.Next()
            policy_id = $PolicyID
        }
        switch ($UserIndex)
        {
            0 {
                $opt.add("credentials.Windows+credentials.364", $Credential.GetNetworkCredential().UserName)
                $opt.add("credentials.Windows+credentials.365", $Credential.GetNetworkCredential().Password)
                $opt.add("credentials.Windows+credentials.366", $Credential.GetNetworkCredential().Domain)
              }

            1 {
                $opt.add("credentials.Windows+credentials.368", $Credential.GetNetworkCredential().UserName)
                $opt.add("credentials.Windows+credentials.369", $Credential.GetNetworkCredential().Password)
                $opt.add("credentials.Windows+credentials.370", $Credential.GetNetworkCredential().Domain)
            }

            2 {
                $opt.add("credentials.Windows+credentials.371", $Credential.GetNetworkCredential().UserName)
                $opt.add("credentials.Windows+credentials.372", $Credential.GetNetworkCredential().Password)
                $opt.add("credentials.Windows+credentials.373", $Credential.GetNetworkCredential().Domain)
            }

            3 {
                $opt.add("credentials.Windows+credentials.374", $Credential.GetNetworkCredential().UserName)
                $opt.add("credentials.Windows+credentials.375", $Credential.GetNetworkCredential().Password)
                $opt.add("credentials.Windows+credentials.376", $Credential.GetNetworkCredential().Domain)
            }
        }

        switch ($PasswordType)
        {
            "Password" {$opt.add("credentials.Windows+credentials.367",'Password')}
            "NTLMHash" {$opt.add("credentials.Windows+credentials.367",'NTLM+Hash')}
            "LMHash"   {$opt.add("credentials.Windows+credentials.367",'LM+Hash')}
        }

        if ($NTLMv2)
        {
            $opt.add("credentials.Windows+credentials.378",'yes')
        }
        else
        {
            $opt.add("credentials.Windows+credentials.378",'no')
        }

        if ($KerberosOnly)
        {
            $opt.add("credentials.Windows+credentials.379",'yes')
        }
        else
        {
            $opt.add("credentials.Windows+credentials.379",'no')
        }

        # Make sure the credentials are never sent in as cleartext
        $opt.add("credentials.Windows+credentials.377",'yes')
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
            Write-Verbose "Setting credentia on policy $($PolicyID)"
            $request_reply = $NSession.SessionState.ExecuteCommand("/policy/update", $opt)
            
        }
        Catch [Net.WebException] 
        {
           if ($_.exception -match ".*403.*") 
           {
                write-verbose "The session has expired, Re-authenticating"
                $reauth = $ns.SessionManager.Login(
                    $ns.SessionState.Username, 
                    $ns.SessionState.Password, 
                    [ref]$true)
                if ($reauth.reply.status -eq "OK")
                {
                    $request_reply = $NSession.SessionState.ExecuteCommand("/policy/update", $opt)
                }
                else
                {
                    throw "Session expired could not Re-Authenticate"
                }
            }
            elseif ($_.exception -match ".*404.*") 
            {
                throw "A policy with that ID was not found on Nessus Server"
            } 
        }
        
        if ($request_reply.reply.status -eq "OK")
        {
            Write-Verbose "We got OK on request." 
            $true
        }
        else
        {
            $false
        }
    }
    End
    {
    }
}

function Set-NessusPolicySSHCredential
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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

        # Numeric ID of the Policy to update.
        [Parameter(Mandatory=$false,
        Position=1,
        ParameterSetName = "Session")]
        [Parameter(ParameterSetName = "Index")]
        [int]$PolicyID,

        # A index value from 0 to 5 for the credentials. Nessus can have up to 4 credentials to try.
        [Parameter(Mandatory=$true,
        Position=2)]
        [ValidateRange(0,5)] 
        $UserIndex,

        # Credential object with credentials that will be set.
        [Parameter(Mandatory=$true,
        Position=3)]
        [Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false,
        ParameterSetName = "Index")]
        [int32]$SSHPort = 22,

        # Credential object with credentials that will be used for elevation.
        [Parameter(Mandatory=$false)]
        [Management.Automation.PSCredential]$ElevationCredential,

        [Parameter(Mandatory=$false,
        Position=6)]
        [ValidateSet("su", "sudo", "su+sudo", "pbrun", "Cisco_Enable", "dzdo", "Nothing")]
        [String]$ElevationMethod

    )

    Begin
    {
        # Random number for sequence request
        $rand = New-Object System.Random

        # Options for XMLRPC request
        $opt = @{ 
            seq  = $rand.Next()
            policy_id = $PolicyID
        }

        switch ($UserIndex)
        {
            0 {
                $opt.add("credentials.SSH+settings.306", $Credential.GetNetworkCredential().UserName)
                $opt.add("credentials.SSH+settings.307", $Credential.GetNetworkCredential().Password)
              }

            1 {
                $opt.add("credentials.SSH+settings.319", $Credential.GetNetworkCredential().UserName)
                $opt.add("credentials.SSH+settings.320", $Credential.GetNetworkCredential().Password)
            }

            2 {
                $opt.add("credentials.SSH+settings.321", $Credential.GetNetworkCredential().UserName)
                $opt.add("credentials.SSH+settings.322", $Credential.GetNetworkCredential().Password)
            }

            3 {
                $opt.add("credentials.SSH+settings.323", $Credential.GetNetworkCredential().UserName)
                $opt.add("credentials.SSH+settings.324", $Credential.GetNetworkCredential().Password)
            }

            4 {
                $opt.add("credentials.SSH+settings.325", $Credential.GetNetworkCredential().UserName)
                $opt.add("credentials.SSH+settings.326", $Credential.GetNetworkCredential().Password)
            }

            5 {
                $opt.add("credentials.SSH+settings.327", $Credential.GetNetworkCredential().UserName)
                $opt.add("credentials.SSH+settings.328", $Credential.GetNetworkCredential().Password)
            }
        }

        if ($SSHPort)
        {
            $opt.add("credentials.SSH+settings.317", $SSHPort)
        }

        if ($ElevationCredential)
        {
            $opt.add("credentials.SSH+settings.314", $ElevationCredential.GetNetworkCredential().UserName)
            $opt.add("credentials.SSH+settings.315", $ElevationCredential.GetNetworkCredential().Password)
        }

        if ($ElevationMethod)
        {
            switch ($ElevationMethod)
            {

                "su"{$opt.add("credentials.SSH+settings.311", "su")}

                "sudo"{$opt.add("credentials.SSH+settings.311", "sudo")}

                "su+sudo"{$opt.add("credentials.SSH+settings.311", "su%2Bsudo")}

                "pbrun"{$opt.add("credentials.SSH+settings.311", "pbrun")}

                "Cisco_Enable"{$opt.add("credentials.SSH+settings.314", "Cisco+'enable'")}

                "dzdo"{$opt.add("credentials.SSH+settings.314", "dzdo")}

                "Nothing"{$opt.add("credentials.SSH+settings.314", "Nothing")}

                default {$opt.add("credentials.SSH+settings.314", "Nothing")}
            }
        }
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
            Write-Verbose "Setting credentia on policy $($PolicyID)"
            $request_reply = $NSession.SessionState.ExecuteCommand("/policy/update", $opt)
            
        }
        Catch [Net.WebException] 
        {
           if ($_.exception -match ".*403.*") 
           {
                write-verbose "The session has expired, Re-authenticating"
                $reauth = $ns.SessionManager.Login(
                    $ns.SessionState.Username, 
                    $ns.SessionState.Password, 
                    [ref]$true)
                if ($reauth.reply.status -eq "OK")
                {
                    $request_reply = $NSession.SessionState.ExecuteCommand("/policy/update", $opt)
                }
                else
                {
                    throw "Session expired could not Re-Authenticate"
                }
            }
            elseif ($_.exception -match ".*404.*") 
            {
                throw "A policy with that ID was not found on Nessus Server"
            } 
        }
        
        if ($request_reply.reply.status -eq "OK")
        {
            Write-Verbose "We got OK on request." 
            $true
        }
        else
        {
            $false
        }
    }
    End
    {
    }
}

