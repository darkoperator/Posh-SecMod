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
                if ($ScanName -eq $null){
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
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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
