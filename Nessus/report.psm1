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
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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
                                                            Get-NessusReportItems -session $this.session -ReportID $this.ReportID
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
                                                                Get-NessusReportItems -session $this.session -ReportID $this.ReportID
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


function Publish-NessusReport
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
            $import_reply = $NSession.SessionState.executecommand("/file/report/import",$ops)
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
   Removes a specified report from a Nessus Server
.DESCRIPTION
   Removes a specified report from a Nessus Server given the Report ID.
.EXAMPLE
   Remove-NessusReport -Index 0 -ReportID a50ecb7d-f847-9e77-dd3c-9791ed31222ea16bfde21c223641 -Verbose
   True

   Removes a specified report from a Nessus Server

#>
function Remove-NessusReport
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
            $request_reply = $NSession.SessionManager.DeleteReport($ReportID)
        }
        Catch [Net.WebException] {
           if ($_.exception -match ".*403.*") {
                write-verbose "The session has expired, Re-authenticating"
                $reauth = $ns.SessionManager.Login(
                    $ns.SessionState.Username, 
                    $ns.SessionState.Password, 
                    [ref]$true)
                if ($reauth.reply.status -eq "OK"){
                    $request_reply = $NSession.SessionManager.DeleteReport($ReportID)
                }
                else{
                    throw "Session expired could not Re-Authenticate"
                }
            }
            elseif ($_.exception -match ".*404.*") {
                throw "A report with that ID was not found on Nessus Server"
            } 
        }

        if ($request_reply.reply.status -eq "OK")
        {
            $true
        }
        else
        {
            $false
        }
    }
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
                PluginVersion        = $reportitem.script_version
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
function Get-NessusReportItems
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
                    PluginVersion        = $reportitem.script_version
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
        [int[]]$PluginID
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

        foreach ($Id in $PluginID)
        {
            try 
            {
                $request_reply = $NSession.SessionManager.GetAuditTrail($ReportID, $host, $PluginID)
            }
        
            Catch [Net.WebException] 
            {
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
    }
    END 
    {}
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
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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
                    PluginVersion        = $reportitem.script_version
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
    [CmdletBinding(DefaultParameterSetName = 'Index')]
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

<#
.Synopsis
   Imports and Parses a Nessus KB File
.DESCRIPTION
   Import and Parses a Nessus KB file showing plugins that triggered, passed or information gathered.
   One can also provide a list of Pligin IDs to look inside the given KB to know their status
.EXAMPLE
   Import-NessusKB -KBFile .\lab.txt -PluginID 12217,10785,2343

   Searches a given KB for a list of given Plugin IDs
.EXAMPLE
    Import-NessusKB -KBFile .\lab.txt -InfoType Triggered

   Get all plugins that triggered on the host.
#>
function Import-NessusKB
{
    [CmdletBinding(DefaultParameterSetName = 'Index')]

    Param
    (
        # Nessus Version 2 report file
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0,
                   ParameterSetName = "File")]
        [Parameter(ParameterSetName = "Filter")]
        [ValidateScript({Test-Path $_})] 
        $KBFile,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0,
                   ParameterSetName = "StringDoc")]
        [Parameter(ParameterSetName = "Filter")]
        [string]$InputObject,

        # Type of Information to return
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [Parameter(ParameterSetName = "StringDoc")]
        [Parameter(ParameterSetName = "File")]
        [ValidateSet("All", "Triggered", "Passed", "Info")] 
        $InfoType = "Plugins",


        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0,
                   ParameterSetName = "Filter")]
        [int[]]$PluginID
    ) 

    Begin
    {
        
    }
    Process
    {
        $successfull = @()
        $launched = @()
        $info = @()

        if ($KBFile)
        {
            $file = Get-ChildItem $KBFile
            $KBData = Get-Content $file.FullName
        }
        elseif ($InputObject)
        {
            $KBData = $InputObject.split("`r")
        }

        # Populate variables
        foreach ($KBEntry in $KBData) 
        { 
            if ($KBEntry -like "*Launched/*")
            {
                $launched += $KBEntry.Split(" ")[2].Split("/")[1].Split("=")[0]
            }
            elseif ($KBEntry -like "*Success/*")
            {
                $successfull += $KBEntry.Split(" ")[2].Split("/")[1].Split("=")[0]
            }
            else
            {
                $info += $KBEntry
            }
        }

        if ($PluginID.Length -eq 0)
        {
            switch ($InfoType)
            {
                "All"
                {
                    foreach ($plugin in $launched)
                    {
                        $status = "Passed"
                        if ($plugin -in $successfull)
                        {
                            $status = "Triggered"
                        }
                        [pscustomobject][ordered]@{PluginID = $plugin; Status = $status}
                    }
                }

                "Triggered"
                {
                    foreach ($plugin in $launched)
                    {
                        if ($plugin -in $successfull)
                        {
                            [pscustomobject][ordered]@{PluginID = $plugin; Status = "Triggered"}
                        }
                    }
                }

                "Passed"
                {
                    foreach ($plugin in $launched)
                    {
                        if ($plugin -notin $successfull)
                        {
                            [pscustomobject][ordered]@{PluginID = $plugin; Status = "Passed"}
                        }
                    }
                
                }

                "Info" 
                {
                    $info
                }
                default {return}
            }
         }
         else
         {
            $pluginresults = @()
            foreach($plugin_id in $PluginID)
            {
                if ($plugin_id -in $launched)
                {
                    $status = "Passed"
                    if ($plugin_id -in $successfull)
                    {
                        [pscustomobject][ordered]@{PluginID = $plugin_id; Status = "Triggered"}
                    }
                    else
                    {
                        [pscustomobject][ordered]@{PluginID = $plugin_id; Status = "Passed"}
                    }
                    
                }
                else
                {
                    [pscustomobject][ordered]@{PluginID = $plugin_id; Status = "Not Executed"}
                }
            }
         }
    }
    End
    {
    }
}