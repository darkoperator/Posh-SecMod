<#
.Synopsis
   Enumerates Logged On Sessions on a give host.
.DESCRIPTION
   Enumerates Logged On Sessions on a give host using WMI.
.EXAMPLE
   Get-AuditLogedOnSessions | where {$_.processes.count -gt 0}

   Retrieves sessions that have running processes.

#>
function Get-AuditLogedOnSessions 
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory=$false)]
        [string]$ComputerName = "localhost"
    )
    begin 
    {
        $loggedsessions = @()
        $SessionType = @{
            2  = 'Interactive'
            3  = 'Network'
            4  = 'Batch'
            5  = 'Servie'
            6  = 'Proxy'
            7  = 'Unlock'
            8  = 'NetworkCleartext'
            9  = 'NewCredentials'
            10 = 'Terminal'
            11 = 'CachedInteractive'
            12 = 'CachedTerminal'
            13 = 'CachedUnlock'
        }
    }
    process 
    {
        $sessions = Get-WmiObject win32_logonsession -Credential $Credential -ComputerName $ComputerName | select -Unique

        foreach ($session in $sessions) 
        {
            try{
                $account = $session.getrelated('win32_useraccount')
                if ($account -ne $null)
                {
                   $loggedsessions += [pscustomobject][ordered]@{Name=$account.Caption
                        SID=$account.SID
                        FullName=$account.fullname
                        Created=[System.Management.ManagementDateTimeConverter]::todatetime($session.StartTime)
                        AuthenticationType=$session.AuthenticationPackage
                        LogonType=$SessionType[[int]$session.LogonType]
                        Processes=$session.GetRelated('win32_process')
                   }
                }
            }
            catch {}
        }
    }

    end {$loggedsessions}
} 


<#
.Synopsis
   Gets a list of Domain Computer accounts and their details using ADSI.
.DESCRIPTION
   Gets a list of Domain coputer accounts and their details using ADSI. If the machine it is ran from is
   in the domain and no Domain Controller is specified it will run with the privelages of the user. 
   Support the use of alternate user credentials when ran against a domain controller. The host must use 
   the same DNS server to be able to reseolve the hostnames to the proper IPAddress.
.EXAMPLE
  
Get-AuditDSComputerAccount -DomainController 192.168.10.10 -Credential (Get-Credential)
cmdlet Get-Credential at command pipeline position 1
Supply values for the following parameters:


HostName        : DC01.acmelabs.com
OperatingSystem : Windows Server 2012 Standard
ServicePack     : 
Version         : 6.2 (9200)
DN              : CN=DC01,OU=Domain Controllers,DC=acmelabs,DC=com
Created         : 1/12/2013 2:08:47 AM
LastModified    : 9/4/2013 7:07:02 PM
IPAddress       : {192.168.10.10}

HostName        : DC02.acmelabs.com
OperatingSystem : Windows Server 2008 R2 Enterprise
ServicePack     : Service Pack 1
Version         : 6.1 (7601)
DN              : CN=DC02,OU=Domain Controllers,DC=acmelabs,DC=com
Created         : 1/12/2013 2:15:02 AM
LastModified    : 8/27/2013 9:29:39 AM
IPAddress       : {192.168.10.12}

HostName        : WIN701.acmelabs.com
OperatingSystem : Windows 7 Enterprise
ServicePack     : Service Pack 1
Version         : 6.1 (7601)
DN              : CN=WIN701,OU=HR,DC=acmelabs,DC=com
Created         : 1/12/2013 2:45:21 AM
LastModified    : 8/26/2013 6:45:50 PM
IPAddress       : {192.168.10.20}

HostName        : WIN702.acmelabs.com
OperatingSystem : Windows 7 Ultimate
ServicePack     : Service Pack 1
Version         : 6.1 (7601)
DN              : CN=WIN702,OU=HR,DC=acmelabs,DC=com
Created         : 1/13/2013 3:27:10 PM
LastModified    : 8/26/2013 6:42:00 PM
IPAddress       : {192.168.10.21}

HostName        : WIN801.acmelabs.com
OperatingSystem : Windows 8 Enterprise
ServicePack     : 
Version         : 6.2 (9200)
DN              : CN=WIN801,CN=Computers,DC=acmelabs,DC=com
Created         : 1/13/2013 5:48:57 PM
LastModified    : 9/5/2013 5:09:25 AM
IPAddress       : {192.168.10.40}

HostName        : WIN2K01.acmelabs.com
OperatingSystem : Windows Server 2012 Standard
ServicePack     : 
Version         : 6.2 (9200)
DN              : CN=WIN2K01,CN=Computers,DC=acmelabs,DC=com
Created         : 1/14/2013 4:31:58 PM
LastModified    : 8/25/2013 5:28:07 PM
IPAddress       : {192.168.10.2}

HostName        : win2k301.acmelabs.com
OperatingSystem : Windows Server 2003
ServicePack     : Service Pack 2
Version         : 5.2 (3790)
DN              : CN=WIN2K301,CN=Computers,DC=acmelabs,DC=com
Created         : 1/18/2013 12:51:59 PM
LastModified    : 8/15/2013 8:39:43 PM
IPAddress       : {192.168.10.50}
#>
function Get-AuditDSComputerAccount
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000 .")]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
        HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]$SearchScope = "Subtree",

        [Parameter(Mandatory=$false,
        HelpMessage="Distinguished Name Path to limit search to.")]

        [string]$SearchDN
    )
    Begin
    {
        if ($DomainController -and $Credential.GetNetworkCredential().Password)
        {
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)", $Credential.UserName,$Credential.GetNetworkCredential().Password
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
        else
        {
            $objDomain = [ADSI]""  
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
    }

    Process
    {
        $CompFilter = "(&(objectCategory=Computer))"
        $ObjSearcher.PageSize = $Limit
        $ObjSearcher.Filter = $CompFilter
        $ObjSearcher.SearchScope = "Subtree"

        if ($SearchDN)
        {
            $objSearcher.SearchDN = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($SearchDN)")
        }

        $ObjSearcher.FindAll() | ForEach-Object {
            $CompProps = [ordered]@{}
            $CompProps.Add('HostName', "$($_.properties.dnshostname)")
            $CompProps.Add('OperatingSystem', "$($_.properties.operatingsystem)")
            $CompProps.Add('ServicePack', "$($_.properties.operatingsystemservicepack)")
            $CompProps.Add('Version', "$($_.properties.operatingsystemversion)")
            $CompProps.Add('DN', "$($_.properties.distinguishedname)")
            $CompProps.Add('Created', [datetime]"$($_.properties.whencreated)")
            $CompProps.Add('LastModified', [datetime]"$($_.properties.whenchanged)")
            $CompProps.Add('IPAddress',([System.Net.Dns]::GetHostAddresses("$($_.properties.dnshostname)")))

            [pscustomobject]$CompProps
         }
        
    }

    End
    {

    }
}


<#
.Synopsis
   Gets a list of Domain users and their details using ADSI.
.DESCRIPTION
   Gets a list of Domain users and their details using ADSI. If the machine it is ran from is
   in the domain and no Domain Controller is specified it will run with the privelages of the user. 
   Support the use of alternate user credentials when ran against a domain controller.
.EXAMPLE
   Get-AuditDSUserAcount -Credential (Get-Credential) -DomainController 192.168.10.10
cmdlet Get-Credential at command pipeline position 1
Supply values for the following parameters:


SAMAccount      : Administrator
Description     : Built-in account for administering the computer/domain
UserPrincipal   : Administrator@acmelabs.com
DN              : CN=Administrator,CN=Users,DC=acmelabs,DC=com
Created         : 1/12/2013 2:06:53 AM
LastModified    : 9/10/2013 4:00:28 AM
PasswordLastSet : 8/20/2013 2:13:07 PM
AccountExpires  : <Never>
LastLogon       : 9/14/2013 2:47:43 PM
GroupMembership : CN=Organization Management,OU=Microsoft Exchange Security Groups,DC=acmelabs,DC=com CN=Group Policy Creator Owners,CN=Users,DC=acmelabs,DC=com 
                  CN=Domain Admins,CN=Users,DC=acmelabs,DC=com CN=Enterprise Admins,CN=Users,DC=acmelabs,DC=com CN=Schema Admins,CN=Users,DC=acmelabs,DC=com 
                  CN=Administrators,CN=Builtin,DC=acmelabs,DC=com
SID             : S-1-5-21-3435989536-2782530369-1314837659-500

SAMAccount      : Guest
Description     : Built-in account for guest access to the computer/domain
UserPrincipal   : 
DN              : CN=Guest,CN=Users,DC=acmelabs,DC=com
Created         : 1/12/2013 2:06:53 AM
LastModified    : 1/12/2013 2:06:53 AM
PasswordLastSet : 12/31/1600 8:00:00 PM
AccountExpires  : <Never>
LastLogon       : 12/31/1600 8:00:00 PM
GroupMembership : CN=Guests,CN=Builtin,DC=acmelabs,DC=com
SID             : S-1-5-21-3435989536-2782530369-1314837659-501

SAMAccount      : krbtgt
Description     : Key Distribution Center Service Account
UserPrincipal   : 
DN              : CN=krbtgt,CN=Users,DC=acmelabs,DC=com
Created         : 1/12/2013 2:08:47 AM
LastModified    : 3/20/2013 4:38:18 PM
PasswordLastSet : 1/11/2013 10:08:47 PM
AccountExpires  : <Never>
LastLogon       : 12/31/1600 8:00:00 PM
GroupMembership : CN=Denied RODC Password Replication Group,CN=Users,DC=acmelabs,DC=com
SID             : S-1-5-21-3435989536-2782530369-1314837659-502

SAMAccount      : cperez
Description     : 
UserPrincipal   : cperez@acmelabs.com
DN              : CN=carlos Perez,CN=Users,DC=acmelabs,DC=com
Created         : 1/13/2013 9:32:18 PM
LastModified    : 7/3/2013 1:34:00 AM
PasswordLastSet : 1/13/2013 5:32:18 PM
AccountExpires  : <Never>
LastLogon       : 6/26/2013 7:24:53 PM
GroupMembership : 
SID             : S-1-5-21-3435989536-2782530369-1314837659-1604
#>
function Get-AuditDSUserAcount
{
    [CmdletBinding(DefaultParametersetName="Default")]
    Param(
        [Parameter(ParameterSetName='Modified')]
        [Parameter(ParameterSetName='Created')]
        [Parameter(ParameterSetName='Default')]
        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(ParameterSetName='Modified')]
        [Parameter(ParameterSetName='Created')]
        [Parameter(ParameterSetName='Default')]
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(ParameterSetName='Modified')]
        [Parameter(ParameterSetName='Created')]
        [Parameter(ParameterSetName='Default')]
        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000 .")]
        [int]$Limit = 1000,

        [Parameter(ParameterSetName='Modified')]
        [Parameter(ParameterSetName='Created')]
        [Parameter(ParameterSetName='Default')]
        [Parameter(Mandatory=$false,
        HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]$SearchScope = "Subtree",

        [Parameter(ParameterSetName='Modified')]
        [Parameter(ParameterSetName='Created')]
        [Parameter(ParameterSetName='Default')]
        [Parameter(Mandatory=$false,
        HelpMessage="Distinguished Name Path to limit search to.")]
        [string]$SearchDN,

        [Parameter(ParameterSetName='Modified',
        HelpMessage="Date to search for users mofied on or after this date.")]
        [datetime]$ModifiedAfter,

        [Parameter(ParameterSetName='Modified',
        HelpMessage="Date to search for users mofied on or before this date.")]
        [datetime]$ModifiedBefore,

        [Parameter(ParameterSetName='Created',
        HelpMessage="Date to search for users created on or after this date.")]
        [datetime]$CreatedAfter,

        [Parameter(ParameterSetName='Created',
        HelpMessage="Date to search for users created on or after this date.")]
        [datetime]$CreatedBefore
    )

    Begin
    {
        if ($DomainController -and $Credential.GetNetworkCredential().Password)
        {
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)", $Credential.UserName,$Credential.GetNetworkCredential().Password
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
        else
        {
            $objDomain = [ADSI]""  
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
    }

    Process
    {
        $SAMAccountFilter = "(sAMAccountType=805306368)"

        # Filter for modification time
        if ($ModifiedAfter -and $ModifiedBefore)
        {
            $SAMAccountFilter = "(&$($SAMAccountFilter)(whenChanged>=$($ModifiedAfter.ToString("yyyyMMddhhmmss.sZ")))(whenChanged<=$($ModifiedBefore.ToString("yyyyMMddhhmmss.sZ"))))"
        }
        elseif ($ModifiedAfter)
        {
            $SAMAccountFilter = "(&$($SAMAccountFilter)(whenChanged>=$($ModifiedAfter.ToString("yyyyMMddhhmmss.sZ"))))"
        }
        elseif ($ModifiedBefore)
        {
            $SAMAccountFilter = "(&$($SAMAccountFilter)(whenChanged<=$($ModifiedBefore.ToString("yyyyMMddhhmmss.sZ"))))"
        }

        # Fileter for creation time
        if ($CreatedAfter -and $CreatedBefore)
        {
            $SAMAccountFilter = "(&$($SAMAccountFilter)(whenChanged>=$($CreatedAfter.ToString("yyyyMMddhhmmss.sZ")))(whenChanged<=$($CreatedBefore.ToString("yyyyMMddhhmmss.sZ"))))"
        }
        elseif ($CreatedAfter)
        {
            $SAMAccountFilter = "(&$($SAMAccountFilter)(whenChanged>=$($CreatedAfter.ToString("yyyyMMddhhmmss.sZ"))))"
        }
        elseif ($CreatedBefore)
        {
            $SAMAccountFilter = "(&$($SAMAccountFilter)(whenChanged<=$($CreatedBefore.ToString("yyyyMMddhhmmss.sZ"))))"
        }
        
        # Search parameters
        $ObjSearcher.PageSize = $Limit
        $ObjSearcher.Filter = $SAMAccountFilter
        $ObjSearcher.SearchScope = $SearchScope

        if ($SearchDN)
        {
            $objSearcher.SearchDN = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($SearchDN)")
        }

        $ObjSearcher.FindAll() | ForEach-Object {
            $UserProps = [ordered]@{}
            $UserProps.Add('SAMAccount', "$($_.properties.samaccountname)")
            $UserProps.Add('Description', "$($_.properties.description)")
            $UserProps.Add('UserPrincipal', "$($_.properties.userprincipalname)")
            $UserProps.Add('DN', "$($_.properties.distinguishedname)")
            $UserProps.Add('Created', [dateTime]"$($_.properties.whencreated)")
            $UserProps.Add('LastModified', [dateTime]"$($_.properties.whenchanged)")
            $UserProps.Add('PasswordLastSet', [dateTime]::FromFileTime("$($_.properties.pwdlastset)"))
            $UserProps.Add('AccountExpires',( &{$exval = "$($_.properties.accountexpires)"
                If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                {
                    $AcctExpires = "<Never>"
                }
                Else
                {
                    $Date = [DateTime]$exval
                    $AcctExpires = $Date.AddYears(1600).ToLocalTime()
                }
                $AcctExpires
            
            }))
            $UserProps.Add('LastLogon', [dateTime]::FromFileTime("$($_.properties.lastlogon)"))
            $UserProps.Add('GroupMembership', "$($_.properties.memberof)")
            $UserProps.Add('SID', "$(&{$sidobj = [byte[]]"$($_.Properties.objectsid)".split(" ");$sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; $sid.Value})")
	    $UserProps.Add('PropertyNames', "$($_.properties.PropertyNames)")
	    
            [pscustomobject]$UserProps
            }
    }
}



<#
.Synopsis
   Gets a list of Domain users and their details using ADSI.
.DESCRIPTION
   Gets a list of Domain users and their details using ADSI. If the machine it is ran from is
   in the domain and no Domain Controller is specified it will run with the privelages of the user. 
   Support the use of alternate user credentials when ran against a domain controller.
.EXAMPLE
   Get-AuditDSLockedUserAcount -DomainController 192.168.10.10 -Credential (Get-Credential)
cmdlet Get-Credential at command pipeline position 1
Supply values for the following parameters:

SAMAccount      : lockeduser
Description     : 
UserPrincipal   : lockeduser@acmelabs.com
DN              : CN=lockeduser,CN=Users,DC=acmelabs,DC=com
Created         : 6/27/2013 8:23:20 PM
LastModified    : 9/15/2013 12:40:13 AM
PasswordLastSet : 6/27/2013 4:23:20 PM
AccountExpires  : <Never>
LastLogon       : 12/31/1600 8:00:00 PM
GroupMembership : 
SID             : S-1-5-21-3435989536-2782530369-1314837659-1614

#>
function Get-AuditDSLockedUserAcount
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000 .")]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
        HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]$SearchScope = "Subtree",

        [Parameter(Mandatory=$false,
        HelpMessage="Distinguished Name Path to limit search to.")]
        [string]$SearchDN
    )

    Begin
    {
        if ($DomainController -and $Credential.GetNetworkCredential().Password)
        {
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)", $Credential.UserName,$Credential.GetNetworkCredential().Password
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
        else
        {
            $objDomain = [ADSI]""  
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
    }

    Process
    {
        $SAMAccountFilter = "(&(sAMAccountType=805306368)(lockoutTime>=1))"
        $ObjSearcher.PageSize = $Limit
        $ObjSearcher.Filter = $SAMAccountFilter
        $ObjSearcher.SearchScope = $SearchScope

        if ($SearchDN)
        {
            $objSearcher.SearchDN = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($SearchDN)")
        }

        $ObjSearcher.FindAll() | ForEach-Object {
            $UserProps = [ordered]@{}
            $UserProps.Add('SAMAccount', "$($_.properties.samaccountname)")
            $UserProps.Add('Description', "$($_.properties.description)")
            $UserProps.Add('UserPrincipal', "$($_.properties.userprincipalname)")
            $UserProps.Add('DN', "$($_.properties.distinguishedname)")
            $UserProps.Add('Created', [dateTime]"$($_.properties.whencreated)")
            $UserProps.Add('LastModified', [dateTime]"$($_.properties.whenchanged)")
            $UserProps.Add('PasswordLastSet', [dateTime]::FromFileTime("$($_.properties.pwdlastset)"))
            $UserProps.Add('AccountExpires',( &{$exval = "$($_.properties.accountexpires)"
                If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                {
                    $AcctExpires = "<Never>"
                }
                Else
                {
                    $Date = [DateTime]$exval
                    $AcctExpires = $Date.AddYears(1600).ToLocalTime()
                }
                $AcctExpires
            
            }))
            $UserProps.Add('LastLogon', [dateTime]::FromFileTime("$($_.properties.lastlogon)"))
            $UserProps.Add('GroupMembership', "$($_.properties.memberof)")
            $UserProps.Add('SID', "$(&{$sidobj = [byte[]]"$($_.Properties.objectsid)".split(" ");$sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; $sid.Value})")

            [pscustomobject]$UserProps
            }
    }
}


function Get-AuditDSDisabledUserAcount
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000 .")]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
        HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]$SearchScope = "Subtree",

        [Parameter(Mandatory=$false,
        HelpMessage="Distinguished Name Path to limit search to.")]
        [string]$SearchDN
    )

    Begin
    {
        if ($DomainController -and $Credential.GetNetworkCredential().Password)
        {
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)", $Credential.UserName,$Credential.GetNetworkCredential().Password
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
        else
        {
            $objDomain = [ADSI]""  
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
    }

    Process
    {
        $SAMAccountFilter = "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=2))"
        $ObjSearcher.PageSize = $Limit
        $ObjSearcher.Filter = $SAMAccountFilter
        $ObjSearcher.SearchScope = $SearchScope

        if ($SearchDN)
        {
            $objSearcher.SearchDN = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($SearchDN)")
        }

        $ObjSearcher.FindAll() | ForEach-Object {
            $UserProps = [ordered]@{}
            $UserProps.Add('SAMAccount', "$($_.properties.samaccountname)")
            $UserProps.Add('Description', "$($_.properties.description)")
            $UserProps.Add('UserPrincipal', "$($_.properties.userprincipalname)")
            $UserProps.Add('DN', "$($_.properties.distinguishedname)")
            $UserProps.Add('Created', [dateTime]"$($_.properties.whencreated)")
            $UserProps.Add('LastModified', [dateTime]"$($_.properties.whenchanged)")
            $UserProps.Add('PasswordLastSet', [dateTime]::FromFileTime("$($_.properties.pwdlastset)"))
            $UserProps.Add('AccountExpires',( &{$exval = "$($_.properties.accountexpires)"
                If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                {
                    $AcctExpires = "<Never>"
                }
                Else
                {
                    $Date = [DateTime]$exval
                    $AcctExpires = $Date.AddYears(1600).ToLocalTime()
                }
                $AcctExpires
            
            }))
            $UserProps.Add('LastLogon', [dateTime]::FromFileTime("$($_.properties.lastlogon)"))
            $UserProps.Add('GroupMembership', "$($_.properties.memberof)")
            $UserProps.Add('SID', "$(&{$sidobj = [byte[]]"$($_.Properties.objectsid)".split(" ");$sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; $sid.Value})")

            [pscustomobject]$UserProps
            }
    }
}


function Get-AuditDSDeletedAccount
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000 .")]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
        HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]$SearchScope = "Subtree",

        [Parameter(Mandatory=$false,
        HelpMessage="Distinguished Name Path to limit search to.")]
        [string]$SearchDN
    )

    Begin
    {
        if ($DomainController -and $Credential.GetNetworkCredential().Password)
        {
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)", $Credential.UserName,$Credential.GetNetworkCredential().Password
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
        else
        {
            $objDomain = [ADSI]""  
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
    }

    Process
    {
        $SAMAccountFilter = "(&(objectClass=user)(isDeleted=*))"
        $ObjSearcher.PageSize = $Limit
        $ObjSearcher.Filter = $SAMAccountFilter
        $ObjSearcher.SearchScope = $SearchScope
        $objSearcher.Tombstone = $true

        if ($SearchDN)
        {
            $objSearcher.SearchDN = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($SearchDN)")
        }

        $ObjSearcher.FindAll() | ForEach-Object {
            $UserProps = [ordered]@{}
            $UserProps.Add('SAMAccount', "$($_.properties.samaccountname)")

            $UserProps.Add('DN', "$($_.properties.distinguishedname)")
            $UserProps.Add('Created', [dateTime]"$($_.properties.whencreated)")
            $UserProps.Add('LastModified', [dateTime]"$($_.properties.whenchanged)")
            $UserProps.Add('PasswordLastSet', [dateTime]::FromFileTime("$($_.properties.pwdlastset)"))
            $UserProps.Add('LastLogon', [dateTime]::FromFileTime("$($_.properties.lastlogon)"))
            $UserProps.Add('SID', "$(&{$sidobj = [byte[]]"$($_.Properties.objectsid)".split(" ");$sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; $sid.Value})")
            $UserProps.Add('LastKnownParent', "$($_.properties.lastknownparent)")
            [pscustomobject]$UserProps
            }
    }
}


function Get-AuditInstallSoftware
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [string]$ComputerName = $env:COMPUTERNAME
    )
    begin
    {
        
    }
    Process
    {
        # Set initial values
        $reg = Get-WmiObject -List "StdRegprov" -ComputerName $computername -Credential $Credential
        $x86SoftInstallKey = "Software\Microsoft\Windows\CurrentVersion\Uninstall"
        $x64SoftInstallkey = "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        $data = $reg.EnumKey(2147483650,$x86SoftInstallKey)
        if ($data.ReturnValue -eq 0)
        {
            $x86keys = $data.snames
            $HKSoftKeys = $reg.EnumKey(2147483650,"SOFTWARE").snames
            if ($HKSoftKeys -contains "Wow6432Node")
            {
                $x64keys = $reg.EnumKey(2147483650,$x64SoftInstallkey).snames
            }
        }
        else
        {
            Write-Error "Failed to connect to remote server vial WMI to pull registry information"
            return
        }
        
        $x86keys | foreach {
            $sName = ($reg.GetStringValue(2147483650, "$x86SoftInstallKey\$($_)", 'DisplayName')).svalue 
            if ($sName)
            {
                $sVersion = ($reg.GetStringValue(2147483650, "$x86SoftInstallKey\$($_)", 'DisplayVersion')).svalue 
                $sInstallDate = ($reg.GetStringValue(2147483650, "$x86SoftInstallKey\$($_)", 'InstallDate')).svalue 
                $sPublisher = ($reg.GetStringValue(2147483650, "$x86SoftInstallKey\$($_)", 'Publisher')).svalue 
                $SoftProps = [ordered]@{Name = $sName; Version = $sVersion; Publisher = $sPublisher; InstallDate = $sInstallDate; PSComputerName = $ComputerName}
                [pscustomobject]$SoftProps
            }
        }

        if ($x64keys)
        {
            $x64keys | foreach {   
                $sName = ($reg.GetStringValue(2147483650, "$x64SoftInstallkey\$($_)", 'DisplayName')).svalue 
                if ($sName)
                {
                    $sVersion = ($reg.GetStringValue(2147483650, "$x64SoftInstallkey\$($_)", 'DisplayVersion')).svalue 
                    $sInstallDate = ($reg.GetStringValue(2147483650, "$x64SoftInstallkey\$($_)", 'InstallDate')).svalue 
                    $sPublisher = ($reg.GetStringValue(2147483650, "$x64SoftInstallkey\$($_)", 'Publisher')).svalue 
                    $SoftProps = [ordered]@{Name = $sName; Version = $sVersion; Publisher = $sPublisher; InstallDate = $sInstallDate; PSComputerName = $ComputerName}
                    [pscustomobject]$SoftProps
                }
            }
        }
    }
    End
    {
    }
}


function Get-AuditPrefechList
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [string]$ComputerName = $env:COMPUTERNAME
    )
    $winInfo = (Get-WmiObject -query "SELECT WindowsDirectory from Win32_OperatingSystem"  -ComputerName $ComputerName -Credential $Credential).WindowsDirectory.split("\")
    if ($winInfo)
    {
        $pfquery = "SELECT Caption,CreationDate,LastAccessed,LastModified FROM CIM_DataFile WHERE Drive = '$($winInfo[0])' and Path = '\\$($winInfo[1])\\prefetch\\' AND Extension = 'pf'"
        if ($pfquery)
        {
            Get-WmiObject -Query $pfquery  -ComputerName $ComputerName -Credential $Credential | ForEach-Object {
                $pfprops = [ordered]@{
                    Filename = $_.Caption
                    CreationDate = $_.ConvertToDateTime($_.CreationDate)
                    LastAccessed = $_.ConvertToDateTime($_.LastAccessed)
                    LastModified = $_.ConvertToDateTime($_.LastModified)
                }
                [pscustomobject]$pfprops
            }
        }
        else
        {
            Write-Warning "Could not find pf files in the prefetch folder."
        }
    }
    else
    {
        Write-Warning "Could not connect to WMI on the remote system."
    }
}


<#
    .SYSNOPSIS
        Retrieves the timestamps for a given file.

    .DESCRIPTION
        Retrieves the timestamps for a given file. This not only shows the LastAccess, LastWrite and Creation timestamps, 
        but also shows the Entrie Modified timestamp, which is not viewable just by looking at the properties of a file.

    .PARAMETER File
        Name of the file to get timestamps from.

    .NOTES
        Name: Get-AuditFileTimeStamp
        Author: Boe Prox
        DateCreated: 26 Feb 2013
        DateModified: 26 Feb 2013
        Version: 1.0 - Initial Creation

    .LINK
        http://learn-powershell.net

    .INPUTS
        System.String

    .OUPUTS
        None

    .EXAMPLE
        Get-AuditFileTimeStamp -File 'SystemError.txt'
        CreationDate   : 2/13/2013 7:56:13 AM
        EntrieModifiedTime     : 2/26/2013 8:49:28 AM
        ModifiedTime  : 2/13/2013 7:56:13 AM
        AccessTime : 2/26/2013 8:48:00 AM
        FileName       : C:\users\Administrator\desktop\SystemError.txt


        Description
        -----------
        Displays all timestamps for the file SystemError.txt


#>
Function Get-AuditFileTimeStamp 
{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline = $True)]
        [string[]]$File 
    )
    Begin {
        #region Debug Information
        $PSBoundParameters.GetEnumerator() | ForEach {
            Write-Verbose ("{0}" -f $_)
        }
        Write-Verbose ("Using ParameterSetName: {0}" -f $PSCmdlet.ParameterSetName)
        #endregion Debug Information


        #region Create reference variables
        $creationTime = (Get-Date)
        $lastAccessTime = (Get-Date)
        $lastWriteTime = (Get-Date)
        $changeTime = (Get-Date)
        $errorMsg = $null
        #endregion Create reference variables
    }
    Process {
        #region Check file name
        ForEach ($item in $File) {
            If (-Not ([uri]$item).IsAbsoluteUri) {
                Write-Verbose ("{0} is not a full path, using current directory: {1}" -f $item,$pwd)
                $item = (Join-Path $pwd ($item -replace "\.\\",""))
            }
            #endregion Check file name

            #region Get file timestamps
            $return = [NT]::GetFourFileTimes($item,
                                  [ref]$creationTime,
                                  [ref]$lastAccessTime,
                                  [ref]$lastWriteTime,
                                  [ref]$changeTime,
                                  [ref]$errorMsg
                                  )
            If ($return) {
                If (-Not $errorMsg) {
                    $object = New-Object PSObject -Property @{
                        FileName = $item
                        CreationDate = $creationTime
                        ModifiedTime = $lastWriteTime
                        AccessTime = $lastAccessTime 
                        EntrieModifiedTime = $changeTime
                    }
                    $object.pstypenames.insert(0,'System.File.TimeStamp')
                    Write-Output $object
                } Else {
                    Write-Warning ("{0}" -f $errorMsg)
                }
            } Else {
                Write-Warning ("An issue occurred querying the timestamp!")
            }
        }
        #endregion Get file timestamps
    }
    End {}
}


 <#
	.SYNOPSIS
	Retrieves the last write time of the supplied registry key

	.DESCRIPTION
	The Registry data that a hive stores in containers are called cells. A cell 
	can hold a key, a value, a security descriptor, a list of subkeys, or a 
	list of key values.

	Get-RegKeyLastWriteTime retrieves the LastWriteTime through a pointer to the
	FILETIME structure that receives the time at which the enumerated subkey was
	last written. Values do not contain a LastWriteTime property, but changes to
	child values update the parent keys lpftLastWriteTime.
	
	The LastWriteTime is updated when a key is created, modified, accessed, or
	deleted.

	.PARAMETER ComputerName
	Computer name to query

	.PARAMETER Key
	Root Key to query

	HKCR - Symbolic link to HKEY_LOCAL_MACHINE \SOFTWARE \Classes.
	HKCU - Symbolic link to a key under HKEY_USERS representing a user's profile
	hive.
	HKLM - Placeholder with no corresponding physical hive. This key contains
	other keys that are hives.
	HKU  - Placeholder that contains the user-profile hives of logged-on
	accounts.
	HKCC - Symbolic link to the key of the current hardware profile

	.PARAMETER SubKey
	Registry Key to query

	.EXAMPLE
	Get-AuditRegKeyLastWriteTime -ComputerName testwks -Key HKLM -SubKey Software

        .EXAMPLE
	Get-AuditRegKeyLastWriteTime -ComputerName testwks1,testwks2 -SubKey Software

	.EXAMPLE
	Get-AuditRegKeyLastWriteTime -SubKey Software\Microsoft

	.EXAMPLE
	"testwks1","testwks2" | Get-RegKeyLastWriteTime -SubKey Software\Microsoft `
	\Windows\CurrentVersion

	.NOTES
	NAME: Get-RegKeyLastWriteTime
	AUTHOR: Shaun Hess
	VERSION: 1.0
	LASTEDIT: 01JUL2011
	LICENSE: Creative Commons Attribution 3.0 Unported License
	(http://creativecommons.org/licenses/by/3.0/)

	.LINK
	http://www.shaunhess.com
	#>   
function Get-AuditRegKeyLastWriteTime 
{            
    [CmdletBinding()]            
            
    param(            
        [parameter(            
        ValueFromPipeline=$true,            
        ValueFromPipelineByPropertyName=$true)]            
        [Alias("CN","__SERVER","Computer","CNAME")]            
        [string[]]$ComputerName=$env:ComputerName,            
        [string]$Key = "HKLM",            
        [string]$SubKey            
    )            
            
    BEGIN
    {            
        switch ($Key) {            
           "HKCR" { $searchKey = 0x80000000} #HK Classes Root            
           "HKCU" { $searchKey = 0x80000001} #HK Current User            
           "HKLM" { $searchKey = 0x80000002} #HK Local Machine            
           "HKU"  { $searchKey = 0x80000003} #HK Users            
           "HKCC" { $searchKey = 0x80000005} #HK Current Config            
           default {            
           "Invalid Key. Use one of the following options:
			        HKCR, HKCU, HKLM, HKU, HKCC"}            
        }            
            
        $KEYQUERYVALUE = 0x1            
        $KEYREAD = 0x19            
        $KEYALLACCESS = 0x3F            
    }            
    PROCESS 
    {            
        foreach($computer in $ComputerName) {            
              
        $sig0 = @'
[DllImport("advapi32.dll", SetLastError = true)]
  public static extern int RegConnectRegistry(
  	string lpMachineName,
	int hkey,
	ref int phkResult);
'@            
        $type0 = Add-Type -MemberDefinition $sig0 -Name Win32Utils -Namespace RegConnectRegistry -Using System.Text -PassThru            
            
        $sig1 = @'
[DllImport("advapi32.dll", CharSet = CharSet.Auto)]
  public static extern int RegOpenKeyEx(
    int hKey,
    string subKey,
    int ulOptions,
    int samDesired,
    out int hkResult);
'@            
        $type1 = Add-Type -MemberDefinition $sig1 -Name Win32Utils -Namespace RegOpenKeyEx -Using System.Text -PassThru            
            
        $sig2 = @'
[DllImport("advapi32.dll", EntryPoint = "RegEnumKeyEx")]
extern public static int RegEnumKeyEx(
    int hkey,
    int index,
    StringBuilder lpName,
    ref int lpcbName,
    int reserved,
    int lpClass,
    int lpcbClass,
    out long lpftLastWriteTime);
'@            
        $type2 = Add-Type -MemberDefinition $sig2 -Name Win32Utils -Namespace RegEnumKeyEx -Using System.Text -PassThru            
            
        $sig3 = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern int RegCloseKey(
    int hKey);
'@            
        $type3 = Add-Type -MemberDefinition $sig3 -Name Win32Utils -Namespace RegCloseKey -Using System.Text -PassThru            
            
            
          $hKey = new-object int            
          $hKeyref = new-object int            
          $searchKeyRemote = $type0::RegConnectRegistry($computer, $searchKey, `  [ref]$hKey)            
          $result = $type1::RegOpenKeyEx($hKey, $SubKey, 0, $KEYREAD, `  [ref]$hKeyref)            
            
          #initialize variables            
          $builder = New-Object System.Text.StringBuilder 1024            
          $index = 0            
          $length = [int] 1024            
          $time = New-Object Long            
            
          #234 means more info, 0 means success. Either way, keep reading            
          while ( 0,234 -contains $type2::RegEnumKeyEx($hKeyref, $index++, $builder, [ref] $length, $null, $null, $null, [ref] $time) )            
          {            
            #create output object            
            $o = "" | Select Key, LastWriteTime, ComputerName             
            $o.ComputerName = "$computer"             
            $o.Key = $builder.ToString()            
            # TODO Change to use the time api            
            $o.LastWriteTime = (Get-Date $time).AddYears(1600).AddHours(-4)            
            $o            
            
            #reinitialize for next time through the loop            
            $length = [int] 1024            
            $builder = New-Object System.Text.StringBuilder 1024            
          }            
            
         $result = $type3::RegCloseKey($hKey);            
         }            
     }            
} 

