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


function Get-AuditDSComputerAccount
{
    Param(
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [string]$DomainController,

        [int]$Limit = 1000
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
        $ObjSearcher.FindAll() | ForEach-Object {
            $CompProps = [ordered]@{}
            $CompProps.Add('HostName', "$($_.properties.dnshostname)")
            $CompProps.Add('OperatingSystem', "$($_.properties.operatingsystem)")
            $CompProps.Add('ServicePack', "$($_.properties.operatingsystemservicepack)")
            $CompProps.Add('Version', "$($_.properties.operatingsystemversion)")
            $CompProps.Add('DN', "$($_.properties.distinguishedname)")
            $CompProps.Add('Created', [datetime]"$($_.properties.whencreated)")
            $CompProps.Add('LastModified', [datetime]"$($_.properties.whenchanged)")
            $CompProps.Add('IPAddress',[System.Net.Dns]::GetHostAddresses("$($_.properties.dnshostname)"))

            [pscustomobject]$CompProps
            }
        
    }

    End
    {

    }
}


function Get-AuditDSUserAcount
{
    Param(
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [string]$DomainController,

        [int]$Limit = 1000
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
        $ObjSearcher.PageSize = $Limit
        $ObjSearcher.Filter = $SAMAccountFilter
        $ObjSearcher.SearchScope = "Subtree"
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


function Get-AuditDSLockedUserAcount
{
    Param(
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [string]$DomainController,

        [int]$Limit = 1000
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
        $ObjSearcher.SearchScope = "Subtree"
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
    Param(
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [string]$DomainController,

        [int]$Limit = 1000
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
        $ObjSearcher.SearchScope = "Subtree"
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
    $pfquery = "SELECT Caption,CreationDate,LastAccessed,LastModified FROM CIM_DataFile WHERE Drive = '$($winInfo[0])' and Path = '\\$($winInfo[1])\\prefetch\\' AND Extension = 'pf'"
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

