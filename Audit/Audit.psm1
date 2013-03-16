<#
.Synopsis
   Enumerates Logged On Sessions on a give host.
.DESCRIPTION
   Enumerates Logged On Sessions on a give host using WMI.
.EXAMPLE
   Get-LogedOnSessions | where {$_.processes.count -gt 0}

   Retrieves sessions that have running processes.

#>

function Get-LogedOnSessions {
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