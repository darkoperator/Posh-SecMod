<#
.Synopsis
   Enumerates the keys that are under a given Registry Key.
.DESCRIPTION
   Enumerates the keys that are under a given Registry Key.
.EXAMPLE
   Listing all of the keys under HKCU\Software key
   PS C:\> Get-RegKeys -Hive HKCU -Key software

    Key                                                                  FullPath                                                            
    ---                                                                  --------                                                            
    7-Zip                                                                HKCU\software\7-Zip                                                 
    AppDataLow                                                           HKCU\software\AppDataLow                                            
    Macromedia                                                           HKCU\software\Macromedia                                            
    Microsoft                                                            HKCU\software\Microsoft                                             
    Microsoft Corporation                                                HKCU\software\Microsoft Corporation                                 
    Mine                                                                 HKCU\software\Mine                                                  
    Policies                                                             HKCU\software\Policies                                              
    RegisteredApplications                                               HKCU\software\RegisteredApplications                                
    ThinPrint                                                            HKCU\software\ThinPrint                                             
    VMware, Inc.                                                         HKCU\software\VMware, Inc.                                          
    Wow6432Node                                                          HKCU\software\Wow6432Node                                           
    Classes                                                              HKCU\software\Classes   
#>
function Get-RegKeys
{
    [CmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]
        [Validateset(“HKCR”, “HKCU”, “HKLM”, "HKUS", "HKCC")]
        $Hive,

        [parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Key,
 
        [parameter(ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Computername="$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Begin
    {
        $reg = Get-WmiObject -List "StdRegprov" -ComputerName $computername -Credential $Credential
    }
    Process
    {
        # We get the correct value associated with the key.
        switch ($hive) 
        {
            "HKCR" {$reg_hive = 2147483648}
            "HKCU" {$reg_hive = 2147483649}
            "HKLM" {$reg_hive = 2147483650}
            "HKUS" {$reg_hive = 2147483651}
            "HKCC" {$reg_hive = 2147483653}
        }

        $data = $reg.EnumKey($reg_hive, $key)
        if ($data.ReturnValue -eq 0)
        {
            $keynum = ($data.snames).Length
            if ($keynum -gt 0) 
            {
                foreach($keyname in $data.snames)
                {
                    New-Object PSObject -Property @{Key=$keyname;FullPath = "$hive\$key\$keyname"}
                } 
            }
            else
            {
                Write-Verbose "Key $key does not have any keys to enumerate"
            }
        }
        elseif ($data.ReturnValue -eq 2)
        {
            Write-Error "Key $key does not exist"
        }
        else
        {
            Write-Error "Error when enumerating keys: $($data.ReturnValue)"
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Creates a registry key under a given Registry Key.
.DESCRIPTION
   Creates a registry key under a given Registry Key.
.EXAMPLE
   Create a key named _deleteme under the registry HKCU key.
   PS C:\> New-RegKey -Hive HKCU -Key _deleteme -Verbose
   VERBOSE: Key HKCU\_deleteme was created.
#>
function New-RegKey
{
    [CmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]
        [Validateset(“HKCR”, “HKCU”, “HKLM”, "HKUS", "HKCC")]
        $Hive,

        [parameter(Mandatory=$true)]
        [string]$Key,
 
        [parameter(ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Computername="$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Begin
    {
        $reg = Get-WmiObject -List "StdRegprov" -ComputerName $computername -Credential $Credential
    }
    Process
    {
        # We get the correct value associated with the key.
        switch ($hive) 
        {
            "HKCR" {$reg_hive = 2147483648}
            "HKCU" {$reg_hive = 2147483649}
            "HKLM" {$reg_hive = 2147483650}
            "HKUS" {$reg_hive = 2147483651}
            "HKCC" {$reg_hive = 2147483653}
        }

        $data = $reg.CreateKey($reg_hive, $key)
        if ($data.ReturnValue -eq 0)
        {
            Write-Verbose "Key $hive\$key was created."
        }
        elseif ($data.ReturnValue -eq 2)
        {
            Write-Error "Key $key does not exist"
        }
        else
        {
            Write-Error "Error when creating key: $($data.ReturnValue)"
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Removes a registry key under a given Registry Key.
.DESCRIPTION
   Removes a registry key under a given Registry Key.
.EXAMPLE
   Remove a key named _deleteme under the registry HKCU key.
   PS C:\> Remove-RegKey -Hive HKCU -Key _deleteme -Verbose
   VERBOSE: Key HKCU\_deleteme was removed.
#>
function Remove-RegKey
{
    [CmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]
        [Validateset(“HKCR”, “HKCU”, “HKLM”, "HKUS", "HKCC")]
        $Hive,

        [parameter(Mandatory=$true)]
        [string]$Key,
 
        [parameter(ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Computername="$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Begin
    {
        $reg = Get-WmiObject -List "StdRegprov" -ComputerName $computername -Credential $Credential
    }
    Process
    {
        # We get the correct value associated with the key.
        switch ($hive) 
        {
            "HKCR" {$reg_hive = 2147483648}
            "HKCU" {$reg_hive = 2147483649}
            "HKLM" {$reg_hive = 2147483650}
            "HKUS" {$reg_hive = 2147483651}
            "HKCC" {$reg_hive = 2147483653}
        }

        $data = $reg.DeleteKey($reg_hive, $key)
        if ($data.ReturnValue -eq 0)
        {
            Write-Verbose "Key $hive\$key was removed."
        }
        elseif ($data.ReturnValue -eq 2)
        {
            Write-Error "Key $key does not exist"
        }
        else
        {
            Write-Error "Error when removing key: $($data.ReturnValue)"
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Enumerates the values and their type of a given Registry Key.
.DESCRIPTION
   Enumerates the values and their type of a given Registry Key.
.EXAMPLE
   Listing all of the console settings in the HKCU\Console key
   Get-RegValues -Hive HKCU -Key console
#>
function Get-RegValues
{
    [CmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]
        [Validateset(“HKCR”, “HKCU”, “HKLM”, "HKUS", "HKCC")]
        $Hive,

        [parameter(Mandatory=$true)]
        [string]$Key,
 
        [parameter(ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Computername="$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Begin
    {
        $reg = Get-WmiObject -List "StdRegprov" -ComputerName $computername -Credential $Credential
    }
    Process
    {
        # We get the correct value associated with the key.
        switch ($hive) 
        {
            "HKCR" {$reg_hive = 2147483648}
            "HKCU" {$reg_hive = 2147483649}
            "HKLM" {$reg_hive = 2147483650}
            "HKUS" {$reg_hive = 2147483651}
            "HKCC" {$reg_hive = 2147483653}
        }

        # Registry value types
        $reg_types = @{
            "1" = "REG_SZ"
            "2" = "REG_EXPAND_SZ"
            "3" = "REG_BINARY"
            "4" = "REG_DWORD"
            "7" = "REG_MULTI_SZ"
            "11" = "REG_QWORD"
        }

        $data = $reg.EnumValues($reg_hive, $key)
        if ($data.ReturnValue -eq 0)
        {
            $keynum = ($data.snames).Length
            if ($keynum -gt 0) 
            {
                for ($i=0; $i -le $keynum; $i++)
                {
                    New-Object PSObject -Property @{ValueName="$($data.snames[$i])";Type = $reg_types["$($data.types[$i])"]}
                }
            }
            else
            {
                Write-Verbose "Key $key does not have any values to enumerate"
            }
        }
        elseif ($data.ReturnValue -eq 2)
        {
            Write-Error "Key $key does not exist"
        }
        else
        {
            Write-Error "Error when enumerating values: $($data.ReturnValue)"
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Checks for specific access type on a given registry key.
.DESCRIPTION
   Checks for specific access type on a given registry key. Returns a Boolean value.
.PARAMETER AccessType
   Access Type to test against a given Registry Key

   - KEY_QUERY_VALUE		Required to query the values of a registry key.
   - KEY_SET_VALUE			Required to create, delete, or set a registry value.
   - KEY_CREATE_SUB_KEY		Required to create a subkey of a registry key.
   - KEY_ENUMERATE_SUB_KEYS	Required to enumerate the subkeys of a registry key.
   - KEY_NOTIFY				Required to request change notifications for a registry key or for subkeys of a registry key.
   - KEY_CREATE_SUB_KEY 	Required to create a registry key.
   - DELETE 				Required to delete a registry key.
   - READ_CONTROL			Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.
   - WRITE_DAC 				Required to modify the DACL in the object's security descriptor.
   - WRITE_OWNER 			Required to change the owner in the object's security descriptor.
.EXAMPLE
   PS C:\> Test-RegKeyAccess -Hive hkcu -Key software -AccessType DELETE
   True
#>
function Test-RegKeyAccess
{
    [CmdletBinding()]
  
    Param
    (
        [parameter(Mandatory=$true)]
        [string]
        [Validateset(“HKCR”, “HKCU”, “HKLM”, "HKUS", "HKCC")]
        $Hive,

        [parameter(Mandatory=$true)]
        [string]
        [Validateset(“KEY_QUERY_VALUE”, "KEY_CREATE_SUB_KEY", "KEY_ENUMERATE_SUB_KEYS", 
        "KEY_NOTIFY", "KEY_CREATE", "DELETE", "READ_CONTROL", "WRITE_DAC", "WRITE_OWNER")]
        $AccessType,

        [parameter(Mandatory=$true)]
        [string]$Key,
 
        [parameter(ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Computername="$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Begin
    {
        $reg = Get-WmiObject -List "StdRegprov" -ComputerName $computername -Credential $Credential
    }
    Process
    {
        # We get the correct value associated with the key.
        switch ($hive) 
        {
            "HKCR" {$reg_hive = 2147483648}
            "HKCU" {$reg_hive = 2147483649}
            "HKLM" {$reg_hive = 2147483650}
            "HKUS" {$reg_hive = 2147483651}
            "HKCC" {$reg_hive = 2147483653}
        }

        switch ($AccessType)
        {
            “KEY_QUERY_VALUE”        {$type2check = 1}
            "KEY_SET_VALUE"          {$type2check = 2}
            "KEY_CREATE_SUB_KEY"     {$type2check = 4}
            "KEY_ENUMERATE_SUB_KEYS" {$type2check = 8}
            "KEY_NOTIFY"             {$type2check = 16}
            "KEY_CREATE"             {$type2check = 32}
            "DELETE"                 {$type2check = 65536}
            "READ_CONTROL"           {$type2check = 131072}
            "WRITE_DAC"              {$type2check = 262144}
            "WRITE_OWNER"            {$type2check = 524288}
        }

        $data = $reg.CheckAccess($reg_hive, $key, $type2check)
        if ($data.ReturnValue -eq 0)
        {
           $data.bGranted
        }
        elseif ($data.ReturnValue -eq 2)
        {
            Write-Error "Key $key does not exist"
        }
        else
        {
            Write-Error "Error when Checking Access Type on key: $($data.ReturnValue)"
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Set a value on a given key.
.DESCRIPTION
   Set a value on a given key using WMI.
.EXAMPLE
   set a SZ value.
   PS C:\> Set-RegValue -Hive HKCU -Key _deleteme -Name stringval -Type SZ -Data "data" -Verbose
   VERBOSE: Value set on HKCU\_deletme\stringval of type SZ
.EXAMPLE
   Set a MULTISZ value.
   PS C:\> Set-RegValue -Hive HKCU -Key _deleteme -Name multistring -Type MULTISZ -Data "str1","str2","str3" -Verbose
   VERBOSE: Value set on HKCU\_deletme\multistring of type MULTISZ
.EXAMPLE
   Set a QWORD value.
   PS C:\> Set-RegValue -Hive HKCU -Key _deleteme -Name qval -Type QWORD -Data 4060 -Verbose
   VERBOSE: Value set on HKCU\_deletme\qval of type QWORD
.EXAMPLE
   Set a EXPANDSZ value.
   PS C:\> Set-RegValue -Hive HKCU -Key _deleteme -Name expanval -Type EXPANDSZ -Data "%envvar%" -Verbose
   VERBOSE: Value set on HKCU\_deletme\expanval of type EXPANDSZ
.EXAMPLE
   Set a DWORD value.
   PS C:\> Set-RegValue -Hive HKCU -Key _deleteme -Name dworval -Type DWORD -Data 10 -Verbose
   VERBOSE: Value set on HKCU\_deletme\dworval of type DWORD
.EXAMPLE
   Set a Binary value.
   PS C:\> Set-RegValue -Hive HKCU -Key _deleteme -Name binval -Type BINARY -Data @([char[]]'PowerShell') -Verbose
   VERBOSE: Value set on HKCU\_deletme\binval of type BINARY
#>
function Set-RegValue
{
    [CmdletBinding()]
    
    Param
    (
        [parameter(Mandatory=$true)]
        [Validateset(“HKCR”, “HKCU”, “HKLM”, "HKUS", "HKCC")]
        [string]$Hive,

        [parameter(Mandatory=$true)]
        [Validateset(“DWORD”, “EXPANDSZ”, “MULTISZ”, "QWORD", "SZ", "BINARY")]
        [string]$Type,

        [parameter(Mandatory=$true)]
        [string]$Key,

        [parameter(Mandatory=$true)]
        [string]$Name,

        [parameter(Mandatory=$true)]
        $Data,
 
        [parameter(ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Computername="$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Begin
    {
        $reg = Get-WmiObject -List "StdRegprov" -ComputerName $computername -Credential $Credential
        
    }
    Process
    {
        # We get the correct value associated with the key.
        switch ($hive) 
        {
            "HKCR" {$reg_hive = 2147483648}
            "HKCU" {$reg_hive = 2147483649}
            "HKLM" {$reg_hive = 2147483650}
            "HKUS" {$reg_hive = 2147483651}
            "HKCC" {$reg_hive = 2147483653}
        }

        # Set according to type
        switch ($type) 
        {
            “DWORD”     {$data = ($reg.SetDwordValue($reg_hive, $key, $Name, $Data))}
            “EXPANDSZ”  {$data = ($reg.SetExpandedStringValue($reg_hive, $key, $Name, $Data))}
            “MULTISZ”   {$data = ($reg.SetMultiStringValue($reg_hive, $key, $Name, $Data))}
            "QWORD"     {$data = ($reg.SetQwordValue($reg_hive, $key, $Name, $Data))}
            "SZ"        {$data = ($reg.SetStringValue($reg_hive, $key, $Name, $Data))}
            "BINARY"    {$data = ($reg.SetBinaryValue($reg_hive, $key, $Name, $Data))}
        }

        # process return value
        if ($data.ReturnValue -eq 0)
        {
           Write-Verbose "Value set on $hive\$key\$name of type $type"
        }
        elseif ($data.ReturnValue -eq 2)
        {
            Write-Error "Key $key does not exist"
        }
        else
        {
            Write-Error "Error when setting value on key: $($data.ReturnValue)"
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Retrives a the content of a specified value in a given key.
.DESCRIPTION
   Retrives a the content of a specified value in a given key.
.EXAMPLE
   Getting the Windows Version fromt the registry
   PS C:\> Get-RegValue -Hive HKLM -key "SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName
   Windows 8 Enterprise
.EXAMPLE
    Read registry binary data and turn it in to ASCII String
    PS C:\> $bindata = Get-RegValue -Hive HKCU -Key _deleteme -Name binval
    PS C:\> ([System.Text.Encoding]::ASCII).GetString($bindata)
    PowerShell
#>
function Get-RegValue
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        [parameter(Mandatory=$true)]
        [Validateset(“HKCR”, “HKCU”, “HKLM”, "HKUS", "HKCC")]
        [string]$Hive,

        [parameter(Mandatory=$true)]
        [string]$Key,

        [parameter(Mandatory=$true)]
        [string]$Name,
 
        [parameter(ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Computername="$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Begin
    {
        $reg = Get-WmiObject -List "StdRegprov" -ComputerName $computername -Credential $Credential
    }
    Process
    {
        # We get the correct value associated with the key.
        switch ($hive) 
        {
            "HKCR" {$reg_hive = 2147483648}
            "HKCU" {$reg_hive = 2147483649}
            "HKLM" {$reg_hive = 2147483650}
            "HKUS" {$reg_hive = 2147483651}
            "HKCC" {$reg_hive = 2147483653}
        }

        $valdata = $reg.EnumValues($reg_hive, $key)
        if ($valdata.returnvalue -eq 0) 
        {
            # check that the value actualy exists
            if ($valdata.snames -contains $Name) 
            {
                # Get value index in the array
                $index = (0..($valdata.snames.Count - 1) | Where { $valdata.snames[$_] -eq $Name })
                $type = $valdata.types[$index]
                # Get according to type
                switch ($type) 
                {
                    “4”  {$data = ($reg.GetDwordValue($reg_hive, $key, $Name)).uvalue}
                    “2”  {$data = ($reg.GetExpandedStringValue($reg_hive, $key, $Name)).svalue}
                    “7”  {$data = ($reg.GetMultiStringValue($reg_hive, $key, $Name)).svalue}
                    "11" {$data = ($reg.GetQwordValue($reg_hive, $key, $Name)).uvalue}
                    "1"  {$data = ($reg.GetStringValue($reg_hive, $key, $Name)).svalue}
                    "3"  {$data = ($reg.GetBinaryValue($reg_hive, $key, $Name)).uvalue}
                }
                $data
            }
            else
            {
                Write-Error "Value $name does not exist in key specified."
            }
        }
        elseif ($valdata.returnvalue -eq 2)
        {
            Write-Error "Key $key does not exist"
        }
        else
        {
            Write-Error "Error when retreaving value on key: $($data.ReturnValue)"
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Removes a specified value in a given key.
.DESCRIPTION
   Removes a specified value in a given key.
.EXAMPLE
   Removing a value from the registry
   PS C:\> Remove-RegValue -Hive HKCU -Key _deleteme -Name dworval -Verbose
   VERBOSE: Value dworval has been removed.
#>
function Remove-RegValue
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        [parameter(Mandatory=$true)]
        [Validateset(“HKCR”, “HKCU”, “HKLM”, "HKUS", "HKCC")]
        [string]$Hive,

        [parameter(Mandatory=$true)]
        [string]$Key,

        [parameter(Mandatory=$true)]
        [string]$Name,
 
        [parameter(ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Computername="$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Begin
    {
        $reg = Get-WmiObject -List "StdRegprov" -ComputerName $computername -Credential $Credential
    }
    Process
    {
        # We get the correct value associated with the key.
        switch ($hive) 
        {
            "HKCR" {$reg_hive = 2147483648}
            "HKCU" {$reg_hive = 2147483649}
            "HKLM" {$reg_hive = 2147483650}
            "HKUS" {$reg_hive = 2147483651}
            "HKCC" {$reg_hive = 2147483653}
        }

        $valdata = $reg.EnumValues($reg_hive, $key)
        if ($valdata.returnvalue -eq 0) 
        {
            # check that the value actualy exists
            if ($valdata.snames -contains $Name) 
            {
                $data = $reg.DeleteValue($reg_hive, $Key, $Name)
                switch ($data.returnvalue)
                {
                    "0"       {Write-Verbose "Value $name has been removed."}
                    default {Write-Error "Error while removing value $name $($data.retunvalue)"}
                }
            }
            else
            {
                Write-Error "Value $name does not exist in key specified."
            }
        }
        elseif ($valdata.returnvalue -eq 2)
        {
            Write-Error "Key $key does not exist"
        }
        else
        {
            Write-Error "Error when removing value on key: $($data.ReturnValue)"
        }
    }
    End
    {
    }
}


<#
.Synopsis
   Gets the Security DACL and Owner of a given Registry Key.
.DESCRIPTION
   Gets the Security DACL and Owner of a given Registry Key.
.EXAMPLE
   Get the DACL for the SAM key in HKLM
   PS C:\> Get-RegKeySecurityDescriptor -Hive HKlm -Key sam

    Trustee                                                                                                              Permission                                                                                                          
    -------                                                                                                              ----------                                                                                                          
    BUILTIN\Administrators                                                                                               Owner                                                                                                               
    BUILTIN\Users                                                                                                        Read Access                                                                                                         
    BUILTIN\Administrators                                                                                               All Access                                                                                                          
    NT AUTHORITY\SYSTEM                                                                                                  All Access                                                                                                          
    \CREATOR OWNER                                                                                                       All Access                                                                                                          
    APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES                                                               Read Access                                                                                                         

#>
function Get-RegKeySecurityDescriptor
{
    [CmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)]
        [string]
        [Validateset(“HKCR”, “HKCU”, “HKLM”, "HKUS", "HKCC")]
        $Hive,

        [parameter(Mandatory=$true)]
        [string]$Key,
 
        [parameter(ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Computername="$env:COMPUTERNAME",

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Begin
    {
        $reg = Get-WmiObject -List "StdRegprov" -ComputerName $computername -Credential $Credential
        $accessmask = @{
            "1" = "Query Value"
            "2" = "Set Value."
            "4" = "Create Subkey"
            "8" = "Enumerate Subkeys"
            "16" = "Notify"
            "32" = "Create Key"
            "65536" = "Delete Key"
            "131072" = "Read Control"
            "262144" = "Write DAC"
            "524288" = "Write Owner"
            "983103" = "All Access"
            "131097" = "Read Access"
        }
    }
    Process
    {
        # We get the correct value associated with the key.
        switch ($hive) 
        {
            "HKCR" {$reg_hive = 2147483648}
            "HKCU" {$reg_hive = 2147483649}
            "HKLM" {$reg_hive = 2147483650}
            "HKUS" {$reg_hive = 2147483651}
            "HKCC" {$reg_hive = 2147483653}
        }

        $data = $reg.GetSecurityDescriptor($reg_hive, $key)
        if ($data.ReturnValue -eq 0)
        {
            $owner = New-Object psobject
            Add-Member -InputObject $owner -MemberType NoteProperty -Name Trustee -Value "$($Data.Descriptor.Owner.Domain)\$($Data.Descriptor.Owner.Name)"
            Add-Member -InputObject $owner -MemberType NoteProperty -Name Permission -Value "Owner"
            $owner
            $data.Descriptor.DACL| ForEach-Object {
                $dacl = New-Object psobject
                Add-Member -InputObject $dacl -MemberType NoteProperty -Name Trustee -Value "$($_.Trustee.Domain)\$($_.Trustee.Name)"
                Write-Verbose "Access mask for $($_.Trustee.Domain)\$($_.Trustee.Name) is $($_.accessmask)"
                Add-Member -InputObject $dacl -MemberType NoteProperty -Name Permission -Value "$($accessmask[[string]$_.accessmask])"
                $dacl
            }
        }
        elseif ($data.ReturnValue -eq 2)
        {
            Write-Error "Key $key does not exist"
        }
        else
        {
            Write-Error "Error when creating key: $($data.ReturnValue)"
        }
    }
    End
    {
    }
}
