$Global:sqliteconn = New-Object System.Collections.ArrayList

function Connect-SQLite3 
{
    [CmdletBinding()]
	param (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateScript({Test-Path $_})]
        [string]$DataBase,
        [switch]$ReadOnly,
        [SecureString]$Password
    )
    
    Begin
    {
        # Load the appropiate DLL Depending on the Archiecture
	    switch ([intptr]::size)
	    {
		    4 {$sqlitedll = [System.Reflection.Assembly]::LoadFrom("$PSScriptRoot\x86\System.Data.SQLite.dll")} 
		    8 {$sqlitedll = [System.Reflection.Assembly]::LoadFrom("$PSScriptRoot\x64\System.Data.SQLite.dll")}
	    }
    }
    Process
    {
	    $cn = New-Object -TypeName System.Data.SQLite.SQLiteConnection
	    $cn.ConnectionString = "Data Source=$DataBase"
	    $cn.Open()
        $conn_obj = $cn
        if ($Global:sqliteconn -notcontains $conn_obj)
        {
            $SessionIndex = $Global:sqliteconn.Count
            write "index is $SessionIndex"
            $NewConnection = New-Object psobject -Property @{
                                Index = $SessionIndex.ToString() ;
                                Connection = $conn_obj; 
                                Database = $DataBase
                                }

            [void]$Global:sqliteconn.Add($NewConnection)
            # Return the connection object.
            $NewConnection
        }
        else
        {
            Write-Warning "A connection to $DataBase already exists."
        }
    }

    End
    {
    }

}


function Remove-SQLite3Connection
{
    [CmdletBinding()]
    param( 
        [Parameter(Mandatory=$false)]
        [Int32[]] $Index
    )
    Begin{
        $currentConnections = @()
        foreach($conn in $Global:sqliteconn) {$currentConnections += $conn}
    }
    Process
    {
        if ($Index.Length -gt 0)
        {
            foreach($i in $Index)
            {
                foreach($Connection in $currentConnections)
                {
                    if ($Connection.Index -eq $i)
                    {
                        Write-Verbose "Removing connection with Index $i"
                        $Connection.connection.close()
                        $Global:sqliteconn.Remove($Connection)
                        Write-Verbose "Connection removed."
                    }
                }
            }
        }
        else
        {
            # Return all database connections.
            $return_sessions = @()
            foreach($s in $Global:sqliteconn){$return_sessions += $s}
            $return_sessions
        }
    }
    End{}

}


function Get-SQLite3Connection 
{
    [CmdletBinding()]
    param( 
        [Parameter(Mandatory=$false)]
        [Int32[]] $Index
    )

    Begin{}
    Process
    {
        if ($Index.Length > 0)
        {
            foreach($i in $Index)
            {
                foreach($Connection in $Global:sqliteconn)
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
            foreach($s in $Global:sqliteconn){$return_sessions += $s}
            $return_sessions
        }
    }
    End{}
}


function Invoke-SQLite3Query           
{
    [CmdletBinding()]            
    param( 
        [Parameter(Mandatory=$true)]
        [string]$SQL,

        [Parameter(Mandatory=$true,
        ParameterSetName = "Index")]
        [int32[]]$Index,

        [Parameter(Mandatory=$true,
        ParameterSetName = "Connection")]
        [PSobject]$Connection            
        )
    if ($Index.Length -gt 0)
    {
        foreach($conn in $Global:sqliteconn)
        {
            if ($conn.index -in $Index)
            {
                $cmd = new-object System.Data.SQLite.SQLiteCommand($SQL,$conn.Connection)            
                $ds = New-Object system.Data.DataSet            
                $da = New-Object System.Data.SQLite.SQLiteDataAdapter($cmd)            
                $da.fill($ds) | Out-Null            
                return $ds.tables[0]
            }
        } 
    }
    elsif ($Connection -ne $null)
    {
        $cmd = new-object System.Data.SQLite.SQLiteCommand($SQL,$Connection.Connection)            
        $ds = New-Object system.Data.DataSet            
        $da = New-Object System.Data.SQLite.SQLiteDataAdapter($cmd)            
        $da.fill($ds) | Out-Null            
        return $ds.tables[0]
    }         
}
