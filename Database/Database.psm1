if (!(Test-Path variable:Global:SQLiteConn ))
{
    $Global:SQLiteConn = New-Object System.Collections.ArrayList
 }



<#
.Synopsis
   Creates a connection to a SQLite3 Database
.DESCRIPTION
   Creates a connection to a SQLite3 Database file and stores the connection in to $Global:sqliteconn.
.EXAMPLE
   Opens database main.db and creates a connection object for it.

   PS C:\> Connect-DBSQLite3 -DataBase .\main.db

    Connection                             Database                               Index                                 
    ----------                             --------                               -----                                 
   System.Data.SQLite.SQLiteConnection    .\main.db                              0  
#>
function Connect-DBSQLite3 
{
    [CmdletBinding()]
	param (

        # Databse file to open.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateScript({Test-Path $_})]
        [string]$DataBase

        # Open Database ReadOnly also.
        #[switch]$ReadOnly,

        # Password for opening the database if it requieres it.
        #[SecureString]$Password
    )
    
    Begin
    {
        $x86Assembly = "$($PSScriptRoot)\x86\System.Data.SQLite.dll"
        $x64Assembly = "$($PSScriptRoot)\x64\System.Data.SQLite.dll"

        # Load the appropiate DLL Depending on the Archiecture
	    switch ([intptr]::size)
	    {
		    4 {$sqlitedll = [System.Reflection.Assembly]::LoadFrom($x86Assembly)} 
		    8 {$sqlitedll = [System.Reflection.Assembly]::LoadFrom($x64Assembly)}
	    }
        
        $DataBaseFile = (Get-ItemProperty $DataBase).FullName
    }
    Process
    {
	    $cn = New-Object -TypeName System.Data.SQLite.SQLiteConnection
	    $cn.ConnectionString = "Data Source=$DataBaseFile"
	    $cn.Open()
        $conn_obj = $cn
        if ($Global:sqliteconn -notcontains $conn_obj)
        {
            $SessionIndex = $Global:sqliteconn.Count
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




<#
.Synopsis
   Removes a specific SQLite3 connection
.DESCRIPTION
   Removes a specific SQLite3 connection given its Index
.EXAMPLE
   Disconnect all SQLite3 connections

   PS C:\> Get-DBSQLite3Connection | Remove-SQLite3Connection

   Connection                             Database                               Index                                 
   ----------                             --------                               -----                                 
   System.Data.SQLite.SQLiteConnection    .\main.db                              0                                     

.EXAMPLE
   Remove a SQLite3 connection given its index

   PS C:\> Remove-DBSQLite3Connection -Index 0

   Connection                             Database                               Index                                 
   ----------                             --------                               -----                                 
   System.Data.SQLite.SQLiteConnection    .\main.db                              0                                     

#>
function Remove-DBSQLite3Connection
{
    [CmdletBinding()]
    param( 
        # Index for the database connection.
        [Parameter(Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Int32] $Index
        
    )
    Begin{
        $currentConnections = @()
        foreach($conn in $Global:sqliteconn) {$currentConnections += $conn}
    }
    Process
    {
        if ($Index -ge 0)
        {
            Write-Verbose "Removing connection with Index $Index"
            foreach($i in $Index)
            {
                foreach($Connection in $currentConnections)
                {
                    if ($Connection.Index -eq $i)
                    {
                        Write-Verbose "Connection Found"
                        $Connection.connection.close()
                        $Global:sqliteconn.Remove($Connection)
                        Write-Verbose "Connection removed."
                    }
                }
            }
        }
    }
    End{}

}



<#
.Synopsis
   Get SQLite3 Connections
.DESCRIPTION
   Get all or a specified existing SQLite3 Connection.
.EXAMPLE
   Gets all SQLIte3 Connections 
   
   PS C:\> Get-DBSQLite3Connection

    Connection                             Database                               Index                                 
    ----------                             --------                               -----                                 
    System.Data.SQLite.SQLiteConnection    .\main.db                              0     

#>
function Get-DBSQLite3Connection 
{
    [CmdletBinding()]
    param( 
        [Parameter(Mandatory=$false)]
        [Int32] $Index
    )

    Begin{}
    Process
    {
        if ($Index)
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



<#
.Synopsis
   Exsecutes SQL query against SQLite3 Connection
.DESCRIPTION
   Exsecutes SQL query against SQLite3 Connection against an existing SQLite3 Connection
.EXAMPLE
   Execute query to list all the tables in the database.

   PS C:\> Invoke-SQLite3Query -SQL "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;" -Index 0

#>
function Invoke-DBSQLite3Query           
{
    [CmdletBinding()]            
    param( 
        [Parameter(Mandatory=$true)]
        [string]$SQL,

        [Parameter(Mandatory=$true,
        ParameterSetName = "Index")]
        [int32]$Index,

        [Parameter(Mandatory=$true,
        ParameterSetName = "Connection")]
        [PSobject]$Connection            
        )
    if ($Index -ge 0)
    {
        Write-Verbose "Executing Query $SQL"
        Write-Verbose "Executing against $Index"
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


function New-DBSQLConnectionString
{
    [CmdletBinding()]
    Param(
        [string]$ServerName,
        [string]$DatabaseName,
        [string]$UserName,
        [string]$Password,
        [Switch]$IntegratedAuth
    )
	If($IntegratedAuth)
	{
		$ConnectionString = "server=$ServerName;database=$DatabaseName;trusted_connection=true;"
 
	}
	Else
	{
		$ConnectionString = "server=$ServerName;database=$DatabaseName;User Id=$UserName;Password=$Password;trusted_connection=False;"
	}
 
	Return $ConnectionString
 
}
