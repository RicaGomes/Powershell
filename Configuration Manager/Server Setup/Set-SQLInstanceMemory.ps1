Function Set-SQLInstanceMemory {
    param (
        [string]$SQLInstanceName = $env:Computername,
        [int]$ReservedOSMemory = 2048,
        [int]$DiffMinMaxSQLMemory = 2048
    )

    [int]$TotalServerMemory = ((Get-WMIObject -class Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1024 / 1024)
    [int]$MinimumSQLMemory = 0
    [int]$MaximumSQLMemory = 0

    
    Switch($TotalServerMemory){
        { $TotalServerMemory -le $ReservedOSMemory } { $MaximumSQLMemory = $TotalServerMemory }
        { $TotalServerMemory -ge 8192} { 
            $MaximumSQLMemory = $TotalServerMemory - $ReservedOSMemory 
            $MinimumSQLMemory = $MaximumSQLMemory - $DiffMinMaxSQLMemory
        }
        Default{ $MaximumSQLMemory = $TotalServerMemory * 0.8 }
    }

    [reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null
    $MSSQLInstance = New-Object Microsoft.SQLServer.Management.Smo.Server($SQLInstanceName)
    if($MSSQLInstance.Status -eq "Online"){
        $MSSQLInstance.Configuration.MaxServerMemory.ConfigValue = $MaximumSQLMemory
        $MSSQLInstance.Configuration.MinServerMemory.ConfigValue = $MinimumSQLMemory
        $MSSQLInstance.Configuration.Alter()
        Restart-Service -Name MSSQLSERVER -Force -WarningAction SilentlyContinue
    }else{}
}

# Configures Microsoft SQL Server Max and Min Memory settings depending on the Server total available memory.
# Calculations for how much memory is allocated to the SQL Server are based on:
# - If the computer has less than 8GB of physical memory, allocate 80% of it to SQL Server and leave 20% for the OS and other applications 
# - If the computer has more than 8GB of physical memory, reserve 2GB for the OS and other applications. SQL Server will get the remaining amount 
Set-SQLInstanceMemory
