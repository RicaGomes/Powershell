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

# Reconfigure WSUS Pool queueLength and privateMemory to optimal settings. Restarts IIS in the end of the procedure.
Import-Module webadministration
Set-ItemProperty IIS:\AppPools\WsusPool -Name queueLength -Value 2000
Set-ItemProperty IIS:\AppPools\WsusPool -Name Recycling.periodicRestart.privateMemory -Value $((Get-ItemProperty IIS:\AppPools\WsusPool -Name Recycling.periodicRestart.privateMemory).Value*4) 
Start-Process "iisreset" -ArgumentList "/noforce" -WindowStyle Hidden -Wait

# Sets Power settings for best performance
Start-Process "powercfg" -ArgumentList "/SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" -WindowStyle Hidden -Wait
Start-Process "powercfg" -ArgumentList "/HIBERNATE Off" -WindowStyle Hidden -Wait
Start-Process "powercfg" -ArgumentList "-change -monitor-timeout-ac 0" -WindowStyle Hidden -Wait
Start-Process "powercfg" -ArgumentList "-change -monitor-timeout-dc 0" -WindowStyle Hidden -Wait
Start-Process "powercfg" -ArgumentList "-change -disk-timeout-ac 0" -WindowStyle Hidden -Wait
Start-Process "powercfg" -ArgumentList "-change -disk-timeout-dc 0" -WindowStyle Hidden -Wait
Start-Process "powercfg" -ArgumentList "-change -standby-timeout-ac 0" -WindowStyle Hidden -Wait
Start-Process "powercfg" -ArgumentList "-change -standby-timeout-dc 0" -WindowStyle Hidden -Wait

# Disables Defrag Maintenance Tasks
$(Get-ScheduledTask -TaskName *defrag* | Disable-ScheduledTask) | Out-Null

# Disables Windows Search from indexing content on the server, this includes files, programs, settings, etc..
$(Get-WMIObject -Class Win32_Volume -Filter "IndexingEnabled=$true" | Set-WmiInstance -Arguments @{IndexingEnabled=$false}) | Out-Null

# The Enable-NetAdapterRss cmdlet enables receive side scaling (RSS) on a network adapter. 
# RSS is a scalability technology that distributes the receive network traffic among multiple processors by hashing the header of the incoming packet. 
# Without RSS in firstref_longhorn and later, network traffic is received on the first processor which can quickly reach full utilization limiting receive network throughput.
# More Information: https://docs.microsoft.com/en-us/powershell/module/netadapter/enable-netadapterrss?view=win10-ps
Enable-NetAdapterRss –Name $(Get-NetAdapter | ? {$_.Status -eq "up"}).Name

# Adjusts Explorer visual effect for best performance (cutting down in the window and menu animations).
# Sets Windows Explorer to open in “This PC” instead of “Quick Access”.
# Sets Server Manager not to show on each logon.
New-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects -Name VisualFXSetting -PropertyType DWORD -Value "0x2" -Force
New-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ -Name "LaunchTo" -PropertyType DWORD -Value "1" -force
New-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value "0x1" –Force
