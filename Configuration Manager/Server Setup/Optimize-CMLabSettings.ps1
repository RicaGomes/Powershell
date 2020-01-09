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
