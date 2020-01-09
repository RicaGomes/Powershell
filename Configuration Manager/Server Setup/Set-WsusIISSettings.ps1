# Reconfigure WSUS Pool queueLength and privateMemory to optimal settings. Restarts IIS in the end of the procedure.
Import-Module webadministration
Set-ItemProperty IIS:\AppPools\WsusPool -Name queueLength -Value 2000
Set-ItemProperty IIS:\AppPools\WsusPool -Name Recycling.periodicRestart.privateMemory -Value $((Get-ItemProperty IIS:\AppPools\WsusPool -Name Recycling.periodicRestart.privateMemory).Value*4) 
Start-Process "iisreset" -ArgumentList "/noforce" -WindowStyle Hidden -Wait
