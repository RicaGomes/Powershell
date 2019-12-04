$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\Users\Public\Desktop\Configuration Manager Applet.lnk")
$Shortcut.TargetPath = "C:\Windows\CCM\SMSCFGRC.cpl"
$Shortcut.IconLocation = "C:\Windows\CCM\SCClient.exe,0"
$Shortcut.Save()