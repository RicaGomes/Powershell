[int]$TotalServerMemory = ((Get-WMIObject -class Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1024 / 1024)
$computersys = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges;
$computersys.AutomaticManagedPagefile = $False;
$computersys.Put();
$pagefile = Get-WmiObject -Query "Select * From Win32_PageFileSetting Where Name like '%pagefile.sys'";
$pagefile.InitialSize = $TotalServerMemory ;
$pagefile.MaximumSize = $TotalServerMemory *3;
$pagefile.Put();
