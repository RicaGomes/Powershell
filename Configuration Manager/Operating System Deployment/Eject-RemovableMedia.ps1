$Eject = New-Object -ComObject Shell.Application
$SMSTSEnvironment = New-Object -COMObject Microsoft.SMS.TSEnvironment
$LaunchMode = $SMSTSEnvironment.Value("_SMSTSLaunchMode")

foreach($Drive in $DriveTypes = @(2,5)){
    Get-WmiObject win32_logicaldisk -filter "DriveType=$($Drive)" | ForEach-Object {
        $DriveSize = [Math]::Round($_.Size/1073741824,2)
        $DriveFree = [Math]::Round($_.FreeSpace/1073741824,2)
        $VolumeName = $_.VolumeName
        $DeviceID = $_.DeviceID
        Switch($Drive){
            '2' { # USB Drives
                Switch($LaunchMode){
                    {($_ -eq 'UFD') -or ($_ -eq 'UFD+FORMAT')} {
                        if($VolumeName -eq "Configuration Manager"){
                            if(($DriveSize-$DriveFree) -lt 2){
                                $Eject.Namespace(17).ParseName($DeviceID).InvokeVerb("Eject")
                            }
                        }else{
                            $Eject.Namespace(17).ParseName($DeviceID).InvokeVerb("Eject")
                        }
                    }
                    Default { $Eject.Namespace(17).ParseName($DeviceID).InvokeVerb("Eject") }
                }
            }
            '5' { # CD/DVD Drives
				if((Get-WMIObject -Class Win32_CDROMDrive -Property *).MediaLoaded -eq $TRUE){
					$Eject.Namespace(17).ParseName($DeviceID).InvokeVerb("Eject")
				}
            }
        }
    }
}
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Eject) | Out-Null
