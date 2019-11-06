$ProductKey = (Get-WmiObject -Query 'select * from SoftwareLicensingService').OA3xOriginalProductKey
$service = Get-WmiObject -Query "select * from SoftwareLicensingService" -ComputerName $env:COMPUTERNAME
$service.InstallProductKey($ProductKey)
Start-Sleep 2
$service.RefreshLicenseStatus()
