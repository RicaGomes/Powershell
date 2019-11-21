<# 
  Runs during WinPE Phase, before drive formatting.
  Gathers and stores in Task Sequence Variables, information about the device TPM Chip readiness (if it's enabled, owned and active) and if
  Secure Boot is enabled in UEFI. These Task Sequence Variables then can be used to trigger certain actions during the Task Sequence OSD.
#>
# Loading SCCM ComObject so we can set Task Sequence Variables
$SMSTSEnvironment = New-Object -COMObject Microsoft.SMS.TSEnvironment

# Clean and Set Variables with WMI queries
$TPMChipInfo = $Null
$SecureBoot = $Null
$BitLockerProtection = $Null
$BitlockerPINlength = '8'

# Gather TPM Chip Information
$TPMChipInfo = Get-WmiObject -class Win32_Tpm -namespace 'root\CIMV2\Security\MicrosoftTpm'
if (Get-WmiObject -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' -Class Win32_EncryptableVolume -Filter "DriveLetter='C:'"){
	$ProtectionStatus = (Get-WmiObject -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' -Class Win32_EncryptableVolume -Filter "DriveLetter='C:'").GetProtectionStatus().ProtectionStatus
}

# Set Task Sequence Variables to be used
# Expected Values:
# 	TPMIsOwned				True or False
# 	TPMIsActive				True or False
# 	TPMIsEnabled			True or False
# 	BitLockerIsEnabled		True or False
# 	SecureBoot				True or False
#	BitLockerIsEnabled		True or False
$SMSTSEnvironment.Value('TPMIsOwned') = $TPMChipInfo.IsOwned_InitialValue
$SMSTSEnvironment.Value('TPMIsActive') = $TPMChipInfo.IsActivated_InitialValue
$SMSTSEnvironment.Value('TPMIsEnabled') = $TPMChipInfo.IsEnabled_InitialValue
$SMSTSEnvironment.Value('BitLockerIsEnabled') = $ProtectionStatus -match "1"
$SMSTSEnvironment.Value('SecureBootIsEnabled') = Confirm-SecureBootUEFI

# Generate Random Bitlocker PIN.
if($TPMChipInfo.IsEnabled_InitialValue -eq $True){
	$SMSTSEnvironment.Value('OSDBitlockerPIN') = ((1..$BitlockerPINlength) | ForEach-Object { Get-Random -Minimum 0 -Maximum 9 }) -join ''
}
