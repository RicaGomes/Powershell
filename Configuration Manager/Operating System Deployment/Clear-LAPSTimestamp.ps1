<# 
  Run after WinPE Phase
  If you use LAPS, after a device wipe and load the local admin password stored in Active Directory will no longer be valid. 
  Depending on the last time the password change was triggered (updating it in Active Directory and regenerating a new timestamp) 
  and the next time change the password according to policy (in days), you may find your self locked from using the Local 
  Administrator for this device.
  
  To prevent this, run this script during the OSD Task Sequence to clear 'ms-Mcs-AdmPwdExpirationTime' in the Active Directory
  computer object and force LAPS to generate a new password after the Device grabs the domain policies.
#>
# Get NetBIOS domain name
$Info=new-object -com ADSystemInfo
$t=$info.GetType()

$domainName=$t.InvokeMember("DomainShortName","GetProperty",$null,$info,$null)
$computerName=$env:computerName

#translate domain\computername to distinguishedName
$translator = new-object -com NameTranslate
$t = $translator.gettype()
$t.InvokeMember(“Init”,”InvokeMethod”,$null,$translator,(3,$null)) #resolve via GC
$t.InvokeMember(“Set”,”InvokeMethod”,$null,$translator,(3,”$domainName\$ComputerName`$”))
$computerDN=$t.InvokeMember(“Get”,”InvokeMethod”,$null,$translator,1)

#connect to computer object
$computerObject= new-object System.DirectoryServices.DirectoryEntry("LDAP://$computerDN")

#clear password expiration time
($computerObject.'ms-Mcs-AdmPwdExpirationTime').Clear()

$computerObject.CommitChanges()
