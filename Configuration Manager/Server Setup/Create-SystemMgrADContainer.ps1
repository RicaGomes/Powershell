Import-Module ActiveDirectory

Function Create-SystemMgrADContainer{
    Param(
        [string]$ConfigMgrServer
    )
    $DomainInfo = Get-ADDomain
    $ContainerName = "System Management"
    $ContainerPath = "CN=System,$($DomainInfo.DistinguishedName)"
    

    if(!(Test-Path -Path $ContainerPath)){
        $Container = New-ADObject -Type Container -name $ContainerName -Path $ContainerPath -PassThru    
        $ContainerACL = (Get-ACL "AD:$($Container.DistinguishedName)")
        $ConfigMgrServerSID = [System.Security.Principal.SecurityIdentifier](Get-ADComputer $ConfigMgrServer).SID
    
        $ADRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
        $Type = [System.Security.AccessControl.AccessControlType] "Allow"
        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"  
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $ConfigMgrServerSID,$adRights,$type,$inheritanceType
    
        $ContainerACL.AddAccessRule($ACE)
        Set-Acl -AclObject $ContainerACL "AD:$($Container.DistinguishedName)"
    }
}

Create-SystemMgrADContainer -ConfigMgrServer $env:COMPUTERNAME
