<#

.SYNOPSIS
Automate the creation of the Sourcefiles/Packages folder structure for Microsoft Endpoint Configuration Manager infrastructure.

.DESCRIPTION
Automate the creation of the Sourcefiles/Packages folder structure for storing installation update files, packages and applications used in a Microsoft Endpoint Configuration Manager infrastructure.

.EXAMPLE
.\Create-CMFolderStructure.ps1 -Sourcefolder H:\Sourcefolder -NetworkShareName Sourcefolder$

.NOTES


.LINK


#>

Param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
    [STRING]$SourceFolder,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
    [STRING]$NetworkShareName,
    [STRING]$SCCMMachineName = $env:COMPUTERNAME,
    [STRING]$DomainName = $env:USERDOMAIN,
    [SWITCH]$CreateExtraFolders
)

Begin{
    Try{
        # Test if current user
        if(-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
            Write-Warning "You are not running this as local administrator. Run it again in an elevated prompt." ; Exit 1
        }
        if( -not(Get-InstalledModule -name "NTFSSecurity" -ErrorAction SilentlyContinue ) ){ 
            Write-Warning "Installing 'NTFSSecurity' PowerShell Module. Please wait ..."
            Install-Module -name "NTFSSecurity" -Force -Confirm:false 
        }
    }Catch{
        Write-Warning "An error occurred:"
        Write-Warning $_ ; Exit 1 
    }
    
    $ComputerAccount = $SCCMMachineName+"$"
}

Process{
    # Feel free to change/adapt this folder structure to fit your requirements        
    # Main folder
    New-Item -ItemType Directory "$SourceFolder" | Out-Null

    # Applications and Packages Type content
    New-Item -ItemType Directory "$SourceFolder\Packages" | Out-Null
    New-Item -ItemType Directory "$SourceFolder\Applications\Microsoft\Office365 ProPlus\SAC" | Out-Null
    New-Item -ItemType Directory "$SourceFolder\Applications\Microsoft\Office365 ProPlus\SAC-t" | Out-Null
    New-Item -ItemType Directory "$SourceFolder\Applications\Microsoft\Office365 ProPlus\Monthly" | Out-Null

    # Operating System and Boot Images/Media
    New-Item -ItemType Directory "$SourceFolder\OSD\Boot\" | Out-Null
    New-Item -ItemType Directory "$SourceFolder\OSD\Images\" | Out-Null
    New-Item -ItemType Directory "$SourceFolder\OSD\Media\" | Out-Null
    New-Item -ItemType Directory "$SourceFolder\OSD\Drivers\Sources" | Out-Null
    New-Item -ItemType Directory "$SourceFolder\OSD\Drivers\Packages" | Out-Null

    # Log folder
    New-Item -ItemType Directory "$SourceFolder\Logs\DesktopAnalytics" | Out-Null

    # Software update for ADR Packages
    New-Item -ItemType Directory "$SourceFolder\SoftwareUpdates\Windows\7" | Out-Null
    New-Item -ItemType Directory "$SourceFolder\SoftwareUpdates\Windows\8" | Out-Null
    New-Item -ItemType Directory "$SourceFolder\SoftwareUpdates\Windows\10" | Out-Null
    New-Item -ItemType Directory "$SourceFolder\SoftwareUpdates\Office365 ProPlus\SAC" | Out-Null
    New-Item -ItemType Directory "$SourceFolder\SoftwareUpdates\Office365 ProPlus\SAC-T" | Out-Null
    New-Item -ItemType Directory "$SourceFolder\SoftwareUpdates\Office365 ProPlus\Monthly" | Out-Null
    New-Item -ItemType Directory "$SourceFolder\SoftwareUpdates\EndpointProtection" | Out-Null

    # Extra Folders
    if($ExtraFolders -eq $true){
        New-Item -ItemType Directory "$SourceFolder\Tools" | Out-Null
        New-Item -ItemType Directory "$SourceFolder\Import" | Out-Null
        New-Item -ItemType Directory "$SourceFolder\Capture" | Out-Null
        New-Item -ItemType Directory "$SourceFolder\Logs\MDT" | Out-Null
    }
}

End{
    Try{
        # Adding NTFS Permissions to Allow Access
        Add-NTFSAccess -Path "$SourceFolder" -Account "Domain Computers" -AccessRights Read | Out-Null 
        Add-NTFSAccess -Path "$SourceFolder" -Account "$DomainName\$ComputerAccount" -AccessRights FullControl | Out-Null
        Add-NTFSAccess -Path "$SourceFolder" -Account "Administrators" -AccessRights FullControl | Out-Null
        # Comment, remove or adapt this line if the Logs folder was moved or removed from the path Sourcefolder variable
        if(Test-Path -Path "$SourceFolder\Logs"){ Add-NTFSAccess -Path "$SourceFolder\Logs" -Account "Domain Computers" -AccessRights Modify | Out-Null }
        
        # Creating network share and granting the appropriated permissions
        New-SmbShare -Name "$NetworkShareName" -Path "$SourceFolder" -CachingMode None -FullAccess "Administrators","$DomainName\$ComputerAccount" | Out-Null
        Grant-SmbShareAccess -Name "$NetworkShareName" -AccountName "Authenticated Users" -AccessRight Read -Confirm:$false | out-null
    }Catch{
        Write-Warning "An error occurred:"
        Write-Warning $_ 
        Write-Warning "Removing folder Structure $SourceFolder"
        Remove-Item $SourceFolder -Recurse -Force -Confirm:$false; Exit 1 
    }
}
