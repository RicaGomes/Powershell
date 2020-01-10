Function Create-VMSwitch{
    Param(
        [Parameter (Mandatory =$true )]
        [STRING]$Name = $null,
        [Parameter (Mandatory =$true )][ValidateSet ("Private","Internal")]
        [STRING]$Type = "Private"
    )
    Switch($Type){
        {($_ -eq 'Private') -or ($_ -eq 'Internal')} {
            if(-not(Get-VMSwitch | Where-Object { $_.Name -eq $Name }) ){
                New-VMSwitch -Name $Name -SwitchType $Type | Out-Null
            }
        }
    }
}

Function Create-VM{
    Param(
        [Parameter (Mandatory =$true )][String]$VMName,
        [Parameter (Mandatory =$true )][String]$VMLocation,
        [Parameter (Mandatory =$true )][Array]$VMSwitch = @(),
        # Hardware
        [Parameter (Mandatory =$false )][Array]$VMDiskSize = @("50"),
        [Parameter (Mandatory =$false )][ValidateSet (1, 2)][Int] $VMGen = 2,
        [Parameter (Mandatory =$false )][ValidateSet (1, 2, 4, 8)][Int]$VMCPUCores = 4,
        [Parameter (Mandatory =$false )][ValidateSet ('512', '768', '1024','3072', '2048', '4096', '8192', '12288', '16384')][String]$VMMemory = '4096MB',
        # Other
        [Parameter (Mandatory =$false )][String]$VMISO,
        [Parameter (Mandatory =$false )][Switch]$VMTPM,
        [Parameter (Mandatory =$false )][Switch]$VMSecureBootOff,
        [Parameter (Mandatory =$false )][ValidateSet ("Standard", "Production")][String] $VMCheckpointType = "Standard"

    )
    
    Try{
        New-VM -Name $VMName -MemoryStartupBytes (Invoke-Expression "$($VMMemory)MB") -Generation $VMGen -Path $VMLocation -BootDevice CD -NoVHD | Out-Null
        Set-VM -Name $VMName -SnapshotFileLocation "$VMLocation\$VMName\Checkpoints\" -CheckpointType $VMCheckpointType
        Set-VMProcessor $VMName -Count $VMCPUCores | Out-Null

        $x = 1
        foreach($DiskSize in ($VMDiskSize)){
            New-VHD -Path "$VMLocation\$VMName\Virtual Hard Disks\$VMName-Disk$x.vhdx" -SizeBytes (Invoke-Expression "$($DiskSize)GB") | Out-Null
            Add-VMHardDiskDrive -VMName $VMName -Path "$VMLocation\$VMName\Virtual Hard Disks\$VMName-Disk$x.vhdx" | Out-Null
            $x++
        }

        Get-VMNetworkAdapter -VMName $VMName | Remove-VMNetworkAdapter
        foreach($NIC in $VMSwitch){
            Create-VMSwitch -Name $NIC -Type Private
            Add-VMNetworkAdapter -VMName $VMName -Name "$(($NIC).Replace("$ObjectPrefix-",'')) Network Card" -SwitchName $NIC            
        }

        if($VMGen -eq 2){
            if($VMTPM -eq $True){
                if(-not (Get-HgsGuardian 'UntrustedGuardian' -ErrorAction SilentlyContinue) ){ New-HgsGuardian -Name 'UntrustedGuardian' -GenerateCertificates }
                Set-VMKeyProtector -VMName $VMName -KeyProtector $(New-HgsKeyProtector -Owner $(Get-HgsGuardian UntrustedGuardian) -AllowUntrustedRoot).RawData
                Enable-VMTPM $VMName
            }
            if($VMSecureBootOff){ Set-VMFirmware -VMName $VMName -EnableSecureBoot Off }
        }

        if($VMISO){ Set-VMDvdDrive -VMName $VMName -Path $VMISO | Out-Null }
    }Catch{
    
    }
}


$Location = "E:\DemoEnviroment"
$SharedFolder = "$Location\Shared"
$MediaFolder = "$Location\Media"
$VMsFolder = "$Location\VMs"
$ObjectPrefix = "Demo"

if(-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
    Write-Warning "You are not running this as local administrator. Run it again in an elevated prompt." ; Exit 1
}

if(-not(Test-Path $Location)){
    New-Item -Path $SharedFolder -ItemType Directory
    New-SmbShare -Name "$ObjectPrefix$" -Path "$SharedFolder" -CachingMode None -FullAccess "Administrators" -Description "Shared folder to facilitate the large file transfers between Hyper-V and it's VMs" | Out-Null
    New-Item -Path $MediaFolder -ItemType Directory
    New-Item -Path $VMsFolder -ItemType Directory
}

# Gateway Machine (PFsense)
Create-VM -VMName "$ObjectPrefix-GW1" -VMLocation $VMsFolder -VMSwitch InternalNATSwitch-1,"$ObjectPrefix-Datacenter","$ObjectPrefix-SiteA","$ObjectPrefix-SiteB" -VMCPUCores 2 -VMDiskSize 30 -VMMemory 1024 -VMGen 2 -VMSecureBootOff -VMISO (Get-ChildItem -Path $MediaFolder | Where-Object { $_.Name -like "pfSense*" }).fullname

# Domain Controller (Windows Server Core 2019)
Create-VM -VMName "$ObjectPrefix-DC1" -VMLocation $VMsFolder -VMSwitch "$ObjectPrefix-Datacenter" -VMCPUCores 4 -VMDiskSize 50 -VMMemory 4096 -VMGen 2 -VMTPM -VMISO (Get-ChildItem -Path $MediaFolder | Where-Object { $_.Name -like "*SERVER_EVAL*" }).fullname

# Configurarion Manager (Windows Server 2019)
Create-VM -VMName "$ObjectPrefix-CM1" -VMLocation $VMsFolder -VMSwitch "$ObjectPrefix-Datacenter" -VMCPUCores 4 -VMDiskSize 120,500,40,40,40 -VMMemory 12288 -VMGen 2 -VMTPM -VMISO (Get-ChildItem -Path $MediaFolder | Where-Object { $_.Name -like "*SERVER_EVAL*" }).fullname

# Windows Enterprise Clients
Create-VM -VMName "$ObjectPrefix-W10-1909-AD-01" -VMLocation $Location -VMSwitch "$ObjectPrefix-SiteA" -VMCPUCores 4 -VMDiskSize 50 -VMMemory 4096 -VMGen 2 -VMTPM
Create-VM -VMName "$ObjectPrefix-W10-1909-AP-01" -VMLocation $Location -VMSwitch "$ObjectPrefix-SiteA" -VMCPUCores 4 -VMDiskSize 50 -VMMemory 4096 -VMGen 2 -VMTPM
