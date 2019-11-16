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
        [Parameter (Mandatory =$false )][ValidateSet (1, 2)][Int] $VMGen = 2,
        [Parameter (Mandatory =$false )][ValidateSet (1, 2, 4, 8)][Int]$VMCPUCores = 4,
        [Parameter (Mandatory =$false )][ValidateSet ('512', '768', '1024','3072', '2048', '4096', '8192', '12288', '16384')]
        [String]$VMMemory = '4096MB',
        [Parameter (Mandatory =$false )][Array]$VMDiskSize = @("50"),
        # Other
        [Parameter (Mandatory =$false )][Switch]$VMTPM,
        [Parameter (Mandatory =$false )][Switch]$VMSecureBootOff,
        [Parameter (Mandatory =$false )][String]$VMISO
    )
    
    Try{
        New-VM -Name $VMName -MemoryStartupBytes (Invoke-Expression "$($VMMemory)MB") -Generation $VMGen -Path $VMLocation -BootDevice CD -NoVHD | Out-Null
        Get-VMNetworkAdapter -VMName $VMName | Remove-VMNetworkAdapter
        Set-VMProcessor $VMName -Count $VMCPUCores | Out-Null

        $x = 1
        foreach($DiskSize in ($VMDiskSize)){
            New-VHD -Path "$VMLocation\$VMName\Virtual Hard Disks\$VMName-Disk$x.vhdx" -SizeBytes (Invoke-Expression "$($DiskSize)GB") | Out-Null
            Add-VMHardDiskDrive -VMName $VMName -Path "$VMLocation\$VMName\Virtual Hard Disks\$VMName-Disk$x.vhdx" | Out-Null
            $x++
        }

        foreach($NIC in $VMSwitch){
            Create-VMSwitch -Name $NIC -Type Private
            Add-VMNetworkAdapter -VMName $VMName -Name $NIC -SwitchName $NIC            
        }

        if(($VMTPM -eq $True) -and ($VMGen -eq 2)){ 
            if(-not (Get-HgsGuardian 'UntrustedGuardian' -ErrorAction SilentlyContinue) ){ New-HgsGuardian -Name 'UntrustedGuardian' -GenerateCertificates }
            Set-VMKeyProtector -VMName $VMName -KeyProtector $(New-HgsKeyProtector -Owner $(Get-HgsGuardian UntrustedGuardian) -AllowUntrustedRoot).RawData
            Enable-VMTPM $VMName
        }

        if($VMISO){ Set-VMDvdDrive -VMName $VMName -Path $VMISO | Out-Null }
        if($VMSecureBootOff){ Set-VMFirmware -VMName $VMName -EnableSecureBoot Off }
    }Catch{
    
    }
}

$Location = "G:\CMSetup"
$ObjectPrefix = "NVNet"
$MediaFolder = "$Location\Media"

# Gateway Machine (PFsense)
Create-VM -VMName "$ObjectPrefix-GW1" -VMLocation $Location -VMSwitch NAT,"$ObjectPrefix-Datacenter","$ObjectPrefix-Tokyo" -VMCPUCores 2 -VMDiskSize 30 -VMMemory 768 -VMGen 2 -VMSecureBootOff -VMISO (Get-ChildItem -Path $MediaFolder | Where-Object { $_.Name -like "pfSense*.iso" }).fullname

# Domain Controller (Windows Server Core 2019)
Create-VM -VMName "$ObjectPrefix-DC1" -VMLocation $Location -VMSwitch "$ObjectPrefix-Datacenter" -VMCPUCores 4 -VMDiskSize 50 -VMMemory 2048 -VMGen 2 -VMTPM -VMISO (Get-ChildItem -Path $MediaFolder | Where-Object { $_.Name -like "*SERVER_EVAL*" }).fullname

# Configurarion Manager (Windows Server 2019)
Create-VM -VMName "$ObjectPrefix-CM1" -VMLocation $Location -VMSwitch "$ObjectPrefix-Datacenter" -VMCPUCores 4 -VMDiskSize 100,500,40,40,40 -VMMemory 12288 -VMGen 2 -VMTPM -VMISO (Get-ChildItem -Path $MediaFolder | Where-Object { $_.Name -like "*SERVER_EVAL*" }).fullname

# Windows Enterprise Clients
Create-VM -VMName "$ObjectPrefix-W10-1909-AD-01" -VMLocation $Location -VMSwitch "$ObjectPrefix-Tokyo" -VMCPUCores 4 -VMDiskSize 50 -VMMemory 3072 -VMGen 2 -VMTPM
Create-VM -VMName "$ObjectPrefix-W10-1909-AP-01" -VMLocation $Location -VMSwitch "$ObjectPrefix-Tokyo" -VMCPUCores 4 -VMDiskSize 50 -VMMemory 3072 -VMGen 2 -VMTPM
