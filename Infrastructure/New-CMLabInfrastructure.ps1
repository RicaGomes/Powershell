Function Start-unGZip{
    Param(
        $infile,
        $outfile = ($infile -replace '\.gz$','')
    )

    $input = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
    $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
    $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)

    $buffer = New-Object byte[](1024)
    while($true){
        $read = $gzipstream.Read($buffer, 0, 1024)
        if ($read -le 0){break}
        $output.Write($buffer, 0, $read)
    }

    $gzipStream.Close()
    $output.Close()
    $input.Close()
}

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

$HyperVNatSwitchName = "NAT"
$ObjectPrefix = "Navinet"
$Location = "G:\Navinetwork"

$SharedFolder = "$Location\Shared"
$MediaFolder = "$Location\Media"
$VMsFolder = "$Location\VMs"
$pfsenseURL = "https://nyifiles.pfsense.org/mirror/downloads/pfSense-CE-2.4.4-RELEASE-p3-amd64.iso.gz"
$pfsenseISO = ("$MediaFolder\$($pfsenseURL.Split("/")[-1])").Replace("\\","\")
$WinSrv2019URL = "https://software-download.microsoft.com/download/pr/17763.737.190906-2324.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us_1.iso"
$WinSrv2019ISO =  ("$MediaFolder\$($WinSrv2019URL.Split("/")[-1])").Replace("\\","\")

if(-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
    Write-Warning "You are not running this as local administrator. Run it again in an elevated prompt." ; Exit 1
}

if(-not(Test-Path $Location)){
    $Output = New-Item -Path $SharedFolder -ItemType Directory
    $Output = New-Item -Path $MediaFolder -ItemType Directory
    $Output = New-Item -Path $VMsFolder -ItemType Directory

    New-SmbShare -Name "$ObjectPrefix$" -Path "$SharedFolder" -CachingMode None -FullAccess "Administrators" -Description "Shared folder to facilitate the large file transfers between Hyper-V and it's VMs" | Out-Null
    Start-BitsTransfer -Source $pfsenseURL -Destination $pfsenseISO
    Start-BitsTransfer -Source $WinSrv2019URL -Destination $WinSrv2019ISO
    Start-unGZip -infile $pfsenseISO -outfile "$($pfsenseISO -replace '.gz','')"
    Remove-Item -Path $pfsenseISO -force
}

# Gateway Machine (PFsense)
Create-VM -VMName "$ObjectPrefix-GW1" -VMLocation $VMsFolder -VMSwitch $HyperVNatSwitchName,"$ObjectPrefix-Datacenter","$ObjectPrefix-SiteA" -VMCPUCores 2 -VMDiskSize 30 -VMMemory 1024 -VMGen 2 -VMSecureBootOff -VMISO (Get-ChildItem -Path $MediaFolder | Where-Object { $_.Name -like "pfSense*" }).fullname

# Domain Controller (Windows Server Core 2019)
Create-VM -VMName "$ObjectPrefix-DC1" -VMLocation $VMsFolder -VMSwitch "$ObjectPrefix-Datacenter" -VMCPUCores 4 -VMDiskSize 50 -VMMemory 4096 -VMGen 2 -VMISO (Get-ChildItem -Path $MediaFolder | Where-Object { $_.Name -like "*SERVER_EVAL*" }).fullname

# Configurarion Manager (Windows Server 2019)
Create-VM -VMName "$ObjectPrefix-CM1" -VMLocation $VMsFolder -VMSwitch "$ObjectPrefix-Datacenter" -VMCPUCores 4 -VMDiskSize 120,200,40,40,40 -VMMemory 16384 -VMGen 2 -VMISO (Get-ChildItem -Path $MediaFolder | Where-Object { $_.Name -like "*SERVER_EVAL*" }).fullname

# Windows Enterprise Clients
#Create-VM -VMName "$ObjectPrefix-W10VM1909AD01" -VMLocation $VMsFolder -VMSwitch "$ObjectPrefix-Tokyo" -VMCPUCores 4 -VMDiskSize 60 -VMMemory 4096 -VMGen 2 -VMTPM
#Create-VM -VMName "$ObjectPrefix-W10VM1909AD02" -VMLocation $VMsFolder -VMSwitch "$ObjectPrefix-Tokyo" -VMCPUCores 4 -VMDiskSize 60 -VMMemory 4096 -VMGen 2 -VMTPM
#Create-VM -VMName "$ObjectPrefix-W10VM1909AD03" -VMLocation $VMsFolder -VMSwitch "$ObjectPrefix-Tokyo" -VMCPUCores 4 -VMDiskSize 60 -VMMemory 4096 -VMGen 2 -VMTPM
