<#
.SYNOPSIS
Automate the creation of a Domain Controller in one "click".

.DESCRIPTION
Automate the creation of the Sourcefiles/Packages folder structure for storing installation update files, packages and applications used in a Microsoft Endpoint Configuration Manager infrastructure.
.EXAMPLE
.\New-DomainController.ps1 
.\New-DomainController.ps1 -WAC
.\New-DomainController.ps1 -Hostname DC1 -NetworkAddress 10.0.0.6 -NetworkGateway 10.0.0.254 -NetworkBits 24 
.NOTES
.LINK
#>

[cmdletbinding()]
Param(
        [INT]$Stage = 1,
        [SWITCH]$WAC,
        [STRING]$Hostname = "DC1",
        [STRING]$NetworkAddress = "10.0.0.6",
        [STRING]$NetworkGateway = "10.0.0.254",
        [STRING]$NetworkBits = "24",
        [ARRAY]$DNSFowarders = "$NetworkGateway",
        [STRING]$AdminPassword = "Passw0rd",
        [STRING]$DomainName = "corp.navinetwork.org",
        [STRING]$DomainNBName = "Navinetwork",
        [Parameter(Mandatory=$false)]
        [STRING]$DomainUPN,
        [STRING]$DomainSafeModeAdminPassword = "S4f3.M0d3P4sSw0d!_4_R3c0v3ry%"
    )

Begin{
    [INT]$Global:ScriptStage = $Stage
    [STRING]$Global:Parameters = $null
    $NetworkInterface = Get-NetAdapter | Where-Object {$_.Status -eq "up"}

    if(-not ($MyInvocation.BoundParameters["Stage"])){ $Global:Parameters += "-Stage 1 " }
    foreach ($key in $MyInvocation.BoundParameters.Keys){
        if($($MyInvocation.BoundParameters[$key]) -eq $True){
            $Global:Parameters += "-$key "
        }else{ 
            $Global:Parameters += "-$key $($MyInvocation.BoundParameters[$key]) "
        }
    }

    Function Set-NextStage{
        Param(
            [Int]$CurrentStage = $Global:ScriptStage,
            [STRING]$Parameters = $Global:Parameters
        )
        $Parameters = $Parameters -replace '(^-Stage (\d+))',"-Stage $($Global:ScriptStage+1)"
        $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        Set-ItemProperty $RunOnceKey "NextRun" ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File ' + "$PSCommandPath $Parameters")
    }

    Function Set-AutoLogon{
        [CmdletBinding()]
        Param(        
            [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String[]]$DefaultUsername,
            [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String[]]$DefaultPassword,
            [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][AllowEmptyString()][String[]]$DefaultDomainName,
            [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][AllowEmptyString()][String[]]$AutoLogonCount
        )
    
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String  
        Set-ItemProperty $RegPath "DefaultUsername" -Value "$DefaultUsername" -type String  
        Set-ItemProperty $RegPath "DefaultPassword" -Value "$DefaultPassword" -type String
        if($DefaultDomainName){ Set-ItemProperty $RegPath "DefaultDomainName" -Value "$DefaultDomainName" -type String }
        if($AutoLogonCount){ Set-ItemProperty $RegPath "AutoLogonCount" -Value "$AutoLogonCount" -type DWord
        }else{ Set-ItemProperty $RegPath "AutoLogonCount" -Value "1" -type DWord }
    }

    Function New-DemoUserBatch{
        [CmdletBinding()]
        Param(
            [ValidateSet("AU","BR","CA","CH","DE","DK","ES","FI","FR","GB","IE","IR","NO","NL","NZ","TR","US")]
            [ARRAY]$Country = "US",
            [ValidateRange(1,2500)] 
            [INT]$Results = 1,
            [STRING]$TargetOUName,
            $DomainPDC,
            [STRING]$UserDefaultUPN
        )

        [STRING]$WebRequestarameters = $null
        foreach($ScriptParameters in $PSBoundParameters.Keys){
            Switch($ScriptParameters){
                'Country' { $WebRequestarameters += "&nat=$(($Country -join ",").ToLower())"   }
                'Results' { $WebRequestarameters += "&results=$Results" }
            }
        }

        [STRING]$PasswordParameters = "upper,lower,number,16"
        $WebRequestURL = "https://randomuser.me/api/?format=PrettyJSON$WebRequestarameters&password=$PasswordParameters&exc=email,registered,dob&noinfo"
        $WebData = Invoke-WebRequest $WebRequestURL -UseBasicParsing | ConvertFrom-Json
        $TextInfo = (Get-Culture).TextInfo

        Foreach($User in $WebData.results ){
            $GivenName = $TextInfo.ToTitleCase($user.name.first)
            $Surname = $TextInfo.ToTitleCase($user.name.Last)
            $ADUserObj = @{
                'Description' = "Demo user"
        
                'Name' = "$GivenName $Surname"
                'DisplayName' = "$GivenName $Surname"
                'GivenName' = $GivenName
                'Surname' = $Surname
                
                'StreetAddress' = "$($User.location.street.Number) $($User.location.street.Name)"
                'City' = $TextInfo.ToTitleCase($User.location.city)
                'PostalCode' = $User.location.postcode
                'State' = $TextInfo.ToTitleCase($User.location.state)
                'Country' = $User.Nat
                'Company' = 'Navinetwork Corporation'
        
                'MobilePhone' = $User.cell
                'OfficePhone' = $User.phone
        
                'UserPrincipalName' = "$(("$GivenName.$Surname").Tolower())@$UserDefaultUPN"
                'SamAccountName' = ("$GivenName.$Surname").Tolower()
                'EmployeeID' = $(Get-Random -Minimum 0 -Maximum 9999).ToString('00000')
                'AccountPassword' = (ConvertTo-SecureString -String "#$($user.login.password)!" -AsPlainText -Force)
                'Enabled' = $True
                'PasswordNeverExpires' = $true
            }
            New-ADUser @ADUserObj -Path $TargetOUName -Server $DomainPDC -ErrorAction SilentlyContinue
            Invoke-WebRequest $User.picture.large -OutFile $env:TEMP\tmp.jpg
            Set-ADUser $ADUserObj["SamAccountName"] -Replace @{thumbnailPhoto=([byte[]](Get-Content $env:TEMP\tmp.jpg -Encoding byte))}
            Start-Sleep -Milliseconds 500
        }
        Remove-Item $env:TEMP\tmp.jpg -Force
    }

    function ConvertTo-IPv4MaskString {
        param(
          [Parameter(Mandatory = $true)][ValidateRange(0, 32)][Int] $MaskBits
        )
        $Mask = ([Math]::Pow(2, $MaskBits) - 1) * [Math]::Pow(2, (32 - $MaskBits))
        $Bytes = [BitConverter]::GetBytes([UInt32] $mask)
        return (($bytes.Count - 1)..0 | ForEach-Object { [String] $bytes[$_] }) -join "."
    } 
}


Process{
    Try{
        Switch($Stage){
            '1' {  Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Setting up Network Card"
                    if(!(Test-Connection $NetWorkGateway -Quiet -Count 2 -ErrorAction SilentlyContinue)){
                        New-NetIPAddress –InterfaceAlias ($NetworkInterface).Name –IPAddress $NetWorkAddress –AddressFamily IPv4 -PrefixLength $NetWorkBits -DefaultGateway $NetWorkGateway | Out-Null
                        Set-DnsClientServerAddress -InterfaceAlias ($NetworkInterface).Name -ServerAddresses 8.8.8.8 | Out-Null
                        Clear-DnsClientCache
                        Start-Sleep -Seconds 5
                    }
                    
                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Setting up 'High Performance' power schema"
                    $output = Start-Process "$($env:windir)\System32\powercfg.exe" -ArgumentList "/SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" -Wait -PassThru -WindowStyle Hidden
                    $output = Start-Process "$($env:windir)\System32\powercfg.exe" -ArgumentList "/HIBERNATE off" -Wait -PassThru -WindowStyle Hidden
                    $output = Start-Process "$($env:windir)\System32\powercfg.exe" -ArgumentList "-change -monitor-timeout-ac 0" -Wait -PassThru -WindowStyle Hidden
                    $output = Start-Process "$($env:windir)\System32\powercfg.exe" -ArgumentList "-change -monitor-timeout-dc 0" -Wait -PassThru -WindowStyle Hidden
                    $output = Start-Process "$($env:windir)\System32\powercfg.exe" -ArgumentList "-change -disk-timeout-ac 0" -Wait -PassThru -WindowStyle Hidden 
                    $output = Start-Process "$($env:windir)\System32\powercfg.exe" -ArgumentList "-change -disk-timeout-dc 0" -Wait -PassThru -WindowStyle Hidden
                    $output = Start-Process "$($env:windir)\System32\powercfg.exe" -ArgumentList "-change -standby-timeout-ac 0" -Wait -PassThru -WindowStyle Hidden
                    $output = Start-Process "$($env:windir)\System32\powercfg.exe" -ArgumentList "-change -standby-timeout-dc 0" -Wait -PassThru -WindowStyle Hidden

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Preparing system for restart and autologon"
                    Set-AutoLogon -DefaultUsername "Administrator" -DefaultPassword $AdminPassword
                    Set-NextStage
                    
                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Updating Operating System ..."
                    Install-PackageProvider -Name "Nuget" -MinimumVersion "2.8.5.201" -Force -confirm:$false | Out-Null
                    Set-PSRepository -InstallationPolicy Trusted -Name "PSGallery"
                    Find-Module PSWindowsUpdate -Repository PSGallery | Install-Module -Scope AllUsers -confirm:$false
                    Install-Windowsupdate -AcceptAll -Autoreboot -Confirm:$false
                }
            '2' { Write-Output "[$(Get-Date)] Resuming Script: Stage $($Global:ScriptStage) - Configuring server"
                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Applying Operating System customizations and tweaks"
                    $output = Start-Process "$($env:windir)\System32\fsutil.exe" -ArgumentList "8dot3name set $($env:SystemDrive) 1" -Wait -PassThru -WindowStyle Hidden
                    $output = Start-Process "$($env:windir)\System32\fsutil.exe" -ArgumentList "8dot3name set 1" -Wait -PassThru -WindowStyle Hidden
                    Get-WMIObject -Class Win32_Volume -Filter "IndexingEnabled=$true" | Set-WmiInstance -Arguments @{IndexingEnabled=$false} | Out-Null
                    Get-ScheduledTask -TaskName *defrag* | Disable-ScheduledTask | Out-Null
                    Set-Volume -DriveLetter $(($env:SystemDrive).Replace(":","")) -NewFileSystemLabel "System"
                    Get-WMIObject -Class Win32_Volume -Filter "DriveType = 5" | Set-WmiInstance -Arguments @{DriveLetter = 'Z:'} | Out-Null
                    Set-SmbServerConfiguration -EnableSMB1Protocol $false -confirm:$false
                    Enable-NetAdapterRss –Name ($NetworkInterface).Name
                    New-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ -Name "LaunchTo" -PropertyType DWORD -Value "1" | Out-Null
                    New-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\ServerManager -Name "DoNotOpenServerManagerAtLogon" -PropertyType DWORD -Value "0x1" –Force | Out-Null
                    New-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects -Name "VisualFXSetting" -PropertyType DWORD -Value "0x2" -Force | Out-Null

                    if(($InstallWAC) -and (Test-NetConnection "aka.ms" -CommonTCPPort HTTP -InformationLevel Quiet)){
                        Write-Output "[$(Get-Date)] Installing ""Windows Administrative Center"""
                            $WACurl = "https://aka.ms/WACDownload"
                            $DownloadFolder = "$env:windir\temp"
                            $MSIinstaller  = "$DownloadFolder\wac.msi"
                            $MSIInstallerLog = "$DownloadFolder\WAC-Install.log"
                            Start-BitsTransfer -Source $WACURL -Destination $MSIinstaller
                            if(Test-Path -Path "$MSIinstaller"){ $output = Start-Process "msiexec" -ArgumentList "/i ""$MSIinstaller"" /qb /l*v ""$MSIInstallerLog"" SME_PORT=4443 SSL_CERTIFICATE_OPTION=generate" -Wait -PassThru }
                            New-NetFirewallRule -DisplayName 'HTTPS for Windows Admin Center' -Profile @('Domain', 'Private') -Direction Inbound -Action Allow -Protocol TCP -LocalPort '4443' | Out-Null
                    }

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Preparing system for restart and autologon"
                    Set-AutoLogon -DefaultUsername "Administrator" -DefaultPassword $AdminPassword
                    Set-NextStage

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Renaming system to ""$Hostname"" and restarting"
                    Rename-Computer $Hostname -Restart -Force
                }
            '3' { Write-Output "[$(Get-Date -Format 'HH:mm:ss') Resuming Script: Stage $($Global:ScriptStage) - Installing and Configuring Active Directory Forest"
                    $CurrentNetworkConfiguration = (Get-NetIPConfiguration | Where-Object { ($_.IPv4DefaultGateway -ne $null) -and ($_.NetAdapter.Status -ne "Disconnected") } )
                    $NetworkInterfaceAlias = ($CurrentNetworkConfiguration).InterfaceAlias
                    $CurrentNetworkAddress = ($CurrentNetworkConfiguration).Ipv4Address.IpAddress
                    $ADDSParams = @{ 
                        CreateDnsDelegation = $false
                        DatabasePath = "C:\Windows\NTDS"
                        DomainMode = "WinThreshold"
                        DomainName = "$DomainName"
                        DomainNetbiosName = "$DomainNBName"
                        ForestMode = "WinThreshold"
                        InstallDns = $true 
                        LogPath = "C:\Windows\NTDS" 
                        NoRebootOnCompletion = $true 
                        SafeModeAdministratorPassword = $( ConvertTo-SecureString -String $DomainSafeModeAdminPassword -AsPlainText -Force ) 
                        SysvolPath = "C:\Windows\SYSVOL"
                        Force = $true
                    }

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss') Reconfiguring Network Card DNS Servers"
                    Set-DnsClientServerAddress -InterfaceAlias $NetworkInterfaceAlias -ServerAddresses "$CurrentNetworkAddress, 127.0.0.1"

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss') Installing Active Directory Domain Services Role"
                    $output = Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
    
                    Write-Output "[$(Get-Date -Format 'HH:mm:ss') Setting up Active Directory Florest"
                    $output = Install-ADDSForest @ADDSParams 3>$null

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss') Preparing system for restart and autologon"
                    Set-AutoLogon -DefaultUsername "Administrator" -DefaultPassword $AdminPassword -DefaultDomainName $ADDSParams['DomainNetbiosName']
                    Set-NextStage
                    Restart-Computer -Force  
                }
            '4' { Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Resuming Script: Stage $($Global:ScriptStage) - Install and Configure Domain Controller Roles and Services"
                    $Domain = Get-ADDomain
                    $DomainDN = ($Domain).DistinguishedName
                    $DomainPDC = ($Domain).PDCEmulator
                    $DomainForest = ($Domain).Forest
                    $DomainControllerFQDN = ([System.Net.Dns]::GetHostByName(($env:computerName))).Hostname
                    $CurrentNetworkAddress = (Get-NetIPConfiguration | Where-Object { ($_.IPv4DefaultGateway -ne $null) -and ($_.NetAdapter.Status -ne "Disconnected") } ).Ipv4Address.IpAddress
                    $DNSScavengingSchedule = New-TimeSpan -Days 7 -Hours 0 -Minutes 0 -Seconds 0

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Configure $Hostname as authoritative time server"
                    Stop-Service w32time -WarningAction SilentlyContinue | Out-Null
                    $Output = w32tm /config /syncfromflags:manual /manualpeerlist:"0.europe.pool.ntp.org,0x1 1.europe.pool.ntp.org,0x1 2.europe.pool.ntp.org,0x2 3.europe.pool.ntp.org,0x2" /reliable:yes 2>&1 | Out-Null
                    Start-Service w32time -WarningAction SilentlyContinue | Out-Null

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Configuring DNS role"
                    Add-DnsServerResourceRecordA -Name "gw1" -ZoneName "$DomainForest" -IPv4Address $NetworkGateway -TimeToLive 01:00:00 -ComputerName $DomainControllerFQDN
                    if(((Get-DnsServerForwarder).IPAddress).Count -gt 0){ $(Get-DnsServerForwarder | Remove-DnsServerForwarder -WarningAction SilentlyContinue -Force -confirm:$false) | Out-Null }
                    Add-DnsServerForwarder -IPaddress $DNSFowarders | Out-Null
                    Set-DnsServerScavenging -ApplyOnAllZones:$true -RefreshInterval $DNSScavengingSchedule -ScavengingInterval $DNSScavengingSchedule -NoRefreshInterval $DNSScavengingSchedule
                    Restart-Service -Name DNS | Out-Null

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Installing and configuring DHCP role"
                    $Output = Install-WindowsFeature DHCP -IncludeManagementTools 3>$null
                    Add-DhcpServerInDC -DnsName "$DomainControllerFQDN" -ipaddress "$CurrentNetworkAddress"
                    Set-DhcpServerv4OptionValue -DnsDomain "$DomainForest" -DnsServer "$CurrentNetworkAddress"
                    Set-DhcpServerv4OptionValue -OptionId "42" -Value "$CurrentNetworkAddress"
                    # Clear DHCP Post-Installation Notification from Server Dashboard
                    Set-ItemProperty –Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 –Name ConfigurationState –Value 2

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Enable Active Directory Recyble Bin and Copy PolicyDefinitions folder to Domain SYSVOL"
                    Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $DomainForest -Confirm:$false 3>$null
                    Copy-Item -Path $env:windir\PolicyDefinitions -Destination $env:windir\SYSVOL\domain\Policies -Recurse -Force                   

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Creating an organized OU structure and populate it with realistic demo users"
                    New-ADOrganizationalUnit -Name "Corp" -Path $DomainDN 
                    $MainOrgUnits = @('Administrators','Groups','Service Accounts','Users','Workstations')
                    $MainOrgUnits | ForEach-Object { New-ADOrganizationalUnit -Name $_ -Path "OU=Corp,$DomainDN " -ProtectedFromAccidentalDeletion:$true  }
                    if($DomainUPN){ Get-ADForest | Set-ADForest -UPNSuffixes @{add="$DomainUPN"} }else{ $DomainUPN = ($Domain).Forest }
                    New-DemoUserBatch -Country US -Results 25 -TargetOUName "OU=Users,OU=Corp,$DomainDN " -DomainPDC $DomainPDC -UserDefaultUPN $DomainUPN

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Creating and Configuring Active Directory Sites (including DNS Reverse lookup zones and DHCP scopes)"
                    $jsondata = Get-Content -Raw -Path "$PSScriptRoot\ActiveDirectorySites.json"  | ConvertFrom-Json
                    foreach($Site in ($jsondata).ActiveDirectorySites){
                        Add-DnsServerPrimaryZone -NetworkID "$(($Site).Network)/$(($Site).NetworkBits)" -ReplicationScope "Domain"
                    
                        Add-DhcpServerv4Scope -StartRange ($Site).DHCPSettings.StartRange -EndRange ($Site).DHCPSettings.EndRange -SubnetMask $(ConvertTo-IPv4MaskString -MaskBits ($Site).NetworkBits) -LeaseDuration ($Site).DHCPSettings.LeaseDuration -Name "$(($Site).Name) Branch Office" -Description "$(($Site).Name) Corp Net"
                        Set-DhcpServerv4OptionValue -ScopeId ($Site).Network -OptionId 3 -Value $Site.Gateway
                        foreach($Exclusion in ($Site).DHCPSettings.Exclusions){
                            Add-Dhcpserverv4ExclusionRange -ScopeId ($site).Network -StartRange ($Exclusion).Start -EndRange ($Exclusion).End
                        }
                    
                        if($site.Defaultsite -eq "Yes"){
                            Get-ADObject -SearchBase(Get-ADRootDSE).configurationNamingContext -Filter { Objectclass -EQ 'Site' } | Set-ADObject -DisplayName "$(($Site).Name)"
                            Get-ADObject -SearchBase(Get-ADRootDSE).configurationNamingContext -Filter { Objectclass -EQ 'Site' } | Rename-ADObject -NewName "$(($Site).Name)"
                        }else{ New-ADReplicationSite ($Site).Name }
                    
                        New-ADReplicationSubnet -Name "$(($site).Network)/$(($Site).NetworkBits)" -Site ($Site).Name -Server $DomainControllerFQDN
                        Set-ADReplicationSiteLink "DEFAULTIPSITELINK" -SitesIncluded @{Add="$(($Site).Name)"} -server $DomainControllerFQDN
                    }

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Disable Maps Broker Service"
                    Get-Service -Name "MapsBroker" | Set-Service -StartupType Disabled -Confirm:$false

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Running Best Practice Analyzer"
                    $ModelIDs = @("Microsoft/Windows/DirectoryServices", "Microsoft/Windows/DNSServer")
                    ForEach ($ModelID in $ModelIDs) {
                        $Output = Invoke-BpaModel -ModelId $ModelID -Mode All
                        $Output = Get-BpaResult -ModelID $ModelID -Filter NonCompliant | Where-Object Severity -EQ Error | Set-BpaResult -Exclude:$true
                    }

                    Register-DnsClient
                }
        }
    }Catch{
        $_.Exception.ItemName
        $_.Exception.Message
        Pause
    }    
}

End{
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        Set-ItemProperty $RegPath "AutoAdminLogon" -Value "0" -type String
        Set-ItemProperty $RegPath "AutoLogonCount" -Value "$AutoLogonCount" -type DWord
        Set-ItemProperty $RegPath "DefaultUsername" -Value "" -type String  
        Set-ItemProperty $RegPath "DefaultPassword" -Value "" -type String
        Set-ItemProperty $RegPath "DefaultDomainName" -Value ""
}
