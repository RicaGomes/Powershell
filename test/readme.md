# Test
These scripts were created with the intent to automate the configuration and update of the DHCP role installed in to Hyper-V host and the DNS Server that is part of a Active Directory Directory Services in order to maintain a healthy domain and services.

## Getting Started

### Prerequisites

### Installation

Copy the <b>Action-UpdateDNSJson.ps1</b> script to the hyper-v host 
```powershell
.\Action-UpdateDNSJson.ps1 -Install -DCIpAddr 192.168.2.6
```
##### Arguments explanation
- <b>Install</b>: This flag is only meant to automate the initial deployment of the script. 
- <b>DCIpAddr</b>:

Next copy the <b>Action-UpdateDNSFowarders.ps1</b> script to the newly created domain controller
```powershell
.\Action-UpdateDNSFowarders.ps1 -Install
```
