# Test
These scripts were created with the intent to automate the configuration and update of the DHCP role installed in to Hyper-V host and the DNS Server that is part of a Active Directory Directory Services in order to maintain a healthy domain and services.

## Getting Started

### Prerequisites

### Installation

Copy the <b>Action-UpdateDNSJson.ps1</b> script to the c:\Scripts\ folder in the system drive of your Hyper-v host. Open a powershell command line as administrator, navigate to the folder Scripts folder and execute the script as follows:
<b>
```powershell
cd c:\Scripts\
.\Action-UpdateDNSJson.ps1 -Install -DCIpAddr 192.168.2.6
```
</b>
##### Arguments explanation
- <b>Install</b>: This flag is only meant to automate the initial deployment of the script. The <b>Install</b> flag will trigger the following actions:
  - It will disable the <B>Action-UpdateDHCPDNS</B> scheduled task
  - Will create a new scheduled task to run the <B>Action-UpdateDNSJson.ps1</B>
- <b>DCIpAddr</b>:

Next copy the <b>Action-UpdateDNSFowarders.ps1</b> script to the newly created domain controller
```powershell
cd c:\Scripts\
.\Action-UpdateDNSFowarders.ps1 -Install
```
