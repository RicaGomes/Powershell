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
- <b>Install</b>: This flag is only meant to automate the initial deployment of the script on the Hyper-V host. The <b>Install</b> flag will trigger the following actions:
  - Disable the existing <B>Action-UpdateDHCPDNS</B> scheduled task
  - Create a new scheduled task to run the <B>Action-UpdateDNSJson.ps1</B>
  - Reconfigure the DHCP Scopes lease duration for 12 hours, option "006 DNS Servers" to match the domain controller IP Address (set by the flag <b>DCIpAddr</b>
- <b>DCIpAddr</b>:

Next copy the <b>Action-UpdateDNSFowarders.ps1</b> script to the newly created domain controller
<b>
```powershell
cd c:\Scripts\
.\Action-UpdateDNSFowarders.ps1 -Install
```
</b>
