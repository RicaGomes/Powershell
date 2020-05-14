# Test
These scripts were created with the intent to automate the configuration  and updating the DHCP Scopes in the Hyper-V host and the DNS Server that is part of a Active Directory Directory Services.

The way our VMAS environments are configured, after the Hyper-V host is powered on from a cold boot, it will grab the Network information from it's external network DHCP server (IP address, Network Subnet Mask, Gateway and DNS Servers). After the operating system booted, it will run the <b>Action-UpdateDHCPDNS</b> task (that will invoke the Action-UpdateDHCPDNS.ps1 script located under the C:\Scripts\ folder)

## Getting Started

### Prerequisites

### Installation

Copy the <b>Action-UpdateDNSJson.ps1</b> script to the redbox
```powershell
.\Action-UpdateDNSJson.ps1 -Install -DCIpAddr 192.168.2.6
```

Copy the <b>Action-UpdateDNSFowarders.ps1</b> script to the redbox
```powershell
.\Action-UpdateDNSFowarders.ps1 -Install
```
