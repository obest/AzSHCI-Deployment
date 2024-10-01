# Prepare Active Directory
## Download Preparation Module
Install-Module AsHciADArtifactsPreCreationTool -Repository PSGallery -Force
$azshciOUName = 'DC=xxxx,DC=yyyy,DC=de'
$azshciLCMUser = 'azchciadm'
$azshciLCMPassword = ConvertTo-SecureString 'asdfsafsdfgsdfhkjlsdfkhdsfkjhdsf' -AsPlainText -Force
$azshcicredential = New-Object System.Management.Automation.PSCredential ($azshciLCMUser, $azshciLCMPassword)
New-HciAdObjectsPreCreation -AzureStackLCMUserCredential $azshcicredential -AsHciOUName $azshciOUName 

# Prepare AzureStackHCI Hosts
$aschcihostname = '<Hostname>'

## Rename Computer
Rename-Computer -NewName $aschcihostname -Restart

## Network Configuration
### Renaming Network Adapters
Rename-NetAdapter -Name 'Port0' -NewName 'iDRAC NIC'
Rename-NetAdapter -Name 'Port1' -NewName 'LOM1'
Rename-NetAdapter -Name 'Port2' -NewName 'LOM2'
Rename-NetAdapter -Name 'Port3' -NewName 'SMB1'
Rename-NetAdapter -Name 'Port4' -NewName 'tNIC1'
Rename-NetAdapter -Name 'Port5' -NewName 'tNIC2'
Rename-NetAdapter -Name 'Port6' -NewName 'SMB2'

### Disable DHCP
Set-NetIPInterface -InterfaceAlias 'tNIC1', 'tNIC2' -Dhcp Disabled

### Disable Disconnected Adapters
Get-NetAdapter | Where-Object {$_.status -eq "disconnected"} | Disable-NetAdapter

### Assign Management IP Address to the first Adapter
New-NetIPAddress -InterfaceAlias 'tNIC1' -IPAddress <IPAddress> -DefaultGateway <DefaultGateway> -PrefixLength <Prefix> -AddressFamily IPv4 -Verbose
### Set VLAN ID for management adapter
Set-NetAdapter -Name 'tNIC1', 'tNIC2' -VlanID <VLANID> -Confirm: $false
### SET DNS Server for management adapter
Set-DnsClientServerAddress -InterfaceAlias 'tNIC1' -ServerAddresses <DNSServer>

# Power Schema auf High Performance
powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

## Enable Remote Desktop
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' 

## Exclude iRDAC USB NIC from cluster validation
New-Item -Path HKLM:\system\currentcontrolset\services\clussvc
New-Item -Path HKLM:\system\currentcontrolset\services\clussvc\parameters
New-ItemProperty -Path HKLM:\system\currentcontrolset\services\clussvc\parameters -Name ExcludeAdaptersByDescription -Value 'Remote NDIS Compatible Device'

## Configure time source 
w32tm /config /manualpeerlist:'<DNS IP>' /syncfromflags:manual /update

## Configure WinRM
winrm quickconfig

## Enable ICMP firewall rule
netsh advfirewall firewall add rule name='ICMP Allow incoming V4 echo request' protocol=icmpv4:8,any dir=in action=allow


# Azure ARC Registrierung

# Define the subscription where you want to register your server as Arc device
	$Subscription = "xxxxxxxxxxxxxxxxxx"
# Define the resource group where you want to register your server as Arc device
	$RG = "azashci-rg"
# Define the region you will use to register your server as Arc device
	$Region = "westeurope"
# Define the tenant you will use to register your server as Arc device
	$Tenant = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

#      https://microsoft.com/devicelogin

#Connect to your Azure account and Subscription
	Connect-AzAccount -SubscriptionId $Subscription -TenantId $Tenant -DeviceCode
#Get the Access Token for the registration
	$ARMtoken = (Get-AzAccessToken).Token
#Get the Account ID for the registration
	$id = (Get-AzContext).Account.Id


#Invoke the registration script. Use a supported region.
Invoke-AzStackHciArcInitialization -SubscriptionID $Subscription -ResourceGroup $RG -TenantID $Tenant -Region $Region -Cloud "AzureCloud" -ArmAccessToken $ARMtoken -AccountID $id



# Day One Operation
## Configure Page File
$blockCacheMB = (Get-Cluster).BlockCacheSize 
$pageFilePath = 'C:\pagefile.sys'
$initialSize = [Math]::Round(51200 + $blockCacheMB)
$maximumSize = [Math]::Round(51200 + $blockCacheMB)

$system = Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges
if ($system.AutomaticManagedPagefile) {
 $system.AutomaticManagedPagefile = $false
 $system.Put()
}
$currentPageFile = Get-WmiObject -Class Win32_PageFileSetting
if ($currentPageFile.Name -eq $pageFilePath)
{
 $currentPageFile.InitialSize = $InitialSize
 $currentPageFile.MaximumSize = $MaximumSize
 $currentPageFile.Put()
}
else
{
 $currentPageFile.Delete()
 Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{Name=$pageFilePath; 
InitialSize = $initialSize; MaximumSize = $maximumSize}
}

## Set Hardware Timeout for Space Port
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00002710 -Verbose
Restart-Computer -Force


