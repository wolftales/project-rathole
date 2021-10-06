Powershell Commands to build a custom image

Install-Module -Name VMware.PowerCLI

$env:PSModulePath
cd .\OneDrive\Documents\WindowsPowerShell\
cd C:\Program Files\WindowsPowerShell\Modules
cd C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules

ls
Get-ChildItem * -Recurse | Unblock-File
Get-Module -Name VMware.PowerCLI -ListAvailable
Update-Module -Name VMware.PowerCLI

cd ~/
ls
cd .\Downloads\vmware\
ls
pwd

Add-EsxSoftwareDepot C:\Users\wolft\Downloads\vmware\Net-Community-Driver_1.2.0.0-1vmw.700.1.0.15843807_1802883...
Import-Module VMware.ImageBuilder
Get-ExecutionPolicy
Get-ExecutionPolicy -List
Get-ExecutionPolicy -Scope CurrentUser
Set-ExecutionPolicy -ExecutionPolicy AllSigned
Get-ExecutionPolicy -List

Import-Module VMware.ImageBuilder
Import-Module VMware.ImageBuilder

Add-EsxSoftwareDepot C:\Users\wolft\Downloads\vmware\VMware-ESXi-7.0U2a-17867351-depot-NUC-update.zip
Add-EsxSoftwareDepot C:\Users\wolft\Downloads\vmware\Net-Community-Driver_1.2.0.0-1vmw.700.1.0.15843807_1802883...

Get-EsxImageProfile | ft Name

New-EsxImageProfile -CloneProfile ESXi-7.0U2a-17867351-standard -Name ESXi-7.0U2a-17867351-NUC-update -Vendor "...

Add-EsxSoftwarePackage -ImageProfile ESXi-7.0U2a-17867351-NUC-update -SoftwarePackage Net-Community-Driver -Force

Add-EsxSoftwareDepot C:\Users\wolft\Downloads\vmware\Net-Community-Driver_1.2.0.0-1vmw.700.1.0.15843807_1802883...

Set-EsxImageProfile -AcceptanceLevel CommunitySupported –ImageProfile ESXi-7.0U2a-17867351-NUC-update
Export-EsxImageProfile -ImageProfile ESXi-7.0U2a-17867351-NUC-update -FilePath C:\Users\wolft\Downloads\vmware\...

ls

Add-EsxSoftwareDepot .\VMware-ESXi-7.0U2a-17867351-depot.zip
Add-EsxSoftwareDepot .\VMware-ESXi-7.0U2a-17867351-depot.zip -Force
Add-EsxSoftwareDepot .\VMware-ESXi-7.0U2a-17867351-depot.zip
ls
Add-EsxSoftwareDepot .\Net-Community-Driver_1.2.0.0-1vmw.700.1.0.15843807_18028830.zip

Get-EsxImageProfile | ft Name

Remove-EsxSoftwareDepot .\VMware-ESXi-7.0U2a-17867351-depot.zip

pwd
ls

Add-EsxSoftwareDepot C:\Users\wolft\Downloads\vmware\VMware-ESXi-7.0U2a-17867351-depot.zip
Remove-EsxSoftwareDepot C:\Users\wolft\Downloads\vmware\VMware-ESXi-7.0U2a-17867351-depot.zip
Remove-EsxSoftwareDepot -SoftwareDepot C:\Users\wolft\Downloads\vmware\VMware-ESXi-7.0U2a-17867351-depot.zip
Add-EsxSoftwareDepot https://hostupdate.vmware.com/software/VUM/PRODUCTION/main/vmw-depot-index.xml

Get-EsxSoftwareDepot
Remove-EsxSoftwareDepot $DefaultSoftwareDepots
Get-EsxSoftwareDepot

Add-EsxSoftwareDepot C:\Users\wolft\Downloads\vmware\VMware-ESXi-7.0U2a-17867351-depot.zip
Get-EsxSoftwareDepot

Add-EsxSoftwareDepot .\Net-Community-Driver_1.2.0.0-1vmw.700.1.0.15843807_18028830.zip
Get-EsxSoftwareDepot

Add-EsxSoftwareDepot https://hostupdate.vmware.com/software/VUM/PRODUCTION/main/vmw-depot-index.xml
Get-EsxSoftwareDepot

Get-EsxImageProfile | ft Name
New-EsxImageProfile -CloneProfile ESXi-7.0U3-18644231-standard -Name ESXICUSTOM

Add-EsxSoftwarePackage -ImageProfile ESXICUSTOM -SoftwarePackage Net-Community-Driver -Force
Get-EsxSoftwareDepot

Add-EsxSoftwarePackage -ImageProfile ESXICUSTOM -SoftwarePackage net-community-driver -Force
Get-EsxSoftwarePackage
