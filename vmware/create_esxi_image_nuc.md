Powershell Commands to build a custom image

References:

Creating custom ESXi Image By Rajesh Radhakrishnan

https://www.vembu.com/blog/how-to-build-custom-esxi-image/

Pink Screen | ESXi 6.5 Failed Install | Unable to Verify Acceptance Level. Unable to Check Acceptance Level: None

https://communities.vmware.com/t5/ESXi-Discussions/Pink-Screen-ESXi-6-5-Failed-Install-Unable-to-Verify-Acceptance/td-p/504350


## Step #0:

Open PowerCLI

From  "PowerCLI C:\>"  change directory to Workbench

--> cd c:\esxi  <press enter>

## Step #1:

From PowerCLI C:\esxi> run ESXi-Customizer-PS Script, select ESXi OLB Version (-vXX), select ZIP (-ozip) and download to Workbench

PowerCLI C:\esxi> .\ESXi-Customizer-PS-v2.5.ps1 -vXX -ozip  <press enter>

Wait for CLI to complete the task.  After download is complete, verify that ESXi OLB for the -vXX you selected has been downloaded onto the Workbench.  Running this script with these two switches will cause CLI to write the ESXi OLB into the Workbench.

## Step #2:

Check Acceptance Level of the ESXi OLB you just downloaded to your Workbench

add-esxsoftwaredepot [specify full path to the ESXi OLB now in your Workbench]  <press enter>

get-esximageprofile [type just the command only]  <press enter>

--> Note "Acceptance Level" of the ESXi OLB sitting in your Workbench

--> More than likely the acceptance level is not "CommunitySupported" and will need to be changed

## Step #3:

Change Acceptance Level of ESXi OLB sitting in Workbench

new-esximageprofile -cloneprofile [name of OLB only.  do not include .zip file extension] -name ["name of clone in quotes"]  <press enter>

---> Vendor: [enter a new vendor name for the clone]  <press enter>

set-esximageprofile -name [enter name of clone] -acceptancelevel [enter CommunitySupported]  <press enter>

---> ImageProfile: [enter name of clone]  <press enter>

## Step #4:

List Available Image Profiles

get-esximageprofile  <press enter>

---> Note Acceptance Level of new Clone

## Step #5:

Inject OLB VIB into ESXi Clone and confirm post-injection Acceptance Level of Clone

add-esxsoftwaredepot [type full path to: net55-r8168-8.039.01-napi-offline_bundle.zip]  <press enter>

---> Note that Depot Url shows full path to the RealTek Driver OLB VIB

add-esxsoftwarepackage [type just the command only]  <press enter>

---> ImageProfile: [enter name of clone]  <press enter>

---> SoftwarePackage: [enter name of driver being injected 'net55-r8168' without quotes]  <press enter>

---> <press enter> again to return cursor to Workbench

get-esxsoftwarepackage  -acceptancelevel  [type 'CommunitySupported' without quotes]  <press enter>

---> This will list all VIBs within the Clone that have an Acceptance Level = CommunitySupported

---> You should now see "net55-r8168" with vendor RealTek version 8.039.01-napi in the list

## Step #6:

Confirm OLB VIB (net55-r8168) Injection

(get-esximageprofile ESXi-6.0.0-20161104001-standard-clone#1).viblist  <press enter>

---> Note1: The above command must be wrapped with parenthesis (string here).viblist

---> Note2: Scroll through the list of Vibs and make certain that net55-r8186 is now within the Vib list

## Step #7:

Export ESXi Clone to Workbench as ZIP (Bundle)

`export-esximageprofile -imageprofile  [enter name of clone]  -exporttobundle  -filepath  [full path to c:\esxi\"name_of_clone.zip"]  -nosignaturecheck  -Force  <press enter>`

Note here the use of switches "-nosignaturecheck" and "-force".

## Step #8:

Export ESXi Clone to Workbench as ISO (Installable)

`export-esximageprofile -imageprofile  [enter name of clone]  -exporttoiso  -filepath  [full path to c:\esxi\"name _of_clone.iso"]  -nosignaturecheck  -Force  <press enter>`

Note: here the use of switches "-nosignaturecheck" and "-force".


## Step #9:

Create Bootable USB Using Rufus

## Step #10:

Boot system with USB boot drive


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

Get-EsxSoftwarePackage | findstr -i 15843807
Add-EsxSoftwarePackage -ImageProfile ESXICUSTOM -SoftwarePackage net-community -Force

Get-EsxSoftwareDepot

Get-EsxImageProfile | ft Name 
Get-EsxImageProfile | ft name | findstr -i ESXICUSTOM

Remove-EsxSoftwareDepot https://hostupdate.vmware.com/software/VUM/PRODUCTION/main/vmw-depot-index.xml

Get-EsxImageProfile | ft Name

get-EsxImageProfile

Set-EsxImageProfile -AcceptanceLevel CommunitySupported –ImageProfile ESXICUSTOM

Name                           Vendor          Last Modified   Acceptance Level
----                           ------          -------------   ----------------
ESXICUSTOM                     Wolftales, LTD. 10/6/2021 10... CommunitySupported

Export-EsxImageProfile -ImageProfile ESXICUSTOM -FilePath C:\Users\wolft\Downloads\vmware\ESXI-7.0.2-CUSTOM.iso -ExportToIso -Force

# Get started with VMware.PowerCLI

Install-Module -Name VMware.PowerCLI

$env:PSModulePath
cd .\OneDrive\Documents\WindowsPowerShell\
cd C:\Program Files\WindowsPowerShell\Modules
cd C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules

ls
Get-ChildItem * -Recurse | Unblock-File
Get-Module -Name VMware.PowerCLI -ListAvailable

cd ~/
Update-Module -Name VMware.PowerCLI
Import-Module VMware.ImageBuilder

# Remove-All - refresh
Remove-EsxSoftwareDepot $DefaultSoftwareDepots
Remove-EsxSoftwareDepot https://hostupdate.vmware.com/software/VUM/PRODUCTION/main/vmw-depot-index.xml

Get-EsxSoftwareDepot

# Load SoftwareDepot(s)

Add-EsxSoftwareDepot C:\Users\wolft\Downloads\vmware\VMware-ESXi-7.0U2a-17867351-depot.zip

Depot Url
---------
zip:C:\Users\wolft\Downloads\vmware\VMware-ESXi-7.0U2a-17867351-depot.zip?index.xml


Add-EsxSoftwareDepot C:\Users\wolft\Downloads\vmware\Net-Community-Driver_1.2.0.0-1vmw.700.1.0.15843807_18028830.zip

Depot Url
---------
zip:C:\Users\wolft\Downloads\vmware\Net-Community-Driver_1.2.0.0-1vmw.700.1.0.15843807_18028830.zip?index.xml


Get-EsxSoftwareDepot

Depot Url
---------
zip:C:\Users\wolft\Downloads\vmware\VMware-ESXi-7.0U2a-17867351-depot.zip?index.xml
zip:C:\Users\wolft\Downloads\vmware\Net-Community-Driver_1.2.0.0-1vmw.700.1.0.15843807_18028830.zip?index.xml

## Check "Acceptance Level"

Get-EsxImageProfile

Name                           Vendor          Last Modified   Acceptance Level
----                           ------          -------------   ----------------
ESXi-7.0U2a-17867351-no-tools  VMware, Inc.    4/9/2021 5:5... PartnerSupported
ESXi-7.0U2a-17867351-standard  VMware, Inc.    4/29/2021 12... PartnerSupported

## Clone Image & Set Image to CommunitySupported 

Get-EsxImageProfile

Name                           Vendor          Last Modified   Acceptance Level
----                           ------          -------------   ----------------
ESXi-7.0U2a-17867351-no-tools  VMware, Inc.    4/9/2021 5:5... PartnerSupported
ESXi-7.0U2a-17867351-standard  VMware, Inc.    4/29/2021 12... PartnerSupported

## Clone (Create) new image)

Get-EsxImageProfile | ft Name

Name
----
ESXi-7.0U2a-17867351-no-tools
ESXi-7.0U2a-17867351-standard

New-EsxImageProfile -CloneProfile ESXi-7.0U2a-17867351-standard -Name ESXi-7.0U2-Custom -Vendor "Wolftales, LTD."

**Or**
New-EsxImageProfile -CloneProfile ESXi-7.0U2a-17867351-standard -Name ESXI-7.0U2a-CU
STOM

cmdlet New-EsxImageProfile at command pipeline position 1
Supply values for the following parameters:
(Type !? for Help.)
Vendor: Wolftales, LTD.

Name                           Vendor          Last Modified   Acceptance Level
----                           ------          -------------   ----------------
ESXi-7.0U2-Custom              Wolftales, LTD. 4/29/2021 12... PartnerSupported


PS C:\Users\wolft\Downloads\vmware> Get-EsxImageProfile | ft Name

Name
----
ESXi-7.0U2-Custom
ESXi-7.0U2a-17867351-no-tools
ESXi-7.0U2a-17867351-standard

## Set Image to CommunitySupported

PS C:\Users\wolft\Downloads\vmware> Get-EsxImageProfile

Name                           Vendor          Last Modified   Acceptance Level
----                           ------          -------------   ----------------
ESXi-7.0U2-Custom              Wolftales, LTD. 4/29/2021 12... PartnerSupported
ESXi-7.0U2a-17867351-no-tools  VMware, Inc.    4/9/2021 5:5... PartnerSupported
ESXi-7.0U2a-17867351-standard  VMware, Inc.    4/29/2021 12... PartnerSupported

Set-EsxImageProfile -name ESXi-7.0U2-Custom -AcceptanceLevel CommunitySupported

cmdlet Set-EsxImageProfile at command pipeline position 1
Supply values for the following parameters:
(Type !? for Help.)
ImageProfile: ESXi-7.0U2-Custom

Name                           Vendor          Last Modified   Acceptance Level
----                           ------          -------------   ----------------
ESXi-7.0U2-Custom              Wolftales, LTD. 10/7/2021 8:... CommunitySupported


## Check & Verify

Get-EsxImageProfile 

Name                           Vendor          Last Modified   Acceptance Level
----                           ------          -------------   ----------------
ESXi-7.0U2-Custom              Wolftales, LTD. 10/7/2021 9:... CommunitySupported
ESXi-7.0U2a-17867351-no-tools  VMware, Inc.    4/9/2021 5:5... PartnerSupported
ESXi-7.0U2a-17867351-standard  VMware, Inc.    4/29/2021 12... PartnerSupported

## Add Custom driver(s)

Add-EsxSoftwarePackage -ImageProfile ESXi-7.0U2-Custom -SoftwarePackage net-community -Force

Name                           Vendor          Last Modified   Acceptance Level
----                           ------          -------------   ----------------
ESXi-7.0U2-Custom              Wolftales, LTD. 10/7/2021 9:... CommunitySupported


Set-EsxImageProfile -AcceptanceLevel CommunitySupported –ImageProfile ESXI-7.0U2a-CUSTOM

Name                           Vendor          Last Modified   Acceptance Level
----                           ------          -------------   ----------------
ESXI-7.0U2a-CUSTOM             WOlftales, LTD. 10/6/2021 10... CommunitySupported

Get-EsxSoftwarePackage | findstr net-community
net-community            1.2.0.0-1vmw.700.1.0.15843807  VMW        5/7/2021 4:57...

## Export EsxImageProfile out to ISO
### Added `-nosignaturecheck`

Export-EsxImageProfile -ImageProfile ESXI-7.0U2a-CUSTOM -FilePath C:\Users\wolft\Downloads\vmware\ESXI-7.0.2-CUSTOM.iso -ExportToIso -nosignaturecheck -Force

Export-EsxImageProfile -ImageProfile ESXi-7.0U2-Custom -FilePath C:\Users\wolft\Downloads\vmware\ESXi-7.0U2-Custom.iso -ExportToIso -NoSignatureCheck -Force

