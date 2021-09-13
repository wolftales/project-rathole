# NetApp StorageGRID Automation

The goal of these automation pieces are to:
1. Leverage Ansible where possible
2. Configure - Basic GRID administriation
3. Provision - Common provisioning workflows

## Deployment Notes
1. Deploy StorageGRID with anisble role
2. Approve nodes & Configure minimal services through UI
    * provisioning password: `exampleLab`
    * GRID administrative "root" password: `exampleGRID`
3. Configure GRID settings with Ansible:
    * Update DNS
    * Update NTP
    * Admin group - exampleAdmins
    * Admin users - gridadmins[1, 2, 3]
4. 

## Provisioning Notes


References:

Automating StorageGRID Operations with Ansible
https://netapp.io/2020/06/26/Automating-StorageGRID-Operations-with-Ansible/

Introducing Ansible Modules for StorageGRID
https://netapp.io/2020/06/26/ansible-modeules-for-storagegrid/

Nice summary of modules & their intended use

Adrian Bronder's NetApp Automationo repo
https://github.com/AdrianBronder/ntap-automation 

