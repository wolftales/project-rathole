# Project `Rathole`
Onprem Private Cloud Automation Foundation

## Overview

This repo's goal is to assemble various pieces of predominately Ansible automation
to create a automation foundation to deploy, configure, and use a NetApp private
cloud solution.

### Components
1. ONTAP
2. StorageGRID
3. ActiveIQ Unified Manager
4. Ansible & Ansible AWX
5. NGINX
6. VMware Infrastructure


### ONTAP
ONTAP 9.9.1 Simulator OVA's
* VSIM (x2) - non-HA
* Single cluster
* Ethernet (x6)
    * e0a & e0b - clus1 & clus2
    * e0c - intercluster, node & cluster_mgmt
    * e0d - SVM LIFs 
    * e0e & e0f - ifgrp a0a

### StorageGRID
StorageGRID 11.5 OVA's
* Admin node (x2)
* Load-balancer (gateway) node (x1)
* Storage nodes (x4)

```
ansible-galaxy role install -f -p ./roles git+https://github.com/madlabber/deploy_ovf_storagegrid.git,main
```


### ActiveIQ Unified Manager
AIQUM 9.9 OVA (Currently running 9.10x2 EVP)

```
ansible-galaxy role install -f -p ./roles git+https://github.com/madlabber/deploy_ovf_aiqum.git,main
```

### Ansible & Ansible AWX
Ansible 2.9+  
Ansible AWX 13.0  
Collections:  
* netapp.ontap
* netapp.storagegrid


### NGINX
NGINX 1.20 for Webform / Portal

### VMware Infrastructure
VMware vCenter 7.0
