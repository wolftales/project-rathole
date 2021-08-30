```
ansible-galaxy role install -f -p ./roles git+https://github.com/madlabber/deploy_ovf_storagegrid.git,main
```

Integrations steps:
1. Create a test directory to install roles in
2. Update varibles to align with role varible syntax, for example nested vs flat "vcenter.address vs vcenter_address"
```
vcenter_address: "{{ vcenter.address }}"
vcenter_username: "{{ vcenter.username }}"
vcenter_password: "{{ vcenter.password }}"
vcenter_datacenter: "{{ vcenter.datacenter }}"
vcenter_cluster: "{{ vcenter.cluster }}"
vm_datastore: "{{ vcenter.datastore }}"
```
3. Adjust "files" directory so role can find SG files - `ln-s ../files`
