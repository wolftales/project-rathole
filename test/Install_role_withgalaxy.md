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
    - can leverage ovf_file varible

Result:
* Worked like the older role did
* 1 caveat was all nodes were created - need to figure out what got changed
    * Added: ` and sg.storage1.deploy is true` to the conditional statement

Feedback:
* Should try to align varible management
* Should see about updating the "Task name dynamically" to help illustrate progress better

deploy_ovf_vsim
```
ansible-galaxy role install -f -p ./roles git+https://github.com/madlabber/deploy_ovf_vsim.git,main
```
