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

## Updated role test - 2 Sept 21

`ansible-playbook -i ./test/privatej.yml ./test/test.yml -e "state=absent"`

Updates:
* Can manage `NIC` count
* Ability to remove `vsim's`
* Updated disk architecture - More human readable + supports larger sizes (allowing the use of virtual disks instead of simulated disks):
    * `vdevinit=some.wierd.string.of.codes`
    * `shelf0_disk_size=4000`
* Ability to set password . . . Can we `cluster join` now?

Test Plan:
1. Install updated role

`ansible-galaxy role install -f -p ./roles git+https://github.com/madlabber/deploy_ovf_vsim.git,main`

Verified new NIC and DISK code

2. Update to use `ovf_file` & Remove existing test vsims

Simply added `-e "state=absent`
Removal of `vsim-01` worked however `vsim-02` remained

3. Install new sims with:
    * 6 nics

Ran:
`ansible-playbook vm_deploy_ontap.yml -e "state=present"`

ANd got this:

```json
TASK [deploy_ovf_vsim : remove if absent or forced] ****************************
fatal: [localhost -> localhost]: FAILED! => {"msg": "The conditional check 'state == \"absent\" or force' failed. The error was: error while evaluating conditional (state == \"absent\" or force): 'force' is undefined\n\nThe error appears to be in '/home/ken/Documents/git/project-rathole/test/roles/deploy_ovf_vsim/tasks/main.yml': line 2, column 3, but may\nbe elsewhere in the file depending on the exact syntax problem.\n\nThe offending line appears to be:\n\n---\n- name: remove if absent or forced\n  ^ here\n"}
```

Is this the only place `force` is defined?

```yaml
- name: remove if absent or forced
  vmware_guest:
    hostname: '{{ vcenter_address }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'    
    validate_certs: no 
    name: '{{ vm_name }}'
    state: absent
    ***force: yes***
  delegate_to: localhost
  when: state == "absent" or force
  ```
Ran without `-e "state=present"`

Re-ran and got an add_nics error:
```yaml
TASK [deploy_ovf_vsim : add nics] **********************************************
fatal: [localhost]: FAILED! => {"reason": "Could not find or access '/home/ken/Documents/git/project-rathole/test/add_nics' on the Ansible Controller."}
```

4. see if `cluster join` works on `node-02` using `cluster-name`

Feedback:

README.md
* Serial number - thinking default is fine, but example could show alternate serial number
* I see updated disk varibles - but not sure how to use it vs what the default is - a short disk section?
* Add `NIC's` could comment that 4 is the default/minimum
* Dependencies - I see **community.vmware** in `add-nics` but not in the main task
* Using `set_admin_password` - unclear