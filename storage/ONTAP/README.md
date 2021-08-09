#  Storage Architecture Summary

### ONTAP VSIMs

OS
2 X ONTAP 9.x in a HA configuration within a single cluster

Storgae
2 X data aggrs on each

Network
6 X ethernet connections - e0a .. e0f
e0a & e0b are cluster interconnects
e0c - assumed node & cluster_mgmt
e0d .. e0f are data connections
