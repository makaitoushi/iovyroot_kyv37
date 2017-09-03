# iovyroot
A root tool based on the [CVE-2015-1805 vulnerability](https://access.redhat.com/security/cve/cve-2015-1805)
It supports 32 and 64bit but requires absolute kernel addresses (see [offsets.c](jni/offsets.c))
poc was done by idler1984 https://github.com/idl3r/testcode

# iovyroot KYOCERA KYV37 ONLY
* device version 100.0.2210

Kernel Symbol
========

* ptmx_fops
 `0xffffffc0011da4a8`

* joploc
 `0xffffffc00025A548`
 
* jopret
 `0xffffffc00017a0cc`

* prepare_kernel_cred

 `0xffffffc0000c1b30`
 
* commit_cred

 `0xffffffc0000c17d0`
 
* reset_security_ops

 `0xffffffc00023d3d0`
 
* selinux_enforcing

 `0xffffffc00112d19c`
 
* selinux_enabled
 `0xffffffc000f3c780`

 
* template
 ``
