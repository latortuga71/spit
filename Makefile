build:
	gcc -fPIC -DPIC -shared -rdynamic -o pam_spit.so pam_spit.c
