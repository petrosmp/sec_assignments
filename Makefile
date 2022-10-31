all: diffie-hellman RSA


diffie-hellman:
	gcc diffie-hellman.c -o dh_assign_1 -lgmp
RSA:
	gcc rsa_tool.c -o rsa_assign_1 -lgmp