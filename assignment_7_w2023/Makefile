Greeter: Greeter.c
	gcc -ansi -static -fno-stack-protector -z execstack -fno-pie -g -m32 Greeter.c -o Greeter

secure_greeter: Greeter_secure.c
	gcc -ansi -fno-stack-protector -g -m32 Greeter_secure.c -o SecGreeter
clean:
	rm Greeter SecGreeter
