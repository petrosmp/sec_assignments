all: logger acmonitor test_aclog rsa yes-hello

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl -g

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

rsa: rsa_tool.c
	gcc rsa_tool.c -o rsa_assign_1 -lgmp

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
