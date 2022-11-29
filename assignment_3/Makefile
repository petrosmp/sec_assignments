all: logger acmonitor test_aclog rsa dict-lib test

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl -g

acmonitor: acmonitor.c 
	gcc -L. -Wl,-rpath=. acmonitor.c -o acmonitor -ldict

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

dict-lib: dict.h dict.c
	gcc -Wall -fPIC -shared -o libdict.so dict.c

test: test.c
	gcc -L. -Wl,-rpath=. -o test test.c -ldict
