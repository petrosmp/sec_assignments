all: rsa logger dict-lib acmonitor test_aclog  

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

dict-lib: dict.h dict.c
	gcc -Wall -fPIC -shared -o libdict.so dict.c

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
	rm -rf libdict.so

#-Wl,option
#           Pass option as an option to the linker.  If option contains commas, it is split into multiple options at the commas.  You can use this syntax to pass an argument
#           to the option.  For example, -Wl,-Map,output.map passes -Map output.map to the linker.  When using the GNU linker, you can also get the same effect with
#           -Wl,-Map=output.map.
