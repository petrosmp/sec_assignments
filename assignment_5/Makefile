all: pcap test

pcap: pcap_ex.c
	gcc -Wall pcap_ex.c -o pcap_ex -lpcap

test: test.c
	gcc -Wall test.c -o test -lpcap
