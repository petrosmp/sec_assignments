all: lib pcap #test

pcap: pcap_ex.c
	gcc -L. -Wl,-rpath=. pcap_ex.c -o pcap_ex -lutil -lpcap -Wall -g

#test: libutil.so test.c
#	gcc -L. -Wl,-rpath=. test.c -o test -lutil -lpcap -Wall

lib: util.h util.c
	gcc -Wall -fPIC -shared -o libutil.so util.c -g
