all: lib pcap

pcap: pcap_ex.c
	gcc -L. -Wl,-rpath=. pcap_ex.c -o pcap_ex -lutil -lpcap -Wall -g

lib: util.h util.c
	gcc -Wall -fPIC -shared -o libutil.so util.c -g

clean:
	rm -rf libutil.so
	rm -rf pcap_ex
	rm -rf log.txt