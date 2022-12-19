onjly one filter supported, for multiplke filters e.g. port = 80 and host = ece.tuc.gr they have to be in the same expression

libpcap version used (verbatim from pcap_lib_version(), installed from https://www.tcpdump.org/release/libpcap-1.10.1.tar.gz, link found in https://www.tcpdump.org/index.html#latest-releases)
    libpcap version 1.10.1 (with TPACKET_V3)

As per the tutorial on https://www.tcpdump.org/pcap.html,
"OPENING THE DEVICE FOR SNIFFING" section, we should check if
the interface we are scanning on supports ethernet headers (or
any other link layer headers), which is skipped. We assume that
the program will only be used on interfaces that support the link
layer headers that we need (which are?)

check if lo is supported

sudo apt install netsniff-ng kai https://man7.org/linux/man-pages/man8/trafgen.8.html gia testing

https://man7.org/linux/man-pages/man3/getopt.3.html
https://man7.org/linux/man-pages/man3/pcap.3pcap.html
https://www.tcpdump.org/manpages/pcap-filter.7.html
https://man7.org/linux/man-pages/man3/pcap_setfilter.3pcap.html