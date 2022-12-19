This assignment was to develop a tool to sniff and/or analyze network traffic
at the lowest level, intercepting packets right from the kernel.

The tool supports 2 main modes of operation, live capture and savefile analysis.
    1) Live Capture: The user provides the interface that the program should
       sniff on, and the capture starts. It can only be stopped by the user with
       a keyboard interrupt (Ctrl-C) or by an internal error. The capture traffic
       is analyzed and the results are saved in the log.txt file (will be overwritten
       if it already exists on program execution). On halting, the program will print
       out various statistics regarding the capture session.
    2) Savefile Analysis: The user provides the tool with a binary file that contains
       (raw) captured traffic. The program then parses the file, analyzing each packet
       and printing information about it on stdout (the output may not fit in the
       terminal so manually redirecting this to a file is a good idea). The program
       stops on end of file or on keyboard interrupt by the user. Again, before exiting,
       the program will print various statistics about the session.





COMPILATION AND EXECITION INSTRUCTIONS:
    - The program can be successfully compiled by running 'make', and running 'make clean' will
      remove the executables and the log file if they exist.
    - As per the project specification, the program offers the following options for
      command line arguments (also found when run with --help or -h):
        # -i <interface>
            Provide an interface to capture live on
        
        # -r <filename>
            Provide a file to read traffic from (assumed to be properly formatted, not checked)
        
        # -f "port <portnum>"
            Only process traffic that passes thorugh the specified port (either on source or destination
            of each packet).





FILTERING:
    The program supports a very basic form of display filtering (done by the program
    in user space). The user can provide a specific port that they are interested in
    and the program will only analyze and display information for traffic going through
    that specific port (either as source or as destination).





IMPLEMENTATION DETAILS:
    - This program uses libpcap in order to capture traffic from a live interface or
      to parse the binary file packet by packet. Specifically, it uses pcap_open_live()
      and pcap_open_offline() (respectively), which provide us with a session handle.
      That session handle is then used with pcap_dispatch() in a loop, so that a callback
      function is called for each packet in the stream (regardless of its origin - live or
      offline).
    - In order to analyze the packets while maintaining readability (and not just playing
      with numeric offsets), tokeep track of the network flows and to be able to detect TCP
      retransmissions* this program uses a variety of structures, most of them falling
      under 1 of 2 categories:
          > per-layer/protocol header structures (IP, TCP, UDP)
          > a network flow structure and a linked list of them.
      The above structures as well as the related macros and functions are defined in util.h
      and implemented in util.c.





NOTES:
    - The program was successfully compiled with gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0 and
      the version of libpcap used in development was libpcap version 1.10.1 (with TPACKET_V3),
      (as per libpcap's own pcap_lib_version()) which was downloaded and built from 
      https://www.tcpdump.org/release/libpcap-1.10.1.tar.gz, link found in https://www.tcpdump.org/index.html#latest-releases.





SOURCES:
    The header structures were designed in accordance with the RFCs of the respective protocols:
        - TCP: https://www.rfc-editor.org/rfc/rfc793.html
        - UDP: https://www.rfc-editor.org/rfc/rfc768
        - IP : https://www.rfc-editor.org/rfc/rfc791
    
    Regarding the code and libpcap:
        - https://www.tcpdump.org/pcap.html
        - http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf
        - https://man7.org/linux/man-pages/man3/getopt.3.html
        - https://man7.org/linux/man-pages/man3/pcap.3pcap.html
        - https://www.tcpdump.org/manpages/pcap-filter.7.html
        - https://man7.org/linux/man-pages/man3/pcap_setfilter.3pcap.html
    
    Regarding the more "theoretical" aspects of network knowledge required:
        - several chapters of https://gaia.cs.umass.edu/kurose_ross/index.php






*According to WireShark, in the test_pcap_5mins.pcap file there are 126 retrasmitted
TCP packets, however the simple mechanism the program employs to detect them produces
a different result (442 retransmissions).