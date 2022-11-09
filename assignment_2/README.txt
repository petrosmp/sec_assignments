This assignment was to implement a server and a client that can securely communicate
using TLS 1.2. The OpenSSL C library (https://www.openssl.org/) was used, so 
functions performing handshakes, certificate verification or encryption/decryption
were not implemented from scratch.

The following is a brief description of how the server and the client work:

  SERVER:
    - create the SSL context needed for the connection
    - load the certificate from the corresponding file
    - open a listener at a given port and accept connections
    - once a connection is established, wait for the client to
      initiate the SSL/TLS handshake (SSL_accept())
    - if the handshake was successfully completed and a 
      TLS/SSL connection was established, wait for the client to
      send application data
    - upon receiving application data from the client, calculate
      and send an appropriate response
  
  CLIENT:
    - create the SSL context needed for the connection
    - create a socket and connect to the given hostname and port
      (assuming that a server is listening there)
    - if the above socket connected to a server, initiate the
      SSL/TLS handshake (SSL_connect())
    - if the handshake was successfully completed and a TLS/SSL
      connections was established, prompt the user to enter a
      username and a password (application data) to send to the
      server
    - print the server's response





USAGE EXAMPLE:
  The server and client have to be compiled, which can be done by running make. make server
  or make client can also be used to only compile a specific program, and make clean will
  remove the compiled binaries.

  Once compilation is finished, there should be 2 new files, server and client.

  To start the server at a given port, run the following command:

    sudo ./server <port> (Example: sudo ./server 8082)
  
    sudo is needed because server calls the bind() syscall to bind a socket to a port, which
    requires elevated priviledges.

    in the example, the server will start listening on port 8082

  To launch a client that will attempt to connect to a server, run the following command:

    ./client <host> <port>  (Example: ./client 127.0.0.1 8082)

    127.0.0.1 is the localhost (loopback) address, an address that is associated with "this computer",
    as in the computer that refers to it. This means that the server is in the same machine. This
    could also be achieved by using the address found under every network interface (lo, ethx, wlanx etc)
    next to "inet" when we execute ifconfig.

    8082 is the port on which the server is listening on the host machine.





IMPORTANT NOTES:
  - In order for the tool to work, the server needs to have a valid SSL
    certificate. A self-signed certificate can be easily obtained by
    running the following command*:

      openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mycert.pem -out mycert.pem    

    A breakdown of this command, explaining what each parameter stands
    for can be found in openssl_command_analysis.txt.
  - Both tools were successfully compiled using gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0
  - The OpenSSL version that everything was developed and tested with was
    OpenSSL 1.1.1f.
  - Included in this folder is a screenshot of a packet sent from the client to the server
    during a test, captured with Wireshark. We can see that the application data is encrypted,
    and looks like noise to a potential attacker. This means that the connection between client
    and server is indeed secure.





IMPLEMENTATION NOTES:
  - Both the server and the client use the sockaddr_in struct to represent socket addresses.
    This means that the sockets can be used for connections through the internet
    as well (and not just on the same machine).
  - The client program is executing one-off, meaning that in the scenario of a successful
    connection, once the server responds to the application data, the client exits.
  - The server has a function (Servlet()) that is called after a client connects
    to the listener socket. This function calls SSL_accept() (as the skeleton file**
    requested) and is responsible for serving the connection (handling application
    data). It too (like the client) can only serve one request, and it then exits.
    To "combat" that, Servlet() is called in main() inside a while loop, thus allowing
    the user to keep the server running and connect from multiple clients (although no client
    will be served until the previous client is finished - a better way to implement this 
    would be to create a new thread to serve each connection). 
  - Since the project requirements only asked for one certificate, the client has no certificate.
    However, since the server has no reason to reject it, if the client presented a valid certificate,
    the connection would not fail. In order for the connection to fail, the server would have to
    explicitly request a certificate that the client would fail to provide.

* The command for the certificate and private key generation was altered to produce
  2048 bit long keys (both public/certificate and private) instead of 1024 bit long
  ones, because the 1024 bit long keys caused a crash with the following error:

    [...]SSL routines:SSL_CTX_use_certificate:ee key too small [...]

    (In LoadCertificates() we use SSL_CTX_use_certificate() that calls ssl_security_cert()
    (found at https://github.com/openssl/openssl/blob/master/ssl/t1_lib.c#L3050) and
    decides that the key is too small)

** "Skeleton file" refers to the file that was given alongside the project specification.





SOURCES:
  Sockets:
    - https://www.geeksforgeeks.org/socket-programming-cc/
    - https://www.csd.uoc.gr/~hy556/material/tutorials/cs556-3rd-tutorial.pdf
    - https://man7.org/linux/man-pages/man2/socket.2.html
    - https://man7.org/linux/man-pages/man7/ip.7.html
    - https://man7.org/linux/man-pages/man7/unix.7.html
    - https://man7.org/linux/man-pages/man5/protocols.5.html
    - https://man7.org/linux/man-pages/man2/bind.2.html
    - https://pubs.opengroup.org/onlinepubs/009695399/functions/inet_addr.html
    - https://man7.org/linux/man-pages/man2/connect.2.html
    - https://man7.org/linux/man-pages/man2/listen.2.html
    - https://man7.org/linux/man-pages/man7/capabilities.7.html
    - https://man7.org/linux/man-pages/man3/gethostbyname.3.html

  OpenSSL:
    - https://www.openssl.org/docs/man1.1.1/man3/SSL_set_fd.html
    - https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_new.html
    - https://www.openssl.org/docs/man1.1.1/man7/ssl.html
    - https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html
    - https://www.openssl.org/docs/man1.1.1/man3/SSL_accept.html
    - https://www.openssl.org/docs/manmaster/man3/SSL_get_certificate.html
    - https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_verify.html
    - https://stackoverflow.com/questions/71674624/openssl-how-to-request-client-certificate-but-dont-verify-it

  Not strictly needed for the project, mainly regarding OpenSSL's internals:
    - https://docs.huihoo.com/doxygen/openssl/1.0.1c/structssl__ctx__st.html
    - https://github.com/openssl/openssl/blob/master/ssl/statem/README.md
    - https://wiki.openssl.org/index.php/BIO
    - https://www.openssl.org/docs/man1.0.2/man3/bn.html
    - https://en.wikipedia.org/wiki/ASN.1
    - https://docs.huihoo.com/doxygen/openssl/1.0.1c/crypto_2crypto_8h_source.html#l00285
    - https://github.com/openssl/openssl/tree/master/ssl in general

  Misc:
    - https://stackoverflow.com/a/745877
    - https://www.tutorialspoint.com/c_standard_library/c_function_sprintf.htm
