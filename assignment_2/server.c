#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define FAIL                -1
#define PRIVATE_KEY_FILE    "mycert.pem"
#define CERTIFICATE_FILE    "mycert.pem"

/**
 * Create a socket, bind it to the given port, and mark it as a listener.
 * 
 * Return its socket descriptor, which should be ready to accept().
 * 
 * Aborts on error, so any return value can be assumed to be valid.
*/
int OpenListener(int port) {

    int sd; /* socket descriptor */
    struct sockaddr_in addr;

    // intialize the socket
    sd = socket(PF_INET, SOCK_STREAM, 0);

    /**
     * Create the addr object (according to the rules of the AF_INET
     * address family, which is Linux's implementation of the IPv4
     * protocol)
    */
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    // bind the socket descriptor to the address (root access needed)
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) == FAIL) {
        perror("can't bind port");
        abort();
    }

    // mark the socket as a passive (listener) one, basically preparing to accept()
    if (listen(sd, 10) == FAIL) {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

/**
 * Check if the user executing the program is root.
*/
int isRoot() {
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

/**
 * Create and return the server's SSL context object, containing the
 * ciphersuites that the server supports and other data needed
 * to establish a secure connection.
*/
SSL_CTX* InitServerCTX(void) {

	/* load & register all cryptos, etc. */
    OpenSSL_add_all_algorithms();

	/* load all error messages */
	SSL_load_error_strings();

    /* create new server-method instance */
    const SSL_METHOD *meth = TLSv1_2_server_method();
	
    /* create new context from method */
    SSL_CTX *ctx = SSL_CTX_new(meth); 

    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

/**
 * Load the server's certificate into the SSL context object.
*/
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "The specified private key is not the one corresponding to the server's certificate!\n");
        abort();
    }
}

/**
 * Print the server's certificate info to stdout.
*/
void ShowCerts(SSL* ssl) {
	
    /* Get certificates (if available) */
    X509 *cert = SSL_get_peer_certificate(ssl); 

    if ( cert != NULL ) {
        printf("Client certificates:\n");
        printf("Subject:\n");
        X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert), 0, XN_FLAG_MULTILINE);
        printf("Issuer:\n");
        X509_NAME_print_ex_fp(stdout, X509_get_issuer_name(cert), 0, XN_FLAG_MULTILINE);
        printf("\n");
    }
    else {
        printf("Client has no certificates.\n");
    }

    X509_free(cert);    // even if cert is NULL, this won't crash
}

/**
 * Actual server function called once a (basic) connection with the 
 * client is established.
 *  - Upgrades the connection to use SSL/TLS
 *  - Uses OpenSSL's secure functions to perform I/O operations on
 *    the connection
 *  - Responds to the client 
*/
void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024] = {0};
    int sd, bytes;
    const char* ServerResponse="<\\Body>\
                               <Name>sousi.com</Name>\
                 <year>1.5</year>\
                 <BlogType>Embedede and c\\c++<\\BlogType>\
                 <Author>John Johny<Author>\
                 <\\Body>";
    const char *invalidMessageResponse = "Invalid Message";
    const char *cpValidMessage = "<Body>\
                               <UserName>sousi<UserName>\
                 <Password>123<Password>\
                 <\\Body>";

    printf("Establishing SSL/TLS connection...\n");
	/* do SSL-protocol accept */
    if (SSL_accept(ssl) != FAIL) {
        printf("SSL/TLS connection established. Messages from now on will be encrypted with %s\n", SSL_get_cipher_name(ssl));
        /* if any input is detected, handle it */
        bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes > 0) {
            /* if the input is the valid message, send the response */
            buf[bytes-1] = 0;
            if (!strcmp(buf, cpValidMessage)) {
                SSL_write(ssl, ServerResponse, strlen(ServerResponse));
                printf("Valid request received, appropriate response sent.\n");
            }
            else {  /*else print "Invalid Message" */
                SSL_write(ssl, invalidMessageResponse, strlen(invalidMessageResponse));
                printf("Invalid request received, error response sent.\n");
            }
        }
    }
    else {
        ERR_print_errors_fp(stderr);
    }

    /**
     * We will only get here if SSL_accept fails. This should be also
     * what happens when a SIGINT (Ctrl-C) signal is received.
    */

    /* get socket connection */
    sd = SSL_get_fd(ssl);

    /* release SSL state */
    SSL_free(ssl);

    /* close connection */
    close(sd);
}


int main(int count, char *Argc[]) {

    //Only root user have the permsion to run the server
    if(!isRoot()) {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }

    // check if the arguments are valid
    if ( count != 2 ) {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }

    printf("Initializing server...\n");

    // Initialize the SSL library
    /* initialize SSL */
    SSL_library_init();
    SSL_CTX *ctx = InitServerCTX();
    
    /* load certs */
    LoadCertificates(ctx, CERTIFICATE_FILE, PRIVATE_KEY_FILE); 


    /* create server socket */
    int port = atoi(Argc[1]);   // convert ascii port number to int
    int server = OpenListener(port);
    
    // since SSL_accept is in servlet, the loop has got to be there too, meaning this one is not needed
    printf("Server running. Waiting for connections...\n");
    while (1)
    {
        struct sockaddr_in peer_addr; // struct to hold peer's address
        socklen_t peer_addr_len = sizeof(peer_addr);    // needed for accept, it has __restrict__ for its pointer args, so we cant just sizeof() (https://stackoverflow.com/a/745877)

		/* accept connection as usual */
        int peer = accept(server, (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (peer == FAIL) {
            perror("error accepting connection");
            exit(-1);
        }

        printf("\n\nAccepted connection request from %s:%d\n",inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port));

        /* get new SSL state with context */
        SSL *ssl = SSL_new(ctx);

        /* set connection socket to SSL state */
		SSL_set_fd(ssl, peer);

        /* print peer's certificates */
        ShowCerts(ssl);

        /* service connection */
        Servlet(ssl); 
    }
		/* close server socket */
        close(server);
		
        /* release context */
        SSL_CTX_free(ctx);
}
