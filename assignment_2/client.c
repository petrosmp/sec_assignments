#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL    -1

/**
 * Create a socket and attempt to connect to hostname::port.
 * 
 * Return the socket descriptor of the connected socket.
 * 
 * Aborts on error, so any return value can be assumed to be valid.
*/
int OpenConnection(const char *hostname, int port) {

    int sd; /* socket descriptor */

    /* get host entity from name */
    struct hostent *host = gethostbyname(hostname);
    struct sockaddr_in host_addr;

    // check if host is valid (can this be done without netdb? include arpa/inet.h -> inetaddr)
    if (host == NULL) {
        perror(hostname);
        abort();
    }
    
    // intialize the socket
    sd = socket(AF_INET, SOCK_STREAM, 0);

    /*
     * Create the addr object (according to the rules of the AF_INET
     * address family, which is Linux's implementation of the IPv4
     * protocol)
    */
    bzero(&host_addr, sizeof(host_addr));
    host_addr.sin_family = AF_INET;
    host_addr.sin_port = htons(port);
    host_addr.sin_addr.s_addr = *(long *)(host->h_addr);

    // connect to the socket ()
    if (connect(sd, (struct sockaddr*)&host_addr, sizeof(host_addr)) == FAIL) {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;

}

/**
 * Create and return the client's SSL context object, containing the
 * ciphersuites that the client supports and other data needed
 * to establish a secure connection.
*/
SSL_CTX* InitCTX(void) {
	/* Load cryptos, et.al. */
    OpenSSL_add_all_algorithms();

	/* Bring in and register error messages */
    SSL_load_error_strings();

	/* Create new client-method instance */
    const SSL_METHOD *method = TLSv1_2_client_method();

	/* Create new context */
    SSL_CTX *ctx = SSL_CTX_new(method);

    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

/**
 * Print the peer's (server's) certificate info to stdout.
*/
void ShowCerts(SSL* ssl) {

	/* get the server's certificate */
    X509 *cert = SSL_get_peer_certificate(ssl);
    
    if ( cert != NULL ) {
        printf("Server certificates:\n");
        printf("Subject\n");
        X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert), 0, XN_FLAG_MULTILINE);
        printf("\n");
        fflush(stdout);
        printf("Issuer:\n");
        X509_NAME_print_ex_fp(stdout, X509_get_issuer_name(cert), 0, XN_FLAG_MULTILINE);
        printf("\n");
        fflush(stdout);
    }
    else {
        printf("Info: No client certificates configured.\n");
    }

    X509_free(cert);    // even if cert is NULL, this won't crash
}


int main(int count, char *strings[])
{

    // check if command line arguments are valid and parse them
    if ( count != 3 ) {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    char *hostname = strings[1];
    int port = atoi(strings[2]);

    /* initialize SSL */
    SSL_library_init(); /*load encryption and hash algo's in ssl*/
    SSL_CTX *ctx = InitCTX();

    /* establish a (non-SSL/TLS) connection to server*/
    int server = OpenConnection(hostname, port);

    /* create new SSL connection state */
    SSL *ssl = SSL_new(ctx);

	/* attach the socket descriptor */
    SSL_set_fd(ssl, server);

	/* perform the (SSL/TLS) connection */
    if ( SSL_connect(ssl) == FAIL )   /* connection fail */
        ERR_print_errors_fp(stderr);
    else
    {

        // TODO: no while loop here? only one off?
        printf("\n\nConnected to %s:%d with %s encryption\n", hostname, port, SSL_get_cipher(ssl));
        /* get any certs */
        ShowCerts(ssl);

        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage = "<Body>\
                               <UserName>%s<UserName>\
                 <Password>%s<Password>\
                 <\\Body>";

        printf("Enter the User Name : ");
        scanf("%s",acUsername);
        printf("Enter the Password : ");
        scanf("%s",acPassword);
		
        /* construct message */
        char message[1024];
        sprintf(message, cpRequestMessage, acUsername, acPassword);

        /* encrypt & send message */
        SSL_write(ssl, message, sizeof(message));

        /* get reply & decrypt */
        char reply[1024];
        SSL_read(ssl, reply, sizeof(reply));

        /* print server reply */
        printf("Server reply: %s\n", reply);

	    /* release connection state */
        SSL_free(ssl);
    }
		/* close socket */
        close(server);

		/* release context */
        SSL_CTX_free(ctx);

     return 0;
}
