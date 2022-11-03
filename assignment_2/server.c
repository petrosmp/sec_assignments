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
#define FAIL    -1
// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
SSL_CTX* InitServerCTX(void)
{
	/* load & register all cryptos, etc. */
	/* load all error messages */
	/* create new server-method instance */
	/* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    
    /* set the private key from KeyFile (may be the same as CertFile) */

    /* verify private key */

}
void ShowCerts(SSL* ssl)
{
	/* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        /* */
        printf("Subject: %s\n", line);
        free(line);
        /* */
        printf("Issuer: %s\n", line);
        free(line);
    }
    else
        printf("No certificates.\n");
}
void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024] = {0};
    int sd, bytes;
    const char* ServerResponse="<\Body>\
                               <Name>sousi.com</Name>\
                 <year>1.5</year>\
                 <BlogType>Embedede and c\c++<\BlogType>\
                 <Author>John Johny<Author>\
                 <\Body>";
    const char *cpValidMessage = "<Body>\
                               <UserName>sousi<UserName>\
                 <Password>123<Password>\
                 <\Body>";
	/* do SSL-protocol accept */
  /*else print "Invalid Message" */
  
	/* get socket connection */
	/* release SSL state */
  /* close connection */
}
int main(int count, char *Argc[])
{

//Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }
    // Initialize the SSL library
    /* initialize SSL */
    /* load certs */
    /* create server socket */
    while (1)
    {
			/* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
			/* get new SSL state with context */
			/* set connection socket to SSL state */
			/* service connection */
    }
		/* close server socket */
		/* release context */
}
