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
int OpenConnection(const char *hostname, int port)
{

}
SSL_CTX* InitCTX(void)
{
	/* Load cryptos, et.al. */
	/* Bring in and register error messages */
	/* Create new client-method instance */
	/* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void ShowCerts(SSL* ssl)
{
	/* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        /* */
        printf("Subject: %s\n", line);
       	/* */
        printf("Issuer: %s\n", line);
        free(line);
    }
    else
        printf("Info: No client certificates configured.\n");
}
int main(int count, char *strings[])
{
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    /* */
    /* create new SSL connection state */
		/* attach the socket descriptor */
		/* perform the connection */
    if ( SSL_connect(ssl) == FAIL )   /* connection fail */
        ERR_print_errors_fp(stderr);
    else
    {
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage = "<Body>\
                               <UserName>%s<UserName>\
                 <Password>%s<Password>\
                 <\Body>";
        printf("Enter the User Name : ");
        scanf("%s",acUsername);
        printf("\n\nEnter the Password : ");
        scanf("%s",acPassword);
				/* construct reply */
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
   			/* get any certs */
        /* encrypt & send message */
        /* get reply & decrypt */
	      /* release connection state */
    }
		/* close socket */
		/* release context */
    return 0;
}
