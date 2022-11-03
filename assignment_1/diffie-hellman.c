#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <string.h>

/*
    Options:
        -o path     Path to output file
        -p number   Prime number
        -g number   Primitive Root for previous prime number
        -a number   Private key A
        -b number   Private key B
        -h          This help message
*/

int main(int argc, char *argv[]){

    char *outfile_name;
    int p = -1;
    int g = -1;
    int a = -1;
    int b = -1;
    const char* help_message = "Options:\n\t-o path\t\tPath to output file\n\t-p number\tPrime number\n\t-g number\tPrimitive Root for previous prime number\n\t-a number\tPrivate key A\n\t-b number\tPrivate key B\n\t-h\t\tThis help message";

    // parse command line arguments
    for (int i=1; i<argc; i++){

        if (strcmp(argv[i], "-h") == 0) {
            printf("%s\n", help_message);
            exit(0);
        }
        else if (strcmp(argv[i], "-o") == 0) {
            if (i+1 >= argc) {
                printf("There is no value for parameter o. Please provide one. Use option -h for help.\n");
                exit(-1);
            }
            outfile_name = argv[i+1];
        }
        else if (strcmp(argv[i], "-p") == 0) {
            if (i+1 >= argc) {
                printf("There is no value for parameter p. Please provide one. Use option -h for help.\n");
                exit(-1);
            }
            p = atoi(argv[i+1]);
        }
        else if (strcmp(argv[i], "-g") == 0) {
            if (i+1 >= argc) {
                printf("There is no value for parameter g. Please provide one. Use option -h for help.\n");
                exit(-1);
            }
            g = atoi(argv[i+1]);
        }
        else if (strcmp(argv[i], "-a") == 0) {
            if (i+1 >= argc) {
                printf("There is no value for parameter a. Please provide one. Use option -h for help.\n");
                exit(-1);
            }
            a = atoi(argv[i+1]);
        }
        else if (strcmp(argv[i], "-b") == 0) {
            if (i+1 >= argc) {
                printf("There is no value for parameter b. Please provide one. Use option -h for help.\n");
                exit(-1);
            }
            b = atoi(argv[i+1]);
        }
    }

    // if after parsing arguments the path to the output file is NULL, an argument was missing
    if (outfile_name == NULL) {
        printf("Cannot proceed without an output file path! Please provide one. Use the -h option for help.\n");
        exit(-1);
    }

    if (a == -1) {
        printf("Cannot proceed without a value for parameter 'a'. Please provide one. Use the -h option for help.\n");
        exit(-1);
    }

    if (b == -1) {
        printf("Cannot proceed without a value for parameter 'b'. Please provide one. Use the -h option for help.\n");
        exit(-1);
    }

    if (p == -1) {
        printf("Cannot proceed without a value for parameter 'p'. Please provide one. Use the -h option for help.\n");
        exit(-1);
    }

    if (g == -1) {
        printf("Cannot proceed without a value for parameter 'g'. Please provide one. Use the -h option for help.\n");
        exit(-1);
    }

    /*
    ============================================================================================================================
    ============================================================================================================================
    ======================================================= PARSING OVER =======================================================
    ============================================================================================================================
    ============================================================================================================================
    */

    // import the inputs to GMP variables
    mpz_t gmp_p, gmp_g, gmp_a, gmp_b;
    mpz_init_set_ui(gmp_p, p);
    mpz_init_set_ui(gmp_g, g);
    mpz_init_set_ui(gmp_a, a);
    mpz_init_set_ui(gmp_b, b);

    // calculate public keys A, B
    mpz_t A, B;
    mpz_init(A);
    mpz_init(B);
    mpz_powm(A, gmp_g, gmp_a, gmp_p); // also mpz_powm_ui (for unsigned integers) and mpz_powm_sec (specifically developed for cryptographic purposed might be good alternatives here)
    mpz_powm(B, gmp_g, gmp_b, gmp_p);

    // calculate secret key both ways (Alice's and Bob's way) and verify that they are equal
    mpz_t alice_s, bob_s;
    mpz_init(alice_s);
    mpz_init(bob_s);
    mpz_powm(alice_s, B, gmp_a, gmp_p);
    mpz_powm(bob_s, A, gmp_b, gmp_p);

    // compare the secret keys
    if (mpz_cmp(alice_s, bob_s) != 0) { // >0 means a>b, <0 means a<b, 0 means equal
        printf("something has gone wrong");
    }

    // write the output to the file
    FILE *outfile = fopen(outfile_name, "w");
    gmp_fprintf(outfile, "%Zd, %Zd, %Zd", A, B, alice_s);   // alice_s is the same as bob_s

    // clean up (free GMP variables and close file)
    mpz_clear(gmp_p);
    mpz_clear(gmp_g);
    mpz_clear(gmp_a);
    mpz_clear(gmp_b);
    mpz_clear(A);
    mpz_clear(B);
    mpz_clear(alice_s);
    mpz_clear(bob_s);

    fclose(outfile);
}
