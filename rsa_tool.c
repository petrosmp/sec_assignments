#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <string.h>

#define SIZE_OF_CIPHER_BYTE 8

void calculate_e(mpz_t e, mpz_t lambda);

/*
Options:
    -i path Path to the input file
    -o path Path to the output file
    -k path Path to the key file
    -g Perform RSA key-pair generation
    -d Decrypt input and store results to output
    -e Encrypt input and store results to output
    -h This help message
*/

int main(int argc, char *argv[]){

    char *outfile_name=NULL, *infile_name=NULL, *keyfile_name=NULL;
    int mode = -1;  // -1 is error, 0 is generate, 1 is encrypt, 2 is decrypt
    const char *help_message = "Options:\n\t-i path Path to the input file\n\t-o path Path to the output file\n\t-k path Path to the key file\n\t-g Perform RSA key-pair generation\n\t-d Decrypt input and store results to output\n\t-e Encrypt input and store results to output\n\t-h This help message";

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
        else if (strcmp(argv[i], "-i") == 0) {
            if (i+1 >= argc) {
                printf("There is no value for parameter i. Please provide one. Use option -h for help.\n");
                exit(-1);
            }
            infile_name = argv[i+1];
        }
        else if (strcmp(argv[i], "-k") == 0) {
            if (i+1 >= argc) {
                printf("There is no value for parameter k. Please provide one. Use option -h for help.\n");
                exit(-1);
            }
            keyfile_name = argv[i+1];
        }
        else if (strcmp(argv[i], "-g") == 0) {
            if (mode != -1) {
                printf("Multiple modes specified. Use option -h for help\n");
                exit(-1);
            }
            mode = 0;
        }
        else if (strcmp(argv[i], "-e") == 0) {
            if (mode != -1) {
                printf("Multiple modes specified. Use option -h for help\n");
                exit(-1);
            }
            mode = 1;
        }
        else if (strcmp(argv[i], "-d") == 0) {
            if (mode != -1) {
                printf("Multiple modes specified. Use option -h for help\n");
                exit(-1);
            }
            mode = 2;
        }
    }

    // if after parsing arguments any of the filenames is NULL, an argument was missing
    if (mode == 1 || mode == 2) {
        if (outfile_name == NULL) {
            printf("Cannot proceed without an output file path! Please provide one. Use the -h option for help.\n");
            exit(-1);
        }
        
        if (infile_name == NULL) {
            printf("Cannot proceed without an input file path! Please provide one. Use the -h option for help.\n");
            exit(-1);
        }
        
        if (keyfile_name == NULL) {
            printf("Cannot proceed without a key file path! Please provide one. Use the -h option for help.\n");
            exit(-1);
        }
    }

    // do things
    if (mode == 0) {        // key generation

        int p, q;

        // read p and q from the command line
        printf("You have selected the key generation mode.\n");
        printf("You need to insert 2 prime numbers (p and q)\n");
        printf("Enter p: ");
        scanf("%d", &p);
        printf("Enter q: ");
        scanf("%d", &q);

        // import p and q as GMP variables
        mpz_t gmp_p, gmp_q;
        mpz_init_set_ui(gmp_p, p);
        mpz_init_set_ui(gmp_q, q);

        // test if p and q are prime
        int p_is_prime = mpz_probab_prime_p(gmp_p, 33);
        int q_is_prime = mpz_probab_prime_p(gmp_q, 33);

        /*
            mpz_probab_prime_p() returns 2 if the number is definitely prime, 1 if the
            number is probably prime and 0 if the number is definitely not prime.
            (https://gmplib.org/manual/Number-Theoretic-Functions)

            For this assignment we will only accept definitely prime numbers, since according to
            GMP documentation regarding primality testing, a composite number passing the test
            is extremely rare.
            (https://gmplib.org/manual/Prime-Testing-Algorithm)
        */

        if (p_is_prime != 2) {
            printf("p (%d) is not prime. Please enter a prime number. Use option -h for help.\n", p);
            exit(-1);
        }
        if (q_is_prime != 2) {
            printf("q (%d) is not prime. Please enter a prime number. Use option -h for help.\n", q);
            exit(-1);
        }

        // since both p and q are prime, we can conitnue
        // calculate n and lambda(n)
        mpz_t gmp_n;
        mpz_init(gmp_n);
        mpz_mul(gmp_n, gmp_p, gmp_q);

        mpz_t lambda_n, gmp_one;
        mpz_init(lambda_n);
        mpz_init_set_ui(gmp_one, 1);
        mpz_sub(gmp_p, gmp_p, gmp_one);   // gmp_p --
        mpz_sub(gmp_q, gmp_q, gmp_one);   // gmp_q --
        mpz_mul(lambda_n, gmp_p, gmp_q);      // lambda(n) = (p-1) * (q-1) (Euler's totient function)

        // choose e (e is required to be prime and also < lambda)
        mpz_t gmp_e;
        mpz_init(gmp_e);
        calculate_e(gmp_e, lambda_n);

        // calculate d, where d is the modular inverse of e and lambda_n
        mpz_t gmp_d;
        mpz_init(gmp_d);
        mpz_invert(gmp_d, gmp_e, lambda_n);

        // math over, store results in files
        FILE *pub_key_file = fopen("public.key", "w");
        FILE *priv_key_file = fopen("private.key", "w");

        // clean up and exit
        mpz_clear(gmp_d);
        mpz_clear(gmp_e);
        mpz_clear(lambda_n);
        mpz_clear(gmp_one);
        mpz_clear(gmp_n);
        mpz_clear(gmp_p);
        mpz_clear(gmp_q);
        fclose(pub_key_file);
        fclose(priv_key_file);

    } else if (mode == 1) {  // encryption

        // get the key (e, n) from the file and import it to GMP
        int e, n;
        FILE *keyfile = fopen(keyfile_name, "r");
        fscanf(keyfile, "%d %d", &n, &e);
        mpz_t gmp_e, gmp_n;
        mpz_init_set_ui(gmp_e, e);
        mpz_init_set_ui(gmp_n, n);

        // prepare to iterate through the file
        mpz_t gmp_m, gmp_res;
        mpz_init(gmp_m);
        mpz_init(gmp_res);
        long *tmp =  (long*) malloc(SIZE_OF_CIPHER_BYTE); // variable to store the cipher of each byte.
        int m;  // the cursor
        FILE *infile = fopen(infile_name, "r");
        FILE *outfile = fopen(outfile_name, "w");

        if (outfile==NULL || infile==NULL) {
            printf("Something has gone wrong while opening the files.\n");
            exit(-1);
        }

        // iterate throught the characters of the file
        while ((m=fgetc(infile)) != EOF) { 
            // import the letter to GMP and calculate the cipher
            mpz_set_ui(gmp_m, m);
            mpz_powm(gmp_res, gmp_m, gmp_e, gmp_n); // m^e mod n

            // export the result to a primitive and write it to the file
            mpz_export(tmp, NULL, 0, SIZE_OF_CIPHER_BYTE, 0, 0, gmp_res);
            fwrite(tmp, 8, 1, outfile);
        }
        
        // clean up and exit
        mpz_clear(gmp_e);
        mpz_clear(gmp_n);
        mpz_clear(gmp_m);
        mpz_clear(gmp_res);
        fclose(infile);
        fclose(outfile);
        fclose(keyfile);
        free(tmp);

    } else if (mode == 2){   // decryption
        
        // get the key (d, n) from the file and import it to GMP
        int d, n;
        FILE *keyfile = fopen(keyfile_name, "r");
        fscanf(keyfile, "%d %d", &n, &d);
        mpz_t gmp_d, gmp_n;
        mpz_init_set_ui(gmp_d, d);
        mpz_init_set_ui(gmp_n, n);

        // prepare to iterate through the file
        mpz_t gmp_c, gmp_res;
        mpz_init(gmp_c);
        mpz_init(gmp_res);
        long *tmp =  (long*) malloc(SIZE_OF_CIPHER_BYTE); // variable to store the cipher of each byte.
        int *c = (int*) malloc(sizeof(int));    // the deciphered cursor
        FILE *infile = fopen(infile_name, "r");
        FILE *outfile = fopen(outfile_name, "w");

        // iterate through the file 8 bytes at a time
        while (fread(tmp, SIZE_OF_CIPHER_BYTE, 1, infile) != 0) {

            // import the bytes to GMP and decipher it
            mpz_import (gmp_c, 1, 0, SIZE_OF_CIPHER_BYTE, 0, 0, tmp);
            mpz_powm(gmp_res, gmp_c, gmp_d, gmp_n); // c^d mod n

            // export the deciphered character to a primitive and write it to the file
            mpz_export(c, NULL, 0, sizeof(int), 0, 0, gmp_res);
            fputc((char)*c, outfile);
        }

        mpz_clear(gmp_d);
        mpz_clear(gmp_n);
        mpz_clear(gmp_c);
        mpz_clear(gmp_res);
        fclose(infile);
        fclose(outfile);
        fclose(keyfile);
        free(c);
        free(tmp);
    }

}


void calculate_e(mpz_t e, mpz_t lambda){

    mpz_t one, mod, gcd;
    mpz_init(mod);
    mpz_init(gcd);
    mpz_set_ui(e, 2);
    mpz_init_set_ui(one, 1);

    while(1){

        mpz_mod(mod, e, lambda);
        mpz_gcd(gcd, e, lambda);
        if (mpz_cmp(mod, one)!=0 && mpz_cmp(gcd, one)==0) {
            break;
        }
        mpz_nextprime(e, e);
    }

    mpz_clear(one);
    mpz_clear(mod);
    mpz_clear(gcd);
}
