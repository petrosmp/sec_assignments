The assignment was to develop the following two tools. For each
tool, you can find here a brief description of the way it works,
the way it should be compiled and the way it should be used.

Both tools were successfully compiled without errors or warnings of any kind
using gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0.

Diffie-Hellman key exchange tool:
    This tool calculates the keys used in a Diffie-Hellman key
    exchange (https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange),
    given some of the parameters. Specifically, given two prime numbers
    p and g, as well as two secret keys a and b, the tool calculates the
    public keys that will be exchanged, as well as the shared secret.

    The tool first parses the command line arguments, calculates the public
    and the secret keys, compares the secret keys and writes them to the output file.

    To compile, run make (or 'make diffie-hellman' to compile this tool without compiling the RSA one).

    The options when using the tool are:
        -o path     Path to output file
        -p number   Prime number
        -g number   Primitive Root for previous prime number
        -a number   Private key A
        -b number   Private key B
        -h          This help message

RSA Algorithm tool:
    This tool can be used to generate an RSA key pair and to encrypt or to decrypt a message
    using the RSA Algorithm (https://en.wikipedia.org/wiki/RSA_(cryptosystem)).
        - When used for key generation, the tool will ask for two prime integers that will
        act as seeds for the key derivation function (KDF). It will verify the primality of
        the input, generate the key pair and write each key to the corresponding file (public.key
        and private.key).

        - When used for encryption, the input file (where the message is), the key file and the
        output file (where the ciphertext will be written) should be passed as command line arguments.
          The key file may contain any key (public or private, depending on what the user intends on
        doing), which consists of 2 integers, n and e (or d) as described in the original RSA paper
        (https://people.csail.mit.edu/rivest/Rsapaper.pdf), separated by a single space.
          The tool will then iterate through the bytes of the input file, generating SIZE_OF_CIPHER_BYTE
        (see rsa_tool.c, line 6) bytes of ciphertext for each byte and writing them to the specified
        output file.

        - When used for decryption, the files should also be passed as command line arguments.
        The tool iterates through the ciphertext SIZE_OF_CIPHER_BYTE bytes at a time, decrypts it
        (assuming that it was encrypted with the corresponding key) and writes the resulting
        cleartext to the specified output file.

    To compile, run make (or 'make RSA' to compile this tool without compiling the Diffie-Hellman one).

    The options when using the tool are:
        -i path Path to the input file
        -o path Path to the output file
        -k path Path to the key file
        -g Perform RSA key-pair generation
        -d Decrypt input and store results to output
        -e Encrypt input and store results to output
        -h This help message

        Notes regarding the options:
        > The arguments “i”, “o” and “k” are always required when using “e” or “d”
        > Using -i and a path the user specifies the path to the input file.
        > Using -o and a path the user specifies the path to the output file.
        > Using -k and a path the user specifies the path to the key file.
        > Using -g the tool generates a public and a private key and stores them to the public.key
          and private.key files respectively.
        > Using -d the user specifies that the tool should read the ciphertext from the input file,
          decrypt it and then store the plaintext in the output file.
        > Using -e the user specifies that the tool should read the plaintext from the input file,
          encrypt it and store the ciphertext in the output file


General Notes:
    - The implementation of the RSA Algorithm uses Euler's totient function when calculating lambda(n).
    - The implementation of the RSA Algorithm uses a very simplistic method to find a prime that
      satisfies the criteria for choosing e.
    - Both tools were developed with no checks regarding misuse whatsoever, the user is assumed to always
      use them properly.
    - Both tools use C's int data type for conversions to and from the GMP data types. This means that both
      tools are subject to limitations regarding the size of the seeds, as neither the seeds nor the keys
      that are derived from them can exceed the 4-byte limit that C has for integers.
      This can be quite easily overcome by either using unsigned long long as the primitive data type or
      by handling I/O directly through the interface that the GMP library provides (gmp_printf, gmp_scanf
      and friends).
      This problem was not addressed even though it was identified due to insufficient time.
