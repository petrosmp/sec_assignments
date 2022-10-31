The assignment was to develop the following two tools. For each
tool, you can find here a brief description of the way it works,
the way it should be compiled and the way it should be used.

Note that both tools were compiled with gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0.

Diffie-Hellman key exchange tool:
    This tool calculates the keys used in a Diffie-Hellman key
    exchange (https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange),
    given some of the parameters. Specifically, given two prime numbers
    p and g, as well as two secret keys a and b, the tool calculates the
    public keys that will be exchanged, as well as the shared secret.

    The tool first parses the command line arguments, calculates the public
    and the secret keys, compares the secret keys and writes them to the output file.

    To compile, just run make.

    The options when using the tool are:
        -o path     Path to output file
        -p number   Prime number
        -g number   Primitive Root for previous prime number
        -a number   Private key A
        -b number   Private key B
        -h          This help message
