This assignment was assigned in winter semester 2023. It is similar to that
in assignment7/, however it requires exploiting a buffer overflow vulnerability
in a 32-bit program, while assignment 7 does so in a 64-bit program.

The exploit process is the same, the shellcode is just different.
    > python exploit.py
    > { cat payload.bin ; cat ; } | ./Greeter

The ./Greeter file is a pre-compiled executable, given along with the project specification.
