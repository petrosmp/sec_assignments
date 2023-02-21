This assignment was to develop a buffer overflow exploit that could
spawn a shell when passed as input to the given program. The vulnerable
program was designed and compiled in a way that made the attack both
possible and consistent between different executions of the program.






EXECUTION INSTRUCTIONS AND POC (Proof Of Concept):
    - First of all we need to compile the program by running make.
      To generate the payload we can run the python script found in this folder,
      exploit.py. It will create a new binary file, payload.bin, which we can
      then pass as input to the executable, using cat:

        { cat payload.bin ; cat ;} | ./bof

    - Notice the second "cat"  (the one with no arguments) in the first part of
      the command. This is done because once we successfully spawn the shell we
      need to redirect stdin to the newly spawned shell to be able to interact
      with it.

    - A screenshot of the exploit working as intended can be found at
      https://i.imgur.com/4wcnODB.png and also in this directory (poc.png)






EXPLOIT PROCESS
    - We start by investigating the source code of the program that we want to
      exploit. We can see that it uses gets(), which is what actually allows us to overflow
      the buffer and poke around in the stack. We can also see that the first 100 bytes
      of the input are copied to a global variable called big_boy_buffer. This interests us
      because we intend to overwrite the return address that is saved in the stack, which is
      what main() (and not vuln()) will try to return to, so we need to go beyond vuln()'s
      scope. 

      ^ Note: The last sentence is wrong. We overwrite the return address which should be on
      the top of the stack frame of the caller function. We jump to the malicious code when
      vuln() returns, not main(). Therefore we do not really need to go beyond vuln()'s scope,
      since we can (safely) assume that even after it returns its frame has not been overwritten,
      the stack pointer has just moved "past" it.

      Picture the stack right before vuln() returns (the addresses are arbitrary, they're just there for reference):

                            ┌───────────────────┐high
                            │                   │
        0x00007fffffffdfe8  ├───────────────────┤ <-stack pointer before the "call vuln" instruction
                            │  return addrress  │ <-this is what we intend to overwrite
        0x00007fffffffdfe0  ├───────────────────┤ <-stack pointer before the actual jump instruction
                            │   main()'s %rbp   │
        0x00007fffffffdfd8  ├───────────────────┤ <-stack pointer right after vuln() takes control, vuln()'s base pointer
                            │                   │
                            │                   │
                            │       buffer      │ <-this is what we intend to overflow
                            │                   │
                            │                   │
        0x00007fffffffdf68  ├───────────────────┤
                            │         .         │
                            │         .         │ <-the rest of vuln()'s stack frame  (we don't care what's in here)
                            │         .         │
                            ├───────────────────┤ <- vuln()'s stack pointer when vuln() finishes and has to clean up
                            │                   │
                            ├───────────────────┤
                            │                   │
                            └───────────────────┘low
      
      When vuln() ends, 2 instructions will be called to give control back to main(): "leave" and "ret".
        > "leave" is equivalent to 
                mov rsp, rbp
                pop rbp
          so it will set vuln()'s rsp to vuln()'s rbp (aka 0x00007fffffffdfd8), effectively cleaning up
          vuln()'s stack frame. Then pop will restore %rbp's value to the address of main()'s stack frame,
          also moving the stack pointer to 0x00007fffffffdfe0.

        > "ret" will then pop the return address from the stack and jump to it.

      It becomes clear that if we can overwrite the return address, we can control where the program will
      jump to, giving us the ability to point it towards our malicious code.


    - We now need to see the exact effect that a "malicious" input can have on the
      program execution. We open GDB and when prompted for input we enter a string with
      more than 100 characters and with an easily recognizable pattern. Each letter
      of the alphabet repeated 8 times (8 bytes, because of the 64-bit architecture of
      the target machine) will do. We also set a breakpoint (doesn't really matter
      exactly where, but right after the input was read would be a good place to start),
      so we can look at the registers and the stack while the program is running. Using
      the tools that GDB provides* we can see that the characters that overwrite the return
      address are at offset 120**, so we now know where the new address should be.

    - We now need to do 2 things: inject some shellcode that can spawn a shell into the
      stack and find the address of that code. We start by finding some shellcode. We use
      the shellcode provided here https://www.exploit-db.com/exploits/47008 for an x86_64
      machine, that calls execve (https://man7.org/linux/man-pages/man2/execve.2.html) with
      the location of the shell executable (/bin/sh) as an argument (see https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86_64-64_bit,
      syscall number 59 for details). The program is written and compiled in such a way
      that in every execution the addresses of the variables are the same, so we do not need
      to prepend that code with a no-op sled or anything, we can just place it right at the
      start of the payload. We can fill the rest of the payload with no-op instructions (hex
      code 0x90), or any other character, until the desired length of 120 characters is reached,
      where we can put the address of the shellcode.

    - As we can see in the source code of the program that we want to exploit, the first 100
      bytes of the input we provide are copied (using memcpy()) into the big_boy_buffer. Using
      a tool like readelf (https://man7.org/linux/man-pages/man1/readelf.1.html), we can examine
      the executable and find the address of that buffer, which because of the way the program
      is written and compiled should remain unchanged from execution to execution. We see that
      the address we are looking for is 0x0000000000404080. We now have to pack the address in
      bytes and adjust for the endianness of the target system. We do that with python's struct
      (https://docs.python.org/3/library/struct.html#format-characters) and append the bytes to the
      payload.

    - We write the payload to a binary file, which we will the pass as input to the program.

    - Running the program through GDB with the payload as input, we can see that the exploit works
      but the shell closes as soon as it opens. To overcome this we use a second call to 'cat',
      that we pipe into the executable (the first one reads the payload file). That second call
      binds stdin to the newly opened shell. We now have a fully working interactive shell!


* After reaching the breakpoint, we can execute instructions one by one,
checking the state of the CPU and the memory in each step to figure out
exactly what is happenning. On each step we canexamine the stack (or any
part of memory) with 'x/20gw <addr>' (where x/ stands for eXamine, 20 is
the number of words we want to read and gw stands for 8-byte words), we
can examine the instructions that will be run next in the same way, just
substituting 'gw' with 'i' (for Instruction) and using $rip (the instruction
pointer register) as an address, and we can also see information about the
whole stack frame (such as the saved return address which we overwrote) using
'info frame' (or 'i f' for short).

** We can also find that out by disassembling vuln()'s code ('disas vuln' in
GDB), where we can see that 112 bytes are allocated on the stack for the buffer
in which our input goes, and right before that, the base pointer and the instruction
pointer were written in the stack when vuln was called, each taking up 8 bytes,
since the machine is 64-bit. So the offset between the start of the buffer and the
return address we wish to overwrite is 112+8=120 bytes. The trial-and-error method
is "better" because it is foolproof, meaning that even if we miss something in the
asm code we will get the correct result by trying, and it also allows us to check
the endianness of the target system.






SOURCES:
    - LiveOverflow's binary exploitation video series (and the channel in general):
      https://youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN
    
    - Computerphile's example of a buffer overflow exploit:
      https://youtu.be/1S0aBV-Waeo
    
    - Original Phrack article (also linked in the project specification):
      http://www.phrack.com/issues/49/14.html#article
    
    - ExploitDB for the shellcode:
      https://www.exploit-db.com/exploits/47008

    - The various documentation pages mentioned above






NOTES:
    - Everything was run on an x86 64bit virtual machine running Ubuntu 22.04.1 LTS (Jammy Jellyfish).
      The given program was compiled using GNU Make 4.3 and gcc 11.3.0 (Ubuntu 11.3.0-1ubuntu1~22.04).
      Python 3.10.6 was used to execute the script that creates the payload.
