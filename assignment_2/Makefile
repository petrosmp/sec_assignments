all: clean server client

clean:
	rm -f client server
server:
	gcc -Wall server.c -o server -L/usr/lib -lssl -lcrypto -Wno-deprecated-declarations
client:
	gcc -Wall client.c -o client -L/usr/lib -lssl -lcrypto -Wno-deprecated-declarations

# The -Wno-deprecated-declarations flag that is used in compilations disables warnings about
# using code that has been declared deprecated.
# As per the project's requirements and specification, the client and the server use TLS
# version 1.2, which has been declared deprecated, so the above flag is needed to silence
# compiler warnings.
