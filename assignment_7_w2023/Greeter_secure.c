#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>




unsigned char Name[1024];

void readString() {
	char buf[32];
	gets(Name);
        memcpy(buf, Name, strlen(Name));
    
   	return;
}



int main(void) {


	printf("What is your name?\n");
	readString();
	printf("Hello %s, have a nice day.\n", Name);
	
	exit(0);
}
