#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main() {


    char *a = malloc(89);
    memcpy(a, "hello", 6);

    printf("a is %s\n", a);


}