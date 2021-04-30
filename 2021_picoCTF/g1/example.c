#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
    char *a;
    char b[100];

    read(0, b, 10);
    a = malloc(0x80);
    
    return 0;
}
