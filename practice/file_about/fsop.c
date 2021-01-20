#include <stdio.h>
#include <stdlib.h>

int main()
{
    void *a = malloc(0x18);
    free(a);
    free(a);
}
