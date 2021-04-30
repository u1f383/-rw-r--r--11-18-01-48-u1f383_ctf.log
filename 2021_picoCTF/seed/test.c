#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main()
{
    unsigned int seed = time(NULL);
    srand(seed);

    for (int i = 0; i < 30; i++) {
        printf("%d ",  rand() & 0xF);
    }
    
    return 0;
}
