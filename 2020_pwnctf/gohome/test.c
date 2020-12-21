#include <stdio.h>
#include <stdlib.h>

int main()
{
    srand(time(NULL));

    printf("%d", rand()%100);

    return 0;
}
