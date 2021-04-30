#include <stdio.h>
#include <unistd.h>

int main()
{
    for (int i = 0; i < 20; i++)
        printf("%ld,", (rand() % 4096) + 1);
}
