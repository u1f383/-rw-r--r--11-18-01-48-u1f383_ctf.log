#include <stdio.h>
#include <stdlib.h>

int main()
{
    char *s = malloc(300);

    scanf("%300s", s);
    printf(s);

    return 0;
}
