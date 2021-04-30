#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    char *a;
    char *b;
    int c = 0, d = 0;

    for (int i = 0; i <= 6; i++) {
        a = malloc(0x80);
    }
    b = malloc(0x80);

    free(a);
    free(b);

    scanf("%d %c", &c, &d);

    a[c] = d;

    char *e = malloc(0x80);

    strcpy(e, "OWO...");

    return 0;
}
