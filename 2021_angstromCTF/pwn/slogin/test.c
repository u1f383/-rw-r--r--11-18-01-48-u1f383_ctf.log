#include <stdio.h>
#include <string.h>

int main()
{
    char str[] = "Hello,world!";
    char buf[20] = {0};
    fgets(buf, 20, stdin);

    if (strcmp(str, buf) == 0) {
        printf("OWO");
    }

    return 0;
}
