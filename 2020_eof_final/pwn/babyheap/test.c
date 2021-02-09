#include <stdio.h>
#include <unistd.h>

int main()
{
    char buf [0x20];

    read(0, 0, 0x10);
    read(0, buf, 0x10);

    printf("%s", buf);
}
