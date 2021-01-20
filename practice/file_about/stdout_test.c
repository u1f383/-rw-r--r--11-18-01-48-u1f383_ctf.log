#include <stdio.h>

int main()
{
    setvbuf(stdout, 0, 2, 0);

    char *s = "hello";

    puts(s);
    stdout->_flags = 0xfbad1800;
    stdout->_IO_write_base = &(stdout->_flags);
    puts(s);

    return 0;
}
