#include <stdio.h>
#include <stdlib.h>

int main()
{
    char msg[100];
    char *s = malloc(100);

    FILE *fp = fopen("./flag2.txt", "r");
    fp->_flags &= ~4; // ~_IO_NO_READS
    fp->_IO_buf_base = msg;
    fp->_IO_buf_end = msg+100;
    fp->_fileno = 0;

    fread(s, 1, 6, fp);
    puts(msg);

    return 0;
}
