#include <stdio.h>
#include <stdlib.h>

int main()
{
    char *msg = "hello world!";
    char *s = malloc(100);
    read(0, s, 100);

    FILE *fp = fopen("./flag.txt", "r");
    fp->_flags &= ~8; // ~_IO_NO_WRITES
    fp->_flags |= 0x800; // _IO_CURRENTLY_PUTTING
    fp->_IO_write_base = msg;
    fp->_IO_write_ptr = msg+6;
    fp->_IO_read_end = fp->_IO_write_base;
    fp->_fileno = 1;

    fwrite(s, 1, 100, fp);

    return 0;
}
