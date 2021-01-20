#include <stdio.h>
#include <stdlib.h>

int main()
{
    FILE *fp = fopen("./flag.txt", "r");
    
    fclose(fp);

    return 0;
}
