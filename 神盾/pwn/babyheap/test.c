#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
	int a;
	char *b;
	b = malloc(0x500); // unsorted bin
	malloc(0x30); // prevent merge
	//free(b);
	
	//b = malloc(0x10); // split unsorted bin
	//b = malloc(0x20); // split unsorted bin
	read(0, b, 8);
	printf("%s\n", b); // leak libc address
	//scanf("%d", &a);
	scanf("%d", &a);
}
