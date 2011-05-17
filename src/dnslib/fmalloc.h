#ifndef FMALLOC_H
#define FMALLOC_H
#include <malloc.h>
#include <string.h>
#include <stdio.h>
static unsigned int malloc_count = 0;
static char *file = "dnslib/dname.c";
static void inline *malloc_with_count(size_t size) {
	malloc_count++;
	if (malloc_count % 100 && (strcmp(file, __FILE__ ))) {
		return malloc(size);
	} else {
		printf("Failing malloc on purpose in %s!\n", file);
		return NULL;
	}
}
#endif // FMALLOC_H
