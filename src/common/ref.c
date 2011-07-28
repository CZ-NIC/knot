#include <stdio.h>

#include "ref.h"

void ref_init(ref_t *p, ref_destructor_t dtor)
{
	p->count = 0;
	p->dtor = dtor;
}

void ref_retain(ref_t *p)
{
	__sync_add_and_fetch(&p->count, 1);
}

void ref_release(ref_t *p)
{
	if (__sync_sub_and_fetch(&p->count, 1) <= 0) {
		p->dtor(p);
	}
}
