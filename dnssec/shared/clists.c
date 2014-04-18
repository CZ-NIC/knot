#include <stdlib.h>
#include "clists.h"

ptrnode_t *ptrlist_add(clist_t *list, void *ptr)
{
	ptrnode_t *node = malloc(sizeof(*node));
	if (node == NULL) {
		return NULL;
	} else {
		node->ptr = ptr;
	}
	clist_add_tail(list, &node->n);
	return node;
}

void ptrlist_free(clist_t *list)
{
	cnode_t *n = NULL, *tmp = NULL;
	CLIST_WALK_DELSAFE(n, *list, tmp) {
		free(n);
	}
	clist_init(list);
}

bool ptrlist_contains(clist_t *list, const void *search)
{
	ptrnode_t *n = NULL;
	CLIST_WALK(n, *list) {
		if (n->ptr == search) {
			return true;
		}
	}
	return false;
}
