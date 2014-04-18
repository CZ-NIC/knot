#include <stdlib.h>
#include <string.h>
#include "clists.h"

cptrnode_t *cptrlist_add(clist_t *list, void *ptr)
{
	cptrnode_t *node = malloc(sizeof(*node));
	memset(node, 0, sizeof(*node));

	if (node == NULL) {
		return NULL;
	} else {
		node->ptr = ptr;
	}
	clist_add_tail(list, &node->n);
	return node;
}

void cptrlist_free(clist_t *list)
{
	cnode_t *n = NULL, *tmp = NULL;
	CLIST_WALK_DELSAFE(n, *list, tmp) {
		free(n);
	}
	clist_init(list);
}

bool cptrlist_contains(clist_t *list, const void *search)
{
	cptrnode_t *n = NULL;
	CLIST_WALK(n, *list) {
		if (n->ptr == search) {
			return true;
		}
	}
	return false;
}
