#include <malloc.h>

#include "node.h"
#include "common.h"
#include "rrset.h"

//void print_node(void *key, void *val)
//{
//	dnslib_rrset_t *rrset = (dnslib_node_t*) val;
//	int *key_i = (int*)key;
//	printf("key %d\n", key_i);
//	printf("%d\n", rrset->type);
//}

static int compare_rrset_types(void *key1, void *key2)
{
	return (*((uint16_t *)key1) == *((uint16_t *)key2) ?
	        0 : *((uint16_t *)key1) < *((uint16_t *)key2) ? -1 : 1);
}

dnslib_node_t *dnslib_node_new(dnslib_dname_t *owner, dnslib_node_t *parent)
{
	dnslib_node_t *ret = malloc(sizeof(dnslib_node_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	ret->owner = owner;
	ret->parent = parent;
	ret->next = NULL;
	ret->rrsets = skip_create_list(compare_rrset_types);
	return ret;
}

int dnslib_node_add_rrset(dnslib_node_t *node, dnslib_rrset_t *rrset)
{
	if ((skip_insert(node->rrsets, 
			 (void *)&rrset->type, (void *)rrset, NULL)) != 0) {
		return -2;
	}

	return 0;
}

const dnslib_rrset_t *dnslib_node_get_rrset(const dnslib_node_t *node,
                                            uint16_t type)
{
	return (dnslib_rrset_t *)skip_find(node->rrsets, (void *)&type);
}

const dnslib_node_t *dnslib_node_get_parent(const dnslib_node_t *node)
{
	return node->parent;
}

void dnslib_node_set_parent(dnslib_node_t *node, dnslib_node_t *parent)
{
	node->parent = parent;
}

void dnslib_node_free(dnslib_node_t **node)
{
	skip_destroy_list(&(*node)->rrsets, NULL, NULL);
	free(*node);
	*node = NULL;
}

