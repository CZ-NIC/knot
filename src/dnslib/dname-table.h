#ifndef DNAMETABLE_H
#define DNAMETABLE_H

#include <config.h>

#include "common/tree.h"

#include "dnslib/dname.h"
#include "dnslib/dnslib-common.h"


struct dname_table_node {
	dnslib_dname_t *dname;
	TREE_ENTRY(dname_table_node) avl;
};

typedef TREE_HEAD(avl, dname_table_node) table_tree_t;

/*!< \note contains only tree now, but might change in the future. */
struct dnslib_dname_table {
	unsigned int id_counter;
	table_tree_t *tree;
};

typedef struct dnslib_dname_table dnslib_dname_table_t;

dnslib_dname_table_t *dnslib_dname_table_new();

dnslib_dname_t *dnslib_dname_table_find_dname(const dnslib_dname_table_t *table,
					      dnslib_dname_t *dname);

int dnslib_dname_table_add_dname(dnslib_dname_table_t *table,
				 dnslib_dname_t *dname);

void dnslib_dname_table_free(dnslib_dname_table_t **table);
void dnslib_dname_table_deep_free(dnslib_dname_table_t **table);

#endif // DNAMETABLE_H
