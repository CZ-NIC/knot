/*
 *	BIRD Library -- Linked Lists
 *
 *	(c) 1998 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Linked lists
 *
 * The BIRD library provides a set of functions for operating on linked
 * lists. The lists are internally represented as standard doubly linked
 * lists with synthetic head and tail which makes all the basic operations
 * run in constant time and contain no extra end-of-list checks. Each list
 * is described by a &list structure, nodes can have any format as long
 * as they start with a &node structure. If you want your nodes to belong
 * to multiple lists at once, you can embed multiple &node structures in them
 * and use the SKIP_BACK() macro to calculate a pointer to the start of the
 * structure from a &node pointer, but beware of obscurity.
 *
 * There also exist safe linked lists (&slist, &snode and all functions
 * being prefixed with |s_|) which support asynchronous walking very
 * similar to that used in the &fib structure.
 */

#define _BIRD_LISTS_C_

#include <stdlib.h>
#include <string.h>
#include "libknot/internal/macros.h"
#include "libknot/internal/lists.h"

/**
 * add_tail - append a node to a list
 * @l: linked list
 * @n: list node
 *
 * add_tail() takes a node @n and appends it at the end of the list @l.
 */
LIST_INLINE void
add_tail(list_t *l, node_t *n)
{
  node_t *z = l->tail;

  n->next = (node_t *) &l->null;
  n->prev = z;
  z->next = n;
  l->tail = n;
}

/**
 * add_head - prepend a node to a list
 * @l: linked list
 * @n: list node
 *
 * add_head() takes a node @n and prepends it at the start of the list @l.
 */
LIST_INLINE void
add_head(list_t *l, node_t *n)
{
  node_t *z = l->head;

  n->next = z;
  n->prev = (node_t *) &l->head;
  z->prev = n;
  l->head = n;
}

/**
 * insert_node - insert a node to a list
 * @n: a new list node
 * @after: a node of a list
 *
 * Inserts a node @n to a linked list after an already inserted
 * node @after.
 */
LIST_INLINE void
insert_node(node_t *n, node_t *after)
{
  node_t *z = after->next;

  n->next = z;
  n->prev = after;
  after->next = n;
  z->prev = n;
}

/**
 * rem_node - remove a node from a list
 * @n: node to be removed
 *
 * Removes a node @n from the list it's linked in.
 */
LIST_INLINE void
rem_node(node_t *n)
{
  node_t *z = n->prev;
  node_t *x = n->next;

  z->next = x;
  x->prev = z;
  n->prev = 0;
  n->next = 0;
}

/**
 * init_list - create an empty list
 * @l: list
 *
 * init_list() takes a &list structure and initializes its
 * fields, so that it represents an empty list.
 */
LIST_INLINE void
init_list(list_t *l)
{
  l->head = (node_t *) &l->null;
  l->null = NULL;
  l->tail = (node_t *) &l->head;
}

/**
 * add_tail_list - concatenate two lists
 * @to: destination list
 * @l: source list
 *
 * This function appends all elements of the list @l to
 * the list @to in constant time.
 */
LIST_INLINE void
add_tail_list(list_t *to, list_t *l)
{
  node_t *p = to->tail;
  node_t *q = l->head;

  p->next = q;
  q->prev = p;
  q = l->tail;
  q->next = (node_t *) &to->null;
  to->tail = q;
}

/**
 * list_dup - duplicate list
 * @to: destination list
 * @l: source list
 *
 * This function duplicates all elements of the list @l to
 * the list @to in linear time.
 *
 * This function only works with a homogenous item size.
 */
void list_dup(list_t *dst, list_t *src, size_t itemsz)
{
	node_t *n = 0;
	WALK_LIST(n, *src) {
		node_t *i = malloc(itemsz);
		memcpy(i, n, itemsz);
		add_tail(dst, i);
	}
}

/**
 * list_size - gets number of nodes
 * @l: list
 *
 * This function counts nodes in list @l and returns this number.
 */
size_t list_size(const list_t *l)
{
	size_t count = 0;

	node_t *n = 0;
	WALK_LIST(n, *l) {
		count++;
	}

	return count;
}

/**
 * ptrlist_add - add pointer to pointer list
 * @to: destination list
 * @val: added pointer
 * @mm: memory context
 */
ptrnode_t *ptrlist_add(list_t *to, void *val, mm_ctx_t *mm)
{
	ptrnode_t *node = mm_alloc(mm , sizeof(ptrnode_t));
	if (node == NULL) {
		return NULL;
	} else {
		node->d = val;
	}
	add_tail(to, &node->n);
	return node;
}

/**
 * ptrlist_free - free all nodes in pointer list
 * @list: list nodes
 * @mm: memory context
 */
void ptrlist_free(list_t *list, mm_ctx_t *mm)
{
	node_t *n = NULL, *nxt = NULL;
	WALK_LIST_DELSAFE(n, nxt, *list) {
		mm_free(mm, n);
	}
	init_list(list);
}

/**
 * ptrlist_rem - remove pointer node
 * @val: pointer to remove
 * @mm: memory context
 */
void ptrlist_rem(ptrnode_t *node, mm_ctx_t *mm)
{
	rem_node(&node->n);
	mm_free(mm, node);
}
