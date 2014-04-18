/*
 *	UCW Library -- Circular Linked Lists
 *
 *	(c) 2003--2010 Martin Mares <mj@ucw.cz>
 *
 *	This software may be freely distributed and used according to the terms
 *	of the GNU Lesser General Public License.
 */

#pragma once

#include <stdlib.h>
#include <stdbool.h>

/*
 * NOTICE:
 * - based on ucw clists (LGPL), altered to use typedefs with _t
 * - ptrnode_t taken from Knot DNS (GPLv3+)
 */

/**
 * Common header for list nodes.
 **/
typedef struct cnode {
  struct cnode *next, *prev;
} cnode_t;

/**
 * Circular doubly linked list.
 **/
typedef struct clist {
  struct cnode head;
} clist_t;

/**
 * Initialize a new circular linked list. Must be called before any other function.
 **/
static inline void clist_init(clist_t *l)
{
  cnode_t *head = &l->head;
  head->next = head->prev = head;
}

/**
 * Return the first node on @l or NULL if @l is empty.
 **/
static inline void *clist_head(clist_t *l)
{
  return (l->head.next != &l->head) ? l->head.next : NULL;
}

/**
 * Return the last node on @l or NULL if @l is empty.
 **/
static inline void *clist_tail(clist_t *l)
{
  return (l->head.prev != &l->head) ? l->head.prev : NULL;
}

/**
 * Find the next node to @n or NULL if @n is the last one.
 **/
static inline void *clist_next(clist_t *l, cnode_t *n)
{
  return (n->next != &l->head) ? (void *) n->next : NULL;
}

/**
 * Find the previous node to @n or NULL if @n is the first one.
 **/
static inline void *clist_prev(clist_t *l, cnode_t *n)
{
  return (n->prev != &l->head) ? (void *) n->prev : NULL;
}

/**
 * Return a non-zero value iff @l is empty.
 **/
static inline int clist_empty(clist_t *l)
{
  return (l->head.next == &l->head);
}

/**
 * Loop over all nodes in the @list and perform the next C statement on them. The current node is stored in @n which must be defined before as pointer to any type.
 * The list should not be changed during this loop command.
 **/
#define CLIST_WALK(n,list) for(n=(void*)(list).head.next; (cnode_t*)(n) != &(list).head; n=(void*)((cnode_t*)(n))->next)

/**
 * Same as @CLIST_WALK(), but allows removal of the current node. This macro requires one more variable to store some temporary pointers.
 **/
#define CLIST_WALK_DELSAFE(n,list,tmp) for(n=(void*)(list).head.next; tmp=(void*)((cnode_t*)(n))->next, (cnode_t*)(n) != &(list).head; n=(void*)tmp)

/**
 * Same as @CLIST_WALK(), but it defines the variable for the current node in place. @type should be a pointer type.
 **/
#define CLIST_FOR_EACH(type,n,list) for(type n=(void*)(list).head.next; (cnode_t*)(n) != &(list).head; n=(void*)((cnode_t*)(n))->next)

/**
 * Same as @CLIST_WALK_DELSAFE(), but it defines the variable for the current node in place. @type should be a pointer type. The temporary variable must be still known before.
 **/
#define CLIST_FOR_EACH_DELSAFE(type,n,list,tmp) for(type n=(void*)(list).head.next; tmp=(void*)((cnode_t*)(n))->next, (cnode_t*)(n) != &(list).head; n=(void*)tmp)

/**
 * Reversed version of @CLIST_FOR_EACH().
 **/
#define CLIST_FOR_EACH_BACKWARDS(type,n,list) for(type n=(void*)(list).head.prev; (cnode_t*)(n) != &(list).head; n=(void*)((cnode_t*)(n))->prev)

/**
 * Insert a new node just after the node @after. To insert at the head of the list, use @clist_add_head() instead.
 **/
static inline void clist_insert_after(cnode_t *what, cnode_t *after)
{
  cnode_t *before = after->next;
  what->next = before;
  what->prev = after;
  before->prev = what;
  after->next = what;
}

/**
 * Insert a new node just before the node @before. To insert at the tail of the list, use @clist_add_tail() instead.
 **/
static inline void clist_insert_before(cnode_t *what, cnode_t *before)
{
  cnode_t *after = before->prev;
  what->next = before;
  what->prev = after;
  before->prev = what;
  after->next = what;
}

/**
 * Insert a new node in front of all other nodes.
 **/
static inline void clist_add_head(clist_t *l, cnode_t *n)
{
  clist_insert_after(n, &l->head);
}

/**
 * Insert a new node after all other nodes.
 **/
static inline void clist_add_tail(clist_t *l, cnode_t *n)
{
  clist_insert_before(n, &l->head);
}

/**
 * Remove node @n.
 **/
static inline void clist_remove(cnode_t *n)
{
  cnode_t *before = n->prev;
  cnode_t *after = n->next;
  before->next = after;
  after->prev = before;
}

/**
 * Remove the first node in @l, if it exists. Return the pointer to that node or NULL.
 **/
static inline void *clist_remove_head(clist_t *l)
{
  cnode_t *n = clist_head(l);
  if (n)
    clist_remove(n);
  return n;
}

/**
 * Remove the last node in @l, if it exists. Return the pointer to that node or NULL.
 **/
static inline void *clist_remove_tail(clist_t *l)
{
  cnode_t *n = clist_tail(l);
  if (n)
    clist_remove(n);
  return n;
}

/**
 * Merge two lists by inserting the list @what just after the node @after in a different list.
 * The first list is then cleared.
 **/
static inline void clist_insert_list_after(clist_t *what, cnode_t *after)
{
  if (!clist_empty(what))
    {
      cnode_t *w = &what->head;
      w->prev->next = after->next;
      after->next->prev = w->prev;
      w->next->prev = after;
      after->next = w->next;
      clist_init(what);
    }
}

/**
 * Move all items from a source list to a destination list. The source list
 * becomes empty, the original contents of the destination list are destroyed.
 **/
static inline void clist_move(clist_t *to, clist_t *from)
{
  clist_init(to);
  clist_insert_list_after(from, &to->head);
  clist_init(from);
}

/**
 * Compute the number of nodes in @l. Beware of linear time complexity.
 **/
static inline size_t clist_size(clist_t *l)
{
  size_t i = 0;
  CLIST_FOR_EACH(cnode_t *, n, *l)
    i++;
  return i;
}

/**
 * Remove a node @n and mark it as unlinked by setting the previous and next pointers to NULL.
 **/
static inline void clist_unlink(cnode_t *n)
{
  clist_remove(n);
  n->prev = n->next = NULL;
}

/**
 * Remove the first node on @l and mark it as unlinked.
 * Return the pointer to that node or NULL.
 **/
static inline void *clist_unlink_head(clist_t *l)
{
  cnode_t *n = clist_head(l);
  if (n)
    clist_unlink(n);
  return n;
}

/**
 * Remove the last node on @l and mark it as unlinked.
 * Return the pointer to that node or NULL.
 **/
static inline void *clist_unlink_tail(clist_t *l)
{
  cnode_t *n = clist_tail(l);
  if (n)
    clist_unlink(n);
  return n;
}

/**
 * Check if a node is linked a list. Unlinked nodes are recognized by having their
 * previous and next pointers equal to NULL. Returns 0 or 1.
 *
 * Nodes initialized to all zeroes are unlinked, inserting a node anywhere in a list
 * makes it linked. Normal removal functions like @clist_remove() do not mark nodes
 * as unlinked, you need to call @clist_unlink() instead.
 **/
static inline int clist_is_linked(cnode_t *n)
{
  return !!n->next;
}

/*!
 * \brief Generic pointer list implementation.
 */
typedef struct cptrnode {
	cnode_t n;
	void *ptr;
} cptrnode_t;

cptrnode_t *cptrlist_add(clist_t *, void *);
void cptrlist_free(clist_t *);
bool cptrlist_contains(clist_t *, const void *);
