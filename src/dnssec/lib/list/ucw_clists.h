/*
 *	UCW Library -- Circular Linked Lists
 *
 *	(c) 2003--2010 Martin Mares <mj@ucw.cz>
 *
 *	This software may be freely distributed and used according to the terms
 *	of the GNU Lesser General Public License.
 */

#ifndef _UCW_CLISTS_H
#define _UCW_CLISTS_H

/**
 * Common header for list nodes.
 **/
typedef struct cnode {
  struct cnode *next, *prev;
} cnode;

/**
 * Circular doubly linked list.
 **/
typedef struct clist {
  struct cnode head;
} clist;

/**
 * Initialize a new circular linked list. Must be called before any other function.
 **/
static inline void clist_init(clist *l)
{
  cnode *head = &l->head;
  head->next = head->prev = head;
}

/**
 * Return the first node on \p l or NULL if \p l is empty.
 **/
static inline void *clist_head(clist *l)
{
  return (l->head.next != &l->head) ? l->head.next : NULL;
}

/**
 * Return the last node on \p l or NULL if \p l is empty.
 **/
static inline void *clist_tail(clist *l)
{
  return (l->head.prev != &l->head) ? l->head.prev : NULL;
}

/**
 * Find the next node to \p n or NULL if \p n is the last one.
 **/
static inline void *clist_next(clist *l, cnode *n)
{
  return (n->next != &l->head) ? (void *) n->next : NULL;
}

/**
 * Find the previous node to \p n or NULL if \p n is the first one.
 **/
static inline void *clist_prev(clist *l, cnode *n)
{
  return (n->prev != &l->head) ? (void *) n->prev : NULL;
}

/**
 * Return a non-zero value iff \p l is empty.
 **/
static inline int clist_empty(clist *l)
{
  return (l->head.next == &l->head);
}

/**
 * Loop over all nodes in the \ref list and perform the next C statement on them. The current node is stored in \p n which must be defined before as pointer to any type.
 * The list should not be changed during this loop command.
 **/
#define CLIST_WALK(n,list) for(n=(void*)(list).head.next; (cnode*)(n) != &(list).head; n=(void*)((cnode*)(n))->next)

/**
 * Same as \ref CLIST_WALK(), but allows removal of the current node. This macro requires one more variable to store some temporary pointers.
 **/
#define CLIST_WALK_DELSAFE(n,list,tmp) for(n=(void*)(list).head.next; tmp=(void*)((cnode*)(n))->next, (cnode*)(n) != &(list).head; n=(void*)tmp)

/**
 * Same as \ref CLIST_WALK(), but it defines the variable for the current node in place. \p type should be a pointer type.
 **/
#define CLIST_FOR_EACH(type,n,list) for(type n=(void*)(list).head.next; (cnode*)(n) != &(list).head; n=(void*)((cnode*)(n))->next)

/**
 * Same as \ref CLIST_WALK_DELSAFE(), but it defines the variable for the current node in place. \p type should be a pointer type. The temporary variable must be still known before.
 **/
#define CLIST_FOR_EACH_DELSAFE(type,n,list,tmp) for(type n=(void*)(list).head.next; tmp=(void*)((cnode*)(n))->next, (cnode*)(n) != &(list).head; n=(void*)tmp)

/**
 * Reversed version of \ref CLIST_FOR_EACH().
 **/
#define CLIST_FOR_EACH_BACKWARDS(type,n,list) for(type n=(void*)(list).head.prev; (cnode*)(n) != &(list).head; n=(void*)((cnode*)(n))->prev)

/**
 * Insert a new node just after the node \p after. To insert at the head of the list, use \ref clist_add_head() instead.
 **/
static inline void clist_insert_after(cnode *what, cnode *after)
{
  cnode *before = after->next;
  what->next = before;
  what->prev = after;
  before->prev = what;
  after->next = what;
}

/**
 * Insert a new node just before the node \p before. To insert at the tail of the list, use \ref clist_add_tail() instead.
 **/
static inline void clist_insert_before(cnode *what, cnode *before)
{
  cnode *after = before->prev;
  what->next = before;
  what->prev = after;
  before->prev = what;
  after->next = what;
}

/**
 * Insert a new node in front of all other nodes.
 **/
static inline void clist_add_head(clist *l, cnode *n)
{
  clist_insert_after(n, &l->head);
}

/**
 * Insert a new node after all other nodes.
 **/
static inline void clist_add_tail(clist *l, cnode *n)
{
  clist_insert_before(n, &l->head);
}

/**
 * Remove node \p n.
 **/
static inline void clist_remove(cnode *n)
{
  cnode *before = n->prev;
  cnode *after = n->next;
  before->next = after;
  after->prev = before;
}

/**
 * Remove the first node in \p l, if it exists. Return the pointer to that node or NULL.
 **/
static inline void *clist_remove_head(clist *l)
{
  cnode *n = clist_head(l);
  if (n)
    clist_remove(n);
  return n;
}

/**
 * Remove the last node in \p l, if it exists. Return the pointer to that node or NULL.
 **/
static inline void *clist_remove_tail(clist *l)
{
  cnode *n = clist_tail(l);
  if (n)
    clist_remove(n);
  return n;
}

/**
 * Merge two lists by inserting the list \p what just after the node \p after in a different list.
 * The first list is then cleared.
 **/
static inline void clist_insert_list_after(clist *what, cnode *after)
{
  if (!clist_empty(what))
    {
      cnode *w = &what->head;
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
static inline void clist_move(clist *to, clist *from)
{
  clist_init(to);
  clist_insert_list_after(from, &to->head);
  clist_init(from);
}

/**
 * Compute the number of nodes in \p l. Beware of linear time complexity.
 **/
static inline unsigned int clist_size(clist *l)
{
  unsigned int i = 0;
  CLIST_FOR_EACH(cnode *, n, *l)
    i++;
  return i;
}

/**
 * Remove a node \p n and mark it as unlinked by setting the previous and next pointers to NULL.
 **/
static inline void clist_unlink(cnode *n)
{
  clist_remove(n);
  n->prev = n->next = NULL;
}

/**
 * Remove the first node on \p l and mark it as unlinked.
 * Return the pointer to that node or NULL.
 **/
static inline void *clist_unlink_head(clist *l)
{
  cnode *n = clist_head(l);
  if (n)
    clist_unlink(n);
  return n;
}

/**
 * Remove the last node on \p l and mark it as unlinked.
 * Return the pointer to that node or NULL.
 **/
static inline void *clist_unlink_tail(clist *l)
{
  cnode *n = clist_tail(l);
  if (n)
    clist_unlink(n);
  return n;
}

/**
 * Check if a node is linked a list. Unlinked nodes are recognized by having their
 * previous and next pointers equal to NULL. Returns 0 or 1.
 *
 * Nodes initialized to all zeroes are unlinked, inserting a node anywhere in a list
 * makes it linked. Normal removal functions like \ref clist_remove() do not mark nodes
 * as unlinked, you need to call \ref clist_unlink() instead.
 **/
static inline int clist_is_linked(cnode *n)
{
  return !!n->next;
}

#endif
