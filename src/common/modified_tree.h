/* tree.h -- AVL trees (in the spirit of BSD's 'queue.h')	-*- C -*-	*/

/* Copyright (c) 2005 Ian Piumarta
 *
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the 'Software'), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so,
 * provided that the above copyright notice(s) and this permission notice appear
 * in all copies of the Software and that both the above copyright notice(s) and
 * this permission notice appear in supporting documentation.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS'.  USE ENTIRELY AT YOUR OWN RISK.
 */

/* This file defines an AVL balanced binary tree [Georgii M. Adelson-Velskii and
 * Evgenii M. Landis, 'An algorithm for the organization of information',
 * Doklady Akademii Nauk SSSR, 146:263-266, 1962 (Russian).  Also in Myron
 * J. Ricci (trans.), Soviet Math, 3:1259-1263, 1962 (English)].
 *
 * An AVL tree is headed by pointers to the root node and to a function defining
 * the ordering relation between nodes.  Each node contains an arbitrary payload
 * plus three fields per tree entry: the depth of the subtree for which it forms
 * the root and two pointers to child nodes (singly-linked for minimum space, at
 * the expense of direct access to the parent node given a pointer to one of the
 * children).  The tree is rebalanced after every insertion or removal.  The
 * tree may be traversed in two directions: forward (in-order left-to-right) and
 * reverse (in-order, right-to-left).
 *
 * Because of the recursive nature of many of the operations on trees it is
 * necessary to define a number of helper functions for each type of tree node.
 * The macro TREE_DEFINE(node_tag, entry_name) defines these functions with
 * unique names according to the node_tag.  This macro should be invoked,
 * thereby defining the necessary functions, once per node tag in the program.
 *
 * For details on the use of these macros, see the tree(3) manual page.
 */

#ifndef _modified_tree_h
#define _modified_tree_h


#define MOD_TREE_DELTA_MAX	1

#define MOD_TREE_ENTRY(type)			\
  struct {					\
    struct type	*avl_left;			\
    struct type	*avl_right;			\
    int		 avl_height;			\
  }

#define MOD_TREE_HEAD(name, type)				\
  struct name {						\
    struct type *th_root;				\
    int  (*th_cmp)(void *lhs, void *rhs);	\
  }

#define MOD_TREE_INITIALIZER(cmp) { 0, cmp}

#define MOD_TREE_DELTA(self, field)								\
  (( (((self)->field.avl_left)  ? (self)->field.avl_left->field.avl_height  : 0))	\
   - (((self)->field.avl_right) ? (self)->field.avl_right->field.avl_height : 0))

/* Recursion prevents the following from being defined as macros. */

#define MOD_TREE_DEFINE(node, field)									\
													\
  struct node *MOD_TREE_BALANCE_##node##_##field(struct node *);						\
													\
  struct node *MOD_TREE_ROTL_##node##_##field(struct node *self)						\
  {													\
    struct node *r= self->field.avl_right;								\
    self->field.avl_right= r->field.avl_left;								\
    r->field.avl_left= MOD_TREE_BALANCE_##node##_##field(self);						\
    return MOD_TREE_BALANCE_##node##_##field(r);								\
  }													\
													\
  struct node *MOD_TREE_ROTR_##node##_##field(struct node *self)						\
  {													\
    struct node *l= self->field.avl_left;								\
    self->field.avl_left= l->field.avl_right;								\
    l->field.avl_right= MOD_TREE_BALANCE_##node##_##field(self);						\
    return MOD_TREE_BALANCE_##node##_##field(l);								\
  }													\
													\
  struct node *MOD_TREE_BALANCE_##node##_##field(struct node *self)						\
  {													\
    int delta= MOD_TREE_DELTA(self, field);									\
													\
    if (delta < -MOD_TREE_DELTA_MAX)									\
      {													\
	if (MOD_TREE_DELTA(self->field.avl_right, field) > 0)						\
	  self->field.avl_right= MOD_TREE_ROTR_##node##_##field(self->field.avl_right);			\
	return MOD_TREE_ROTL_##node##_##field(self);							\
      }													\
    else if (delta > MOD_TREE_DELTA_MAX)									\
      {													\
	if (MOD_TREE_DELTA(self->field.avl_left, field) < 0)						\
	  self->field.avl_left= MOD_TREE_ROTL_##node##_##field(self->field.avl_left);			\
	return MOD_TREE_ROTR_##node##_##field(self);							\
      }													\
    self->field.avl_height= 0;										\
    if (self->field.avl_left && (self->field.avl_left->field.avl_height > self->field.avl_height))	\
      self->field.avl_height= self->field.avl_left->field.avl_height;					\
    if (self->field.avl_right && (self->field.avl_right->field.avl_height > self->field.avl_height))	\
      self->field.avl_height= self->field.avl_right->field.avl_height;					\
    self->field.avl_height += 1;									\
    return self;											\
  }													\
													\
  struct node *MOD_TREE_INSERT_##node##_##field								\
    (struct node *self, struct node *elm, int (*compare)(void *lhs, void *rhs), int (*merge)(void **lhs, void **rhs), int *merged)\
  {													\
    if (!self) {											\
      *merged = 0;											\
      return elm; }											\
    int cmp = compare(elm->data, self->data);									\
    if (cmp < 0)											\
      self->field.avl_left= MOD_TREE_INSERT_##node##_##field(self->field.avl_left, elm, compare, merge, merged);	\
    else if (cmp > 0)											\
      self->field.avl_right= MOD_TREE_INSERT_##node##_##field(self->field.avl_right, elm, compare, merge, merged);	\
    else if (merge) {											\
      merge(&(elm->data), &(self->data));								\
      *merged = 1; }											\
    else												\
      self->field.avl_right= MOD_TREE_INSERT_##node##_##field(self->field.avl_right, elm, compare, merge, merged);	\
    return MOD_TREE_BALANCE_##node##_##field(self);								\
  }													\
													\
  struct node *MOD_TREE_FIND_##node##_##field								\
    (struct node *self, struct node *elm, int (*compare)(void *lhs, void *rhs))			\
  {													\
    if (!compare)											\
      return 0;												\
    if (!self)												\
      return 0;												\
    if (compare(elm->data, self->data) == 0)									\
      return self;											\
    if (compare(elm->data, self->data) < 0)										\
      return MOD_TREE_FIND_##node##_##field(self->field.avl_left, elm, compare);				\
    else												\
      return MOD_TREE_FIND_##node##_##field(self->field.avl_right, elm, compare);				\
  }													\
													\
  int MOD_TREE_FIND_LESS_EQUAL_##node##_##field								\
    (struct node *self, struct node *elm, int (*compare)(void *lhs, void *rhs), struct node **found, struct node **prev)		\
  {													\
    if (!self)												\
      return 0;												\
    if (compare(elm->data, self->data) == 0) {									\
      *found = self;											\
      return 1;												\
    }													\
    if (compare(elm->data, self->data) < 0) {										\
      int ret = MOD_TREE_FIND_LESS_EQUAL_##node##_##field(self->field.avl_left, elm, compare, found, prev);	\
      if (ret == 0 && *prev == NULL) {									\
        *prev = self;											\
        ret = -1;											\
      }													\
      return ret;											\
    } else {												\
      *found = self;											\
      *prev = self;											\
      return MOD_TREE_FIND_LESS_EQUAL_##node##_##field(self->field.avl_right, elm, compare, found, prev);	\
    }													\
  }													\
													\
  struct node *MOD_TREE_MOVE_RIGHT_##node##_##field(struct node *self, struct node *rhs)					\
  {													\
    if (!self)												\
      return rhs;											\
    self->field.avl_right= MOD_TREE_MOVE_RIGHT_##node##_##field(self->field.avl_right, rhs);					\
    return MOD_TREE_BALANCE_##node##_##field(self);								\
  }													\
													\
  struct node *MOD_TREE_REMOVE_##node##_##field								\
    (struct node *self, struct node *elm, int (*compare)(void *lhs, void *rhs), void (*del)(struct node *lhs))		\
  {													\
    if (!self) return 0;										\
													\
    if (compare(elm->data, self->data) == 0)									\
      {													\
	struct node *tmp= MOD_TREE_MOVE_RIGHT_##node##_##field(self->field.avl_left, self->field.avl_right);			\
	self->field.avl_left= 0;									\
	self->field.avl_right= 0;									\
	del(self);											\
	return tmp;											\
      }													\
    if (compare(elm->data, self->data) < 0)										\
      self->field.avl_left= MOD_TREE_REMOVE_##node##_##field(self->field.avl_left, elm, compare, del);	\
    else												\
      self->field.avl_right= MOD_TREE_REMOVE_##node##_##field(self->field.avl_right, elm, compare, del);	\
    return MOD_TREE_BALANCE_##node##_##field(self);								\
  }													\
													\
  void MOD_TREE_FORWARD_APPLY_ALL_##node##_##field								\
    (struct node *self, void (*function)(void *node, void *data), void *data)			\
  {													\
    if (self)												\
      {													\
	MOD_TREE_FORWARD_APPLY_ALL_##node##_##field(self->field.avl_left, function, data);			\
	function(self->data, data);										\
	MOD_TREE_FORWARD_APPLY_ALL_##node##_##field(self->field.avl_right, function, data);			\
      }													\
  }													\
													\
  void MOD_TREE_REVERSE_APPLY_ALL_##node##_##field								\
    (struct node *self, void (*function)(struct node *node, void *data), void *data)			\
  {													\
    if (self)												\
      {													\
	MOD_TREE_REVERSE_APPLY_ALL_##node##_##field(self->field.avl_right, function, data);			\
	function(self, data);										\
	MOD_TREE_REVERSE_APPLY_ALL_##node##_##field(self->field.avl_left, function, data);			\
      }													\
  }													\
													\
  void MOD_TREE_POST_ORDER_APPLY_ALL_##node##_##field							\
    (struct node *self, void (*function)(struct node *node, void *data), void *data)			\
  {													\
    if (self)												\
      {													\
	MOD_TREE_POST_ORDER_APPLY_ALL_##node##_##field(self->field.avl_left, function, data);			\
	MOD_TREE_POST_ORDER_APPLY_ALL_##node##_##field(self->field.avl_right, function, data);			\
	function(self, data);										\
      }													\
  }													\
												\
void MOD_TREE_DESTROY_ALL_##node##_##field							\
  (struct node *self, void (*function)(void *node, void *data), void(*dest)(struct node *node), void *data)			\
{													\
  if (self)												\
    {													\
      MOD_TREE_DESTROY_ALL_##node##_##field(self->field.avl_left, function, dest, data);		\
      MOD_TREE_DESTROY_ALL_##node##_##field(self->field.avl_right, function, dest, data);		\
      if (function != NULL)										\
         function(self->data, data);									\
      dest(self);											\
    }													\
}													\
													\
  void MOD_TREE_REVERSE_APPLY_POST_ALL_##node##_##field							\
    (struct node *self, void (*function)(struct node *node, void *data), void *data)			\
  {													\
    if (self)												\
      {													\
        MOD_TREE_REVERSE_APPLY_POST_ALL_##node##_##field(self->field.avl_right, function, data);	\
        MOD_TREE_REVERSE_APPLY_POST_ALL_##node##_##field(self->field.avl_left, function, data);		\
        function(self, data);										\
      }													\
}

#define MOD_TREE_INSERT(head, node, field, elm, merge, merged)						\
  ((head)->th_root= MOD_TREE_INSERT_##node##_##field((head)->th_root, (elm), (head)->th_cmp, merge, merged))

#define MOD_TREE_FIND(head, node, field, elm)				\
  (MOD_TREE_FIND_##node##_##field((head)->th_root, (elm), (head)->th_cmp))

#define MOD_TREE_FIND_LESS_EQUAL(head, node, field, elm, found, prev)				\
  (MOD_TREE_FIND_LESS_EQUAL_##node##_##field((head)->th_root, (elm), (head)->th_cmp, found, prev))

#define MOD_TREE_REMOVE(head, node, field, elm, rem)					\
  ((head)->th_root= MOD_TREE_REMOVE_##node##_##field((head)->th_root, (elm), (head)->th_cmp, (rem)))

#define MOD_TREE_DEPTH(head, field)			\
  ((head)->th_root->field.avl_height)

#define MOD_TREE_FORWARD_APPLY(head, node, field, function, data)	\
  MOD_TREE_FORWARD_APPLY_ALL_##node##_##field((head)->th_root, function, data)

#define MOD_TREE_REVERSE_APPLY(head, node, field, function, data)	\
  MOD_TREE_REVERSE_APPLY_ALL_##node##_##field((head)->th_root, function, data)

#define MOD_TREE_POST_ORDER_APPLY(head, node, field, function, data)	\
  MOD_TREE_POST_ORDER_APPLY_ALL_##node##_##field((head)->th_root, function, data)

#define MOD_TREE_DESTROY(head, node, field, function, dest, data)	\
  MOD_TREE_DESTROY_ALL_##node##_##field((head)->th_root, function, dest, data)

#define MOD_TREE_REVERSE_APPLY_POST(head, node, field, function, data)	\
  MOD_TREE_REVERSE_APPLY_POST_ALL_##node##_##field((head)->th_root, function, data)

#define MOD_TREE_INIT(head, cmp) do {		\
    (head)->th_root= 0;				\
    (head)->th_cmp= (cmp);			\
  } while (0)


#endif /* __MOD_TREE_h */
