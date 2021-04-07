#pragma once
#include <stdatomic.h>
#include <stdint.h>
#include <stdalign.h>

#ifndef container_of
#define container_of(ptr, type, member) \
 ((type *)                              \
   (  ((char *)(ptr))                   \
    - ((char *)(&((type*)0)->member)) ))

#endif

typedef struct lockless_stack_node
{
    struct lockless_stack_node *next;      /*!< Pointer to next node in the stack. */
} lockless_stack_node_t;

typedef struct
{
    alignas(16) lockless_stack_node_t *head; /*!< Pointer to top/first node in the stack. */
    uint64_t aba_cookie;                     /*!< Value used to determine if the stack was updated to ensure atomicity.*/
                                             /*!< To detect pop(item1), pop(item2), push(item1) causing issues with pop(item1) executing in parallel. */
} lockless_stack_t;

void lockless_stack_init(lockless_stack_t *stack);

void lockless_stack_push(lockless_stack_t *stack, lockless_stack_node_t *node);

lockless_stack_node_t *lockless_stack_pop(lockless_stack_t *stack);
