#include <stddef.h>
#include "knot/include/lstack.h"

void lockless_stack_init(lockless_stack_t *stack) {
    stack->head = NULL;
    stack->aba_cookie = 0;
}

void lockless_stack_push(lockless_stack_t *stack, lockless_stack_node_t *node) {
    lockless_stack_t new;
    lockless_stack_t expect = atomic_load(stack);
    do
    {
        node->next = expect.head;
        new.head = node;
        new.aba_cookie = expect.aba_cookie + 1;
    }
    while(!atomic_compare_exchange_weak(stack, &expect, new));
}

lockless_stack_node_t *lockless_stack_pop(lockless_stack_t *stack) {
    lockless_stack_t new;
    lockless_stack_t expect = atomic_load(stack);
    do
    {
        if (expect.head == NULL)
        {
            return NULL;
        }

        new.head = atomic_load(&expect.head->next);
        new.aba_cookie = expect.aba_cookie + 1;
    }
    while (!atomic_compare_exchange_weak(stack, &expect, new));

    return expect.head;
}

