#include <stddef.h>
#include "knot/include/lstack.h"
#include <assert.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Watomic-alignment"

int knotd_lockless_stack_init(knotd_lockless_stack_t *stack) {
	if (posix_memalign( (void**)&stack->head, 16, sizeof(knotd_lockless_stack_head_t)) != 0) {
		return ENOMEM;
	}

	memset((void*)stack->head, 0, sizeof(knotd_lockless_stack_head_t));
	knotd_lockless_stack_head_t head = {0};
	KNOT_ATOMIC_INIT(stack->head[0], head);
	return 0;
}

void knotd_lockless_stack_cleanup(knotd_lockless_stack_t *stack) {
    free(stack->head);
    stack->head = NULL;
}

void knotd_lockless_stack_push(knotd_lockless_stack_t *stack, knotd_lockless_stack_node_t *node) {
    knotd_lockless_stack_head_t expect, new;
    assert(node->next == NULL);

    KNOT_ATOMIC_GET(stack->head, expect);
    do
    {
        node->next = expect.next;
        new.next = node;
        new.count = expect.count + 1;
        new.aba_cookie = expect.aba_cookie + 1;
    }
    while(!KNOT_ATOMIC_COMPARE_EXCHANGE_WEAK(stack->head, expect, new));
}

knotd_lockless_stack_node_t *knotd_lockless_stack_pop(knotd_lockless_stack_t *stack) {
    knotd_lockless_stack_head_t expect, new;

    KNOT_ATOMIC_GET(stack->head, expect);
    do
    {
        if (expect.next == NULL)
        {
            assert(expect.count == 0);
            return NULL;
        }

        new.next = expect.next->next;       // DONOT free up stack nodes after pop, it can cause invalid memory access here.
        new.count = expect.count - 1;
        new.aba_cookie = expect.aba_cookie + 1;
    }
    while (!KNOT_ATOMIC_COMPARE_EXCHANGE_WEAK(stack->head, expect, new));

    expect.next->next = NULL;
    return expect.next;
}

uint32_t knotd_lockless_stack_count(knotd_lockless_stack_t *stack)
{
    knotd_lockless_stack_head_t expect;
    KNOT_ATOMIC_GET_RELAXED(stack->head, expect);
    return expect.count;
}

#pragma GCC diagnostic pop
