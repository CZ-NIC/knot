#pragma once
#include "knot/include/atomic.h"

#pragma pack(push, 1)
/*!
 * \brief A node object that can be inserted into stack.
 */
typedef struct knotd_lockless_stack_node {
    struct knotd_lockless_stack_node *next;      /*!< Pointer to next node in the stack. */
} knotd_lockless_stack_node_t;

/*!
 * \brief The head of the stack linked list.
 */
typedef struct {
	KNOT_ALIGN(16)
    knotd_lockless_stack_node_t *next;       /*!< Pointer to top/first node in the stack. */
    uint32_t count;                          /*!< Keeps track of number of elements in the stack. */
    uint32_t aba_cookie;                     /*!< Value used to determine if the stack was updated to ensure atomicity.*/
                                             /*!< To detect pop(item1), pop(item2), push(item1) causing issues with pop(item1) executing in parallel. */
} knotd_lockless_stack_head_t;

/*!
 * \brief Lockless stack structure. Call knotd_lockless_stack_init to initialize before using this structure.
 * The stack is implemented using linked list of nodes. The node is preallocated as part of the items that are allocated.
 * So there is no size limit on number of objects that can be added in the stack.
 * Also, push and pop operations wont fail as the required memory for list are already pre-allocated as part of the object being pushed.
 */
typedef struct {
    KNOT_ATOMIC knotd_lockless_stack_head_t *head;
} knotd_lockless_stack_t;
#pragma pack(pop)

/*!
 * \brief Initialize lockless structure.
 *
 * \param stack Stack to be initialized.
 *
 * \retval 0 if successful.
 */
int knotd_lockless_stack_init(knotd_lockless_stack_t *stack);

/*!
 * \brief Cleanup lockless structure. The members in the stack are not altered.
 *
 * \param stack Stack initialized using knotd_lockless_stack_init.
 */
void knotd_lockless_stack_cleanup(knotd_lockless_stack_t *stack);

/*!
 * \brief Push the node into the lockless stack.
 *
 * \param stack Stack initialized using knotd_lockless_stack_init.
 * \param node Node to be inserted into stack.
 */
void knotd_lockless_stack_push(knotd_lockless_stack_t *stack, knotd_lockless_stack_node_t *node);

/*!
 * \brief Pop the node from the stack.
 *
 * \param stack Stack initialized using knotd_lockless_stack_init.
 *
 * \retval Node that is popped from stack, NULL if no nodes present.
 */
knotd_lockless_stack_node_t *knotd_lockless_stack_pop(knotd_lockless_stack_t *stack);

/*!
 * \brief Get the number of elements in the stack.
 *
 * \param stack Stack initialized using knotd_lockless_stack_init.
 *
 * \retval Count of objects in the stack.
 */
uint32_t knotd_lockless_stack_count(knotd_lockless_stack_t *stack);
