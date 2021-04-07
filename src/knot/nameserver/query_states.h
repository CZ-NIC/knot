#pragma once

typedef enum {
	process_query_state_begin,
	process_query_state_done_prepare_answer,
	process_query_state_done_plan_begin,
	process_query_state_done_zone_plan_begin,
	process_query_state_done_query,
	process_query_state_done_post_query,
	process_query_state_done_handle_error,
	process_query_state_done_plan_end,
	process_query_state_done_zone_plan_end,
} process_query_state_t;

typedef enum {
    internet_process_query_state_begin,
    internet_process_query_state_done_preprocess,
} internet_process_query_state_t;

typedef enum {
    answer_query_state_begin,
    answer_query_state_done_preanswer,
    answer_query_state_done_answer_begin,
    answer_query_state_done_solve_answer,
    answer_query_state_done_solve_answer_dnssec,
    answer_query_state_done_stage_answer,
    answer_query_state_done_auth_begin,
    answer_query_state_done_solve_auth,
    answer_query_state_done_solve_auth_dnssec,
    answer_query_state_done_stage_auth,
    answer_query_state_done_additional_begin,
    answer_query_state_done_solve_additional,
    answer_query_state_done_solve_aadditional_dnssec,
    answer_query_state_done_stage_aadditional,
    answer_query_state_done_set_error,
} answer_query_state_t;

typedef struct {
	process_query_state_t process_query_state;
    internet_process_query_state_t internet_process_query_state;
    answer_query_state_t answer_query_state;
    int process_query_next_state;
    int process_query_next_state_in;
	struct query_step *step;
} state_machine_t;

#ifdef ENABLE_ASYNC_QUERY_HANDLING
#define STATE_MACHINE_RUN_STATE(state, next_state, async_state, sub_state, curr_state) \
	if (((state) == NULL) || ((next_state) != async_state && (state)->sub_state < (curr_state)))

#define STATE_MACHINE_COMPLETED_STATE(state, next_state, async_state, sub_state, curr_state) \
	if (((state) != NULL) && (next_state) != async_state) { (state)->sub_state = (curr_state); }
#else
#define STATE_MACHINE_RUN_STATE(state, next_state, async_state, sub_state, curr_state)

#define STATE_MACHINE_COMPLETED_STATE(state, next_state, async_state, sub_state, curr_state)
#endif

