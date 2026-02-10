#pragma once

typedef enum {
	PROCESS_QUERY_STATE_BEGIN,
	PROCESS_QUERY_STATE_DONE_PREPARE_ANSWER,
	PROCESS_QUERY_STATE_DONE_PLAN_BEGIN,
	PROCESS_QUERY_STATE_DONE_ZONE_PLAN_BEGIN,
	PROCESS_QUERY_STATE_DONE_QUERY,
	PROCESS_QUERY_STATE_DONE_POST_QUERY,
	PROCESS_QUERY_STATE_DONE_HANDLE_ERROR,
	PROCESS_QUERY_STATE_DONE_PLAN_END,
	PROCESS_QUERY_STATE_DONE_ZONE_PLAN_END,
} process_query_state_t;

typedef enum {
	INTERNET_PROCESS_QUERY_STATE_BEGIN,
	INTERNET_PROCESS_QUERY_STATE_DONE_PREPROCESS,
} internet_process_query_state_t;

typedef enum {
	ANSWER_QUERY_STATE_BEGIN,
	ANSWER_QUERY_STATE_DONE_PREANSWER,
	ANSWER_QUERY_STATE_DONE_ANSWER_BEGIN,
	ANSWER_QUERY_STATE_DONE_SOLVE_ANSWER,
	ANSWER_QUERY_STATE_DONE_SOLVE_ANSWER_DNSSEC,
	ANSWER_QUERY_STATE_DONE_STAGE_ANSWER,
	ANSWER_QUERY_STATE_DONE_AUTH_BEGIN,
	ANSWER_QUERY_STATE_DONE_SOLVE_AUTH,
	ANSWER_QUERY_STATE_DONE_SOLVE_AUTH_DNSSEC,
	ANSWER_QUERY_STATE_DONE_STAGE_AUTH,
	ANSWER_QUERY_STATE_DONE_ADDITIONAL_BEGIN,
	ANSWER_QUERY_STATE_DONE_SOLVE_ADDITIONAL,
	ANSWER_QUERY_STATE_DONE_SOLVE_AADDITIONAL_DNSSEC,
	ANSWER_QUERY_STATE_DONE_STAGE_AADDITIONAL,
	ANSWER_QUERY_STATE_DONE_SET_ERROR,
} answer_query_state_t;

typedef enum {
	SOLVE_ANSWER_STATE_BEGIN,
	SOLVE_ANSWER_HANDLE_INCOMING_STATE,
	SOLVE_ANSWER_SOLVE_NAME_FIRST,
	SOLVE_ANSWER_SOLVE_NAME_FIRST_DONE,
	SOLVE_ANSWER_SOLVE_NAME_FOLLOW,
} solve_answer_query_state_t;

typedef enum {
	SOLVE_NAME_STATE_BEGIN,
	SOLVE_NAME_HANDLE_INCOMING_STATE,
	SOLVE_NAME_STAGE_LOOKUP,
	SOLVE_NAME_STAGE_LOOKUP_DONE,
} solve_name_query_state_t;

/*! \brief State machine state data.
	Preserves execution state of the function like
		1. Position within function
		2. Local variables whose values need to be preserved between resume.
	TBD: Unions can be used to save space for functions that cant execute in parallel. */
typedef struct {
	struct query_step *step;
	process_query_state_t process_query_state;
	internet_process_query_state_t internet_process_query_state;
	answer_query_state_t answer_query_state;
	solve_answer_query_state_t solve_answer_state;
	solve_name_query_state_t solve_name_state;
	int process_query_next_state;
	int process_query_next_state_in;
	int solve_answer_old_state;
	int solve_name_incoming_state;
	bool solve_answer_loop_in_async;
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

