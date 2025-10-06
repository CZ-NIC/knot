#pragma once
#include "knot/include/atomic.h"

#pragma pack(push, 1)
typedef struct qps_limit {
	KNOT_ALIGN(8) uint32_t time;
	uint32_t query_cnt;
} qps_limit_t;
#pragma pack(pop)

typedef struct qps_limiter {
	time_t start_time;
	int log_qps;
	int log_err_qps;
	KNOT_ATOMIC	qps_limit_t *qps_limit;
} qps_limiter_t;

/*!
 * \brief Initialize QPS Limiter object.
 *
 * \param limiter QPS Limiter object.
 *
 * \retval 0 if sucessfully initialized.
 * \retval Other values to indicate error.
 */
int qps_limiter_init(qps_limiter_t *limiter);

/*!
 * \brief Cleans up QPS Limiter object.
 *
 * \param limiter QPS Limiter object.
 */
void qps_limiter_cleanup(qps_limiter_t *limiter);

/*!
 * \brief Checks whether the query is allowed and meets qps limits.
 *
 * \param limiter QPS Limiter object.
 * \param time Time second value from real time clock.
 * \param is_err Is the log required for error case.
 */
bool qps_limiter_is_allowed(qps_limiter_t *limiter, time_t time, bool is_err);
