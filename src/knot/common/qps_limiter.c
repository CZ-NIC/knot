#include "qps_limiter.h"
#include "contrib/time.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Watomic-alignment"

int qps_limiter_init(qps_limiter_t *limiter)
{
	if (posix_memalign( (void**)&limiter->qps_limit, 16, sizeof(qps_limit_t)) != 0) {
		return ENOMEM;
	}

	memset((void*)limiter->qps_limit, 0, sizeof(qps_limit_t));

	struct timespec tv;
	if (clock_gettime(CLOCK_REALTIME_COARSE, &tv)) {
		return errno;
	}

	limiter->start_time = tv.tv_sec;

	qps_limit_t limit = {0};

	KNOT_ATOMIC_INIT(limiter->qps_limit[0], limit);

	return 0;
}

void qps_limiter_cleanup(qps_limiter_t *limiter)
{
	free((void*)limiter->qps_limit);
	limiter->qps_limit = NULL;
}

bool qps_limiter_is_allowed(qps_limiter_t *limiter, time_t time, bool is_err)
{
	qps_limit_t expect;
	qps_limit_t new;

	KNOT_ATOMIC_GET(limiter->qps_limit, expect);

	 /* time_t could be 64bit. Using 64bit time will cause 128bit atomic operations which is not optimal.
	    We can keep time as from start of program to ensure 32bit gives us 68 years of run without restart,
		and still be 64bit atomic operations. */
	uint32_t rel_time = time - limiter->start_time;

	do
	{
		int diff = rel_time - expect.time;
		if (diff <= 0) {
			/* time is old, need throttling */
			new.time = expect.time;
			if ( (expect.query_cnt < limiter->log_qps)
				 || (is_err && expect.query_cnt < limiter->log_err_qps) ) {
				new.query_cnt = expect.query_cnt + 1;
			} else {
				return false;
			}
		} else  {
			/* time is new, reset limit */
			new.time = rel_time;
			long time_adj = (long)diff * limiter->log_qps;
			if (expect.query_cnt < time_adj) {
				/* enough time passed to reset the time */
				new.query_cnt = 1;
			} else {
				/* already used more time previously */
				int spill = expect.query_cnt - time_adj;
				if ( (spill < limiter->log_qps)
					 || (is_err && spill < limiter->log_err_qps) ) {
					new.query_cnt = spill + 1;
				} else {
					return false;
				}
			}
		}
	}
	while (!KNOT_ATOMIC_COMPARE_EXCHANGE_WEAK(limiter->qps_limit, expect, new));

	return true;
}

#pragma GCC diagnostic pop