
#define DECAY_BITS 16
#define DECAY_T  uint16_t
#define DECAY_TL uint32_t
#define DECAY_T_BITS_LOG 4

/// Parametrization for speed of decay.
struct decay_config {
	/// Length of one tick is 2 ^ ticklen_log.
	uint32_t ticklen_log;
	/// Exponential decay with half-life of (2 ^ half_life_log) ticks.
	uint32_t half_life_log;
	/// Precomputed scaling constants.  Indexed by tick count [1 .. 2^half_life_log - 1],
	///   contains the corresponding factor of decay (<1, scaled to 2^32 and rounded).
	DECAY_T scales[];
};

/// Catch up the time drift with configurably slower decay.
static void update_time(struct load_cl *l, const uint32_t time_now,
			const struct decay_config *decay)
{
	// We get `ticks` in this loop:
	//  - first, non-atomic check that no tick's happened (typical under attack)
	//  - on the second pass we advance l->time atomically
	uint32_t ticks;
	uint32_t time_last = l->time;
	for (int i = 1; i < 2; ++i,time_last = atomic_exchange(&l->time, time_now)) {
		ticks = (time_now - time_last) >> decay->ticklen_log;
		if (__builtin_expect(!ticks, true)) // we optimize for time not advancing
			return;
		// We accept some desynchronization of time_now (e.g. from different threads).
		if (ticks > (uint32_t)-1024)
			return;
	}
	// If we passed here, we should be the only thread updating l->time "right now".

	// Don't bother with complex computations if lots of ticks have passed.
	const uint32_t max_ticks_log = /* ticks to shift by one bit */ decay->half_life_log
					/* + log2(bit count) */ + DECAY_T_BITS_LOG;
	if (ticks >> max_ticks_log > 0) {
		memset(l->loads, 0, sizeof(l->loads));
		return;
	}

	// some computations pulled outside of the cycle
	const uint32_t decay_frac = ticks & (((uint32_t)1 << decay->half_life_log) - 1);
	const uint32_t load_nonfrac_shift = ticks >> decay->half_life_log;
	for (int i = 0; i < LOADS_LEN; ++i) {
		// decay: first do the "fractibonal part of the bit shift"
		DECAY_TL m = (DECAY_TL)l->loads[i] * decay->scales[decay_frac];
		DECAY_T l1 = (m >> DECAY_BITS) + /*rounding*/((m >> (DECAY_BITS-1)) & 1);
		// finally the non-fractional part of the bit shift
		l->loads[i] = l1 >> load_nonfrac_shift;
	}

}

/// Half-life of 32 ticks, consequently forgetting in about 1k ticks.
static const struct decay_config DECAY_32 = {
	.ticklen_log = 0,
	.half_life_log = 5,
	/// Experiment: if going by a single tick, after 330 steps fixed-point at +-23,
	///  but accuracy at the beginning of that (first 32 ticks) is very good,
	///  getting from max 2^15 - 1 to 2^14 + 2 or -2^15 to -2^14 - 3.
	///  Max. decay per tick is 702 but for limit computation it will be more like 350.
	.scales = { // ghci> map (\i -> round(2^16 * 0.5 ** (i/32))) [1..31]
		0,64132,62757,61413,60097,58809,57549,56316,55109,53928,52773,
		51642,50535,49452,48393,47356,46341,45348,44376,43425,42495,41584,
		40693,39821,38968,38133,37316,36516,35734,34968,34219,33486
	}
};

