
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
static inline void update_time(struct load_cl *l, const uint32_t time_now,
			const struct decay_config *decay)
{
	uint32_t ticks;
	uint32_t time_last = atomic_load_explicit(&l->time, memory_order_relaxed);
	do {
		ticks = (time_now - time_last) >> decay->ticklen_log;
		if (__builtin_expect(!ticks, true)) // we optimize for time not advancing
			return;
		// We accept some desynchronization of time_now (e.g. from different threads).
		if (ticks > (uint32_t)-1024)
			return;
	} while (!atomic_compare_exchange_weak_explicit(&l->time, &time_last, time_now, memory_order_relaxed, memory_order_relaxed));
		// TODO: check correctness under memory_order_relaxed

	// If we passed here, we have acquired a time difference we are responsibe for.

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
		// We perform decay for the acquired time difference; decays from different threads are commutative.
		_Atomic DECAY_T *load_at = (_Atomic DECAY_T *)&l->loads[i];
		DECAY_T l1, load_orig = atomic_load_explicit(load_at, memory_order_relaxed);
		do {
			// decay: first do the "fractibonal part of the bit shift"
			DECAY_TL m = (DECAY_TL)load_orig * decay->scales[decay_frac];
			l1 = (m >> DECAY_BITS) + /*rounding*/((m >> (DECAY_BITS-1)) & 1);
			// finally the non-fractional part of the bit shift
			l1 = l1 >> load_nonfrac_shift;
		} while (!atomic_compare_exchange_weak_explicit(load_at, &load_orig, l1, memory_order_relaxed, memory_order_relaxed));
			// TODO: check correctness under memory_order_relaxed
	}
}

/// Half-life of 32 ticks, consequently forgetting in a couple hundred ticks.
static const struct decay_config DECAY_32 = {
	.ticklen_log = 0,
	.half_life_log = 5,
	/// Experiment: if going by a single tick, after 362 steps fixed-point at 23,
	///  but accuracy at the beginning of that (first 32 ticks) is very good,
	///  getting from max 2^16 - 1 to 2^15 + 5.  Max. decay per tick is 1404.
	.scales = { // ghci> map (\i -> round(2^16 * 0.5 ** (i/32))) [1..31]
		0,64132,62757,61413,60097,58809,57549,56316,55109,53928,52773,
		51642,50535,49452,48393,47356,46341,45348,44376,43425,42495,41584,
		40693,39821,38968,38133,37316,36516,35734,34968,34219,33486
	}
};
