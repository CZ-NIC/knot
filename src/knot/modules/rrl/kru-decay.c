#if   KRU_DECAY_BITS == 32
#define KRU_DECAY_T  uint32_t
#define KRU_DECAY_TL uint64_t
#define KRU_DECAY_T_BITS_LOG 5

#elif KRU_DECAY_BITS == 31
#define KRU_DECAY_T  int32_t
#define KRU_DECAY_TL int64_t
#define KRU_DECAY_T_BITS_LOG 5

#elif KRU_DECAY_BITS == 16
#define KRU_DECAY_T  uint16_t
#define KRU_DECAY_TL uint32_t
#define KRU_DECAY_T_BITS_LOG 4

#elif KRU_DECAY_BITS == 15
#define KRU_DECAY_T  int16_t
#define KRU_DECAY_TL int32_t
#define KRU_DECAY_T_BITS_LOG 4

#endif


/// Parametrization for speed of decay.
struct decay_config {
	/// Length of one tick is 2 ^ ticklen_log.
	uint32_t ticklen_log;
	/// Exponential decay with half-life of (2 ^ half_life_log) ticks.
	uint32_t half_life_log;
	/// Precomputed scaling constants.  Indexed by tick count [1 .. 2^half_life_log - 1],
	///   contains the corresponding factor of decay (<1, scaled to 2^32 and rounded).
	KRU_DECAY_T scales[];
};
typedef const struct decay_config decay_cfg_t;


/// Catch up the time drift with configurably slower decay.
static void update_time(struct load_cl *l, const uint32_t time_now, decay_cfg_t *decay)
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
					/* + log2(bit count) */ + KRU_DECAY_T_BITS_LOG;
	if (ticks >> max_ticks_log > 0) {
		memset(l->loads, 0, sizeof(l->loads));
		return;
	}

	// some computations pulled outside of the cycle
	const uint32_t decay_frac = ticks & (((uint32_t)1 << decay->half_life_log) - 1);
	const uint32_t load_nonfrac_shift = ticks >> decay->half_life_log;
	for (int i = 0; i < LOADS_LEN; ++i) {
		// decay: first do the "fractibonal part of the bit shift"
		KRU_DECAY_TL m = (KRU_DECAY_TL)l->loads[i] * decay->scales[decay_frac];
		KRU_DECAY_T l1 = (m >> KRU_DECAY_BITS) + /*rounding*/((m >> (KRU_DECAY_BITS-1)) & 1);
		// finally the non-fractional part of the bit shift
		l->loads[i] = l1 >> load_nonfrac_shift;
	}

}


/// Half-life of 32 ticks, consequently forgetting in about 1k ticks.
const struct decay_config DECAY_32 = {
	.ticklen_log = 0,
	.half_life_log = 5,
#if   KRU_DECAY_BITS == 32
/// Experiment: if going by a single tick, fix-point at load 23 after 874 steps,
///  but accuracy at the beginning of that (first 32 ticks) is very good,
///  getting from max 2^32 - 1 to 2^31 - 7.  Max. decay per tick is 92032292.
	.scales = { // ghci> map (\i -> round(2^32 * 0.5 ** (i/32))) [1..31]
		0, 4202935003,4112874773,4024744348,3938502376,3854108391,3771522796,
		3690706840,3611622603,3534232978,3458501653,3384393094,3311872529,
		3240905930,3171459999,3103502151,3037000500,2971923842,2908241642,
		2845924021,2784941738,2725266179,2666869345,2609723834,2553802834,
		2499080105,2445529972,2393127307,2341847524,2291666561,2242560872,2194507417
	}
#elif KRU_DECAY_BITS == 31
/// Experiment: if going by a single tick, after 840 steps +0 (or fixed at -46),
///  but accuracy at the beginning of that (first 32 ticks) is very good,
///  getting from max 2^31 - 1 to 2^30 - 9 or -2^31 to -2^30 - 17.
///  Max. decay per tick is 46016146.
	.scales = { // ghci> map (\i -> round(2^31 * 0.5 ** (i/32))) [1..31]
		0, 2101467502,2056437387,2012372174,1969251188,1927054196,1885761398,
		1845353420,1805811301,1767116489,1729250827,1692196547,1655936265,
		1620452965,1585730000,1551751076,1518500250,1485961921,1454120821,
		1422962010,1392470869,1362633090,1333434672,1304861917,1276901417,
		1249540052,1222764986,1196563654,1170923762,1145833280,1121280436,1097253708
	}
#elif KRU_DECAY_BITS == 16
/// Experiment: if going by a single tick, after 330 steps fixed-point at +-23,
///  but accuracy at the beginning of that (first 32 ticks) is very good,
///  getting from max 2^15 - 1 to 2^14 + 2 or -2^15 to -2^14 - 3.
///  Max. decay per tick is 702 but for limit computation it will be more like 350.
	.scales = { // ghci> map (\i -> round(2^16 * 0.5 ** (i/32))) [1..31]
		0,64132,62757,61413,60097,58809,57549,56316,55109,53928,52773,
		51642,50535,49452,48393,47356,46341,45348,44376,43425,42495,41584,
		40693,39821,38968,38133,37316,36516,35734,34968,34219,33486
	}
#elif KRU_DECAY_BITS == 15
	.scales = { // ghci> map (\i -> round(2^15 * 0.5 ** (i/32))) [1..31]
		0,32066,31379,30706,30048,29405,28774,28158,27554,26964,26386,
		25821,25268,24726,24196,23678,23170,22674,22188,21713,21247,20792,
		20347,19911,19484,19066,18658,18258,17867,17484,17109,16743
	}
#endif
};
