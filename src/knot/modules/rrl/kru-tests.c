#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

void *memzero(void *s, size_t n)
{
	typedef void *(*memset_t)(void *, int, size_t);
	static volatile memset_t volatile_memset = memset;
	return volatile_memset(s, 0, n);
}

#include <knot/modules/rrl/kru-generic.c>

void test_max_decay(void)
{
	struct decay_config decay;
	int cnt = 0;
	for (uint32_t max_decay32 = 1; max_decay32 < (1 << 31); max_decay32+=65537) {
		decay_initialize(&decay, max_decay32);
		uint32_t sum = (1 << 16) - 1;
		for (size_t i = 0; i < 65536; ) {
			struct load_cl l = { .time = 0 };
			for (size_t j = 0; j < LOADS_LEN; j++) l.loads[j] = (1ull << 16) - 1;
			update_time(&l, 1, &decay);
			for (size_t j = 0; (j < LOADS_LEN) && (i < 65536); j++, i++) sum += l.loads[j];
		}
		uint32_t ret = (1ull << 32) - 1 - sum;
		if (ret - max_decay32 == 0) continue;
		if (++cnt >= 100) {
			printf("      ...\n");
			break;
		}
		printf("%9u -> %9u [diff %9d] (%f)\n", max_decay32, ret, ret - max_decay32, decay.shift_bits);
	}
}
void test_decay(uint32_t max_decay32)
{
	printf("max_decay32: %d, max_decay16: %0.4f\n", max_decay32, (double)max_decay32 / (1<<16));
	printf("      tick   decay each tick   single decay\n");
	struct decay_config decay;
	decay_initialize(&decay, max_decay32);
	struct load_cl l  = { .loads[0] = (1ull<<16) - 1, .time = 0 };
	uint32_t checkpoint = 1;
	int zeros_to_end = 2;
	for (uint64_t time = 0;; ++time) {
		struct load_cl l2  = { .loads[0] = (1ull<<16) - 1, .time = 0 };
		update_time(&l, time, &decay);
		update_time(&l2, time, &decay);
		if (time == checkpoint) {
			checkpoint <<= 1;
			printf("%10ld:       %5d            %5d        [diff %9d]\n", time, (int)l.loads[0], (int)l2.loads[0], (int)l2.loads[0] - (int)l.loads[0]);
			if ((l2.loads[0] == 0) && (--zeros_to_end == 0)) break;
		}
	}
}

#ifdef HASH_KEY_T
void test_hash(void)
{
	HASH_KEY_T key;
	(void) HASH_INIT(key);

	char str[] = "abcd";
	HASH_FROM_BUF(key, str, sizeof(str));
	// hashes[0] = -1;
	// hashes[1] = 0;
	// hashes[2] = -1;

	for (size_t i = 0; i < HASH_BITS; i += 7) {
		printf("%ld\n", HASH_GET_BITS(7));
	}
}
#endif


/*===  benchmarking manageable number of attackers  ===*/

struct test_ctx {
	struct kru *kru;
	uint32_t time;        // last time
	uint32_t begin_time;  // time when stats were cleared
	uint32_t price;       // price of all queries
	size_t cnt;           // count of categories
	struct test_cat {     // categories of users
		char *name;
		uint64_t id_min, id_max;  // there is (id_max - id_min + 1) unique users in the category
		uint64_t freq;            // number of queries per tick from the category (each from random user)
		uint64_t passed, total;   // accumulating statistic variables
	} *cats;
};

void test_stage(struct test_ctx *ctx, uint32_t dur) {
	uint64_t freq_bounds[ctx->cnt];
	freq_bounds[0] = ctx->cats[0].freq;
	for (size_t cat = 1; cat < ctx->cnt; ++cat) {
		freq_bounds[cat] = freq_bounds[cat-1] + ctx->cats[cat].freq;
	}

	for (uint64_t end_time = ctx->time + dur; ctx->time < end_time; ctx->time++) {
		for (uint64_t i = 0; i < freq_bounds[ctx->cnt-1]; i++) {
			uint64_t rnd = random() % freq_bounds[ctx->cnt-1];  // uses fixed seed
			size_t cat;
			for (cat = 0; freq_bounds[cat] <= rnd; cat++);

			uint64_t key[2] ALIGNED(16) = {0};
			key[0] = random() % (ctx->cats[cat].id_max - ctx->cats[cat].id_min + 1) + ctx->cats[cat].id_min;

			ctx->cats[cat].total++;
			ctx->cats[cat].passed += !KRU.limited(ctx->kru, ctx->time, (uint8_t *)key, ctx->price);
		}
	}
}

void test_clear_stats(struct test_ctx *ctx) {
	for (size_t i = 0; i < ctx->cnt; i++) {
		ctx->cats[i].passed = 0;
		ctx->cats[i].total = 0;
	}
	ctx->begin_time = ctx->time;
}

void test_print_stats(struct test_ctx *ctx) {
	printf("TICKS %" PRIu32 "-%" PRIu32, ctx->begin_time, ctx->time - 1);

	int price_log = 0;
	for (uint32_t price = ctx->price; price >>= 1; price_log++);
	if (ctx->price == (1 << price_log)) {
		printf(", price 2^%d\n", price_log);
	} else {
		printf(", price 0x%x\n", ctx->price);
	}

	uint32_t dur = ctx->time - ctx->begin_time;
	for (size_t cat = 0; cat < ctx->cnt; ++cat) {
		uint64_t users = ctx->cats[cat].id_max - ctx->cats[cat].id_min + 1;
		char name_users[30];
		snprintf(name_users, sizeof(name_users), "%s (%" PRIu64 "):", ctx->cats[cat].name, users);

		printf("  %-25spassed: %8.4f %%,    per tick:%11.2f /%11.2f,    per tick and user:%8.2f /%10.2f\n",
				name_users,
				100.0 * ctx->cats[cat].passed / ctx->cats[cat].total,
				(float)ctx->cats[cat].passed / dur,         (float)ctx->cats[cat].total / dur,
				(float)ctx->cats[cat].passed / dur / users, (float)ctx->cats[cat].total / dur / users);
	}
	printf("\n");

	test_clear_stats(ctx);
}

#define TEST_STAGE(duration, ...) { \
	uint64_t freq[] = {__VA_ARGS__}; \
	for (size_t i = 0; i < sizeof(cats) / sizeof(*cats); i++) cats[i].freq = freq[i]; \
	test_stage(&ctx, duration); \
	test_print_stats(&ctx); }

void test_single_attacker(void) {
	struct kru *kru = NULL;
	if (posix_memalign((void **)&kru, 64, KRU.get_size(16))) abort();
	KRU.initialize(kru, 16, (1404ll << (KRU_PRICE_BITS - 16)));

	struct test_cat cats[] = {
		{ "normal",       1,1000  },   // normal queries come from 1000 different addreses indexed 1-1000
		{ "attackers", 1001,1001  }    // attacker use only one address indexed 1001
	};

	struct test_ctx ctx = {.kru = kru, .time = 0, .cats = cats, .cnt = sizeof(cats)/sizeof(*cats),
		.price = 1<<(KRU_PRICE_BITS
				-7
#if defined(KRU_IMPL_median32bit) || defined(KRU_IMPL_median16bit_simd)
				-1
#endif
			)
	};
	test_clear_stats(&ctx);

	// in each out of 10 ticks send around 1000 queries from random normal addresses and 1000000 from the attacker
	TEST_STAGE( 10,    1000, 1000000); // (duration, normal, attackers)

	TEST_STAGE( 10,    1000, 1000000);
	TEST_STAGE( 100,   1000, 100000);
	TEST_STAGE( 100,   1000, 10000);
	TEST_STAGE( 100,   1000, 1000);
	TEST_STAGE( 100,   1000, 100);
	TEST_STAGE( 100,   1000, 10);
	TEST_STAGE( 10000, 1000, 1);  // both categories have the same frequency per user

	TEST_STAGE( 100,   1000, 10000); // another attack after a period without limitation

	free(kru);
}

#undef TEST_STAGE

void test_multi_attackers(void) {
	struct kru *kru = NULL;
	if (posix_memalign((void **)&kru, 64, KRU.get_size(15))) abort();
	KRU.initialize(kru, 15, (1404ll << (KRU_PRICE_BITS - 16)));

	struct test_cat cats[] = {
		{ "normal",         1,100000,  100000 },   // 100000 normal queries per tick, ~1 per user
		{ "attackers", 100001,100001,  10     }    // 1 attacker, 10 queries per tick; both will rise by the same factor
	};

	struct test_ctx ctx = {.kru = kru, .time = 0, .cats = cats, .cnt = sizeof(cats)/sizeof(*cats),
		.price = 1<<(KRU_PRICE_BITS
				-7
#if defined(KRU_IMPL_median32bit) || defined(KRU_IMPL_median16bit_simd)
				-1
#endif
			)
	};
	test_clear_stats(&ctx);

	for (size_t i = 0; i < 17; i++) {
		// hidden ticks with new setting, not counted to stats
		test_stage(&ctx, 10);
		test_clear_stats(&ctx);

		// counted ticks
		test_stage(&ctx, 10);
		test_print_stats(&ctx);

		// double attackers, keep the same number of queries per attacker
		cats[1].id_max += cats[1].id_max - cats[1].id_min + 1;  // new ids were unused so far
		cats[1].freq *= 2;
	}

	free(kru);
}


/*=== benchmarking time performance ===*/

#define TIMED_TESTS_TABLE_SIZE_LOG             16
#define TIMED_TESTS_PRICE               ((1 << (KRU_PRICE_BITS - 7)) + 1)
#define TIMED_TESTS_QUERIES              (1 << 26)
#define TIMED_TESTS_TIME_UPDATE_PERIOD          4
#define TIMED_TESTS_MAX_THREADS                64
#define TIMED_TESTS_WAIT_BEFORE_SEC             2

#define TIMED_TESTS_BATCH_SIZE                  1  // each query still counted individually in MQPS; should be set to 1 if PREFIXES are set
#define TIMED_TESTS_PREFIXES                    (uint8_t []){64, 65, 66, 67}  // one query contains all prefixes, MQPS is lowered

struct timed_test_ctx {
	struct kru *kru;
	uint64_t first_query, increment;
	int key_mult;
};


void *timed_runnable(void *arg) {
	struct timed_test_ctx *ctx = arg;

	struct timespec now_ts = {0};
	uint32_t now_msec = 0;
	uint64_t now_last_update = -TIMED_TESTS_TIME_UPDATE_PERIOD * ctx->increment;

#ifdef TIMED_TESTS_PREFIXES
	kru_price_t prices[sizeof(TIMED_TESTS_PREFIXES)];
#else
	kru_price_t prices[TIMED_TESTS_BATCH_SIZE];
#endif
	for (size_t j = 0; j < sizeof(prices)/sizeof(*prices); j++) {
		prices[j] = TIMED_TESTS_PRICE;
	}

	for (uint64_t i = ctx->first_query; i < TIMED_TESTS_QUERIES; ) {
		if (i >= now_last_update + TIMED_TESTS_TIME_UPDATE_PERIOD * ctx->increment) {
			clock_gettime(CLOCK_MONOTONIC_COARSE, &now_ts);
			now_msec = now_ts.tv_sec * 1000 + now_ts.tv_nsec / 1000000;
			now_last_update = i;
		}

		uint64_t key_values[TIMED_TESTS_BATCH_SIZE * 2] = {0,};
		uint8_t *keys[TIMED_TESTS_BATCH_SIZE];

		for (size_t j = 0; j < TIMED_TESTS_BATCH_SIZE; j++) {
			key_values[2 * j] = i * ctx->key_mult;
			key_values[2 * j + 1] = 0xFFFFFFFFFFFFFFFFll;
			keys[j] = (uint8_t *)(key_values + 2 * j);
			i += ctx->increment;
		}

#ifdef TIMED_TESTS_PREFIXES
		KRU.limited_multi_prefix_or(ctx->kru, now_msec, 0, keys[0], TIMED_TESTS_PREFIXES, prices, sizeof(TIMED_TESTS_PREFIXES));
#else
		KRU.limited_multi_or_nobreak(ctx->kru, now_msec, keys, prices, TIMED_TESTS_BATCH_SIZE);
#endif
	}
	return NULL;
}

void timed_tests() {
	struct kru *kru = NULL;
	struct timed_test_ctx ctx[TIMED_TESTS_MAX_THREADS];
	pthread_t thr[TIMED_TESTS_MAX_THREADS];
	struct timespec begin_ts, end_ts;
	uint64_t diff_nsec;
	struct timespec wait_ts = {TIMED_TESTS_WAIT_BEFORE_SEC, 0};


	for (int threads = 1; threads <= TIMED_TESTS_MAX_THREADS; threads *= 2) {
		for (int collide = 0; collide < 2; collide++) {
			nanosleep(&wait_ts, NULL);
			printf("%3d threads, %-15s:  ", threads, (collide ? "single query" : "unique queries"));

			if (posix_memalign((void **)&kru, 64, KRU.get_size(TIMED_TESTS_TABLE_SIZE_LOG))) {
				abort();
			}
			KRU.initialize(kru, TIMED_TESTS_TABLE_SIZE_LOG, (1404ll << (KRU_PRICE_BITS - 16)));
			clock_gettime(CLOCK_REALTIME, &begin_ts);

			for (int t = 0; t < threads; t++) {
				ctx[t].kru = kru;
				ctx[t].first_query = t;
				ctx[t].increment  = threads;
				ctx[t].key_mult = 1 - collide;;
				pthread_create(thr + t, NULL, &timed_runnable, ctx + t);
			}

			for (int t = 0; t < threads; t++) {
				pthread_join(thr[t], NULL);
			}

			clock_gettime(CLOCK_REALTIME, &end_ts);
			free(kru); kru = NULL;

			diff_nsec = (end_ts.tv_sec - begin_ts.tv_sec) * 1000000000ll + end_ts.tv_nsec - begin_ts.tv_nsec;
			double diff_sec = diff_nsec / 1000000000.0;
			printf("%7.2f MQPS,  %7.2f MQPS per thread,  %2.4f s total\n",
				TIMED_TESTS_QUERIES / diff_sec / 1000000,
				TIMED_TESTS_QUERIES / diff_sec / 1000000 / threads,
				diff_sec);
		}
		printf("\n");
	}
}


/*=== benchmarking randomized fractional increments ===*/

void test_count_unlimited() {
	const size_t table_size_log = 5;
	assert(KRU_PRICE_BITS > 16);
	uint8_t key[16] = {};
	struct kru *kru = NULL;
	if (posix_memalign((void **)&kru, 64, KRU.get_size(table_size_log))) {
		abort();
	}
	for (int price_log = 16; price_log >= 0; price_log--) {
		printf("price 2^%d:\n", price_log);
		const kru_price_t price = 1 << price_log;
		const kru_price_t exp_limit = KRU_LIMIT / price;
		for (size_t i = 0; i < 4; i++) {
			memzero(kru, KRU.get_size(table_size_log));
			KRU.initialize(kru, table_size_log, (1404ll << (KRU_PRICE_BITS - 16)));
			for (uint64_t q = 0; q < -1ll; q++) {
				if (KRU.limited(kru, 0, key, price)) {
					printf("  blocked after %10lu queries, diff %10ld (%8.5f %%)\n", q, q - exp_limit, ((double)((signed)q - (signed)exp_limit)/exp_limit) * 100);
					break;
				}
			}
		}
	}
}

/*===*/

int main(int argc, char **argv)
{
	// test_single_attacker();
	// test_multi_attackers();
	// test_count_unlimited();
	timed_tests();

	// test_hash();
	// test_decay(84214);
	// test_max_decay();   // use with least significant bits in rand_bits for exact match
	return 0;
}
