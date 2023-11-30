#include <stdio.h>
#include <inttypes.h>
#include <string.h>

void *memzero(void *s, size_t n)
{
	typedef void *(*memset_t)(void *, int, size_t);
	static volatile memset_t volatile_memset = memset;
	return volatile_memset(s, 0, n);
}

#include <knot/modules/rrl/kru.c>

void test_decay32(void)
{
	struct load_cl l = { .loads[0] = -1, .time = 0 };
	for (uint32_t time = 0; time < 1030; ++time) {
		update_time(&l, time, &DECAY_32);
		printf("%3d: %08zx\n", time, (size_t)l.loads[0]);
	}
}

void test_choose_4_15() {
	#define MAX_HASH    (15*14*13*12) // uniform distribution expected
	//#define MAX_HASH    (1<<15)     // case with exactly 15 bits, a little biased
	#define MAX_BITMAP  (1<<15)
	#define HIST_LEN    (10000)

	uint32_t chosen_cnts[MAX_BITMAP] = {0};
	for (uint64_t i = 0; i < MAX_HASH; i++) {
		uint64_t hash = i;
		uint32_t chosen = choose_4_15(&hash);
		if (chosen > MAX_BITMAP) {
			printf("bitmap out of range: %d %d\n", i, chosen);
			return;
		}
		chosen_cnts[chosen]++;
	}
	uint32_t hist[HIST_LEN] = {0};
	for (size_t i = 0; i < MAX_BITMAP; i++) {
		if (chosen_cnts[i] > HIST_LEN) {
			printf("short hist: %d %d\n", i, chosen_cnts[i]);
			return;
		}
		hist[chosen_cnts[i]]++;
	}
	int nonzero = 0;
	for (size_t i = 0; i < sizeof(hist)/sizeof(uint32_t); i++) {
		if (hist[i] == 0) continue;
		printf("%2d: %5d\n", i, hist[i]);
		if (i > 0) nonzero++;
	}

	if (nonzero = 1) {
		printf("Uniform.\n");
	} else {
		printf("Not uniform.\n");
	}

	#undef MAX_HASH
	#undef MAX_BITMAP
	#undef HIST_LEN
}

struct test_ctx {
	struct kru *kru;
	uint32_t time;
	uint32_t price;
	size_t cnt;
	struct test_cat {
		char *name;
		uint64_t id_min, id_max;
	} *cats;  // categories
};

void test_stage(struct test_ctx *ctx, uint32_t dur, uint64_t *freq) {
	printf("STAGE: ");
	for (size_t cat = 0; cat < ctx->cnt; ++cat) {
		printf("%" PRIu64 ", ", freq[cat]);
	}
	printf("ticks %" PRIu32 "-%" PRIu32 "\n", ctx->time, ctx->time + dur - 1);

	uint64_t freq_bounds[ctx->cnt];
	freq_bounds[0] = freq[0];
	for (size_t cat = 1; cat < ctx->cnt; ++cat) {
		freq_bounds[cat] = freq_bounds[cat-1] + freq[cat];
	}

	uint64_t cat_passed[ctx->cnt], cat_total[ctx->cnt];
	for (size_t cat = 0; cat < ctx->cnt; ++cat) {
		cat_passed[cat] = 0;
		cat_total[cat] = 0;
	}

	for (uint64_t end_time = ctx->time + dur; ctx->time < end_time; ctx->time++) {
		for (uint64_t i = 0; i < freq_bounds[ctx->cnt-1]; i++) {
			long rnd = random() % freq_bounds[ctx->cnt-1];  // TODO initialize random generator
			size_t cat;
			for (cat = 0; freq_bounds[cat] <= rnd; cat++);

			uint64_t id = random() % (ctx->cats[cat].id_max - ctx->cats[cat].id_min + 1) + ctx->cats[cat].id_min;

			cat_total[cat]++;
			cat_passed[cat] += !kru_limited(ctx->kru, &id, sizeof(id), ctx->time, ctx->price);
		}
	}
	for (size_t cat = 0; cat < ctx->cnt; ++cat) {
		printf("  %-15s:  %8.2f /%10.2f per tick, %8" PRIu64 " /%10" PRIu64 " in total, %8.4f %% passed \n",
				ctx->cats[cat].name,
				(float)cat_passed[cat] / dur, (float)cat_total[cat] / dur,
				cat_passed[cat], cat_total[cat],
				100.0 * cat_passed[cat] / cat_total[cat]);
	}
	printf("\n");
}

#define TEST_STAGE(duration, ...) test_stage(&ctx, duration, (uint64_t[]) {__VA_ARGS__});

void test(void) { // TODO more descriptive name
	struct kru *kru = kru_init(16);

	struct test_cat cats[] = {
		{ "normal",       1,1000  },   // normal queries come from 1000 different addreses indexed 1-1000
		{ "attackers", 1001,1001  }    // attackers use only two adresses indexed 1001,1002
	};

	struct test_ctx ctx = {.kru = kru, .time = 0, .cats = cats, .cnt = sizeof(cats)/sizeof(struct test_cat),
		.price = 1<<23  // same price for all packets
	};

	// in each out of 10 ticks send around 1000 queries from random normal addresses and 500000 from each of the two attackers
	TEST_STAGE( 1,     1000, 1000000); // (duration, normal, attackers)
	TEST_STAGE( 10,    1000, 1000000);

	TEST_STAGE( 10,    1000, 1000000);
	TEST_STAGE( 100,   1000, 100000);
	TEST_STAGE( 100,   1000, 10000);
	TEST_STAGE( 100,   1000, 1000);
	TEST_STAGE( 100,   1000, 100);
	TEST_STAGE( 100,   1000, 10);
	TEST_STAGE( 10000, 1000, 2);  // both categories have the same frequency per individual

	TEST_STAGE( 100,   1000, 10000); // another attack after period without limitation

	kru_destroy(kru);
}

#undef TEST_STAGE


int main(int argc, char **argv)
{
	//test_choose_4_15();

	test();

	// struct kru kru __attribute__((unused));
	// test_decay32();
	return 0;
}
