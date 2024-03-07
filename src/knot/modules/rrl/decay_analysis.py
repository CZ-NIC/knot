#!/usr/bin/python

import sys;
import math;

CNT=14   # number of columns (up to 2**13)
BITS=0   # number of bits of counters (to be set later)

def format_int(val):
    val=int(val)
    if val < 10000: return str(val)
    val //= 1000
    if val < 10000: return f"{val}k"
    val //= 1000
    if val < 10000: return f"{val}M"
    val //= 1000
    return f"{val}G"

# print CNT Values of limits for given decay and price
def V(func, price = 1):
	global CNT
	global BITS
	price = int(price)
	desc=func(0)
	sys.stdout.write("{:<7}{:>9}   ".format(desc, format_int(price) + " :" if price != 1 or desc != "" else ":" if func(0) != "" else ""));
	if price < 1:
		print("ZERO PRICE ERROR")
		return
	k = 1
	last = -1
	for i in range(CNT):
		cur = int(func(k) / price)
		sys.stdout.write("{:>5} ".format(format_int(cur) if cur != last else "-"))
		last = cur
		k *= 2
	sys.stdout.write("     [{:>5} from zero]".format(format_int((2**BITS - 1) / price)))
	print()


HEADER = lambda a: a if a > 0 else ""

# exponential decay with fractional bit-shift `shift` per tick, using `BITS` number of bits
def exp_decay(shift):
	def func(ticks):
		global BITS
		if ticks: return (2**BITS - 1) * (1 - 1/2**(ticks * shift))
		s = f'{shift:0.3f}'
		if shift == int(shift):
			s = int(shift)
		elif shift < 1 and int(1/shift) == 1/shift:
			s = "1/{}".format(int(1/shift))
		return "E{:>6}".format(s)
	return func

DECAY_32 = exp_decay(1/32);

# linear decay subtracting `sub` on each tick, using `BITS` nubmer of bits
def lin_decay(sub, max_ticks=math.inf):
	def func(ticks):
		global BITS
		if ticks: return min(2**BITS - 1, min(ticks, max_ticks) * sub)
		return "L{:3.1f}".format(sub)
	return func



#BITS=16
#V(HEADER);
#V(DECAY_32)
#V(exp_decay(1/32), 140)
#V(exp_decay(1   ), 327)

# print()
# V(lin_decay(  100),   1)
# V(lin_decay(10000), 100)
# V(lin_decay(10000),   1)


PREFIXES  = ["v6/128", "v6/64", "v6/56", "v6/48", "v6/32", "v4/32", "v4/24", "v4/20", "v4/18"]
RATE_MULT = [       1,       4,      16,      64,    1024,      16,     512,    4096,   12288]

def prefixes(bits, base_qps, decay_funcs):
	if type(decay_funcs) is not list: decay_funcs = [decay_funcs] * len(PREFIXES)
	print("{}-bit, {} QPS for {}, {} QPS for {}:".format(
		bits, format_int(base_qps * RATE_MULT[0]), PREFIXES[0], format_int(base_qps * RATE_MULT[-1]), PREFIXES[-1]))
	global BITS
	BITS=bits
	for prefix, rate_mult, decay_func in zip(PREFIXES, RATE_MULT, decay_funcs):
		price = decay_func(1) / (base_qps / 1000) / rate_mult
		sys.stdout.write(f"{prefix:<10}"); V(decay_func, price)
	print()


BITS=32
print("PREFIX     DECAY   PRICE      TICKS FROM BLOCKING WITH LIMITS...")
sys.stdout.write("          "); V(HEADER);
print();


# === 16-bit vs. 32-bit vs. 16-bit sqrt instant limits ===

# prefixes(16, 1404 / 12288 * 1000, exp_decay(1/32));
# prefixes(32, 1404 / 12288 * 1000, exp_decay(1/256));
#
# print("sqrt prices' ratios:")
# prefixes(16, 1404 / 12288 * 1000,
# 	[exp_decay(-math.log2(1 - math.sqrt(mult) / 1536)) for mult in RATE_MULT])


# === contant instant limit vs constant ratio instant/rate ===

# prefixes(32,    1, exp_decay(1/256 / 128));        # rate    1 QPS, instant limit 50
# prefixes(32, 2000, exp_decay(1/256 / 128));        # rate 2000 QPS, same decay
# prefixes(32, 2000, exp_decay(1/256 / 128 * 2000)); # rate 2000 QPS, instant limit 50


# === decays given by rate and instant limits of KRU.initialize ===

class KruInfo:
    def __init__(self, rate_limit, instant_limit):
        self.rate_limit = rate_limit
        self.instant_limit = instant_limit
        self.base_price = (2 ** 32) // (self.instant_limit + 1)
        self.max_decay = min(2**32 - 1, (self.base_price * self.rate_limit) // 1000)
        self.decay_mult_per_tick = (2**32 - self.max_decay) / 2**32
        self.decay_shift_per_tick = -math.log2(self.decay_mult_per_tick)
    def get_decay(self):
        return exp_decay(self.decay_shift_per_tick)

def kru_decay(rate_limit, instant_limit):
    sys.stdout.write(f"{rate_limit} QPS rate-limit, {instant_limit} Q instant-limit: ")
    info = KruInfo(rate_limit, instant_limit)
    prefixes(32, rate_limit, info.get_decay())


kru_decay(114, 50)

# default instant limit (50), different rate limits
for rate in [1, 10, 50, 100, 1000, 2000]:
    info = KruInfo(rate, 50)
    shift = info.decay_shift_per_tick
    shift_inv = 1/shift
    price = info.base_price
    max_decay = int(info.get_decay()(1))
    print(f"instant: {50}, rate: {rate:5d}, decay shift: 1/{shift_inv:10.3f}, price: {price}, max decay: {max_decay:10d}")
