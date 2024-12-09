/*  Copyright (C) 2025 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <time.h>

#include "knot/zone/serial.h"

static const serial_cmp_result_t diffbrief2result[4] = {
	[0] = SERIAL_EQUAL,
	[1] = SERIAL_GREATER,
	[2] = SERIAL_INCOMPARABLE,
	[3] = SERIAL_LOWER,
};

serial_cmp_result_t serial_compare(uint32_t s1, uint32_t s2)
{
	uint64_t diff = ((uint64_t)s1 + ((uint64_t)1 << 32) - s2) & 0xffffffff;
	int diffbrief = (diff >> 31 << 1) | ((diff & 0x7fffffff) ? 1 : 0);
	assert(diffbrief > -1 && diffbrief < 4);
	return diffbrief2result[diffbrief];
}

static uint32_t serial_dateserial(uint32_t current)
{
	struct tm now;
	time_t current_time = time(NULL);
	struct tm *gmtime_result = gmtime_r(&current_time, &now);
	if (gmtime_result == NULL) {
		return current;
	}
	return (1900 + now.tm_year) * 1000000 +
	       (   1 + now.tm_mon ) *   10000 +
	       (       now.tm_mday) *     100;
}

uint32_t serial_next_generic(uint32_t current, unsigned policy, uint32_t must_increment,
                             uint8_t rem, uint8_t mod)
{
	uint32_t minimum, result;

	switch (policy) {
	case SERIAL_POLICY_INCREMENT:
		minimum = current;
		break;
	case SERIAL_POLICY_UNIXTIME:
		minimum = time(NULL);
		break;
	case SERIAL_POLICY_DATESERIAL:
		minimum = serial_dateserial(current);
		break;
	default:
		assert(0);
		return 0;
	}
	if (serial_compare(minimum, current) != SERIAL_GREATER) {
		result = current + must_increment;
	} else {
		result = minimum;
	}

	// SERIAL MODULO: find lowest X that fullfils X % mod == rem && X >= result
	assert(rem < mod); // this also asserts mod >= 1
	// rem+mod means "rem" but ensures that rem+mod >= mod > result%mod, so that the difference is > 0
	uint32_t incr = ((rem + mod) - (result % mod)) % mod;
	if (result + incr < result) { // uint32 overflow detected
		result = rem;
	} else {
		result += incr;
	}
	assert(result % mod == rem);

	return result;
}

uint32_t serial_next(uint32_t current, conf_t *conf, const knot_dname_t *zone,
                     unsigned policy, uint32_t must_increment)
{
	assert(conf);
	assert(zone);

	if (policy == SERIAL_POLICY_AUTO) {
		conf_val_t val = conf_zone_get(conf, C_SERIAL_POLICY, zone);
		policy = conf_opt(&val);
	}

	uint32_t rem, mod;
	conf_val_t val = conf_zone_get(conf, C_SERIAL_MODULO, zone);
	if (serial_modulo_parse(conf_str(&val), &rem, &mod) != KNOT_EOK) {
		assert(0); // cannot happen - ensured by conf check
		return 0;
	}

	return serial_next_generic(current, policy, must_increment, rem, mod);
}

serial_cmp_result_t kserial_cmp(kserial_t a, kserial_t b)
{
	return ((a.valid && b.valid) ? serial_compare(a.serial, b.serial) : SERIAL_INCOMPARABLE);
}
