/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <tap/basic.h>

#include "contrib/toeplitz.h"
#include "contrib/wire_ctx.h"

// Test vectors come from Intel Ethernet Controller X710/XXV710/XL710 Series Datasheet
const uint8_t key[] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
	0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
	0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
	0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
	0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
};

void toeplitz_check(int family, const char *src_ip, const char *dst_ip,
                    uint16_t src_port, uint16_t dst_port, uint32_t expected)
{
	uint8_t data[2 * sizeof(struct in6_addr) + 2 * sizeof(uint16_t)];

	wire_ctx_t ctx = wire_ctx_init(data, sizeof(data));

	struct in_addr  src_addr4, dst_addr4;
	struct in6_addr src_addr6, dst_addr6;

	if (family == AF_INET &&
	    inet_pton(AF_INET, src_ip, &src_addr4) == 1 &&
	    inet_pton(AF_INET, dst_ip, &dst_addr4) == 1) {
		wire_ctx_write(&ctx, (uint8_t *)&(src_addr4.s_addr), sizeof(struct in_addr));
		wire_ctx_write(&ctx, (uint8_t *)&(dst_addr4.s_addr), sizeof(struct in_addr));
	} else if (family == AF_INET6 &&
	         inet_pton(AF_INET6, src_ip, &src_addr6) == 1 &&
	         inet_pton(AF_INET6, dst_ip, &dst_addr6) == 1) {
		wire_ctx_write(&ctx, (uint8_t *)&(src_addr6.s6_addr), sizeof(struct in6_addr));
		wire_ctx_write(&ctx, (uint8_t *)&(dst_addr6.s6_addr), sizeof(struct in6_addr));
	} else {
		assert(0);
	}

	wire_ctx_write_u16(&ctx, src_port);
	wire_ctx_write_u16(&ctx, dst_port);

	if (ctx.error != KNOT_EOK) {
		assert(0);
	}

	uint32_t value = toeplitz_hash(key, sizeof(key), data, wire_ctx_offset(&ctx));
	is_int(expected, value, "toeplitz_hash: %u", expected);

	toeplitz_ctx_t toepl;
	for (int i = 0; i <= wire_ctx_offset(&ctx); i++) {
		toeplitz_init(&toepl, i, key, sizeof(key), data, wire_ctx_offset(&ctx));
		value = toeplitz_finish(&toepl);
		is_int(expected, value, "toeplitz_init to %i: %u", i, expected);
	}
}

int main(void)
{
	plan_lazy();

	toeplitz_check(AF_INET,  "66.9.149.187",  "161.142.100.80",  2794,  1766, 0x51ccc178);
	toeplitz_check(AF_INET,  "199.92.111.2",    "65.69.140.83", 14230,  4739, 0xc626b0ea);
	toeplitz_check(AF_INET,  "24.19.198.95",   "12.22.207.184", 12898, 38024, 0x5c2b394a);
	toeplitz_check(AF_INET,  "38.27.205.30",   "209.142.163.6", 48228,  2217, 0xafc7327f);
	toeplitz_check(AF_INET, "153.39.163.191",  "202.188.127.2", 44251,  1303, 0x10e828a2);

	toeplitz_check(AF_INET6, "3ffe:2501:200:1fff::7",               "3ffe:2501:200:3::1",        2794,  1766, 0x40207d3d);
	toeplitz_check(AF_INET6, "3ffe:501:8::260:97ff:fe40:efab",      "ff02::1",                  14230,  4739, 0xdde51bbf);
	toeplitz_check(AF_INET6, "3ffe:1900:4545:3:200:f8ff:fe21:67cf", "fe80::200:f8ff:fe21:67cf", 44251, 38024, 0x02d1feef);

	return 0;
}
