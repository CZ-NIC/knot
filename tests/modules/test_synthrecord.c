/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>

#include <arpa/inet.h>

#include <stdio.h>

#include "knot/modules/synthrecord/utils_rl.h"

const char * const ipv6s[] = {
    // Generic addresses
    "7165:34D5:59B0:7BD6:7837:6422:8740:9BAA",
    "20EF:5CBD:82D3:1303:C751:58D3:98D0:5D0E",
    "C098:7B18:EFB5:7FBE:1F4C:0000:6C9F:CDDD",
    "985D:B1BA:1BFC:0000:0000:344C:8771:0000",
    "0000:86B0:E3D7:219D:693F:9447:0000:6045",
    "FC5F:812F:2B01:6289:8951:0000:A2DB:0000",
    "49BF:920F:0A67:08B3:FBE1:FF70:0060:059E",
    "0000:0819:D199:F286:0000:6742:3275:9ADE",
    "8004:0000:AE1A:0EAD:4CD4:C6C1:0000:4C29",
    "0E37:F749:0000:0DBC:5839:D73F:7D95:DB20",
    "8164:9308:FF1D:0889:925F:0000:ED3D:0B8B",
    "01FF:45C0:264E:526C:D950:E807:0000:4067",
    "7E83:1F36:EC96:520B:6D11:0000:0000:D77C",
    "7C48:750C:B9D9:3C2A:6576:0000:0000:0000",
    "67CB:5F33:ECD5:62AC:8C4A:0000:C0EE:0000",
    "0000:0000:1F1B:C339:0000:0000:0000:0000",
    "0000:F281:D854:A50C:EB01:70A0:0000:0000",
    "055C:0000:BA72:0000:697B:CAFA:DCE9:0000",
    "E481:0FDD:0000:0000:A1B7:0000:0000:6A8C",
    "0000:7761:0000:0000:74C8:0000:AA38:0000",
    "0000:0000:0000:D550:0000:BF38:0000:CD57",
    "0000:7A10:0000:DB82:7B58:07D6:0000:8E81",
    "E727:0000:E290:0000:0000:0000:C55F:0000",
    "0000:0000:0000:B5B6:0000:0000:0000:0000",
    "9B54:0000:0000:0000:0000:0000:0000:0000",
    "0000:4EEE:0000:0000:0000:0000:D1B7:EAB3",
    "1E75:0000:0000:0000:0000:0000:0000:0000",
    "9028:0000:0000:8549:6B4B:0000:0000:0000",
    "0000:0000:DD0B:0000:0000:05F3:0000:0000",
    "0000:0000:0000:0000:0000:0000:0000:393C",
    "193A:0000:0000:0000:7BE2:0000:0000:0000",
    "0000:0000:DB87:0000:0000:0000:0000:0000",

    // Special addresses
    "0000:0000:0000:0000:0000:0000:0000:0000",

    "00aa:0000:00bb:0000:0000:0000:0000:0001",
    "0aaa:0000:00bb:0000:0000:0000:0000:0001",
    "000a:0000:00bb:0000:0000:0000:0000:0001",

    "0000:000a:00bb:0000:0000:0000:0000:0001",
    "0000:0000:00bb:0000:0000:0000:0000:0001",

    NULL
};

void str_replace(char *dst, size_t n, const char from, const char to)
{
    for(size_t i = 0; i < n; ++i) {
        if(dst[i] == from) {
            dst[i] = to;
        }
    }
}

void test_ip6_shortening(const char * const ips[], size_t n)
{
    char buffer[INET6_ADDRSTRLEN];
    unsigned long result_counter = 0;
    for(size_t i = 0; i < n; ++i) {
        if(!ips[i]) break;

        size_t len = shorten_ipv6(buffer, ips[i]);
        str_replace(buffer, len, '-', ':');

        struct in6_addr original, converted;

        int ret = inet_pton(AF_INET6, ips[i], &original);
        if (ret != 1) continue;

        ret = inet_pton(AF_INET6, buffer, &converted);
        if (ret != 1) {
            result_counter++;
            continue;
        }

        int result = true;
        for (int j = 0; j < 4; ++j) {
            result &= (original.__in6_u.__u6_addr32[j] == converted.__in6_u.__u6_addr32[j]);
        }
        result_counter += !result;
    }
    ok(!result_counter, "IPv6 shotrening");
}

int main(int argc, char *argv[])
{
    plan_lazy();

    test_ip6_shortening(ipv6s, sizeof(ipv6s)/sizeof(const char *));

    return 0;
}
