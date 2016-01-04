/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <assert.h>
#include <libknot/descriptor.h>
#include <libknot/rrset-dump.h>
#include <zscanner/scanner.h>

static void parse_error(zs_scanner_t *scanner)
{
	// nop
}

static void filter_dnssec(zs_scanner_t *scanner)
{
	switch (scanner->r_type) {
	case KNOT_RRTYPE_CDNSKEY:
	case KNOT_RRTYPE_DNSKEY:
	case KNOT_RRTYPE_NSEC3:
	case KNOT_RRTYPE_NSEC3PARAM:
	case KNOT_RRTYPE_NSEC:
	case KNOT_RRTYPE_RRSIG:
		break;
	default:
		return;
	}

	knot_rrset_t rrset = { 0 };
	knot_rrset_init(&rrset, scanner->r_owner, scanner->r_type, scanner->r_class);
	knot_rrset_add_rdata(&rrset, scanner->r_data, scanner->r_data_length, scanner->r_ttl, NULL);

	char buffer[65535] = { 0 };
	knot_rrset_txt_dump(&rrset, buffer, sizeof(buffer), &KNOT_DUMP_STYLE_DEFAULT);

	printf("%s", buffer);

//	knot_rrset_clear(&rrset, NULL);
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <zone-file>\n", argv[0]);
		return 1;
	}

	const char *filename = argv[1];

	int exit_code = 1;
	zs_scanner_t scan = { 0 };

	if (zs_init(&scan, ".", KNOT_CLASS_IN, 3600) != 0) {
		fprintf(stderr, "zs_init error\n");
		goto done;
	}

	if (zs_set_input_file(&scan, filename) != 0) {
		fprintf(stderr, "zs_set_input_file error\n");
		goto done;
	}

	if (zs_set_processing(&scan, filter_dnssec, parse_error, NULL) != 0) {
		fprintf(stderr, "zs_set_processing error\n");
		goto done;

	}

	if (zs_parse_all(&scan) != 0) {
		fprintf(stderr, "zs_parse_all\n");
		goto done;
	}

	exit_code = 0;
done:
	zs_deinit(&scan);

	return exit_code;
}
