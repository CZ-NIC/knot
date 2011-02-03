#include <ctype.h>

#include "dnslib.h"
#include "dnslib/utils.h"

/* Taken from RFC 4398, section 2.1.  */
dnslib_lookup_table_t dnslib_dns_certificate_types[] = {
/*	0		Reserved */
	{ 1, "PKIX" },	/* X.509 as per PKIX */
	{ 2, "SPKI" },	/* SPKI cert */
	{ 3, "PGP" },	/* OpenPGP packet */
	{ 4, "IPKIX" },	/* The URL of an X.509 data object */
	{ 5, "ISPKI" },	/* The URL of an SPKI certificate */
	{ 6, "IPGP" },	/* The fingerprint and URL of an OpenPGP packet */
	{ 7, "ACPKIX" },	/* Attribute Certificate */
	{ 8, "IACPKIX" },	/* The URL of an Attribute Certificate */
	{ 253, "URI" },	/* URI private */
	{ 254, "OID" },	/* OID private */
/*	255 		Reserved */
/* 	256-65279	Available for IANA assignment */
/*	65280-65534	Experimental */
/*	65535		Reserved */
	{ 0, NULL }
};

/* Taken from RFC 2535, section 7.  */
dnslib_lookup_table_t dnslib_dns_algorithms[] = {
	{ 1, "RSAMD5" },	/* RFC 2537 */
	{ 2, "DH" },		/* RFC 2539 */
	{ 3, "DSA" },		/* RFC 2536 */
	{ 4, "ECC" },
	{ 5, "RSASHA1" },	/* RFC 3110 */
	{ 252, "INDIRECT" },
	{ 253, "PRIVATEDNS" },
	{ 254, "PRIVATEOID" },
	{ 0, NULL }
};

char *rdata_dname_to_string(dnslib_rdata_item_t item)
{
	return dnslib_dname_to_str(item.dname);
}

char *rdata_dns_name_to_string(dnslib_rdata_item_t item)
{
	return dnslib_dname_to_str(item.dname);
}

char *rdata_text_to_string(dnslib_rdata_item_t item)
{
	const uint8_t *data = (const uint8_t *) item.raw_data + 1;
	uint8_t length = data[0];
	size_t i;

	char *ret = malloc(sizeof(char) * (length + 1));

	memset(ret, 0, sizeof(char) * (length + 1));

	strcat(ret, "\"");
	for (i = 1; i <= length; i++) {
		char ch = (char) data[i];
		if (isprint((int)ch)) {
			if (ch == '"' || ch == '\\') {
				strcat(ret, "\\");
			}
				char tmp_str[2];
				tmp_str[0] = ch;
				tmp_str[1] = 0;
				strcat(ret, tmp_str);
		} else {
			strcat(ret, "\\");
			char tmp_str[2];
			tmp_str[0] = ch;
			tmp_str[1] = 0;

			strcat(ret, tmp_str);
			// XXX
//			buffer_printf(output, "\\%03u", (unsigned) ch);
		}
	}
	strcat(ret, "\"");

	return ret;
}

char *rdata_byte_to_string(dnslib_rdata_item_t item)
{
	uint8_t data = item.raw_data[1];
	char *ret = malloc(sizeof(char) * 4);
	snprintf(ret, 4, "%d", (char) data);
	return ret;
}

/*char *rdata_short_to_string(dnslib_rdata_item_t item)
{
	uint16_t data = read_uint16(rdata_atom_data(rdata));
	buffer_printf(output, "%lu", (unsigned long) data);
	return 1;
}

static int
rdata_long_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	uint32_t data = read_uint32(rdata_atom_data(rdata));
	buffer_printf(output, "%lu", (unsigned long) data);
	return 1;
}

static int
rdata_a_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	int result = 0;
	char str[200];
	if (inet_ntop(AF_INET, rdata_atom_data(rdata), str, sizeof(str))) {
		buffer_printf(output, "%s", str);
		result = 1;
	}
	return result;
}

static int
rdata_aaaa_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	int result = 0;
	char str[200];
	if (inet_ntop(AF_INET6, rdata_atom_data(rdata), str, sizeof(str))) {
		buffer_printf(output, "%s", str);
		result = 1;
	}
	return result;
}

static int
rdata_rrtype_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	uint16_t type = read_uint16(rdata_atom_data(rdata));
	buffer_printf(output, "%s", rrtype_to_string(type));
	return 1;
}

static int
rdata_algorithm_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	uint8_t id = *rdata_atom_data(rdata);
	lookup_table_type *alg
		= lookup_by_id(dns_algorithms, id);
	if (alg) {
		buffer_printf(output, "%s", alg->name);
	} else {
		buffer_printf(output, "%u", (unsigned) id);
	}
	return 1;
}

static int
rdata_certificate_type_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	uint16_t id = read_uint16(rdata_atom_data(rdata));
	lookup_table_type *type
		= lookup_by_id(dns_certificate_types, id);
	if (type) {
		buffer_printf(output, "%s", type->name);
	} else {
		buffer_printf(output, "%u", (unsigned) id);
	}
	return 1;
}

static int
rdata_period_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	uint32_t period = read_uint32(rdata_atom_data(rdata));
	buffer_printf(output, "%lu", (unsigned long) period);
	return 1;
}

static int
rdata_time_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	int result = 0;
	time_t time = (time_t) read_uint32(rdata_atom_data(rdata));
	struct tm *tm = gmtime(&time);
	char buf[15];
	if (strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm)) {
		buffer_printf(output, "%s", buf);
		result = 1;
	}
	return result;
}

static int
rdata_base32_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	int length;
	size_t size = rdata_atom_size(rdata);
	if(size == 0) {
		buffer_write(output, "-", 1);
		return 1;
	}
	size -= 1; // remove length byte from count
	buffer_reserve(output, size * 2 + 1);
	length = b32_ntop(rdata_atom_data(rdata)+1, size,
			  (char *) buffer_current(output), size * 2);
	if (length > 0) {
		buffer_skip(output, length);
	}
	return length != -1;
}


static int
rdata_base64_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	int length;
	size_t size = rdata_atom_size(rdata);
	buffer_reserve(output, size * 2 + 1);
	length = b64_ntop(rdata_atom_data(rdata), size,
			  (char *) buffer_current(output), size * 2);
	if (length > 0) {
		buffer_skip(output, length);
	}
	return length != -1;
}

static void
hex_to_string(buffer_type *output, const uint8_t *data, size_t size)
{
	static const char hexdigits[] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
	};
	size_t i;

	buffer_reserve(output, size * 2);
	for (i = 0; i < size; ++i) {
		uint8_t octet = *data++;
		buffer_write_u8(output, hexdigits[octet >> 4]);
		buffer_write_u8(output, hexdigits[octet & 0x0f]);
	}
}

static int
rdata_hex_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	hex_to_string(output, rdata_atom_data(rdata), rdata_atom_size(rdata));
	return 1;
}

static int
rdata_hexlen_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	if(rdata_atom_size(rdata) <= 1) {
		// NSEC3 salt hex can be empty
		buffer_printf(output, "-");
		return 1;
	}
	hex_to_string(output, rdata_atom_data(rdata)+1, rdata_atom_size(rdata)-1);
	return 1;
}

static int
rdata_nsap_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	buffer_printf(output, "0x");
	hex_to_string(output, rdata_atom_data(rdata), rdata_atom_size(rdata));
	return 1;
}

static int
rdata_apl_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	int result = 0;
	buffer_type packet;

	buffer_create_from(
		&packet, rdata_atom_data(rdata), rdata_atom_size(rdata));

	if (buffer_available(&packet, 4)) {
		uint16_t address_family = buffer_read_u16(&packet);
		uint8_t prefix = buffer_read_u8(&packet);
		uint8_t length = buffer_read_u8(&packet);
		int negated = length & APL_NEGATION_MASK;
		int af = -1;

		length &= APL_LENGTH_MASK;
		switch (address_family) {
		case 1: af = AF_INET; break;
		case 2: af = AF_INET6; break;
		}
		if (af != -1 && buffer_available(&packet, length)) {
			char text_address[1000];
			uint8_t address[128];
			memset(address, 0, sizeof(address));
			buffer_read(&packet, address, length);
			if (inet_ntop(af, address, text_address, sizeof(text_address))) {
				buffer_printf(output, "%s%d:%s/%d",
					      negated ? "!" : "",
					      (int) address_family,
					      text_address,
					      (int) prefix);
				result = 1;
			}
		}
	}
	return result;
}

static int
rdata_services_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	int result = 0;
	buffer_type packet;

	buffer_create_from(
		&packet, rdata_atom_data(rdata), rdata_atom_size(rdata));

	if (buffer_available(&packet, 1)) {
		uint8_t protocol_number = buffer_read_u8(&packet);
		ssize_t bitmap_size = buffer_remaining(&packet);
		uint8_t *bitmap = buffer_current(&packet);
		struct protoent *proto = getprotobynumber(protocol_number);

		if (proto) {
			int i;

			buffer_printf(output, "%s", proto->p_name);

			for (i = 0; i < bitmap_size * 8; ++i) {
				if (get_bit(bitmap, i)) {
					struct servent *service = getservbyport((int)htons(i), proto->p_name);
					if (service) {
						buffer_printf(output, " %s", service->s_name);
					} else {
						buffer_printf(output, " %d", i);
					}
				}
			}
			buffer_skip(&packet, bitmap_size);
			result = 1;
		}
	}
	return result;
}

static int
rdata_ipsecgateway_to_string(buffer_type *output, rdata_atom_type rdata, rr_type* rr)
{
	int gateway_type = rdata_atom_data(rr->rdatas[1])[0];
	switch(gateway_type) {
	case IPSECKEY_NOGATEWAY:
		buffer_printf(output, ".");
		break;
	case IPSECKEY_IP4:
		rdata_a_to_string(output, rdata, rr);
		break;
	case IPSECKEY_IP6:
		rdata_aaaa_to_string(output, rdata, rr);
		break;
	case IPSECKEY_DNAME:
		rdata_dname_to_string(output, rdata, rr);
		break;
	default:
		return 0;
	}
	return 1;
}

static int
rdata_nxt_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	size_t i;
	uint8_t *bitmap = rdata_atom_data(rdata);
	size_t bitmap_size = rdata_atom_size(rdata);

	for (i = 0; i < bitmap_size * 8; ++i) {
		if (get_bit(bitmap, i)) {
			buffer_printf(output, "%s ", rrtype_to_string(i));
		}
	}

	buffer_skip(output, -1);

	return 1;
}

static int
rdata_nsec_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	size_t saved_position = buffer_position(output);
	buffer_type packet;
	int insert_space = 0;

	buffer_create_from(
		&packet, rdata_atom_data(rdata), rdata_atom_size(rdata));

	while (buffer_available(&packet, 2)) {
		uint8_t window = buffer_read_u8(&packet);
		uint8_t bitmap_size = buffer_read_u8(&packet);
		uint8_t *bitmap = buffer_current(&packet);
		int i;

		if (!buffer_available(&packet, bitmap_size)) {
			buffer_set_position(output, saved_position);
			return 0;
		}

		for (i = 0; i < bitmap_size * 8; ++i) {
			if (get_bit(bitmap, i)) {
				buffer_printf(output,
					      "%s%s",
					      insert_space ? " " : "",
					      rrtype_to_string(
						      window * 256 + i));
				insert_space = 1;
			}
		}
		buffer_skip(&packet, bitmap_size);
	}

	return 1;
}

static int
rdata_loc_to_string(buffer_type *ATTR_UNUSED(output),
		    rdata_atom_type ATTR_UNUSED(rdata),
		    rr_type* ATTR_UNUSED(rr))
{
	
	 // Returning 0 forces the record to be printed in unknown format
	return 0;
}

static int
rdata_unknown_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
 	uint16_t size = rdata_atom_size(rdata);
pri	buffer_printf(output, "\\# %lu ", (unsigned long) size);
	hex_to_string(output, rdata_atom_data(rdata), size);
	return 1;
}

*/

typedef char * (*item_to_string_t)(dnslib_rdata_item_t);


static item_to_string_t item_to_string_table[DNSLIB_RDATA_ZF_UNKNOWN + 1] = {
	rdata_dname_to_string,
	rdata_dns_name_to_string,
	rdata_text_to_string,
	rdata_byte_to_string
/*	rdata_short_to_string,
	rdata_long_to_string,
	rdata_a_to_string,
	rdata_aaaa_to_string,
	rdata_rrtype_to_string,
	rdata_algorithm_to_string,
	rdata_certificate_type_to_string,
	rdata_period_to_string,
	rdata_time_to_string,
	rdata_base64_to_string,
	rdata_base32_to_string,
	rdata_hex_to_string,
	rdata_hexlen_to_string,
	rdata_nsap_to_string,
	rdata_apl_to_string,
	rdata_ipsecgateway_to_string,
	rdata_services_to_string,
	rdata_nxt_to_string,
	rdata_nsec_to_string,
	rdata_loc_to_string,
	rdata_unknown_to_string */
};

char *rdata_item_to_string(dnslib_rdata_zoneformat_t type, dnslib_rdata_item_t item)
{
	return item_to_string_table[type](item);
}

