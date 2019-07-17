
#include "knot/modules/synthrecord/utils_rl.h"

%%{
	machine shorten_ipv6;
	write data;
}%%

size_t shorten_ipv6(char *dst, const char *src)
{
	const char *p = src, *pe = src + strlen( src );
	int cs;

	char *dst_ptr = dst;
	bool block_cut = false;
	unsigned separator_cnt = 0;

	%%{
		machine shorten_ipv6;
		
		action printable
		{
			*(dst_ptr++) = fc;
			
			if(block == 1)
				block = 0;
		}

		action printable_zero
		{
			switch(block) {
			case 2:
				*(dst_ptr++) = '-';
				block--;
				break;
			case 0:	
				*(dst_ptr++) = '0';
				*(dst_ptr++) = '-';
				break;
			}
		}

		action separator
		{
			*(dst_ptr++) = '-';
		}

		A = ( '0' | (xdigit-'0')$printable ) ( xdigit$printable ){3} ':'$separator
			;
		B1 = ( (xdigit-'0')$printable ) ( xdigit$printable ){3}
			| '0' ( (xdigit-'0')$printable ) ( xdigit$printable ){2}
			| ( '0' ){2} ( (xdigit-'0')$printable ) ( xdigit$printable )
			| ( '0' ){3} ( (xdigit-'0')$printable )
			;
		B2 = '0' {4}
			;
		B = B1 ':'$separator
			| (B2 ':')%printable_zero
			;
		C = ( '0' | (xdigit-'0')$printable ){3} ( xdigit$printable )
			;
		main := A B{6} C
			;

		write init;
		write exec;

	}%%


	*dst_ptr = '\0';
	if ( cs < shorten_ipv6_first_final ) {
		return 0;
	}
	/**if (separator_cnt != 7) {
		return -1;
	}**/
	
	return dst_ptr - dst;
};

