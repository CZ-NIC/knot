
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
		}

		action separator
		{
			*(dst_ptr++) = '-';
			separator_cnt++;
		}

		action double_separator
		{
			separator_cnt++;
			if (!block_cut) {
				block_cut = true;
				*(dst_ptr++) = '-';
			}
		}

		hextet_first = ( xdigit$printable ){4};
		hextet_nonzero = ( [1-9a-fA-F]$printable ) ( xdigit$printable ){3}
			| '0' ( [1-9a-fA-F]$printable ) ( xdigit$printable ){2}
			| ( '0' ){2} ( [1-9a-fA-F]$printable ) xdigit$printable
			| ( '0' ){3} ( [1-9a-fA-F]$printable )	
			;
		hextet_zero = ( '0' ){4};
		hextet = hextet_nonzero
			| ( '0' ){3} ( '0'$printable )	
			;
		tail = ( ':'$double_separator  hextet > 1 ) 
			|  ( ':'$double_separator hextet_nonzero > 2 ) ( ':'$separator hextet )+
			;

		main := hextet_first ( ':'$separator  hextet_nonzero )*  ( ':'  hextet_zero )+ tail
			;

		# Initialize and execute.
		write init;
		write exec;
	}%%


	*dst_ptr = '\0';
	/**if ( cs < shorten_ipv6_first_final ) {
		return 0;
	}
	if (separator_cnt != 7) {
		return -1;
	}**/
	
	return strlen(dst);
};

