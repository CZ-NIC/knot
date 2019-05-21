#include "knot/modules/synthrecord/utils.h"

/*! \brief Separator character for address family. */
char str_separator(int addr_family) {
	if (addr_family == AF_INET6) {
		return ':';
	}
	return '.';
}

/**
 * Copy IP address (in IPv4 or IPv6 format) from source to destination with possible compression during process
 * 
 * @return Length of address in destination
 **/
size_t synth_addr_cpy(char *dest, const char *src, const int addr_family, const bool shorten) {
	const size_t addr_len = strlen(src);
	const char sep = str_separator(addr_family);
	size_t i;

	if(shorten) {
		size_t idx = 0;
		bool full_shortening = (addr_family == AF_INET6);
        bool begin = true;
		int zero_block = 0;
        int separator_seq = 0;
		for(i = 0; i < addr_len; ++i) {
      		if(src[i] == '0') { // Remove leading '0'
                if(begin) {      
                    zero_block++;
                }
                else {
                    dest[idx++] = '0';
                    separator_seq = 0;
                }
			}
			else if(src[i] == sep) { // Separators
                if(zero_block) {
                    if(full_shortening) {
                        while (separator_seq < 2) {
                            dest[idx++] = '-';
                            separator_seq++;
                        }
                        zero_block = 0;
                        begin = true;
                        full_shortening = false;
                    }
                    else {
                        if(separator_seq < 2) {
                            dest[idx++] = '0';
                            dest[idx++] = '-';
                            separator_seq = 1;
                        }
                        zero_block = 0;
                        begin = true;
                    }
                }
                else {
				    dest[idx++] = '-';
                    separator_seq++;
                    zero_block = 0;
                    begin = true;
                }
			}
			else { // Copy common symbol (symbol other than '0' or separator)
				dest[idx++] = src[i];
                separator_seq = 0;
                zero_block = 0;
                begin = false;
			}
		}
        // Ending of address string
        if(separator_seq && full_shortening) {
		    dest[idx++] = '-';
        }
        else if (separator_seq && !full_shortening) {
            dest[idx++] = '0';
        }
		dest[idx++] = '\0';

		return idx;

	} else { // if (! shorten)
		for(i = 0; i <= addr_len; ++i) {
			dest[i] = (src[i] == sep) ? '-' : src[i];
		}
		return i;
	}
}