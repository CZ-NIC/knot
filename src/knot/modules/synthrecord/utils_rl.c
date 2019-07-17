
#line 1 "./utils.rl"

#include "knot/modules/synthrecord/utils_rl.h"


#line 8 "./utils_rl.c"
static const int shorten_ipv6_start = 1;
static const int shorten_ipv6_first_final = 72;
static const int shorten_ipv6_error = 0;

static const int shorten_ipv6_en_main = 1;


#line 7 "./utils.rl"


size_t shorten_ipv6(char *dst, const char *src)
{
	const char *p = src, *pe = src + strlen( src );
	int cs;

	char *dst_ptr = dst;
	int block = 2;

	
#line 28 "./utils_rl.c"
	{
	cs = shorten_ipv6_start;
	}

#line 33 "./utils_rl.c"
	{
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 48 )
		goto st2;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr2;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr2;
	} else
		goto tr2;
	goto st0;
st0:
cs = 0;
	goto _out;
tr2:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st2;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
#line 67 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr3;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr3;
	} else
		goto tr3;
	goto st0;
tr3:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 90 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr4;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr4;
	} else
		goto tr4;
	goto st0;
tr4:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st4;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
#line 113 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr5;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr5;
	} else
		goto tr5;
	goto st0;
tr5:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 136 "./utils_rl.c"
	if ( (*p) == 58 )
		goto tr6;
	goto st0;
tr6:
#line 43 "./utils.rl"
	{
			*(dst_ptr++) = '-';
		}
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 150 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st7;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr8;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr8;
	} else
		goto tr8;
	goto st0;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
	if ( (*p) == 48 )
		goto st8;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr10;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr10;
	} else
		goto tr10;
	goto st0;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
	if ( (*p) == 48 )
		goto st9;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr12;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr12;
	} else
		goto tr12;
	goto st0;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
	if ( (*p) == 48 )
		goto st10;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr14;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr14;
	} else
		goto tr14;
	goto st0;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
	if ( (*p) == 58 )
		goto st11;
	goto st0;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
	if ( (*p) == 48 )
		goto tr16;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr17;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr17;
	} else
		goto tr17;
	goto st0;
tr16:
#line 29 "./utils.rl"
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
	goto st12;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
#line 248 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st13;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr19;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr19;
	} else
		goto tr19;
	goto st0;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
	if ( (*p) == 48 )
		goto st14;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr21;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr21;
	} else
		goto tr21;
	goto st0;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
	if ( (*p) == 48 )
		goto st15;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr23;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr23;
	} else
		goto tr23;
	goto st0;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
	if ( (*p) == 58 )
		goto st16;
	goto st0;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
	if ( (*p) == 48 )
		goto tr25;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr26;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr26;
	} else
		goto tr26;
	goto st0;
tr25:
#line 29 "./utils.rl"
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
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 331 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st18;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr28;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr28;
	} else
		goto tr28;
	goto st0;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
	if ( (*p) == 48 )
		goto st19;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr30;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr30;
	} else
		goto tr30;
	goto st0;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
	if ( (*p) == 48 )
		goto st20;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr32;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr32;
	} else
		goto tr32;
	goto st0;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
	if ( (*p) == 58 )
		goto st21;
	goto st0;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
	if ( (*p) == 48 )
		goto tr34;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr35;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr35;
	} else
		goto tr35;
	goto st0;
tr34:
#line 29 "./utils.rl"
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
	goto st22;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
#line 414 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st23;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr37;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr37;
	} else
		goto tr37;
	goto st0;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
	if ( (*p) == 48 )
		goto st24;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr39;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr39;
	} else
		goto tr39;
	goto st0;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
	if ( (*p) == 48 )
		goto st25;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr41;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr41;
	} else
		goto tr41;
	goto st0;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
	if ( (*p) == 58 )
		goto st26;
	goto st0;
st26:
	if ( ++p == pe )
		goto _test_eof26;
case 26:
	if ( (*p) == 48 )
		goto tr43;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr44;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr44;
	} else
		goto tr44;
	goto st0;
tr43:
#line 29 "./utils.rl"
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
	goto st27;
st27:
	if ( ++p == pe )
		goto _test_eof27;
case 27:
#line 497 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st28;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr46;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr46;
	} else
		goto tr46;
	goto st0;
st28:
	if ( ++p == pe )
		goto _test_eof28;
case 28:
	if ( (*p) == 48 )
		goto st29;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr48;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr48;
	} else
		goto tr48;
	goto st0;
st29:
	if ( ++p == pe )
		goto _test_eof29;
case 29:
	if ( (*p) == 48 )
		goto st30;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr50;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr50;
	} else
		goto tr50;
	goto st0;
st30:
	if ( ++p == pe )
		goto _test_eof30;
case 30:
	if ( (*p) == 58 )
		goto st31;
	goto st0;
st31:
	if ( ++p == pe )
		goto _test_eof31;
case 31:
	if ( (*p) == 48 )
		goto tr52;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr53;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr53;
	} else
		goto tr53;
	goto st0;
tr52:
#line 29 "./utils.rl"
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
	goto st32;
st32:
	if ( ++p == pe )
		goto _test_eof32;
case 32:
#line 580 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st33;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr55;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr55;
	} else
		goto tr55;
	goto st0;
st33:
	if ( ++p == pe )
		goto _test_eof33;
case 33:
	if ( (*p) == 48 )
		goto st34;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr57;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr57;
	} else
		goto tr57;
	goto st0;
st34:
	if ( ++p == pe )
		goto _test_eof34;
case 34:
	if ( (*p) == 48 )
		goto st35;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr59;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr59;
	} else
		goto tr59;
	goto st0;
st35:
	if ( ++p == pe )
		goto _test_eof35;
case 35:
	if ( (*p) == 58 )
		goto st36;
	goto st0;
st36:
	if ( ++p == pe )
		goto _test_eof36;
case 36:
	if ( (*p) == 48 )
		goto tr61;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr62;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr62;
	} else
		goto tr62;
	goto st0;
tr61:
#line 29 "./utils.rl"
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
	goto st37;
st37:
	if ( ++p == pe )
		goto _test_eof37;
case 37:
#line 663 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st38;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr64;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr64;
	} else
		goto tr64;
	goto st0;
st38:
	if ( ++p == pe )
		goto _test_eof38;
case 38:
	if ( (*p) == 48 )
		goto st39;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr66;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr66;
	} else
		goto tr66;
	goto st0;
tr66:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st39;
st39:
	if ( ++p == pe )
		goto _test_eof39;
case 39:
#line 703 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr67;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr67;
	} else
		goto tr67;
	goto st0;
tr67:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st72;
st72:
	if ( ++p == pe )
		goto _test_eof72;
case 72:
#line 726 "./utils_rl.c"
	goto st0;
tr64:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st40;
st40:
	if ( ++p == pe )
		goto _test_eof40;
case 40:
#line 741 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr66;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr66;
	} else
		goto tr66;
	goto st0;
tr70:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st41;
tr62:
#line 29 "./utils.rl"
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
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st41;
st41:
	if ( ++p == pe )
		goto _test_eof41;
case 41:
#line 786 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr64;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr64;
	} else
		goto tr64;
	goto st0;
tr59:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st42;
st42:
	if ( ++p == pe )
		goto _test_eof42;
case 42:
#line 809 "./utils_rl.c"
	if ( (*p) == 58 )
		goto tr68;
	goto st0;
tr68:
#line 43 "./utils.rl"
	{
			*(dst_ptr++) = '-';
		}
	goto st43;
st43:
	if ( ++p == pe )
		goto _test_eof43;
case 43:
#line 823 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st37;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr70;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr70;
	} else
		goto tr70;
	goto st0;
tr57:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st44;
st44:
	if ( ++p == pe )
		goto _test_eof44;
case 44:
#line 848 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr59;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr59;
	} else
		goto tr59;
	goto st0;
tr55:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st45;
st45:
	if ( ++p == pe )
		goto _test_eof45;
case 45:
#line 871 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr57;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr57;
	} else
		goto tr57;
	goto st0;
tr73:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st46;
tr53:
#line 29 "./utils.rl"
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
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st46;
st46:
	if ( ++p == pe )
		goto _test_eof46;
case 46:
#line 916 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr55;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr55;
	} else
		goto tr55;
	goto st0;
tr50:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st47;
st47:
	if ( ++p == pe )
		goto _test_eof47;
case 47:
#line 939 "./utils_rl.c"
	if ( (*p) == 58 )
		goto tr71;
	goto st0;
tr71:
#line 43 "./utils.rl"
	{
			*(dst_ptr++) = '-';
		}
	goto st48;
st48:
	if ( ++p == pe )
		goto _test_eof48;
case 48:
#line 953 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st32;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr73;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr73;
	} else
		goto tr73;
	goto st0;
tr48:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st49;
st49:
	if ( ++p == pe )
		goto _test_eof49;
case 49:
#line 978 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr50;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr50;
	} else
		goto tr50;
	goto st0;
tr46:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st50;
st50:
	if ( ++p == pe )
		goto _test_eof50;
case 50:
#line 1001 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr48;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr48;
	} else
		goto tr48;
	goto st0;
tr76:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st51;
tr44:
#line 29 "./utils.rl"
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
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st51;
st51:
	if ( ++p == pe )
		goto _test_eof51;
case 51:
#line 1046 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr46;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr46;
	} else
		goto tr46;
	goto st0;
tr41:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st52;
st52:
	if ( ++p == pe )
		goto _test_eof52;
case 52:
#line 1069 "./utils_rl.c"
	if ( (*p) == 58 )
		goto tr74;
	goto st0;
tr74:
#line 43 "./utils.rl"
	{
			*(dst_ptr++) = '-';
		}
	goto st53;
st53:
	if ( ++p == pe )
		goto _test_eof53;
case 53:
#line 1083 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st27;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr76;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr76;
	} else
		goto tr76;
	goto st0;
tr39:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st54;
st54:
	if ( ++p == pe )
		goto _test_eof54;
case 54:
#line 1108 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr41;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr41;
	} else
		goto tr41;
	goto st0;
tr37:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st55;
st55:
	if ( ++p == pe )
		goto _test_eof55;
case 55:
#line 1131 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr39;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr39;
	} else
		goto tr39;
	goto st0;
tr79:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st56;
tr35:
#line 29 "./utils.rl"
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
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st56;
st56:
	if ( ++p == pe )
		goto _test_eof56;
case 56:
#line 1176 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr37;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr37;
	} else
		goto tr37;
	goto st0;
tr32:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st57;
st57:
	if ( ++p == pe )
		goto _test_eof57;
case 57:
#line 1199 "./utils_rl.c"
	if ( (*p) == 58 )
		goto tr77;
	goto st0;
tr77:
#line 43 "./utils.rl"
	{
			*(dst_ptr++) = '-';
		}
	goto st58;
st58:
	if ( ++p == pe )
		goto _test_eof58;
case 58:
#line 1213 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st22;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr79;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr79;
	} else
		goto tr79;
	goto st0;
tr30:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st59;
st59:
	if ( ++p == pe )
		goto _test_eof59;
case 59:
#line 1238 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr32;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr32;
	} else
		goto tr32;
	goto st0;
tr28:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st60;
st60:
	if ( ++p == pe )
		goto _test_eof60;
case 60:
#line 1261 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr30;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr30;
	} else
		goto tr30;
	goto st0;
tr82:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st61;
tr26:
#line 29 "./utils.rl"
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
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st61;
st61:
	if ( ++p == pe )
		goto _test_eof61;
case 61:
#line 1306 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr28;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr28;
	} else
		goto tr28;
	goto st0;
tr23:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st62;
st62:
	if ( ++p == pe )
		goto _test_eof62;
case 62:
#line 1329 "./utils_rl.c"
	if ( (*p) == 58 )
		goto tr80;
	goto st0;
tr80:
#line 43 "./utils.rl"
	{
			*(dst_ptr++) = '-';
		}
	goto st63;
st63:
	if ( ++p == pe )
		goto _test_eof63;
case 63:
#line 1343 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st17;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr82;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr82;
	} else
		goto tr82;
	goto st0;
tr21:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st64;
st64:
	if ( ++p == pe )
		goto _test_eof64;
case 64:
#line 1368 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr23;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr23;
	} else
		goto tr23;
	goto st0;
tr19:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st65;
st65:
	if ( ++p == pe )
		goto _test_eof65;
case 65:
#line 1391 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr21;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr21;
	} else
		goto tr21;
	goto st0;
tr85:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st66;
tr17:
#line 29 "./utils.rl"
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
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st66;
st66:
	if ( ++p == pe )
		goto _test_eof66;
case 66:
#line 1436 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr19;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr19;
	} else
		goto tr19;
	goto st0;
tr14:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st67;
st67:
	if ( ++p == pe )
		goto _test_eof67;
case 67:
#line 1459 "./utils_rl.c"
	if ( (*p) == 58 )
		goto tr83;
	goto st0;
tr83:
#line 43 "./utils.rl"
	{
			*(dst_ptr++) = '-';
		}
	goto st68;
st68:
	if ( ++p == pe )
		goto _test_eof68;
case 68:
#line 1473 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st12;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr85;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr85;
	} else
		goto tr85;
	goto st0;
tr12:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st69;
st69:
	if ( ++p == pe )
		goto _test_eof69;
case 69:
#line 1498 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr14;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr14;
	} else
		goto tr14;
	goto st0;
tr10:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st70;
st70:
	if ( ++p == pe )
		goto _test_eof70;
case 70:
#line 1521 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr12;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr12;
	} else
		goto tr12;
	goto st0;
tr8:
#line 21 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
			
			if(block == 1)
				block = 0;
		}
	goto st71;
st71:
	if ( ++p == pe )
		goto _test_eof71;
case 71:
#line 1544 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr10;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr10;
	} else
		goto tr10;
	goto st0;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof13: cs = 13; goto _test_eof; 
	_test_eof14: cs = 14; goto _test_eof; 
	_test_eof15: cs = 15; goto _test_eof; 
	_test_eof16: cs = 16; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof25: cs = 25; goto _test_eof; 
	_test_eof26: cs = 26; goto _test_eof; 
	_test_eof27: cs = 27; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof31: cs = 31; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 
	_test_eof33: cs = 33; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof72: cs = 72; goto _test_eof; 
	_test_eof40: cs = 40; goto _test_eof; 
	_test_eof41: cs = 41; goto _test_eof; 
	_test_eof42: cs = 42; goto _test_eof; 
	_test_eof43: cs = 43; goto _test_eof; 
	_test_eof44: cs = 44; goto _test_eof; 
	_test_eof45: cs = 45; goto _test_eof; 
	_test_eof46: cs = 46; goto _test_eof; 
	_test_eof47: cs = 47; goto _test_eof; 
	_test_eof48: cs = 48; goto _test_eof; 
	_test_eof49: cs = 49; goto _test_eof; 
	_test_eof50: cs = 50; goto _test_eof; 
	_test_eof51: cs = 51; goto _test_eof; 
	_test_eof52: cs = 52; goto _test_eof; 
	_test_eof53: cs = 53; goto _test_eof; 
	_test_eof54: cs = 54; goto _test_eof; 
	_test_eof55: cs = 55; goto _test_eof; 
	_test_eof56: cs = 56; goto _test_eof; 
	_test_eof57: cs = 57; goto _test_eof; 
	_test_eof58: cs = 58; goto _test_eof; 
	_test_eof59: cs = 59; goto _test_eof; 
	_test_eof60: cs = 60; goto _test_eof; 
	_test_eof61: cs = 61; goto _test_eof; 
	_test_eof62: cs = 62; goto _test_eof; 
	_test_eof63: cs = 63; goto _test_eof; 
	_test_eof64: cs = 64; goto _test_eof; 
	_test_eof65: cs = 65; goto _test_eof; 
	_test_eof66: cs = 66; goto _test_eof; 
	_test_eof67: cs = 67; goto _test_eof; 
	_test_eof68: cs = 68; goto _test_eof; 
	_test_eof69: cs = 69; goto _test_eof; 
	_test_eof70: cs = 70; goto _test_eof; 
	_test_eof71: cs = 71; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 68 "./utils.rl"



	*dst_ptr = '\0';
	if ( cs < shorten_ipv6_first_final ) {
		return 0;
	}
	
	return dst_ptr - dst;
};

