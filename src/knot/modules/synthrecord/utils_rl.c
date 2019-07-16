
#line 1 "./utils.rl"

#include "knot/modules/synthrecord/utils_rl.h"


#line 8 "./utils_rl.c"
static const int shorten_ipv6_start = 1;
static const int shorten_ipv6_first_final = 25;
static const int shorten_ipv6_error = 0;

static const int shorten_ipv6_en_main = 1;


#line 7 "./utils.rl"


size_t shorten_ipv6(char *dst, const char *src)
{
	const char *p = src, *pe = src + strlen( src );
	int cs;

	char *dst_ptr = dst;
	bool block_cut = false;
	unsigned separator_cnt = 0;

	
#line 29 "./utils_rl.c"
	{
	cs = shorten_ipv6_start;
	}

#line 34 "./utils_rl.c"
	{
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr0;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr0;
	} else
		goto tr0;
	goto st0;
st0:
cs = 0;
	goto _out;
tr0:
#line 23 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
		}
	goto st2;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
#line 63 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr2;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr2;
	} else
		goto tr2;
	goto st0;
tr2:
#line 23 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
		}
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 83 "./utils_rl.c"
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
#line 23 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
		}
	goto st4;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
#line 103 "./utils_rl.c"
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
#line 23 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
		}
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 123 "./utils_rl.c"
	if ( (*p) == 58 )
		goto tr5;
	goto st0;
tr5:
#line 28 "./utils.rl"
	{
			*(dst_ptr++) = '-';
			separator_cnt++;
		}
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 138 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st7;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr0;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr0;
	} else
		goto tr0;
	goto st0;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
	if ( (*p) == 48 )
		goto st8;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr2;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr2;
	} else
		goto tr2;
	goto st0;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
	if ( (*p) == 48 )
		goto st9;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr3;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr3;
	} else
		goto tr3;
	goto st0;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
	if ( (*p) == 48 )
		goto st10;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr4;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr4;
	} else
		goto tr4;
	goto st0;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
	if ( (*p) == 58 )
		goto tr10;
	goto st0;
tr10:
#line 34 "./utils.rl"
	{
			separator_cnt++;
			if (!block_cut) {
				block_cut = true;
				*(dst_ptr++) = '-';
			}
		}
	goto st11;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
#line 216 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st12;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr12;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr12;
	} else
		goto tr12;
	goto st0;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
	if ( (*p) == 48 )
		goto st13;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr14;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr14;
	} else
		goto tr14;
	goto st0;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
	if ( (*p) == 48 )
		goto st14;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr16;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr16;
	} else
		goto tr16;
	goto st0;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
	if ( (*p) == 48 )
		goto st10;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr17;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr17;
	} else
		goto tr17;
	goto st0;
tr17:
#line 23 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
		}
	goto st15;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
#line 283 "./utils_rl.c"
	if ( (*p) == 58 )
		goto tr18;
	goto st0;
tr18:
#line 28 "./utils.rl"
	{
			*(dst_ptr++) = '-';
			separator_cnt++;
		}
	goto st16;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
#line 298 "./utils_rl.c"
	if ( (*p) == 48 )
		goto st17;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr20;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr20;
	} else
		goto tr20;
	goto st0;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
	if ( (*p) == 48 )
		goto st18;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr22;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr22;
	} else
		goto tr22;
	goto st0;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
	if ( (*p) == 48 )
		goto st19;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr24;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr24;
	} else
		goto tr24;
	goto st0;
tr24:
#line 23 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
		}
	goto st19;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
#line 350 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr25;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr25;
	} else
		goto tr25;
	goto st0;
tr25:
#line 23 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
		}
	goto st25;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
#line 370 "./utils_rl.c"
	if ( (*p) == 58 )
		goto tr18;
	goto st0;
tr22:
#line 23 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
		}
	goto st20;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
#line 384 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr24;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr24;
	} else
		goto tr24;
	goto st0;
tr20:
#line 23 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
		}
	goto st21;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
#line 404 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr22;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr22;
	} else
		goto tr22;
	goto st0;
tr16:
#line 23 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
		}
	goto st22;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
#line 424 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr17;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr17;
	} else
		goto tr17;
	goto st0;
tr14:
#line 23 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
		}
	goto st23;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
#line 444 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr16;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr16;
	} else
		goto tr16;
	goto st0;
tr12:
#line 23 "./utils.rl"
	{
			*(dst_ptr++) = (*p);
		}
	goto st24;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
#line 464 "./utils_rl.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr14;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr14;
	} else
		goto tr14;
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
	_test_eof25: cs = 25; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 62 "./utils.rl"



	*dst_ptr = '\0';
	/**if ( cs < shorten_ipv6_first_final ) {
		return 0;
	}
	if (separator_cnt != 7) {
		return -1;
	}**/
	
	return strlen(dst);
};

