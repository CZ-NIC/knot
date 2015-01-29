
/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <string.h>

#include "libknot/internal/yparser/yparser.h"
#include "libknot/errcode.h"




// Include parser static data (Ragel internals).

static const char _yparser_actions[] = {
	0, 1, 0, 1, 1, 1, 2, 1, 
	3, 1, 4, 1, 6, 1, 7, 1, 
	8, 1, 9, 1, 10, 2, 1, 0, 
	2, 2, 3, 2, 4, 0, 2, 5, 
	6, 3, 1, 5, 6
};

static const unsigned char _yparser_key_offsets[] = {
	0, 0, 12, 13, 22, 33, 37, 49, 
	62, 67, 72, 77, 88, 92, 105, 117, 
	129, 134, 140, 152, 164, 174, 185, 190, 
	195, 206, 218
};

static const char _yparser_trans_keys[] = {
	9, 10, 13, 32, 35, 45, 48, 57, 
	65, 90, 97, 122, 10, 9, 13, 32, 
	48, 57, 65, 90, 97, 122, 9, 13, 
	32, 45, 58, 48, 57, 65, 90, 97, 
	122, 9, 13, 32, 58, 9, 13, 32, 
	33, 34, 92, 36, 43, 45, 90, 94, 
	126, 9, 10, 13, 32, 33, 35, 92, 
	36, 43, 45, 90, 94, 126, 9, 10, 
	13, 32, 35, 9, 13, 34, 32, 126, 
	9, 10, 13, 32, 35, 9, 13, 32, 
	45, 58, 48, 57, 65, 90, 97, 122, 
	9, 13, 32, 58, 9, 10, 13, 32, 
	34, 35, 91, 33, 43, 45, 92, 94, 
	126, 9, 10, 13, 32, 33, 35, 44, 
	92, 36, 90, 94, 126, 9, 10, 13, 
	32, 34, 35, 44, 92, 33, 90, 94, 
	126, 9, 13, 34, 32, 126, 9, 10, 
	13, 32, 35, 44, 9, 13, 32, 33, 
	34, 92, 36, 43, 45, 90, 94, 126, 
	9, 13, 32, 33, 34, 92, 36, 43, 
	45, 90, 94, 126, 9, 13, 32, 33, 
	44, 93, 36, 90, 92, 126, 9, 13, 
	32, 33, 34, 44, 93, 36, 90, 92, 
	126, 9, 13, 34, 32, 126, 9, 13, 
	32, 44, 93, 9, 13, 32, 45, 58, 
	48, 57, 65, 90, 97, 122, 9, 10, 
	13, 32, 35, 45, 48, 57, 65, 90, 
	97, 122, 9, 10, 13, 32, 35, 45, 
	48, 57, 65, 90, 97, 122, 0
};

static const char _yparser_single_lengths[] = {
	0, 6, 1, 3, 5, 4, 6, 7, 
	5, 3, 5, 5, 4, 7, 8, 8, 
	3, 6, 6, 6, 6, 7, 3, 5, 
	5, 6, 6
};

static const char _yparser_range_lengths[] = {
	0, 3, 0, 3, 3, 0, 3, 3, 
	0, 1, 0, 3, 0, 3, 2, 2, 
	1, 0, 3, 3, 2, 2, 1, 0, 
	3, 3, 3
};

static const unsigned char _yparser_index_offsets[] = {
	0, 0, 10, 12, 19, 28, 33, 43, 
	54, 60, 65, 71, 80, 85, 96, 107, 
	118, 123, 130, 140, 150, 159, 169, 174, 
	180, 189, 199
};

static const char _yparser_indicies[] = {
	1, 2, 1, 1, 3, 4, 5, 5, 
	5, 0, 2, 3, 4, 4, 4, 6, 
	6, 6, 0, 7, 7, 7, 8, 9, 
	8, 8, 8, 0, 10, 10, 10, 11, 
	0, 11, 11, 11, 12, 13, 12, 12, 
	12, 12, 0, 14, 15, 14, 14, 16, 
	17, 16, 16, 16, 16, 0, 18, 2, 
	18, 18, 3, 0, 19, 19, 20, 19, 
	0, 14, 15, 14, 14, 17, 0, 21, 
	21, 21, 22, 23, 22, 22, 22, 0, 
	24, 24, 24, 25, 0, 25, 2, 25, 
	25, 27, 3, 28, 26, 26, 26, 0, 
	29, 15, 29, 29, 30, 17, 31, 30, 
	30, 30, 0, 32, 2, 32, 32, 27, 
	3, 33, 26, 26, 26, 0, 34, 34, 
	35, 34, 0, 29, 15, 29, 29, 17, 
	31, 0, 33, 33, 33, 26, 27, 26, 
	26, 26, 26, 0, 28, 28, 28, 36, 
	37, 36, 36, 36, 36, 0, 38, 38, 
	38, 39, 40, 14, 39, 39, 0, 41, 
	41, 41, 36, 37, 28, 18, 36, 36, 
	0, 42, 42, 43, 42, 0, 38, 38, 
	38, 40, 14, 0, 44, 44, 44, 45, 
	46, 45, 45, 45, 0, 1, 2, 1, 
	1, 3, 4, 47, 47, 47, 0, 48, 
	49, 48, 48, 50, 51, 52, 52, 52, 
	0, 0
};

static const char _yparser_trans_targs[] = {
	0, 1, 26, 2, 3, 24, 4, 5, 
	4, 6, 5, 6, 7, 9, 8, 26, 
	7, 2, 8, 9, 10, 12, 11, 13, 
	12, 13, 14, 16, 19, 15, 14, 18, 
	15, 18, 16, 17, 20, 22, 21, 20, 
	19, 21, 22, 23, 12, 24, 13, 11, 
	1, 26, 2, 3, 11
};

static const char _yparser_trans_actions[] = {
	19, 0, 1, 0, 0, 30, 30, 17, 
	11, 17, 0, 0, 24, 5, 9, 27, 
	7, 9, 0, 7, 0, 13, 11, 13, 
	0, 0, 24, 5, 0, 9, 7, 9, 
	0, 0, 7, 0, 24, 5, 9, 7, 
	9, 0, 7, 0, 15, 11, 15, 30, 
	3, 21, 3, 3, 33
};

static const char _yparser_eof_actions[] = {
	0, 19, 19, 19, 19, 19, 19, 19, 
	19, 19, 19, 19, 19, 19, 19, 19, 
	19, 19, 19, 19, 19, 19, 19, 19, 
	19, 0, 3
};





int _yp_start_state = 
25
;

int _yp_parse(
	yp_parser_t *parser)
{
	// Parser input limits (Ragel internals).
	const char *p, *pe, *eof;

	// Indicates if the current parsing step contains an item.
	bool found = false;

	if (!parser->input.eof) { // Restore parser input limits.
		p = parser->input.current;
		pe = parser->input.end;
		eof = NULL;
	} else { // Set the last artifical block with just one new line char.
		p = "\n";
		pe = p + 1;
		eof = pe;
	}

	// Include parser body.
	
	{
	int _klen;
	unsigned int _trans;
	const char *_acts;
	unsigned int _nacts;
	const char *_keys;

	if ( p == pe )
		goto _test_eof;
	if (  parser->cs == 0 )
		goto _out;
_resume:
	_keys = _yparser_trans_keys + _yparser_key_offsets[ parser->cs];
	_trans = _yparser_index_offsets[ parser->cs];

	_klen = _yparser_single_lengths[ parser->cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + _klen - 1;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + ((_upper-_lower) >> 1);
			if ( (*p) < *_mid )
				_upper = _mid - 1;
			else if ( (*p) > *_mid )
				_lower = _mid + 1;
			else {
				_trans += (unsigned int)(_mid - _keys);
				goto _match;
			}
		}
		_keys += _klen;
		_trans += _klen;
	}

	_klen = _yparser_range_lengths[ parser->cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + (_klen<<1) - 2;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + (((_upper-_lower) >> 1) & ~1);
			if ( (*p) < _mid[0] )
				_upper = _mid - 2;
			else if ( (*p) > _mid[1] )
				_lower = _mid + 2;
			else {
				_trans += (unsigned int)((_mid - _keys)>>1);
				goto _match;
			}
		}
		_trans += _klen;
	}

_match:
	_trans = _yparser_indicies[_trans];
	 parser->cs = _yparser_trans_targs[_trans];

	if ( _yparser_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _yparser_actions + _yparser_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
	{
		// Return if key without value.
		if (parser->event != YP_ENULL && !parser->processed) {
			parser->processed = true;
			found = true;
			{p++; goto _out; }
		}
	}
	break;
	case 1:
	{
		parser->line_count++;
		parser->event = YP_ENULL;
		parser->processed = false;
	}
	break;
	case 2:
	{
		parser->data_len = 0;
	}
	break;
	case 3:
	{
		if (parser->data_len >= sizeof(parser->data)) {
			return KNOT_ESPACE;
		}
		parser->data[parser->data_len++] = (*p);
	}
	break;
	case 4:
	{
		// Return if a value parsed.
		parser->data[parser->data_len] = '\0';
		parser->processed = true;
		found = true;
		{p++; goto _out; }
	}
	break;
	case 5:
	{
		parser->processed = false;
		parser->key_len = 0;
		parser->data_len = 0;
		parser->event = YP_ENULL;
	}
	break;
	case 6:
	{
		if (parser->key_len >= sizeof(parser->key)) {
			return KNOT_ESPACE;
		}
		parser->key[parser->key_len++] = (*p);
	}
	break;
	case 7:
	{
		parser->key[parser->key_len] = '\0';
		parser->event = YP_EKEY0;
	}
	break;
	case 8:
	{
		parser->key[parser->key_len] = '\0';
		parser->event = YP_EKEY1;
	}
	break;
	case 9:
	{
		parser->key[parser->key_len] = '\0';
		parser->event = YP_EID;
	}
	break;
	case 10:
	{
		return KNOT_EPARSEFAIL;
	}
	break;
		}
	}

_again:
	if (  parser->cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	if ( p == eof )
	{
	const char *__acts = _yparser_actions + _yparser_eof_actions[ parser->cs];
	unsigned int __nacts = (unsigned int) *__acts++;
	while ( __nacts-- > 0 ) {
		switch ( *__acts++ ) {
	case 1:
	{
		parser->line_count++;
		parser->event = YP_ENULL;
		parser->processed = false;
	}
	break;
	case 10:
	{
		return KNOT_EPARSEFAIL;
	}
	break;
		}
	}
	}

	_out: {}
	}


	// Store the current parser position.
	if (!parser->input.eof) {
		parser->input.current = p;
	} else {
		parser->input.current = parser->input.end;
	}

	// Check for general parser error.
	if (parser->cs == 
0
) {
		return KNOT_EPARSEFAIL;
	}

	// Check if parsed an item.
	if (found) {
		return KNOT_EOK;
	} else {
		return KNOT_EFEWDATA;
	}
}
