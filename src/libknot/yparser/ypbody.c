
/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <string.h>

#include "libknot/yparser/yparser.h"
#include "libknot/errcode.h"




// Include parser static data (Ragel internals).

static const char _yparser_actions[] = {
	0, 1, 0, 1, 1, 1, 2, 1,
	3, 1, 4, 1, 5, 1, 7, 1,
	8, 1, 9, 1, 10, 1, 11, 1,
	14, 2, 1, 0, 2, 1, 2, 2,
	2, 0, 2, 3, 4, 2, 5, 0,
	2, 6, 7, 2, 11, 12, 2, 13,
	11, 3, 1, 2, 0, 3, 1, 6,
	7, 3, 1, 11, 12, 3, 1, 13,
	11, 3, 2, 6, 7, 3, 2, 11,
	12, 3, 2, 13, 11, 4, 1, 2,
	6, 7, 4, 1, 2, 11, 12, 4,
	1, 2, 13, 11
};

static const unsigned char _yparser_key_offsets[] = {
	0, 0, 13, 15, 16, 25, 36, 38,
	39, 49, 60, 71, 73, 76, 88, 90,
	92, 102, 110, 113, 116, 120, 131, 144,
	157, 170
};

static const char _yparser_trans_keys[] = {
	10, 13, 32, 35, 45, 46, 92, 48,
	57, 65, 90, 97, 122, 10, 13, 32,
	32, 46, 92, 48, 57, 65, 90, 97,
	122, 32, 58, 92, 45, 46, 48, 57,
	65, 90, 97, 122, 32, 58, 32, 32,
	33, 34, 92, 36, 43, 45, 90, 94,
	126, 10, 13, 32, 33, 92, 36, 43,
	45, 90, 94, 126, 32, 58, 92, 45,
	46, 48, 57, 65, 90, 97, 122, 32,
	58, 10, 13, 32, 10, 13, 32, 34,
	35, 91, 33, 43, 45, 92, 94, 126,
	32, 126, 10, 13, 32, 33, 34, 92,
	36, 43, 45, 90, 94, 126, 32, 33,
	44, 93, 36, 90, 92, 126, 32, 44,
	93, 10, 13, 32, 10, 13, 32, 35,
	32, 58, 92, 45, 46, 48, 57, 65,
	90, 97, 122, 10, 13, 32, 35, 45,
	46, 92, 48, 57, 65, 90, 97, 122,
	10, 13, 32, 35, 45, 46, 92, 48,
	57, 65, 90, 97, 122, 10, 13, 32,
	35, 45, 46, 92, 48, 57, 65, 90,
	97, 122, 10, 13, 32, 35, 45, 46,
	92, 48, 57, 65, 90, 97, 122, 0
};

static const char _yparser_single_lengths[] = {
	0, 7, 2, 1, 3, 3, 2, 1,
	4, 5, 3, 2, 3, 6, 0, 2,
	4, 4, 3, 3, 4, 3, 7, 7,
	7, 7
};

static const char _yparser_range_lengths[] = {
	0, 3, 0, 0, 3, 4, 0, 0,
	3, 3, 4, 0, 0, 3, 1, 0,
	3, 2, 0, 0, 0, 4, 3, 3,
	3, 3
};

static const unsigned char _yparser_index_offsets[] = {
	0, 0, 11, 14, 16, 23, 31, 34,
	36, 44, 53, 61, 64, 68, 78, 80,
	83, 91, 98, 102, 106, 111, 119, 130,
	141, 152
};

static const char _yparser_indicies[] = {
	1, 2, 3, 4, 5, 6, 6, 6,
	6, 6, 0, 1, 2, 4, 7, 0,
	7, 8, 8, 8, 8, 8, 0, 9,
	11, 10, 10, 10, 10, 10, 0, 12,
	13, 0, 14, 0, 14, 15, 16, 15,
	15, 15, 15, 0, 17, 18, 19, 20,
	20, 20, 20, 20, 0, 21, 23, 22,
	22, 22, 22, 22, 0, 24, 25, 0,
	26, 27, 28, 0, 26, 27, 28, 16,
	29, 30, 15, 15, 15, 0, 31, 0,
	26, 27, 29, 30, 32, 16, 32, 32,
	32, 32, 0, 33, 34, 35, 36, 34,
	34, 0, 37, 30, 38, 0, 26, 27,
	39, 0, 26, 27, 39, 29, 0, 40,
	42, 41, 41, 41, 41, 41, 0, 1,
	2, 3, 4, 5, 43, 43, 43, 43,
	43, 0, 44, 45, 46, 47, 48, 49,
	49, 49, 49, 49, 0, 50, 51, 52,
	53, 54, 55, 55, 55, 55, 55, 0,
	56, 57, 58, 59, 60, 61, 61, 61,
	61, 61, 0, 0
};

static const char _yparser_trans_targs[] = {
	0, 23, 24, 1, 2, 3, 21, 4,
	5, 6, 5, 7, 6, 7, 8, 9,
	14, 25, 22, 20, 9, 11, 10, 12,
	11, 12, 25, 22, 13, 15, 16, 14,
	17, 18, 17, 16, 19, 18, 19, 20,
	11, 21, 12, 10, 23, 24, 1, 2,
	3, 10, 23, 24, 1, 2, 3, 10,
	23, 24, 1, 2, 3, 10
};

static const char _yparser_trans_actions[] = {
	23, 1, 0, 43, 0, 46, 40, 21,
	40, 19, 13, 19, 0, 0, 0, 34,
	7, 37, 11, 11, 9, 15, 13, 15,
	0, 0, 1, 0, 0, 0, 0, 9,
	34, 11, 9, 11, 11, 0, 0, 0,
	17, 13, 17, 40, 49, 28, 82, 28,
	87, 77, 31, 5, 69, 5, 73, 65,
	25, 3, 57, 3, 61, 53
};

static const char _yparser_eof_actions[] = {
	0, 23, 23, 23, 23, 23, 23, 23,
	23, 23, 23, 23, 23, 23, 23, 23,
	23, 23, 23, 23, 23, 23, 0, 28,
	5, 3
};





int _yp_start_state = 22;

int _yp_parse(
	yp_parser_t *parser)
{
	// Parser input limits (Ragel internals).
	const char *p, *pe, *eof;

	// Current item indent.
	size_t indent = 0;
	// Current id dash position.
	size_t id_pos = 0;
	// Indicates if the current parsing step contains an item.
	bool found = false;

	if (!parser->input.eof) { // Restore parser input limits.
		p = parser->input.current;
		pe = parser->input.end;
		eof = NULL;
	} else { // Set the last artificial block with just one new line char.
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
		indent = 0;
		id_pos = 0;
	}
	break;
	case 3:
	{
		parser->data_len = 0;
	}
	break;
	case 4:
	{
		if (parser->data_len >= sizeof(parser->data) - 1) {
			return KNOT_ESPACE;
		}
		parser->data[parser->data_len++] = (*p);
	}
	break;
	case 5:
	{
		// Return if a value parsed.
		parser->data[parser->data_len] = '\0';
		parser->processed = true;
		found = true;
		{p++; goto _out; }
	}
	break;
	case 6:
	{
		if (indent > 0 && parser->indent > 0 &&
		    indent != parser->indent) {
			return KNOT_YP_EINVAL_INDENT;
		}
		parser->processed = false;
		parser->key_len = 0;
		parser->data_len = 0;
		parser->event = YP_ENULL;
	}
	break;
	case 7:
	{
		if (parser->key_len >= sizeof(parser->key) - 1) {
			return KNOT_ESPACE;
		}
		parser->key[parser->key_len++] = (*p);
	}
	break;
	case 8:
	{
		parser->key[parser->key_len] = '\0';
		parser->indent = 0;
		parser->id_pos = 0;
		parser->event = YP_EKEY0;
	}
	break;
	case 9:
	{
		parser->key[parser->key_len] = '\0';
		parser->indent = indent;
		parser->event = YP_EKEY1;
	}
	break;
	case 10:
	{
		parser->key[parser->key_len] = '\0';
		parser->indent = indent;
		parser->id_pos = id_pos;
		parser->event = YP_EID;
	}
	break;
	case 11:
	{
		indent++;
	}
	break;
	case 12:
	{
		id_pos++;
	}
	break;
	case 13:
	{
		if (id_pos > 0 && parser->id_pos > 0 &&
		    id_pos != parser->id_pos) {
			return KNOT_YP_EINVAL_INDENT;
		}
		parser->indent = 0;
	}
	break;
	case 14:
	{
		switch ((*p)) {
		case '\t':
			return KNOT_YP_ECHAR_TAB;
		default:
			return KNOT_EPARSEFAIL;
		}
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
	case 2:
	{
		indent = 0;
		id_pos = 0;
	}
	break;
	case 14:
	{
		switch ((*p)) {
		case '\t':
			return KNOT_YP_ECHAR_TAB;
		default:
			return KNOT_EPARSEFAIL;
		}
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
	if (parser->cs == 0) {
		return KNOT_EPARSEFAIL;
	}

	// Check if parsed an item.
	if (found) {
		return KNOT_EOK;
	} else {
		return KNOT_EFEWDATA;
	}
}
