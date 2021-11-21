
/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
	3, 1, 4, 1, 6, 1, 8, 1,
	9, 1, 10, 1, 11, 1, 12, 1,
	15, 2, 1, 0, 2, 1, 2, 2,
	1, 15, 2, 2, 0, 2, 3, 4,
	2, 5, 4, 2, 6, 0, 2, 7,
	8, 2, 12, 13, 2, 14, 12, 3,
	1, 2, 0, 3, 1, 7, 8, 3,
	1, 12, 13, 3, 1, 14, 12, 3,
	2, 7, 8, 3, 2, 12, 13, 3,
	2, 14, 12, 4, 1, 2, 7, 8,
	4, 1, 2, 12, 13, 4, 1, 2,
	14, 12
};

static const unsigned char _yparser_key_offsets[] = {
	0, 0, 14, 16, 27, 29, 32, 43,
	44, 54, 65, 67, 68, 78, 90, 94,
	96, 99, 104, 107, 110, 122, 132, 142,
	145, 148, 151, 156, 159, 162, 176, 190,
	204
};

static const char _yparser_trans_keys[] = {
	10, 13, 32, 35, 42, 45, 92, 95,
	46, 57, 65, 90, 97, 122, 10, 13,
	32, 42, 58, 92, 95, 45, 57, 65,
	90, 97, 122, 32, 58, 10, 13, 32,
	32, 42, 58, 92, 95, 45, 57, 65,
	90, 97, 122, 32, 32, 42, 92, 95,
	46, 57, 65, 90, 97, 122, 32, 42,
	58, 92, 95, 45, 57, 65, 90, 97,
	122, 32, 58, 32, 32, 34, 35, 44,
	92, 127, 0, 31, 91, 93, 10, 13,
	32, 44, 92, 127, 0, 31, 34, 35,
	91, 93, 10, 13, 32, 35, 10, 13,
	34, 32, 126, 34, 92, 127, 0, 31,
	10, 13, 32, 34, 32, 126, 10, 13,
	32, 34, 35, 44, 91, 92, 93, 127,
	0, 31, 32, 34, 35, 44, 92, 127,
	0, 31, 91, 93, 32, 44, 91, 92,
	93, 127, 0, 31, 34, 35, 32, 44,
	93, 10, 13, 32, 34, 32, 126, 34,
	92, 127, 0, 31, 32, 44, 93, 34,
	32, 126, 10, 13, 32, 35, 42, 45,
	92, 95, 46, 57, 65, 90, 97, 122,
	10, 13, 32, 35, 42, 45, 92, 95,
	46, 57, 65, 90, 97, 122, 10, 13,
	32, 35, 42, 45, 92, 95, 46, 57,
	65, 90, 97, 122, 10, 13, 32, 35,
	42, 45, 92, 95, 46, 57, 65, 90,
	97, 122, 0
};

static const char _yparser_single_lengths[] = {
	0, 8, 2, 5, 2, 3, 5, 1,
	4, 5, 2, 1, 6, 6, 4, 2,
	1, 3, 3, 1, 10, 6, 6, 3,
	3, 1, 3, 3, 1, 8, 8, 8,
	8
};

static const char _yparser_range_lengths[] = {
	0, 3, 0, 3, 0, 0, 3, 0,
	3, 3, 0, 0, 2, 3, 0, 0,
	1, 1, 0, 1, 1, 2, 2, 0,
	0, 1, 1, 0, 1, 3, 3, 3,
	3
};

static const unsigned char _yparser_index_offsets[] = {
	0, 0, 12, 15, 24, 27, 31, 40,
	42, 50, 59, 62, 64, 73, 83, 88,
	91, 94, 99, 103, 106, 118, 127, 136,
	140, 144, 147, 152, 156, 159, 171, 183,
	195
};

static const char _yparser_indices[] = {
	1, 2, 3, 4, 5, 6, 5, 5,
	5, 5, 5, 0, 1, 2, 4, 7,
	8, 9, 8, 8, 8, 8, 8, 0,
	10, 11, 0, 12, 13, 14, 0, 15,
	16, 17, 16, 16, 16, 16, 16, 0,
	18, 0, 18, 19, 19, 19, 19, 19,
	19, 0, 20, 21, 22, 21, 21, 21,
	21, 21, 0, 23, 24, 0, 25, 0,
	25, 27, 0, 0, 28, 0, 0, 0,
	26, 30, 31, 32, 0, 33, 0, 0,
	0, 0, 29, 12, 13, 34, 35, 0,
	12, 13, 35, 36, 29, 0, 38, 39,
	0, 0, 37, 30, 31, 32, 0, 40,
	37, 0, 12, 13, 14, 27, 35, 0,
	41, 28, 0, 0, 0, 26, 41, 43,
	0, 0, 44, 0, 0, 0, 42, 46,
	47, 0, 48, 49, 0, 0, 0, 45,
	50, 41, 51, 0, 12, 13, 34, 0,
	52, 45, 0, 54, 55, 0, 0, 53,
	46, 47, 49, 0, 56, 53, 0, 1,
	2, 3, 4, 57, 6, 57, 57, 57,
	57, 57, 0, 59, 60, 61, 62, 63,
	64, 63, 63, 63, 63, 63, 58, 65,
	66, 67, 68, 69, 70, 69, 69, 69,
	69, 69, 0, 71, 72, 73, 74, 75,
	76, 75, 75, 75, 75, 75, 58, 0
};

static const char _yparser_trans_targs[] = {
	0, 30, 31, 1, 2, 3, 7, 4,
	3, 5, 4, 5, 32, 29, 20, 4,
	6, 5, 8, 9, 10, 9, 11, 10,
	11, 12, 13, 17, 16, 13, 32, 29,
	14, 16, 14, 15, 13, 17, 18, 19,
	17, 21, 22, 26, 25, 22, 23, 21,
	25, 24, 23, 24, 22, 26, 27, 28,
	26, 6, 0, 30, 31, 1, 2, 6,
	7, 30, 31, 1, 2, 6, 7, 30,
	31, 1, 2, 6, 7
};

static const char _yparser_trans_actions[] = {
	23, 1, 0, 49, 0, 46, 52, 17,
	13, 17, 0, 0, 1, 0, 0, 15,
	13, 15, 21, 46, 19, 13, 19, 0,
	0, 0, 37, 7, 37, 9, 43, 11,
	11, 9, 0, 0, 40, 9, 0, 9,
	40, 0, 37, 7, 37, 9, 11, 11,
	9, 11, 0, 0, 40, 9, 0, 9,
	40, 46, 31, 55, 28, 88, 28, 83,
	93, 34, 5, 75, 5, 71, 79, 25,
	3, 63, 3, 59, 67
};

static const char _yparser_eof_actions[] = {
	0, 23, 23, 23, 23, 23, 23, 23,
	23, 23, 23, 23, 23, 23, 23, 23,
	23, 23, 23, 23, 23, 23, 23, 23,
	23, 23, 23, 23, 23, 0, 28, 5,
	3
};





int _yp_start_state = 29;

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
	_trans = _yparser_indices[_trans];
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
		parser->data_len--;
	}
	break;
	case 6:
	{
		// Return if a value parsed.
		parser->data[parser->data_len] = '\0';
		parser->processed = true;
		found = true;
		{p++; goto _out; }
	}
	break;
	case 7:
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
	case 8:
	{
		if (parser->key_len >= sizeof(parser->key) - 1) {
			return KNOT_ESPACE;
		}
		parser->key[parser->key_len++] = (*p);
	}
	break;
	case 9:
	{
		parser->key[parser->key_len] = '\0';
		parser->indent = 0;
		parser->id_pos = 0;
		parser->event = YP_EKEY0;
	}
	break;
	case 10:
	{
		parser->key[parser->key_len] = '\0';
		parser->indent = indent;
		parser->event = YP_EKEY1;
	}
	break;
	case 11:
	{
		parser->key[parser->key_len] = '\0';
		parser->indent = indent;
		parser->id_pos = id_pos;
		parser->event = YP_EID;
	}
	break;
	case 12:
	{
		indent++;
	}
	break;
	case 13:
	{
		id_pos++;
	}
	break;
	case 14:
	{
		if (id_pos > 0 && parser->id_pos > 0 &&
		    id_pos != parser->id_pos) {
			return KNOT_YP_EINVAL_INDENT;
		}
		parser->indent = 0;
	}
	break;
	case 15:
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
	case 15:
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
