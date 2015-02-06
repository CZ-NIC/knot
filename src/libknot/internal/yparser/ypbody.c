
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
	8, 1, 9, 1, 10, 1, 13, 2, 
	1, 0, 2, 2, 3, 2, 4, 0, 
	2, 5, 6, 2, 10, 11, 2, 12, 
	10, 3, 1, 5, 6, 3, 1, 10, 
	11, 3, 1, 12, 10
};

static const unsigned char _yparser_key_offsets[] = {
	0, 0, 10, 11, 12, 19, 28, 30, 
	31, 41, 51, 54, 57, 59, 68, 70, 
	72, 83, 93, 101, 104, 106, 109, 112, 
	121, 131
};

static const char _yparser_trans_keys[] = {
	10, 32, 35, 45, 48, 57, 65, 90, 
	97, 122, 10, 32, 32, 48, 57, 65, 
	90, 97, 122, 32, 45, 58, 48, 57, 
	65, 90, 97, 122, 32, 58, 32, 32, 
	33, 34, 92, 36, 43, 45, 90, 94, 
	126, 10, 32, 33, 92, 36, 43, 45, 
	90, 94, 126, 10, 32, 35, 34, 32, 
	126, 10, 32, 32, 45, 58, 48, 57, 
	65, 90, 97, 122, 32, 58, 10, 32, 
	10, 32, 34, 35, 91, 33, 43, 45, 
	92, 94, 126, 32, 33, 34, 92, 36, 
	43, 45, 90, 94, 126, 32, 33, 44, 
	93, 36, 90, 92, 126, 32, 44, 93, 
	10, 32, 34, 32, 126, 32, 44, 93, 
	32, 45, 58, 48, 57, 65, 90, 97, 
	122, 10, 32, 35, 45, 48, 57, 65, 
	90, 97, 122, 10, 32, 35, 45, 48, 
	57, 65, 90, 97, 122, 0
};

static const char _yparser_single_lengths[] = {
	0, 4, 1, 1, 1, 3, 2, 1, 
	4, 4, 3, 1, 2, 3, 2, 2, 
	5, 4, 4, 3, 2, 1, 3, 3, 
	4, 4
};

static const char _yparser_range_lengths[] = {
	0, 3, 0, 0, 3, 3, 0, 0, 
	3, 3, 0, 1, 0, 3, 0, 0, 
	3, 3, 2, 0, 0, 1, 0, 3, 
	3, 3
};

static const unsigned char _yparser_index_offsets[] = {
	0, 0, 8, 10, 12, 17, 24, 27, 
	29, 37, 45, 49, 52, 55, 62, 65, 
	68, 77, 85, 92, 96, 99, 102, 106, 
	113, 121
};

static const char _yparser_indicies[] = {
	1, 2, 3, 4, 5, 5, 5, 0, 
	1, 3, 6, 0, 6, 7, 7, 7, 
	0, 8, 9, 10, 9, 9, 9, 0, 
	11, 12, 0, 13, 0, 13, 14, 15, 
	14, 14, 14, 14, 0, 16, 17, 18, 
	18, 18, 18, 18, 0, 1, 19, 3, 
	0, 21, 20, 0, 16, 17, 0, 22, 
	23, 24, 23, 23, 23, 0, 25, 26, 
	0, 1, 27, 0, 1, 27, 15, 3, 
	28, 14, 14, 14, 0, 28, 29, 30, 
	29, 29, 29, 29, 0, 31, 32, 33, 
	34, 32, 32, 0, 35, 28, 36, 0, 
	1, 19, 0, 38, 37, 0, 31, 33, 
	34, 0, 39, 40, 41, 40, 40, 40, 
	0, 1, 2, 3, 4, 42, 42, 42, 
	0, 43, 44, 45, 46, 47, 47, 47, 
	0, 0
};

static const char _yparser_trans_targs[] = {
	0, 25, 1, 2, 3, 13, 4, 5, 
	6, 5, 7, 6, 7, 8, 9, 11, 
	25, 10, 9, 10, 11, 12, 14, 13, 
	15, 14, 15, 16, 17, 18, 21, 19, 
	18, 17, 20, 19, 20, 21, 22, 14, 
	23, 15, 23, 25, 1, 2, 3, 23
};

static const char _yparser_trans_actions[] = {
	21, 1, 35, 0, 38, 32, 19, 32, 
	17, 11, 17, 0, 0, 0, 26, 5, 
	29, 9, 7, 0, 7, 0, 15, 11, 
	15, 0, 0, 0, 0, 26, 5, 9, 
	7, 9, 9, 0, 0, 7, 0, 13, 
	11, 13, 32, 23, 45, 3, 49, 41
};

static const char _yparser_eof_actions[] = {
	0, 21, 21, 21, 21, 21, 21, 21, 
	21, 21, 21, 21, 21, 21, 21, 21, 
	21, 21, 21, 21, 21, 21, 21, 21, 
	0, 3
};





int _yp_start_state = 
24
;

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
		if (parser->data_len >= sizeof(parser->data) - 1) {
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
		if (indent > 0 && parser->indent > 0 &&
		    indent != parser->indent) {
			return KNOT_EPARSEFAIL;
		}
		parser->processed = false;
		parser->key_len = 0;
		parser->data_len = 0;
		parser->event = YP_ENULL;
	}
	break;
	case 6:
	{
		if (parser->key_len >= sizeof(parser->key) - 1) {
			return KNOT_ESPACE;
		}
		parser->key[parser->key_len++] = (*p);
	}
	break;
	case 7:
	{
		parser->key[parser->key_len] = '\0';
		parser->indent = 0;
		parser->event = YP_EKEY0;
	}
	break;
	case 8:
	{
		parser->key[parser->key_len] = '\0';
		parser->indent = indent;
		parser->event = YP_EKEY1;
	}
	break;
	case 9:
	{
		parser->key[parser->key_len] = '\0';
		parser->indent = indent;
		parser->id_pos = id_pos;
		parser->event = YP_EID;
	}
	break;
	case 10:
	{
		indent++;
	}
	break;
	case 11:
	{
		id_pos++;
	}
	break;
	case 12:
	{
		if (id_pos > 0 && parser->id_pos > 0 &&
		    id_pos != parser->id_pos) {
			return KNOT_EPARSEFAIL;
		}
		parser->indent = 0;
	}
	break;
	case 13:
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
	case 13:
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
