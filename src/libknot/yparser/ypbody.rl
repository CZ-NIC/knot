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

%%{
	machine yparser;

	access parser->;

	# Newline processing.
	action _newline_init {
		// Return if key without value.
		if (parser->event != YP_ENULL && !parser->processed) {
			parser->processed = true;
			found = true;
			fbreak;
		}
	}
	action _newline {
		parser->line_count++;
		parser->event = YP_ENULL;
		parser->processed = false;
	}
	newline_char = '\n' >_newline_init %_newline | '\r';

	# Comment processing.
	comment_char = '#';
	comment = comment_char . (^newline_char)*;

	# White space processing.
	sep_char = ' ';
	sep = sep_char+;

	action _blank_exit {
		indent = 0;
		id_pos = 0;
	}

	blank = ( sep? .  comment?       ) . newline_char %_blank_exit;
	rest  = ((sep  :> comment) | sep?) . newline_char;

	# Data processing.
	action _item_data_init {
		parser->data_len = 0;
	}
	action _item_data {
		if (parser->data_len >= sizeof(parser->data) - 1) {
			return KNOT_ESPACE;
		}
		parser->data[parser->data_len++] = fc;
	}
	action _item_rewrite {
		parser->data_len--;
	}
	action _item_data_exit {
		// Return if a value parsed.
		parser->data[parser->data_len] = '\0';
		parser->processed = true;
		found = true;
		fbreak;
	}
	quote_char = '\"';
	list_char = [\[,\]];
	data_char =
		( (ascii - space - cntrl - quote_char - sep_char -
		   comment_char - list_char - '\\')
		| ('\\' . quote_char >_item_rewrite)
		| ('\\' . (32..126 - quote_char))
		) $_item_data;
	data_str_char =
		( (data_char)
		| (sep_char | comment_char | list_char) $_item_data
		);
	data_str = (quote_char . data_str_char* <: quote_char);
	item_data = (data_char+ | data_str) >_item_data_init %_item_data_exit;
	item_data_plus = item_data . ((sep? . ',' . sep?) . item_data)*;
	item_data_list = '\[' . sep? . item_data_plus . sep? . '\]';

	# Key processing.
	action _key_init {
		if (indent > 0 && parser->indent > 0 &&
		    indent != parser->indent) {
			return KNOT_YP_EINVAL_INDENT;
		}
		parser->processed = false;
		parser->key_len = 0;
		parser->data_len = 0;
		parser->event = YP_ENULL;
	}
	action _key {
		if (parser->key_len >= sizeof(parser->key) - 1) {
			return KNOT_ESPACE;
		}
		parser->key[parser->key_len++] = fc;
	}
	action _key0_exit {
		parser->key[parser->key_len] = '\0';
		parser->indent = 0;
		parser->id_pos = 0;
		parser->event = YP_EKEY0;
	}
	action _key1_exit {
		parser->key[parser->key_len] = '\0';
		parser->indent = indent;
		parser->event = YP_EKEY1;
	}
	action _id_exit {
		parser->key[parser->key_len] = '\0';
		parser->indent = indent;
		parser->id_pos = id_pos;
		parser->event = YP_EID;
	}
	action _indent {
		indent++;
	}
	action _id {
		id_pos++;
	}
	action _dash_init {
		if (id_pos > 0 && parser->id_pos > 0 &&
		    id_pos != parser->id_pos) {
			return KNOT_YP_EINVAL_INDENT;
		}
		parser->indent = 0;
	}
	key_name = ((alnum | [\\.]) . (alnum | [\\.\-])*) >_key_init $_key;
	key0 =                                                  key_name %_key0_exit;
	key1 =   sep                                 $_indent . key_name %_key1_exit;
	id   = ((sep $_id)? . '-' >_dash_init . sep) $_indent . key_name %_id_exit;
	item = (((key0 . sep? . ':' . (sep . (item_data_list | item_data))?)
	        |(key1 . sep? . ':' . (sep . (item_data_list | item_data))?)
	        |(id   . sep? . ':' .  sep . item_data)
	        ) . rest
	       );

	# Main processing loop.
	action _error {
		switch (fc) {
		case '\t':
			return KNOT_YP_ECHAR_TAB;
		default:
			return KNOT_EPARSEFAIL;
		}
	}

	main := (blank | item)* $!_error;
}%%

// Include parser static data (Ragel internals).
%% write data;

int _yp_start_state = %%{ write start; }%%;

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
	%% write exec;

	// Store the current parser position.
	if (!parser->input.eof) {
		parser->input.current = p;
	} else {
		parser->input.current = parser->input.end;
	}

	// Check for general parser error.
	if (parser->cs == %%{ write error; }%%) {
		return KNOT_EPARSEFAIL;
	}

	// Check if parsed an item.
	if (found) {
		return KNOT_EOK;
	} else {
		return KNOT_EFEWDATA;
	}
}
