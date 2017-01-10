/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
%%{
	machine zone_scanner;

	# Comeback function to calling state machine.
	action _ret {
		fhold; fret;
	}

	# BEGIN - Blank space processing
	action _newline {
		s->line_counter++;
	}

	action _check_multiline_begin {
		if (s->multiline == true) {
			ERR(ZS_LEFT_PARENTHESIS);
			fhold; fgoto err_line;
		}
		s->multiline = true;
	}
	action _check_multiline_end {
		if (s->multiline == false) {
			ERR(ZS_RIGHT_PARENTHESIS);
			fhold; fgoto err_line;
		}
		s->multiline = false;
	}

	action _rest_error {
		WARN(ZS_BAD_REST);
		fhold; fgoto err_line;
	}

	newline = '\n' $_newline;
	comment = ';' . (^newline)*;

	# White space separation. With respect to parentheses and included comments.
	sep = ( [ \t]                                       # Blank characters.
	      | (comment? . newline) when { s->multiline }  # Comment in multiline.
	      | '(' $_check_multiline_begin                 # Start of multiline.
	      | ')' $_check_multiline_end                   # End of multiline.
	      )+;                                           # Apply more times.

	rest = (sep? :> comment?) $!_rest_error; # Useless text after record.

	# Artificial machines which are used for next state transition only!
	all_wchar = [ \t\n;()];
	end_wchar = [\n;] when { !s->multiline }; # For noncontinuous ending tokens.
	# END

	# BEGIN - Error line processing
	action _err_line_init {
		s->buffer_length = 0;
	}
	action _err_line {
		if (fc == '\r') {
			ERR(ZS_DOS_NEWLINE);
		}

		if (s->buffer_length < sizeof(s->buffer) - 1) {
			s->buffer[s->buffer_length++] = fc;
		}
	}
	action _err_line_exit {
		// Terminate the error context string.
		s->buffer[s->buffer_length++] = 0;

		// Error counter incrementation.
		s->error.counter++;

		// Initialize the fcall stack.
		top = 0;

		// Reset the multiline context.
		s->multiline = false;

		s->state = ZS_STATE_ERROR;

		// Execute the error callback.
		if (s->process.automatic) {
			if (s->process.error != NULL) {
				s->process.error(s);

				// Stop the scanner if required.
				if (s->state == ZS_STATE_STOP) {
					fbreak;
				}
			}

			// Stop the scanner if fatal.
			if (s->error.fatal) {
				s->state = ZS_STATE_STOP;
				fbreak;
			}
		} else {
			// Return if external processing.
			escape = true;
		}
	}
	action _err_line_exit_final {
		if (escape) {
			fnext main; fbreak;
		} else {
			fgoto main;
		}
	}

	# Fill rest of the line to buffer and skip to main loop.
	err_line := (^newline $_err_line)* >_err_line_init
	            %_err_line_exit . newline @_err_line_exit_final;
	# END

	# BEGIN - Domain name labels processing
	action _label_init {
		s->item_length = 0;
		s->item_length_position = s->dname_tmp_length++;
	}
	action _label_char {
		// Check for maximum dname label length.
		if (s->item_length < MAX_LABEL_LENGTH) {
			(s->dname)[s->dname_tmp_length++] = fc;
			s->item_length++;
		} else {
			WARN(ZS_LABEL_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _label_exit {
		// Check for maximum dname length overflow after each label.
		// (at least the next label length must follow).
		if (s->dname_tmp_length < MAX_DNAME_LENGTH) {
			(s->dname)[s->item_length_position] =
				(uint8_t)(s->item_length);
		} else {
			WARN(ZS_DNAME_OVERFLOW);
			fhold; fgoto err_line;
		}
	}

	action _label_dec_init {
		if (s->item_length < MAX_LABEL_LENGTH) {
			(s->dname)[s->dname_tmp_length] = 0;
			s->item_length++;
		} else {
			WARN(ZS_LABEL_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _label_dec {
		(s->dname)[s->dname_tmp_length] *= 10;
		(s->dname)[s->dname_tmp_length] += digit_to_num[(uint8_t)fc];
	}
	action _label_dec_exit {
		s->dname_tmp_length++;
	}
	action _label_dec_error {
		WARN(ZS_BAD_NUMBER);
		fhold; fgoto err_line;
	}

	label_char =
	    ( (alnum | [*\-_/]) $_label_char                 # One common char.
	    | ('\\' . ^digit)   @_label_char                 # One "\x" char.
	    | ('\\'             %_label_dec_init             # Initial "\" char.
	       . digit {3}      $_label_dec %_label_dec_exit # "DDD" rest.
	                        $!_label_dec_error
	      )
	    );

	label  = label_char+ >_label_init %_label_exit;
	labels = (label . '.')* . label;
	# END

	# BEGIN - Domain name processing.
	action _absolute_dname_exit {
		// Enough room for the terminal label is guaranteed (_label_exit).
		(s->dname)[s->dname_tmp_length++] = 0;
	}
	action _relative_dname_exit {
		// Check for (relative + origin) dname length overflow.
		if (s->dname_tmp_length + s->zone_origin_length <= MAX_DNAME_LENGTH) {
			memcpy(s->dname + s->dname_tmp_length,
			       s->zone_origin,
			       s->zone_origin_length);

			s->dname_tmp_length += s->zone_origin_length;
		} else {
			WARN(ZS_DNAME_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _origin_dname_exit {
		// Copy already verified zone origin.
		memcpy(s->dname,
		       s->zone_origin,
		       s->zone_origin_length);

		s->dname_tmp_length = s->zone_origin_length;
	}

	action _dname_init {
		s->item_length_position = 0;
		s->dname_tmp_length = 0;
	}
	action _dname_error {
		WARN(ZS_BAD_DNAME_CHAR);
		fhold; fgoto err_line;
	}

	relative_dname = (labels       ) >_dname_init %_relative_dname_exit;
	absolute_dname = (labels? . '.') >_dname_init %_absolute_dname_exit;

	dname_ := ( relative_dname
	          | absolute_dname
	          | '@' %_origin_dname_exit
	          ) $!_dname_error %_ret . all_wchar;
	dname = (alnum | [\-_/\\] | [*.@]) ${ fhold; fcall dname_; };
	# END

	# BEGIN - Common r_data item processing
	action _item_length_init {
		if (rdata_tail <= rdata_stop) {
			s->item_length_location = rdata_tail++;
		} else {
			WARN(ZS_RDATA_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _item_length_exit {
		s->item_length = rdata_tail - s->item_length_location - 1;

		if (s->item_length <= MAX_ITEM_LENGTH) {
			*(s->item_length_location) = (uint8_t)(s->item_length);
		} else {
			WARN(ZS_ITEM_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	# END

	# BEGIN - Owner processing
	action _r_owner_init {
		s->dname = s->r_owner;
		s->r_owner_length = 0;
	}
	action _r_owner_exit {
		s->r_owner_length = s->dname_tmp_length;
	}
	action _r_owner_empty_exit {
		if (s->r_owner_length == 0) {
			WARN(ZS_BAD_PREVIOUS_OWNER);
			fhold; fgoto err_line;
		}
	}
	action _r_owner_error {
		s->r_owner_length = 0;
		WARN(ZS_BAD_OWNER);
		fhold; fgoto err_line;
	}

	r_owner = ( dname >_r_owner_init %_r_owner_exit
	          | zlen  %_r_owner_empty_exit # Empty owner - use the previous one.
	          ) $!_r_owner_error;
	# END

	# BEGIN - domain name in record data processing
	action _r_dname_init {
		s->dname = rdata_tail;
	}
	action _r_dname_exit {
		rdata_tail += s->dname_tmp_length;
	}

	r_dname = dname >_r_dname_init %_r_dname_exit;
	# END

	# BEGIN - Number processing
	action _number_digit {
		// Overflow check: 10*(s->number64) + fc - '0' <= UINT64_MAX
		if ((s->number64 < (UINT64_MAX / 10)) ||   // Dominant fast check.
			((s->number64 == (UINT64_MAX / 10)) && // Marginal case.
			 ((uint8_t)fc <= (UINT64_MAX % 10) + '0')
			)
		   ) {
			s->number64 *= 10;
			s->number64 += digit_to_num[(uint8_t)fc];
		} else {
			WARN(ZS_NUMBER64_OVERFLOW);
			fhold; fgoto err_line;
		}
	}

	number_digit = [0-9] $_number_digit;

	action _number_init {
		s->number64 = 0;
	}
	action _number_error {
		WARN(ZS_BAD_NUMBER);
		fhold; fgoto err_line;
	}

	# General integer number that cover all necessary integer ranges.
	number = number_digit+ >_number_init;

	action _float_init {
		s->decimal_counter = 0;
	}
	action _decimal_init {
		s->number64_tmp = s->number64;
	}
	action _decimal_digit {
		s->decimal_counter++;
	}

	action _float_exit {
		if (s->decimal_counter == 0 && s->number64 < UINT32_MAX) {
			s->number64 *= pow(10, s->decimals);
		} else if (s->decimal_counter <= s->decimals &&
				 s->number64_tmp < UINT32_MAX) {
			s->number64 *= pow(10, s->decimals - s->decimal_counter);
			s->number64 += s->number64_tmp * pow(10, s->decimals);
		} else {
			WARN(ZS_FLOAT_OVERFLOW);
			fhold; fgoto err_line;
		}
	}

	# Next float can't be used directly (doesn't contain decimals init)!
	float = (number . ('.' . number? >_decimal_init $_decimal_digit)?)
			>_float_init %_float_exit;

	action _float2_init {
		s->decimals = 2;
	}
	action _float3_init {
		s->decimals = 3;
	}

	# Float number (in hundredths)with 2 possible decimal digits.
	float2  = float >_float2_init;
	# Float number (in thousandths) with 3 possible decimal digits.
	float3  = float >_float3_init;

	action _num8_write {
		if (s->number64 <= UINT8_MAX) {
			*rdata_tail = (uint8_t)(s->number64);
			rdata_tail += 1;
		} else {
			WARN(ZS_NUMBER8_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _num16_write {
		if (s->number64 <= UINT16_MAX) {
			*((uint16_t *)rdata_tail) = htons((uint16_t)(s->number64));
			rdata_tail += 2;
		} else {
			WARN(ZS_NUMBER16_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _num32_write {
		if (s->number64 <= UINT32_MAX) {
			*((uint32_t *)rdata_tail) = htonl((uint32_t)(s->number64));
			rdata_tail += 4;
		} else {
			WARN(ZS_NUMBER32_OVERFLOW);
			fhold; fgoto err_line;
		}
	}

	action _type_number_exit {
		if (s->number64 <= UINT16_MAX) {
			s->r_type = (uint16_t)(s->number64);
		} else {
			WARN(ZS_NUMBER16_OVERFLOW);
			fhold; fgoto err_line;
		}
	}

	action _length_number_exit {
		if (s->number64 <= UINT16_MAX) {
			s->r_data_length = (uint16_t)(s->number64);
		} else {
			WARN(ZS_NUMBER16_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	num8  = number %_num8_write  $!_number_error;
	num16 = number %_num16_write $!_number_error;
	num32 = number %_num32_write $!_number_error;

	type_number   = number %_type_number_exit $!_number_error;
	length_number = number %_length_number_exit $!_number_error;
	# END

	# BEGIN - Time processing
	action _time_unit_error {
		WARN(ZS_BAD_TIME_UNIT);
		fhold; fgoto err_line;
	}

	time_unit =
	    ( 's'i
	    | 'm'i ${ if (s->number64 <= (UINT32_MAX / 60)) {
	                  s->number64 *= 60;
	              } else {
	                  WARN(ZS_NUMBER32_OVERFLOW);
	                  fhold; fgoto err_line;
	              }
	            }
	    | 'h'i ${ if (s->number64 <= (UINT32_MAX / 3600)) {
	                  s->number64 *= 3600;
	              } else {
	                  WARN(ZS_NUMBER32_OVERFLOW);
	                  fhold; fgoto err_line;
	              }
	            }
	    | 'd'i ${ if (s->number64 <= (UINT32_MAX / 86400)) {
	                  s->number64 *= 86400;
	              } else {
	                  WARN(ZS_NUMBER32_OVERFLOW);
	                  fhold; fgoto err_line;
	              }
	            }
	    | 'w'i ${ if (s->number64 <= (UINT32_MAX / 604800)) {
	                  s->number64 *= 604800;
	              } else {
	                  WARN(ZS_NUMBER32_OVERFLOW);
	                  fhold; fgoto err_line;
	              }
	            }
	    ) $!_time_unit_error;


	action _time_block_init {
		s->number64_tmp = s->number64;
	}
	action _time_block_exit {
		if (s->number64 + s->number64_tmp < UINT32_MAX) {
			s->number64 += s->number64_tmp;
		} else {
			WARN(ZS_NUMBER32_OVERFLOW);
			fhold; fgoto err_line;
		}
	}

	time_block = (number . time_unit) >_time_block_init %_time_block_exit;

	# Time is either a number or a sequence of time blocks (1w1h1m).
	time = (number . (time_unit . (time_block)*)?) $!_number_error;

	time32 = time %_num32_write;
	# END

	# BEGIN - Timestamp processing
	action _timestamp_init {
		s->buffer_length = 0;
	}
	action _timestamp {
		if (s->buffer_length < MAX_RDATA_LENGTH) {
			s->buffer[s->buffer_length++] = fc;
		} else {
			WARN(ZS_RDATA_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _timestamp_exit {
		s->buffer[s->buffer_length] = 0;

		if (s->buffer_length == 14) { // Date; 14 = len("YYYYMMDDHHmmSS").
			ret = date_to_timestamp(s->buffer, &timestamp);

			if (ret == ZS_OK) {
				*((uint32_t *)rdata_tail) = htonl(timestamp);
				rdata_tail += 4;
			} else {
				WARN(ret);
				fhold; fgoto err_line;
			}
		} else if (s->buffer_length <= 10) { // Timestamp format.
			char *end;

			s->number64 = strtoull((char *)(s->buffer), &end,  10);

			if (end == (char *)(s->buffer) || *end != '\0') {
				WARN(ZS_BAD_TIMESTAMP);
				fhold; fgoto err_line;
			}

			if (s->number64 <= UINT32_MAX) {
				*((uint32_t *)rdata_tail) = htonl((uint32_t)s->number64);
				rdata_tail += 4;
			} else {
				WARN(ZS_NUMBER32_OVERFLOW);
				fhold; fgoto err_line;
			}
		} else {
			WARN(ZS_BAD_TIMESTAMP_LENGTH);
			fhold; fgoto err_line;
		}
	}
	action _timestamp_error {
		WARN(ZS_BAD_TIMESTAMP_CHAR);
		fhold; fgoto err_line;
	}

	timestamp = digit+ >_timestamp_init $_timestamp
	            %_timestamp_exit $!_timestamp_error;
	# END

	# BEGIN - Text processing
	action _text_char {
		if (rdata_tail <= rdata_stop) {
			// Split long string.
			if (s->long_string &&
			    rdata_tail - s->item_length_location == 1 + MAX_ITEM_LENGTH) {
				// _item_length_exit equivalent.
				*(s->item_length_location) = MAX_ITEM_LENGTH;
				// _item_length_init equivalent.
				s->item_length_location = rdata_tail++;

				if (rdata_tail > rdata_stop) {
					WARN(ZS_TEXT_OVERFLOW);
					fhold; fgoto err_line;
				}
			}

			*(rdata_tail++) = fc;
		} else {
			WARN(ZS_TEXT_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _text_char_error {
		WARN(ZS_BAD_TEXT_CHAR);
		fhold; fgoto err_line;
	}
	action _text_error {
		WARN(ZS_BAD_TEXT);
		fhold; fgoto err_line;
	}

	action _text_dec_init {
		if (rdata_tail <= rdata_stop) {
			// Split long string.
			if (s->long_string &&
			    rdata_tail - s->item_length_location == 1 + MAX_ITEM_LENGTH) {
				// _item_length_exit equivalent.
				*(s->item_length_location) = MAX_ITEM_LENGTH;
				// _item_length_init equivalent.
				s->item_length_location = rdata_tail++;

				if (rdata_tail > rdata_stop) {
					WARN(ZS_TEXT_OVERFLOW);
					fhold; fgoto err_line;
				}
			}

			*rdata_tail = 0;
			s->item_length++;
		} else {
			WARN(ZS_TEXT_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _text_dec {
		if ((*rdata_tail < (UINT8_MAX / 10)) ||   // Dominant fast check.
			((*rdata_tail == (UINT8_MAX / 10)) && // Marginal case.
			 (fc <= (UINT8_MAX % 10) + '0')
			)
		   ) {
			*rdata_tail *= 10;
			*rdata_tail += digit_to_num[(uint8_t)fc];
		} else {
			WARN(ZS_NUMBER8_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _text_dec_exit {
		rdata_tail++;
	}
	action _text_dec_error {
		WARN(ZS_BAD_NUMBER);
		fhold; fgoto err_line;
	}

	text_char =
		( (33..126 - [\\;\"]) $_text_char          # One printable char.
		| ('\\' . ^digit)     @_text_char          # One "\x" char.
		| ('\\'               %_text_dec_init      # Initial "\" char.
		   . digit {3}        $_text_dec %_text_dec_exit # "DDD" rest.
		                      $!_text_dec_error
		  )
		) $!_text_char_error;

	quoted_text_char =
		( text_char
		| ([ \t;] | [\n] when { s->multiline }) $_text_char
		) $!_text_char_error;

	# Text string machine instantiation (for smaller code).
	text_ := (('\"' . quoted_text_char* . '\"') | text_char+)
		 $!_text_error %_ret . all_wchar;
	text = ^all_wchar ${ fhold; fcall text_; };

	# Text string with forward 1-byte length.
	text_string = text >_item_length_init %_item_length_exit;

	action _text_array_init {
		s->long_string = true;
	}
	action _text_array_exit {
		s->long_string = false;
	}

	# Text string array as one rdata item.
	text_array =
		( (text_string . (sep . text_string)* . sep?)
		) >_text_array_init %_text_array_exit $!_text_array_exit;
	# END

	# BEGIN - TTL directive processing
	action _default_ttl_exit {
		if (s->number64 <= UINT32_MAX) {
			s->default_ttl = (uint32_t)(s->number64);
		} else {
			ERR(ZS_NUMBER32_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _default_ttl_error {
		ERR(ZS_BAD_TTL);
		fhold; fgoto err_line;
	}

	default_ttl_ := (sep . time . rest) $!_default_ttl_error
	                %_default_ttl_exit %_ret . newline;
	default_ttl = all_wchar ${ fhold; fcall default_ttl_; };
	# END

	# BEGIN - ORIGIN directive processing
	action _zone_origin_init {
		s->dname = s->zone_origin;
	}
	action _zone_origin_exit {
		s->zone_origin_length = s->dname_tmp_length;
	}
	action _zone_origin_error {
		ERR(ZS_BAD_ORIGIN);
		fhold; fgoto err_line;
	}

	zone_origin_ := (sep . absolute_dname >_zone_origin_init . rest)
	                $!_zone_origin_error %_zone_origin_exit %_ret . newline;
	zone_origin = all_wchar ${ fhold; fcall zone_origin_; };
	# END

	# BEGIN - INCLUDE directive processing
	action _incl_filename_init {
		rdata_tail = s->r_data;
	}
	action _incl_filename_exit {
		size_t len = rdata_tail - s->r_data;
		if (len >= sizeof(s->include_filename)) {
			ERR(ZS_BAD_INCLUDE_FILENAME);
			fhold; fgoto err_line;
		}

		// Store zero terminated include filename.
		memcpy(s->include_filename, s->r_data, len);
		s->include_filename[len] = '\0';

		// For detection whether origin is not present.
		s->dname = NULL;
	}
	action _incl_filename_error {
		ERR(ZS_BAD_INCLUDE_FILENAME);
		fhold; fgoto err_line;
	}

	action _incl_origin_init {
		s->dname = s->r_data;
	}
	action _incl_origin_exit {
		s->r_data_length = s->dname_tmp_length;
	}
	action _incl_origin_error {
		ERR(ZS_BAD_INCLUDE_ORIGIN);
		fhold; fgoto err_line;
	}

	action _include_exit {
		// Extend relative file path.
		if (s->include_filename[0] != '/') {
			ret = snprintf((char *)(s->buffer), sizeof(s->buffer),
			               "%s/%s", s->path, s->include_filename);
			if (ret <= 0 || ret > sizeof(s->buffer)) {
				ERR(ZS_BAD_INCLUDE_FILENAME);
				fhold; fgoto err_line;
			}
			memcpy(s->include_filename, s->buffer, ret);
		}

		// Origin conversion from wire to text form in \DDD notation.
		if (s->dname == NULL) { // Use current origin.
			wire_dname_to_str(s->zone_origin,
			                  s->zone_origin_length,
			                  (char *)s->buffer);
		} else { // Use specified origin.
			wire_dname_to_str(s->r_data,
			                  s->r_data_length,
			                  (char *)s->buffer);
		}

		// Let the caller to solve the include.
		if (!s->process.automatic) {
			s->state = ZS_STATE_INCLUDE;
			escape = true;
		} else {
			// Create new scanner for included zone file.
			zs_scanner_t *ss = malloc(sizeof(zs_scanner_t));
			if (ss == NULL) {
				ERR(ZS_UNPROCESSED_INCLUDE);
				fhold; fgoto err_line;
			}

			// Parse included zone file.
			if (zs_init(ss, (char *)s->buffer, s->default_class,
			            s->default_ttl) != 0 ||
			    zs_set_input_file(ss, (char *)(s->include_filename)) != 0 ||
			    zs_set_processing(ss, s->process.record, s->process.error,
			                      s->process.data) != 0 ||
			    zs_parse_all(ss) != 0) {
				// File internal errors are handled by error callback.
				if (ss->error.counter > 0) {
					ERR(ZS_UNPROCESSED_INCLUDE);
				// General include file error.
				} else {
					ERR(ss->error.code);
				}
				zs_deinit(ss);
				free(ss);
				fhold; fgoto err_line;
			}
			zs_deinit(ss);
			free(ss);
		}
	}

	include_file_ :=
		(sep . text >_incl_filename_init %_incl_filename_exit
		 $!_incl_filename_error .
		 (sep . absolute_dname >_incl_origin_init %_incl_origin_exit
		  $!_incl_origin_error
		 )? . rest
		) %_include_exit %_ret newline;
	include_file = all_wchar ${ fhold; fcall include_file_; };
	# END

	# BEGIN - Directive switch
	# Each error/warning in directive should stop processing.
	# Some internal errors cause warning only. This causes stop processing.
	action _directive_init {
		ERR(ZS_OK);
	}
	# Remove stop processing flag.
	action _directive_exit {
		NOERR;
		if (escape) {
			fnext main; fbreak;
		}
	}
	action _directive_error {
		ERR(ZS_BAD_DIRECTIVE);
		fhold; fgoto err_line;
	}

	directive = '$' . ( ("TTL"i     . default_ttl)
	                  | ("ORIGIN"i  . zone_origin)
	                  | ("INCLUDE"i . include_file)
	                  ) >_directive_init %_directive_exit $!_directive_error;
	# END

	# BEGIN - RRecord class and ttl processing
	action _default_r_class_exit {
		s->r_class = s->default_class;
	}

	action _default_r_ttl_exit {
		s->r_ttl = s->default_ttl;
	}

	action _r_class_in_exit {
		s->r_class = KNOT_CLASS_IN;
	}

	action _r_ttl_exit {
		if (s->number64 <= UINT32_MAX) {
			s->r_ttl = (uint32_t)(s->number64);
		} else {
			WARN(ZS_NUMBER32_OVERFLOW);
			fhold; fgoto err_line;
		}
	}

	r_class = "IN"i %_r_class_in_exit;

	r_ttl = time %_r_ttl_exit;
	# END

	# BEGIN - IPv4 and IPv6 address processing
	action _addr_init {
		s->buffer_length = 0;
	}
	action _addr {
		if (s->buffer_length < MAX_RDATA_LENGTH) {
			s->buffer[s->buffer_length++] = fc;
		}
		else {
			WARN(ZS_RDATA_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _addr_error {
		WARN(ZS_BAD_ADDRESS_CHAR);
		fhold; fgoto err_line;
	}

	action _ipv4_addr_exit {
		s->buffer[s->buffer_length] = 0;

		if (inet_pton(AF_INET, (char *)s->buffer, &addr4) <= 0) {
			WARN(ZS_BAD_IPV4);
			fhold; fgoto err_line;
		}
	}
	action _ipv4_addr_write {
		memcpy(rdata_tail, &(addr4.s_addr), INET4_ADDR_LENGTH);
		rdata_tail += INET4_ADDR_LENGTH;
	}

	action _ipv6_addr_exit {
		s->buffer[s->buffer_length] = 0;

		if (inet_pton(AF_INET6, (char *)s->buffer, &addr6) <= 0) {
			WARN(ZS_BAD_IPV6);
			fhold; fgoto err_line;
		}
	}
	action _ipv6_addr_write {
		memcpy(rdata_tail, &(addr6.s6_addr), INET6_ADDR_LENGTH);
		rdata_tail += INET6_ADDR_LENGTH;
	}

	# Address parsers only.
	ipv4_addr = (digit  | '.')+  >_addr_init $_addr %_ipv4_addr_exit
	            $!_addr_error;
	ipv6_addr = (xdigit | [.:])+ >_addr_init $_addr %_ipv6_addr_exit
	            $!_addr_error;

	# Write parsed address to r_data.
	ipv4_addr_write = ipv4_addr %_ipv4_addr_write;
	ipv6_addr_write = ipv6_addr %_ipv6_addr_write;
	# END

	# BEGIN - apl record processing
	action _apl_init {
		memset(&(s->apl), 0, sizeof(s->apl));
	}
	action _apl_excl_flag {
		s->apl.excl_flag = 128; // dec 128  = bin 10000000.
	}
	action _apl_addr_1 {
		s->apl.addr_family = 1;
	}
	action _apl_addr_2 {
		s->apl.addr_family = 2;
	}
	action _apl_prefix_length {
		if ((s->apl.addr_family == 1 && s->number64 <= 32) ||
		    (s->apl.addr_family == 2 && s->number64 <= 128)) {
			s->apl.prefix_length = (uint8_t)(s->number64);
		} else {
			WARN(ZS_BAD_APL);
			fhold; fgoto err_line;
		}
	}
	action _apl_exit {
		// Write address family.
		*((uint16_t *)rdata_tail) = htons(s->apl.addr_family);
		rdata_tail += 2;
		// Write prefix length in bites.
		*(rdata_tail) = s->apl.prefix_length;
		rdata_tail += 1;
		// Copy address to buffer.
		uint8_t len;
		switch (s->apl.addr_family) {
		case 1:
			len = INET4_ADDR_LENGTH;
			memcpy(s->buffer, &(addr4.s_addr), len);
			break;
		case 2:
			len = INET6_ADDR_LENGTH;
			memcpy(s->buffer, &(addr6.s6_addr), len);
			break;
		default:
			WARN(ZS_BAD_APL);
			fhold; fgoto err_line;
		}
		// Find prefix without trailing zeroes.
		while (len > 0) {
			if ((s->buffer[len - 1] & 255) != 0) {
				break;
			}
			len--;
		}
		// Write negation flag + prefix length in bytes.
		*(rdata_tail) = len + s->apl.excl_flag;
		rdata_tail += 1;
		// Write address prefix non-null data.
		memcpy(rdata_tail, s->buffer, len);
		rdata_tail += len;
	}
	action _apl_error {
		WARN(ZS_BAD_APL);
		fhold; fgoto err_line;
	}

	apl = ('!'? $_apl_excl_flag .
	       ( ('1' $_apl_addr_1 . ':' . ipv4_addr . '/' . number
	          %_apl_prefix_length)
	       | ('2' $_apl_addr_2 . ':' . ipv6_addr . '/' . number
	          %_apl_prefix_length)
	       )
	      ) >_apl_init %_apl_exit $!_apl_error;

	# Array of APL records (can be empty).
	apl_array = apl? . (sep . apl)* . sep?;
	# END

	# BEGIN - Hexadecimal string array processing
	action _first_hex_char {
		if (rdata_tail <= rdata_stop) {
			*rdata_tail = first_hex_to_num[(uint8_t)fc];
		} else {
			WARN(ZS_RDATA_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _second_hex_char {
		*rdata_tail += second_hex_to_num[(uint8_t)fc];
		rdata_tail++;
	}
	action _hex_char_error {
		WARN(ZS_BAD_HEX_CHAR);
		fhold; fgoto err_line;
	}

	hex_char  = (xdigit $_first_hex_char . xdigit $_second_hex_char);

	# Hex array with possibility of inside white spaces and multiline.
	hex_array = (hex_char+ . sep?)+ $!_hex_char_error;

	# Continuous hex array (or "-") with forward length processing.
	salt = (hex_char+ | '-') >_item_length_init %_item_length_exit
	       $!_hex_char_error;

	action _type_data_exit {
		if ((rdata_tail - s->r_data) != s->r_data_length) {
			WARN(ZS_BAD_RDATA_LENGTH);
			fhold; fgoto err_line;
		}
	}

	action _type_data_error {
		WARN(ZS_BAD_HEX_RDATA);
		fhold; fgoto err_line;
	}

	# Hex array with control to forward length statement.
	type_data = hex_array %_type_data_exit $!_type_data_error;
	# END

	# BEGIN - Base64 processing (RFC 4648)
	action _first_base64_char {
		if (rdata_tail <= rdata_stop) {
			*rdata_tail = first_base64_to_num[(uint8_t)fc];
		} else {
			WARN(ZS_RDATA_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _second_base64_char {
		*(rdata_tail++) += second_left_base64_to_num[(uint8_t)fc];

		if (rdata_tail <= rdata_stop) {
			*rdata_tail = second_right_base64_to_num[(uint8_t)fc];
		} else {
			WARN(ZS_RDATA_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _third_base64_char {
		*(rdata_tail++) += third_left_base64_to_num[(uint8_t)fc];

		if (rdata_tail <= rdata_stop) {
			*rdata_tail = third_right_base64_to_num[(uint8_t)fc];
		} else {
			WARN(ZS_RDATA_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _fourth_base64_char {
		*(rdata_tail++) += fourth_base64_to_num[(uint8_t)fc];
	}

	action _base64_char_error {
		WARN(ZS_BAD_BASE64_CHAR);
		fhold; fgoto err_line;
	}

	base64_char = alnum | [+/];
	base64_padd = '=';
	base64_quartet =
	    ( base64_char          $_first_base64_char  . # A
	      base64_char          $_second_base64_char . # AB
	      ( ( base64_char      $_third_base64_char  . # ABC
	          ( base64_char    $_fourth_base64_char   # ABCD
	          | base64_padd{1}                        # ABC=
	          )
	        )
	      | base64_padd{2}                            # AB==
	      )
	    );

	# Base64 array with possibility of inside white spaces and multiline.
	base64_ := (base64_quartet+ . sep?)+ $!_base64_char_error
	           %_ret . end_wchar;
	base64 = base64_char ${ fhold; fcall base64_; };
	# END

	# BEGIN - Base32hex processing (RFC 4648)
	action _first_base32hex_char {
		if (rdata_tail <= rdata_stop) {
			*rdata_tail = first_base32hex_to_num[(uint8_t)fc];
		} else {
			WARN(ZS_RDATA_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _second_base32hex_char {
		*(rdata_tail++) += second_left_base32hex_to_num[(uint8_t)fc];

		if (rdata_tail <= rdata_stop) {
			*rdata_tail = second_right_base32hex_to_num[(uint8_t)fc];
		} else {
			WARN(ZS_RDATA_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _third_base32hex_char {
		*rdata_tail += third_base32hex_to_num[(uint8_t)fc];
	}
	action _fourth_base32hex_char {
		*(rdata_tail++) += fourth_left_base32hex_to_num[(uint8_t)fc];

		if (rdata_tail <= rdata_stop) {
			*rdata_tail = fourth_right_base32hex_to_num[(uint8_t)fc];
		} else {
			WARN(ZS_RDATA_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _fifth_base32hex_char {
		*(rdata_tail++) += fifth_left_base32hex_to_num[(uint8_t)fc];

		if (rdata_tail <= rdata_stop) {
			*rdata_tail = fifth_right_base32hex_to_num[(uint8_t)fc];
		} else {
			WARN(ZS_RDATA_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _sixth_base32hex_char {
		*rdata_tail += sixth_base32hex_to_num[(uint8_t)fc];
	}
	action _seventh_base32hex_char {
		*(rdata_tail++) += seventh_left_base32hex_to_num[(uint8_t)fc];

		if (rdata_tail <= rdata_stop) {
			*rdata_tail = seventh_right_base32hex_to_num[(uint8_t)fc];
		} else {
			WARN(ZS_RDATA_OVERFLOW);
			fhold; fgoto err_line;
		}
	}
	action _eighth_base32hex_char {
		*(rdata_tail++) += eighth_base32hex_to_num[(uint8_t)fc];
	}

	action _base32hex_char_error {
		WARN(ZS_BAD_BASE32HEX_CHAR);
		fhold; fgoto err_line;
	}

	base32hex_char = [0-9a-vA-V];
	base32hex_padd = '=';
	base32hex_octet =
	    ( base32hex_char                  $_first_base32hex_char   . # A
	      base32hex_char                  $_second_base32hex_char  . # AB
	      ( ( base32hex_char              $_third_base32hex_char   . # ABC
	          base32hex_char              $_fourth_base32hex_char  . # ABCD
	          ( ( base32hex_char          $_fifth_base32hex_char   . # ABCDE
	              ( ( base32hex_char      $_sixth_base32hex_char   . # ABCDEF
	                  base32hex_char      $_seventh_base32hex_char . # ABCDEFG
	                  ( base32hex_char    $_eighth_base32hex_char    # ABCDEFGH
	                  | base32hex_padd{1}                            # ABCDEFG=
	                  )
	                )
	              | base32hex_padd{3}                                # ABCDE===
	              )
	            )
	          | base32hex_padd{4}                                    # ABCD====
	          )
	        )
	      | base32hex_padd{6}                                        # AB======
	      )
	    );

	# Continuous base32hex (with padding!) array with forward length processing.
	hash = base32hex_octet+ >_item_length_init %_item_length_exit
	       $!_base32hex_char_error;
	# END

	# BEGIN - Simple number write functions.
	action _write8_0 {
		*(rdata_tail++) = 0;
	}
	action _write8_1 {
		*(rdata_tail++) = 1;
	}
	action _write8_2 {
		*(rdata_tail++) = 2;
	}
	action _write8_3 {
		*(rdata_tail++) = 3;
	}
	action _write8_5 {
		*(rdata_tail++) = 5;
	}
	action _write8_6 {
		*(rdata_tail++) = 6;
	}
	action _write8_7 {
		*(rdata_tail++) = 7;
	}
	action _write8_8 {
		*(rdata_tail++) = 8;
	}
	action _write8_10 {
		*(rdata_tail++) = 10;
	}
	action _write8_12 {
		*(rdata_tail++) = 12;
	}
	action _write8_13 {
		*(rdata_tail++) = 13;
	}
	action _write8_14 {
		*(rdata_tail++) = 14;
	}
	action _write8_15 {
		*(rdata_tail++) = 15;
	}
	action _write8_16 {
		*(rdata_tail++) = 16;
	}
	action _write8_252 {
		*(rdata_tail++) = 252;
	}
	action _write8_253 {
		*(rdata_tail++) = 253;
	}
	action _write8_254 {
		*(rdata_tail++) = 254;
	}

	action _write16_1 {
		*((uint16_t *)rdata_tail) = htons(1);
		rdata_tail += 2;
	}
	action _write16_2 {
		*((uint16_t *)rdata_tail) = htons(2);
		rdata_tail += 2;
	}
	action _write16_3 {
		*((uint16_t *)rdata_tail) = htons(3);
		rdata_tail += 2;
	}
	action _write16_4 {
		*((uint16_t *)rdata_tail) = htons(4);
		rdata_tail += 2;
	}
	action _write16_5 {
		*((uint16_t *)rdata_tail) = htons(5);
		rdata_tail += 2;
	}
	action _write16_6 {
		*((uint16_t *)rdata_tail) = htons(6);
		rdata_tail += 2;
	}
	action _write16_7 {
		*((uint16_t *)rdata_tail) = htons(7);
		rdata_tail += 2;
	}
	action _write16_8 {
		*((uint16_t *)rdata_tail) = htons(8);
		rdata_tail += 2;
	}
	action _write16_253 {
		*((uint16_t *)rdata_tail) = htons(253);
		rdata_tail += 2;
	}
	action _write16_254 {
		*((uint16_t *)rdata_tail) = htons(254);
		rdata_tail += 2;
	}
	# END

	# BEGIN - Gateway
	action _gateway_error {
		WARN(ZS_BAD_GATEWAY);
		fhold; fgoto err_line;
	}
	action _gateway_key_error {
		WARN(ZS_BAD_GATEWAY_KEY);
		fhold; fgoto err_line;
	}

	gateway = (( ('0' $_write8_0 . sep . num8 . sep . '.')
	           | ('1' $_write8_1 . sep . num8 . sep . ipv4_addr_write)
	           | ('2' $_write8_2 . sep . num8 . sep . ipv6_addr_write)
	           | ('3' $_write8_3 . sep . num8 . sep . r_dname)
	           ) $!_gateway_error .
	           # If algorithm is 0 then key isn't present and vice versa.
	           ( ((sep . base64) when { s->number64 != 0 })
	           | ((sep?)         when { s->number64 == 0 }) # remove blank space
	           ) $!_gateway_key_error
	          );
	# END

	# BEGIN - Type processing
	action _type_error {
		WARN(ZS_UNSUPPORTED_TYPE);
		fhold; fgoto err_line;
	}

	type_num =
	    ( "A"i          %{ type_num(KNOT_RRTYPE_A, &rdata_tail); }
	    | "NS"i         %{ type_num(KNOT_RRTYPE_NS, &rdata_tail); }
	    | "CNAME"i      %{ type_num(KNOT_RRTYPE_CNAME, &rdata_tail); }
	    | "SOA"i        %{ type_num(KNOT_RRTYPE_SOA, &rdata_tail); }
	    | "PTR"i        %{ type_num(KNOT_RRTYPE_PTR, &rdata_tail); }
	    | "HINFO"i      %{ type_num(KNOT_RRTYPE_HINFO, &rdata_tail); }
	    | "MINFO"i      %{ type_num(KNOT_RRTYPE_MINFO, &rdata_tail); }
	    | "MX"i         %{ type_num(KNOT_RRTYPE_MX, &rdata_tail); }
	    | "TXT"i        %{ type_num(KNOT_RRTYPE_TXT, &rdata_tail); }
	    | "RP"i         %{ type_num(KNOT_RRTYPE_RP, &rdata_tail); }
	    | "AFSDB"i      %{ type_num(KNOT_RRTYPE_AFSDB, &rdata_tail); }
	    | "RT"i         %{ type_num(KNOT_RRTYPE_RT, &rdata_tail); }
	    | "KEY"i        %{ type_num(KNOT_RRTYPE_KEY, &rdata_tail); }
	    | "AAAA"i       %{ type_num(KNOT_RRTYPE_AAAA, &rdata_tail); }
	    | "LOC"i        %{ type_num(KNOT_RRTYPE_LOC, &rdata_tail); }
	    | "SRV"i        %{ type_num(KNOT_RRTYPE_SRV, &rdata_tail); }
	    | "NAPTR"i      %{ type_num(KNOT_RRTYPE_NAPTR, &rdata_tail); }
	    | "KX"i         %{ type_num(KNOT_RRTYPE_KX, &rdata_tail); }
	    | "CERT"i       %{ type_num(KNOT_RRTYPE_CERT, &rdata_tail); }
	    | "DNAME"i      %{ type_num(KNOT_RRTYPE_DNAME, &rdata_tail); }
	    | "APL"i        %{ type_num(KNOT_RRTYPE_APL, &rdata_tail); }
	    | "DS"i         %{ type_num(KNOT_RRTYPE_DS, &rdata_tail); }
	    | "SSHFP"i      %{ type_num(KNOT_RRTYPE_SSHFP, &rdata_tail); }
	    | "IPSECKEY"i   %{ type_num(KNOT_RRTYPE_IPSECKEY, &rdata_tail); }
	    | "RRSIG"i      %{ type_num(KNOT_RRTYPE_RRSIG, &rdata_tail); }
	    | "NSEC"i       %{ type_num(KNOT_RRTYPE_NSEC, &rdata_tail); }
	    | "DNSKEY"i     %{ type_num(KNOT_RRTYPE_DNSKEY, &rdata_tail); }
	    | "DHCID"i      %{ type_num(KNOT_RRTYPE_DHCID, &rdata_tail); }
	    | "NSEC3"i      %{ type_num(KNOT_RRTYPE_NSEC3, &rdata_tail); }
	    | "NSEC3PARAM"i %{ type_num(KNOT_RRTYPE_NSEC3PARAM, &rdata_tail); }
	    | "TLSA"i       %{ type_num(KNOT_RRTYPE_TLSA, &rdata_tail); }
	    | "CDS"i        %{ type_num(KNOT_RRTYPE_CDS, &rdata_tail); }
	    | "CDNSKEY"i    %{ type_num(KNOT_RRTYPE_CDNSKEY, &rdata_tail); }
	    | "SPF"i        %{ type_num(KNOT_RRTYPE_SPF, &rdata_tail); }
	    | "NID"i        %{ type_num(KNOT_RRTYPE_NID, &rdata_tail); }
	    | "L32"i        %{ type_num(KNOT_RRTYPE_L32, &rdata_tail); }
	    | "L64"i        %{ type_num(KNOT_RRTYPE_L64, &rdata_tail); }
	    | "LP"i         %{ type_num(KNOT_RRTYPE_LP, &rdata_tail); }
	    | "EUI48"i      %{ type_num(KNOT_RRTYPE_EUI48, &rdata_tail); }
	    | "EUI64"i      %{ type_num(KNOT_RRTYPE_EUI64, &rdata_tail); }
	    | "URI"i        %{ type_num(KNOT_RRTYPE_URI, &rdata_tail); }
	    | "CAA"i        %{ type_num(KNOT_RRTYPE_CAA, &rdata_tail); }
	    | "TYPE"i      . num16 # TYPE0-TYPE65535.
	    ) $!_type_error;
	# END

	# BEGIN - Bitmap processing
	action _type_bitmap_exit {
		if (s->number64 <= UINT16_MAX) {
			window_add_bit(s->number64, s);
		} else {
			WARN(ZS_NUMBER16_OVERFLOW);
			fhold; fgoto err_line;
		}
	}

	# TYPE0-TYPE65535.
	type_bitmap = number %_type_bitmap_exit;

	type_bit =
	    ( "A"i          %{ window_add_bit(KNOT_RRTYPE_A, s); }
	    | "NS"i         %{ window_add_bit(KNOT_RRTYPE_NS, s); }
	    | "CNAME"i      %{ window_add_bit(KNOT_RRTYPE_CNAME, s); }
	    | "SOA"i        %{ window_add_bit(KNOT_RRTYPE_SOA, s); }
	    | "PTR"i        %{ window_add_bit(KNOT_RRTYPE_PTR, s); }
	    | "HINFO"i      %{ window_add_bit(KNOT_RRTYPE_HINFO, s); }
	    | "MINFO"i      %{ window_add_bit(KNOT_RRTYPE_MINFO, s); }
	    | "MX"i         %{ window_add_bit(KNOT_RRTYPE_MX, s); }
	    | "TXT"i        %{ window_add_bit(KNOT_RRTYPE_TXT, s); }
	    | "RP"i         %{ window_add_bit(KNOT_RRTYPE_RP, s); }
	    | "AFSDB"i      %{ window_add_bit(KNOT_RRTYPE_AFSDB, s); }
	    | "RT"i         %{ window_add_bit(KNOT_RRTYPE_RT, s); }
	    | "KEY"i        %{ window_add_bit(KNOT_RRTYPE_KEY, s); }
	    | "AAAA"i       %{ window_add_bit(KNOT_RRTYPE_AAAA, s); }
	    | "LOC"i        %{ window_add_bit(KNOT_RRTYPE_LOC, s); }
	    | "SRV"i        %{ window_add_bit(KNOT_RRTYPE_SRV, s); }
	    | "NAPTR"i      %{ window_add_bit(KNOT_RRTYPE_NAPTR, s); }
	    | "KX"i         %{ window_add_bit(KNOT_RRTYPE_KX, s); }
	    | "CERT"i       %{ window_add_bit(KNOT_RRTYPE_CERT, s); }
	    | "DNAME"i      %{ window_add_bit(KNOT_RRTYPE_DNAME, s); }
	    | "APL"i        %{ window_add_bit(KNOT_RRTYPE_APL, s); }
	    | "DS"i         %{ window_add_bit(KNOT_RRTYPE_DS, s); }
	    | "SSHFP"i      %{ window_add_bit(KNOT_RRTYPE_SSHFP, s); }
	    | "IPSECKEY"i   %{ window_add_bit(KNOT_RRTYPE_IPSECKEY, s); }
	    | "RRSIG"i      %{ window_add_bit(KNOT_RRTYPE_RRSIG, s); }
	    | "NSEC"i       %{ window_add_bit(KNOT_RRTYPE_NSEC, s); }
	    | "DNSKEY"i     %{ window_add_bit(KNOT_RRTYPE_DNSKEY, s); }
	    | "DHCID"i      %{ window_add_bit(KNOT_RRTYPE_DHCID, s); }
	    | "NSEC3"i      %{ window_add_bit(KNOT_RRTYPE_NSEC3, s); }
	    | "NSEC3PARAM"i %{ window_add_bit(KNOT_RRTYPE_NSEC3PARAM, s); }
	    | "TLSA"i       %{ window_add_bit(KNOT_RRTYPE_TLSA, s); }
	    | "CDS"i        %{ window_add_bit(KNOT_RRTYPE_CDS, s); }
	    | "CDNSKEY"i    %{ window_add_bit(KNOT_RRTYPE_CDNSKEY, s); }
	    | "SPF"i        %{ window_add_bit(KNOT_RRTYPE_SPF, s); }
	    | "NID"i        %{ window_add_bit(KNOT_RRTYPE_NID, s); }
	    | "L32"i        %{ window_add_bit(KNOT_RRTYPE_L32, s); }
	    | "L64"i        %{ window_add_bit(KNOT_RRTYPE_L64, s); }
	    | "LP"i         %{ window_add_bit(KNOT_RRTYPE_LP, s); }
	    | "EUI48"i      %{ window_add_bit(KNOT_RRTYPE_EUI48, s); }
	    | "EUI64"i      %{ window_add_bit(KNOT_RRTYPE_EUI64, s); }
	    | "URI"i        %{ window_add_bit(KNOT_RRTYPE_URI, s); }
	    | "CAA"i        %{ window_add_bit(KNOT_RRTYPE_CAA, s); }
	    | "TYPE"i      . type_bitmap # TYPE0-TYPE65535.
	    );

	action _bitmap_init {
		memset(s->windows, 0, sizeof(s->windows));
		s->last_window = -1;
	}
	action _bitmap_exit {
		for (window = 0; window <= s->last_window; window++) {
			if ((s->windows[window]).length > 0) {
				if (rdata_tail + 2 + (s->windows[window]).length <= rdata_stop)
				{
					// Window number.
					*rdata_tail = (uint8_t)window;
					rdata_tail += 1;
					// Bitmap length.
					*rdata_tail = (s->windows[window]).length;
					rdata_tail += 1;
					// Copying bitmap.
					memcpy(rdata_tail,
					       (s->windows[window]).bitmap,
					       (s->windows[window]).length);
					rdata_tail += (s->windows[window]).length;
				} else {
					WARN(ZS_RDATA_OVERFLOW);
					fhold; fgoto err_line;
				}
			}
		}
	}
	action _bitmap_error {
		WARN(ZS_BAD_BITMAP);
		fhold; fgoto err_line;
	}

	# Blank bitmap is allowed too.
	bitmap_ := ((sep . type_bit)* . sep?) >_bitmap_init
	           %_bitmap_exit %_ret $!_bitmap_error . end_wchar;
	bitmap = all_wchar ${ fhold; fcall bitmap_; };
	# END

	# BEGIN - Location processing
	action _d1_exit {
		if (s->number64 <= 90) {
			s->loc.d1 = (uint32_t)(s->number64);
		} else {
			WARN(ZS_BAD_NUMBER);
			fhold; fgoto err_line;
		}
	}
	action _d2_exit {
		if (s->number64 <= 180) {
			s->loc.d2 = (uint32_t)(s->number64);
		} else {
			WARN(ZS_BAD_NUMBER);
			fhold; fgoto err_line;
		}
	}
	action _m1_exit {
		if (s->number64 <= 59) {
			s->loc.m1 = (uint32_t)(s->number64);
		} else {
			WARN(ZS_BAD_NUMBER);
			fhold; fgoto err_line;
		}
	}
	action _m2_exit {
		if (s->number64 <= 59) {
			s->loc.m2 = (uint32_t)(s->number64);
		} else {
			WARN(ZS_BAD_NUMBER);
			fhold; fgoto err_line;
		}
	}
	action _s1_exit {
		if (s->number64 <= 59999) {
			s->loc.s1 = (uint32_t)(s->number64);
		} else {
			WARN(ZS_BAD_NUMBER);
			fhold; fgoto err_line;
		}
	}
	action _s2_exit {
		if (s->number64 <= 59999) {
			s->loc.s2 = (uint32_t)(s->number64);
		} else {
			WARN(ZS_BAD_NUMBER);
			fhold; fgoto err_line;
		}
	}
	action _alt_exit {
		if ((s->loc.alt_sign ==  1 && s->number64 <= 4284967295) ||
		    (s->loc.alt_sign == -1 && s->number64 <=   10000000))
		{
			s->loc.alt = (uint32_t)(s->number64);
		} else {
			WARN(ZS_BAD_NUMBER);
			fhold; fgoto err_line;
		}
	}
	action _siz_exit {
		if (s->number64 <= 9000000000ULL) {
			s->loc.siz = s->number64;
		} else {
			WARN(ZS_BAD_NUMBER);
			fhold; fgoto err_line;
		}
	}
	action _hp_exit {
		if (s->number64 <= 9000000000ULL) {
			s->loc.hp = s->number64;
		} else {
			WARN(ZS_BAD_NUMBER);
			fhold; fgoto err_line;
		}
	}
	action _vp_exit {
		if (s->number64 <= 9000000000ULL) {
			s->loc.vp = s->number64;
		} else {
			WARN(ZS_BAD_NUMBER);
			fhold; fgoto err_line;
		}
	}
	action _lat_sign {
		s->loc.lat_sign = -1;
	}
	action _long_sign {
		s->loc.long_sign = -1;
	}
	action _alt_sign {
		s->loc.alt_sign = -1;
	}

	d1  = number %_d1_exit;
	d2  = number %_d2_exit;
	m1  = number %_m1_exit;
	m2  = number %_m2_exit;
	s1  = float3 %_s1_exit;
	s2  = float3 %_s2_exit;
	siz = float2 %_siz_exit;
	hp  = float2 %_hp_exit;
	vp  = float2 %_vp_exit;
	alt = ('-' %_alt_sign)? . float2 %_alt_exit;
	lat_sign  = 'N' | 'S' %_lat_sign;
	long_sign = 'E' | 'W' %_long_sign;

	action _loc_init {
		memset(&(s->loc), 0, sizeof(s->loc));
		// Defaults.
		s->loc.siz = 100;
		s->loc.vp  = 1000;
		s->loc.hp  = 1000000;
		s->loc.lat_sign  = 1;
		s->loc.long_sign = 1;
		s->loc.alt_sign  = 1;
	}
	action _loc_exit {
		// Write version.
		*(rdata_tail) = 0;
		rdata_tail += 1;
		// Write size.
		*(rdata_tail) = loc64to8(s->loc.siz);
		rdata_tail += 1;
		// Write horizontal precision.
		*(rdata_tail) = loc64to8(s->loc.hp);
		rdata_tail += 1;
		// Write vertical precision.
		*(rdata_tail) = loc64to8(s->loc.vp);
		rdata_tail += 1;
		// Write latitude.
		*((uint32_t *)rdata_tail) = htonl(LOC_LAT_ZERO + s->loc.lat_sign *
			(3600000 * s->loc.d1 + 60000 * s->loc.m1 + s->loc.s1));
		rdata_tail += 4;
		// Write longitude.
		*((uint32_t *)rdata_tail) = htonl(LOC_LONG_ZERO + s->loc.long_sign *
			(3600000 * s->loc.d2 + 60000 * s->loc.m2 + s->loc.s2));
		rdata_tail += 4;
		// Write altitude.
		*((uint32_t *)rdata_tail) = htonl(LOC_ALT_ZERO + s->loc.alt_sign *
			(s->loc.alt));
		rdata_tail += 4;
	}
	action _loc_error {
		WARN(ZS_BAD_LOC_DATA);
		fhold; fgoto err_line;
	}

	loc = (d1 . sep . (m1 . sep . (s1 . sep)?)? . lat_sign  . sep .
	       d2 . sep . (m2 . sep . (s2 . sep)?)? . long_sign . sep .
	       alt 'm'? . (sep . siz 'm'? . (sep . hp 'm'? . (sep . vp 'm'?)?)?)? .
	       sep?
	      ) >_loc_init %_loc_exit $!_loc_error;
	# END

	# BEGIN - Hexadecimal rdata processing
	action _hex_r_data_error {
		WARN(ZS_BAD_HEX_RDATA);
		fhold; fgoto err_line;
	}

	nonempty_hex_r_data :=
		(sep . length_number . sep . type_data)
		$!_hex_r_data_error %_ret . end_wchar;

	hex_r_data :=
		(sep .
		 ( ('0'                             %_ret . all_wchar)
		 | (length_number . sep . type_data %_ret . end_wchar)
		 )
		) $!_hex_r_data_error;
	# END

	# BEGIN - EUI processing
	action _eui_init {
		s->item_length = 0;
	}
	action _eui_count {
		s->item_length++;
	}
	action _eui48_exit {
		if (s->item_length != 6) {
			WARN(ZS_BAD_EUI_LENGTH);
			fhold; fgoto err_line;
		}
	}
	action _eui64_exit {
		if (s->item_length != 8) {
			WARN(ZS_BAD_EUI_LENGTH);
			fhold; fgoto err_line;
		}
	}
	action _eui_sep_error {
		WARN(ZS_BAD_CHAR_DASH);
		fhold; fgoto err_line;
	}

	eui48 = (hex_char %_eui_count .
	         ('-' >!_eui_sep_error . hex_char %_eui_count)+
		) $!_hex_char_error >_eui_init %_eui48_exit;

	eui64 = (hex_char %_eui_count .
	         ('-' >!_eui_sep_error . hex_char %_eui_count)+
		) $!_hex_char_error >_eui_init %_eui64_exit;
	# END

	# BEGIN - ILNP processing
	action _l64_init {
		s->item_length = 0;
	}
	action _l64_count {
		s->item_length++;
	}
	action _l64_exit {
		if (s->item_length != 4) {
			WARN(ZS_BAD_L64_LENGTH);
			fhold; fgoto err_line;
		}
	}
	action _l64_sep_error {
		WARN(ZS_BAD_CHAR_COLON);
		fhold; fgoto err_line;
	}

	l64_label = (hex_char . hex_char) $!_hex_char_error %_l64_count;
	l64 = (l64_label . (':' >!_l64_sep_error . l64_label)+
	      ) $!_hex_char_error >_l64_init %_l64_exit;

	l32 = ipv4_addr %_ipv4_addr_write;
	# END

	# BEGIN - Mnemomic names processing
	action _dns_alg_error {
		WARN(ZS_BAD_ALGORITHM);
		fhold; fgoto err_line;
	}
	action _cert_type_error {
		WARN(ZS_BAD_CERT_TYPE);
		fhold; fgoto err_line;
	}

	dns_alg_ :=
		( number                %_num8_write
		| "RSAMD5"i             %_write8_1
		| "DH"i                 %_write8_2
		| "DSA"i                %_write8_3
		| "RSASHA1"i            %_write8_5
		| "DSA-NSEC3-SHA1"i     %_write8_6
		| "RSASHA1-NSEC3-SHA1"i %_write8_7
		| "RSASHA256"i          %_write8_8
		| "RSASHA512"i          %_write8_10
		| "ECC-GOST"i           %_write8_12
		| "ECDSAP256SHA256"i    %_write8_13
		| "ECDSAP384SHA384"i    %_write8_14
		| "ED25519"i            %_write8_15
		| "ED448"i              %_write8_16
		| "INDIRECT"i           %_write8_252
		| "PRIVATEDNS"i         %_write8_253
		| "PRIVATEOID"i         %_write8_254
		) $!_dns_alg_error %_ret . all_wchar;
	dns_alg = alnum ${ fhold; fcall dns_alg_; };

	cert_type_ :=
		( number     %_num16_write
		| "PKIX"i    %_write16_1
		| "SPKI"i    %_write16_2
		| "PGP"i     %_write16_3
		| "IPKIX"i   %_write16_4
		| "ISPKI"i   %_write16_5
		| "IPGP"i    %_write16_6
		| "ACPKIX"i  %_write16_7
		| "IACPKIX"i %_write16_8
		| "URI"i     %_write16_253
		| "OID"i     %_write16_254
		) $!_cert_type_error %_ret . all_wchar;
	cert_type = alnum ${ fhold; fcall cert_type_; };
	# END

	# BEGIN - Rdata processing
	action _r_data_init {
		rdata_tail = s->r_data;
	}
	action _r_data_error {
		WARN(ZS_BAD_RDATA);
		fhold; fgoto err_line;
	}

	r_data_a :=
		(ipv4_addr_write)
		$!_r_data_error %_ret . all_wchar;

	r_data_ns :=
		(r_dname)
		$!_r_data_error %_ret . all_wchar;

	r_data_soa :=
		(r_dname . sep . r_dname . sep . num32 . sep . time32 .
		 sep . time32 . sep . time32 . sep . time32)
		$!_r_data_error %_ret . all_wchar;

	r_data_hinfo :=
		(text_string . sep . text_string)
		$!_r_data_error %_ret . all_wchar;

	r_data_minfo :=
		(r_dname . sep . r_dname)
		$!_r_data_error %_ret . all_wchar;

	r_data_mx :=
		(num16 . sep . r_dname)
		$!_r_data_error %_ret . all_wchar;

	r_data_txt :=
		(text_array)
		$!_r_data_error %_ret . end_wchar;

	r_data_aaaa :=
		(ipv6_addr_write)
		$!_r_data_error %_ret . all_wchar;

	r_data_loc :=
		(loc)
		$!_r_data_error %_ret . end_wchar;

	r_data_srv :=
		(num16 . sep . num16 . sep . num16 . sep . r_dname)
		$!_r_data_error %_ret . all_wchar;

	r_data_naptr :=
		(num16 . sep . num16 . sep . text_string . sep . text_string .
		 sep . text_string . sep . r_dname)
		$!_r_data_error %_ret . all_wchar;

	r_data_cert :=
		(cert_type . sep . num16 . sep . dns_alg . sep . base64)
		$!_r_data_error %_ret . end_wchar;

	r_data_apl :=
		(apl_array)
		$!_r_data_error %_ret . end_wchar;

	r_data_ds :=
		(num16 . sep . dns_alg . sep . num8 . sep . hex_array)
		$!_r_data_error %_ret . end_wchar;

	r_data_sshfp :=
		(num8 . sep . num8 . sep . hex_array)
		$!_r_data_error %_ret . end_wchar;

	r_data_ipseckey :=
		(num8 . sep . gateway)
		$!_r_data_error %_ret . end_wchar;

	r_data_rrsig :=
		(type_num . sep . dns_alg . sep . num8 . sep . num32 . sep .
		 timestamp . sep . timestamp . sep . num16 . sep . r_dname .
		 sep . base64)
		$!_r_data_error %_ret . end_wchar;

	r_data_nsec :=
		(r_dname . bitmap)
		$!_r_data_error %_ret . all_wchar;

	r_data_dnskey :=
		(num16 . sep . num8 . sep . dns_alg . sep . base64)
		$!_r_data_error %_ret . end_wchar;

	r_data_dhcid :=
		(base64)
		$!_r_data_error %_ret . end_wchar;

	r_data_nsec3 :=
		(num8 . sep . num8 . sep . num16 . sep . salt . sep .
		 hash . bitmap)
		$!_r_data_error %_ret . all_wchar;

	r_data_nsec3param :=
		(num8 . sep . num8 . sep . num16 . sep . salt)
		$!_r_data_error %_ret . all_wchar;

	r_data_tlsa :=
		(num8 . sep . num8 . sep . num8 . sep . hex_array)
		$!_r_data_error %_ret . end_wchar;

	r_data_l32 :=
		(num16 . sep . l32)
		$!_r_data_error %_ret . all_wchar;

	r_data_l64 :=
		(num16 . sep . l64)
		$!_r_data_error %_ret . all_wchar;

	r_data_eui48 :=
		(eui48)
		$!_r_data_error %_ret . all_wchar;

	r_data_eui64 :=
		(eui64)
		$!_r_data_error %_ret . all_wchar;

	r_data_uri :=
		(num16 . sep . num16 . sep . text)
		$!_r_data_error %_ret . all_wchar;

	r_data_caa :=
		(num8 . sep . text_string . sep . text)
		$!_r_data_error %_ret . all_wchar;

	action _text_r_data {
		fhold;
		switch (s->r_type) {
		case KNOT_RRTYPE_A:
			fcall r_data_a;
		case KNOT_RRTYPE_NS:
		case KNOT_RRTYPE_CNAME:
		case KNOT_RRTYPE_PTR:
		case KNOT_RRTYPE_DNAME:
			fcall r_data_ns;
		case KNOT_RRTYPE_SOA:
			fcall r_data_soa;
		case KNOT_RRTYPE_HINFO:
			fcall r_data_hinfo;
		case KNOT_RRTYPE_MINFO:
		case KNOT_RRTYPE_RP:
			fcall r_data_minfo;
		case KNOT_RRTYPE_MX:
		case KNOT_RRTYPE_AFSDB:
		case KNOT_RRTYPE_RT:
		case KNOT_RRTYPE_KX:
		case KNOT_RRTYPE_LP:
			fcall r_data_mx;
		case KNOT_RRTYPE_TXT:
		case KNOT_RRTYPE_SPF:
			fcall r_data_txt;
		case KNOT_RRTYPE_AAAA:
			fcall r_data_aaaa;
		case KNOT_RRTYPE_LOC:
			fcall r_data_loc;
		case KNOT_RRTYPE_SRV:
			fcall r_data_srv;
		case KNOT_RRTYPE_NAPTR:
			fcall r_data_naptr;
		case KNOT_RRTYPE_CERT:
			fcall r_data_cert;
		case KNOT_RRTYPE_APL:
			fcall r_data_apl;
		case KNOT_RRTYPE_DS:
		case KNOT_RRTYPE_CDS:
			fcall r_data_ds;
		case KNOT_RRTYPE_SSHFP:
			fcall r_data_sshfp;
		case KNOT_RRTYPE_IPSECKEY:
			fcall r_data_ipseckey;
		case KNOT_RRTYPE_RRSIG:
			fcall r_data_rrsig;
		case KNOT_RRTYPE_NSEC:
			fcall r_data_nsec;
		case KNOT_RRTYPE_KEY:
		case KNOT_RRTYPE_DNSKEY:
		case KNOT_RRTYPE_CDNSKEY:
			fcall r_data_dnskey;
		case KNOT_RRTYPE_DHCID:
			fcall r_data_dhcid;
		case KNOT_RRTYPE_NSEC3:
			fcall r_data_nsec3;
		case KNOT_RRTYPE_NSEC3PARAM:
			fcall r_data_nsec3param;
		case KNOT_RRTYPE_TLSA:
			fcall r_data_tlsa;
		case KNOT_RRTYPE_NID:
		case KNOT_RRTYPE_L64:
			fcall r_data_l64;
		case KNOT_RRTYPE_L32:
			fcall r_data_l32;
		case KNOT_RRTYPE_EUI48:
			fcall r_data_eui48;
		case KNOT_RRTYPE_EUI64:
			fcall r_data_eui64;
		case KNOT_RRTYPE_URI:
			fcall r_data_uri;
		case KNOT_RRTYPE_CAA:
			fcall r_data_caa;
		default:
			WARN(ZS_CANNOT_TEXT_DATA);
			fgoto err_line;
		}
	}
	action _hex_r_data {
		switch (s->r_type) {
		// Next types must not have empty rdata.
		case KNOT_RRTYPE_A:
		case KNOT_RRTYPE_NS:
		case KNOT_RRTYPE_CNAME:
		case KNOT_RRTYPE_PTR:
		case KNOT_RRTYPE_DNAME:
		case KNOT_RRTYPE_SOA:
		case KNOT_RRTYPE_HINFO:
		case KNOT_RRTYPE_MINFO:
		case KNOT_RRTYPE_MX:
		case KNOT_RRTYPE_AFSDB:
		case KNOT_RRTYPE_RT:
		case KNOT_RRTYPE_KX:
		case KNOT_RRTYPE_TXT:
		case KNOT_RRTYPE_SPF:
		case KNOT_RRTYPE_RP:
		case KNOT_RRTYPE_AAAA:
		case KNOT_RRTYPE_LOC:
		case KNOT_RRTYPE_SRV:
		case KNOT_RRTYPE_NAPTR:
		case KNOT_RRTYPE_CERT:
		case KNOT_RRTYPE_DS:
		case KNOT_RRTYPE_SSHFP:
		case KNOT_RRTYPE_IPSECKEY:
		case KNOT_RRTYPE_RRSIG:
		case KNOT_RRTYPE_NSEC:
		case KNOT_RRTYPE_KEY:
		case KNOT_RRTYPE_DNSKEY:
		case KNOT_RRTYPE_DHCID:
		case KNOT_RRTYPE_NSEC3:
		case KNOT_RRTYPE_NSEC3PARAM:
		case KNOT_RRTYPE_TLSA:
		case KNOT_RRTYPE_CDS:
		case KNOT_RRTYPE_CDNSKEY:
		case KNOT_RRTYPE_NID:
		case KNOT_RRTYPE_L32:
		case KNOT_RRTYPE_L64:
		case KNOT_RRTYPE_LP:
		case KNOT_RRTYPE_EUI48:
		case KNOT_RRTYPE_EUI64:
		case KNOT_RRTYPE_URI:
		case KNOT_RRTYPE_CAA:
			fcall nonempty_hex_r_data;
		// Next types can have empty rdata.
		case KNOT_RRTYPE_APL:
		default:
			fcall hex_r_data;
		}
	}

	# rdata can be in text or hex format with leading "\#" string.
	r_data =
		( sep  . ^('\\' | all_wchar)     $_text_r_data
		| sep  . '\\' . ^'#' ${ fhold; } $_text_r_data
		| sep  . '\\' .  '#'             $_hex_r_data   # Hex format.
		| sep? . end_wchar               $_text_r_data  # Empty rdata.
		) >_r_data_init $!_r_data_error;
	# END

	# BEGIN - Record type processing
	action _r_type_error {
		WARN(ZS_UNSUPPORTED_TYPE);
		fhold; fgoto err_line;
	}

	r_type =
		( "A"i          %{ s->r_type = KNOT_RRTYPE_A; }
		| "NS"i         %{ s->r_type = KNOT_RRTYPE_NS; }
		| "CNAME"i      %{ s->r_type = KNOT_RRTYPE_CNAME; }
		| "SOA"i        %{ s->r_type = KNOT_RRTYPE_SOA; }
		| "PTR"i        %{ s->r_type = KNOT_RRTYPE_PTR; }
		| "HINFO"i      %{ s->r_type = KNOT_RRTYPE_HINFO; }
		| "MINFO"i      %{ s->r_type = KNOT_RRTYPE_MINFO; }
		| "MX"i         %{ s->r_type = KNOT_RRTYPE_MX; }
		| "TXT"i        %{ s->r_type = KNOT_RRTYPE_TXT; }
		| "RP"i         %{ s->r_type = KNOT_RRTYPE_RP; }
		| "AFSDB"i      %{ s->r_type = KNOT_RRTYPE_AFSDB; }
		| "RT"i         %{ s->r_type = KNOT_RRTYPE_RT; }
		| "KEY"i        %{ s->r_type = KNOT_RRTYPE_KEY; }
		| "AAAA"i       %{ s->r_type = KNOT_RRTYPE_AAAA; }
		| "LOC"i        %{ s->r_type = KNOT_RRTYPE_LOC; }
		| "SRV"i        %{ s->r_type = KNOT_RRTYPE_SRV; }
		| "NAPTR"i      %{ s->r_type = KNOT_RRTYPE_NAPTR; }
		| "KX"i         %{ s->r_type = KNOT_RRTYPE_KX; }
		| "CERT"i       %{ s->r_type = KNOT_RRTYPE_CERT; }
		| "DNAME"i      %{ s->r_type = KNOT_RRTYPE_DNAME; }
		| "APL"i        %{ s->r_type = KNOT_RRTYPE_APL; }
		| "DS"i         %{ s->r_type = KNOT_RRTYPE_DS; }
		| "SSHFP"i      %{ s->r_type = KNOT_RRTYPE_SSHFP; }
		| "IPSECKEY"i   %{ s->r_type = KNOT_RRTYPE_IPSECKEY; }
		| "RRSIG"i      %{ s->r_type = KNOT_RRTYPE_RRSIG; }
		| "NSEC"i       %{ s->r_type = KNOT_RRTYPE_NSEC; }
		| "DNSKEY"i     %{ s->r_type = KNOT_RRTYPE_DNSKEY; }
		| "DHCID"i      %{ s->r_type = KNOT_RRTYPE_DHCID; }
		| "NSEC3"i      %{ s->r_type = KNOT_RRTYPE_NSEC3; }
		| "NSEC3PARAM"i %{ s->r_type = KNOT_RRTYPE_NSEC3PARAM; }
		| "TLSA"i       %{ s->r_type = KNOT_RRTYPE_TLSA; }
		| "CDS"i        %{ s->r_type = KNOT_RRTYPE_CDS; }
		| "CDNSKEY"i    %{ s->r_type = KNOT_RRTYPE_CDNSKEY; }
		| "SPF"i        %{ s->r_type = KNOT_RRTYPE_SPF; }
		| "NID"i        %{ s->r_type = KNOT_RRTYPE_NID; }
		| "L32"i        %{ s->r_type = KNOT_RRTYPE_L32; }
		| "L64"i        %{ s->r_type = KNOT_RRTYPE_L64; }
		| "LP"i         %{ s->r_type = KNOT_RRTYPE_LP; }
		| "EUI48"i      %{ s->r_type = KNOT_RRTYPE_EUI48; }
		| "EUI64"i      %{ s->r_type = KNOT_RRTYPE_EUI64; }
		| "URI"i        %{ s->r_type = KNOT_RRTYPE_URI; }
		| "CAA"i        %{ s->r_type = KNOT_RRTYPE_CAA; }
		| "TYPE"i      . type_number
		) $!_r_type_error;
	# END

	# BEGIN - The highest level processing
	action _record_exit {
		if (rdata_tail - s->r_data > UINT16_MAX) {
			WARN(ZS_RDATA_OVERFLOW);
			fhold; fgoto err_line;
		}
		s->r_data_length = rdata_tail - s->r_data;

		s->state = ZS_STATE_DATA;

		// Execute the record callback.
		if (s->process.automatic) {
			if (s->process.record != NULL) {
				s->process.record(s);

				// Stop the scanner if required.
				if (s->state == ZS_STATE_STOP) {
					fbreak;
				}
			}
		} else {
			// Return if external processing.
			fhold; fbreak;
		}
	}

	# Resource record.
	record =
		r_owner . sep .
		( (r_class . sep . ((r_ttl   . sep) | (zlen %_default_r_ttl_exit  )))
		| (r_ttl   . sep . ((r_class . sep) | (zlen %_default_r_class_exit)))
		| zlen %_default_r_class_exit %_default_r_ttl_exit
		) $!_r_type_error .
		r_type . r_data .
		rest %_record_exit .
		newline;

	# Blank spaces with comments.
	blank = rest . newline;

	# Main processing loop.
	main := (record | directive | blank)*;
	# END
}%%
