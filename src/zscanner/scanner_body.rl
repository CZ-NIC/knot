/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
            SCANNER_ERROR(ZSCANNER_ELEFT_PARENTHESIS);
            fhold; fgoto err_line;
        }
        s->multiline = true;
    }
    action _check_multiline_end {
        if (s->multiline == false) {
            SCANNER_ERROR(ZSCANNER_ERIGHT_PARENTHESIS);
            fhold; fgoto err_line;
        }
        s->multiline = false;
    }

    action _rest_error {
        SCANNER_WARNING(ZSCANNER_EBAD_REST);
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

    rest = (sep? . comment?) $!_rest_error; # Useless text after correct record.

    # Artificial machines which are used for next state transition only!
    all_wchar = [ \t\n;()];
    end_wchar = [\n;] when { !s->multiline }; # For noncontinuous ending tokens.
    # END

    # BEGIN - Error line processing
    action _err_line_init {
        s->buffer_length = 0;
    }
    action _err_line {
        if (s->buffer_length < sizeof(s->buffer) - 1) {
            s->buffer[s->buffer_length++] = fc;
        }
    }
    action _err_line_exit {
        // Ending string in buffer.
        s->buffer[s->buffer_length++] = 0;

        // Error counter incrementation.
        s->error_counter++;

        // Initialization of fcall stack.
        top = 0;

        // Process error message.
        s->process_error(s);

        // Reset.
        s->error_code = KNOT_EOK;
        s->multiline = false;

        // In case of serious error, stop scanner.
        if (s->stop == true) {
            return -1;
        }
    }

    # Fill rest of the line to buffer and skip to main loop.
    err_line := (^newline $_err_line)* >_err_line_init
                %_err_line_exit . newline @{ fgoto main; };
    # END

    # BEGIN - Domain name labels processing
    action _label_init {
        s->item_length = 0;
        s->item_length_position = s->dname_tmp_length++;
    }
    action _label_char {
        if (s->item_length < MAX_LABEL_LENGTH) {
            (s->dname)[s->dname_tmp_length++] = fc;
            s->item_length++;
        }
        else {
            SCANNER_WARNING(ZSCANNER_ELABEL_OVERFLOW);
            fhold; fgoto err_line;
        }
    }
    action _label_upper_char {
        if (s->item_length < MAX_LABEL_LENGTH) {
            (s->dname)[s->dname_tmp_length++] = ascii_to_lower[(uint8_t)fc];
            s->item_length++;
        }
        else {
            SCANNER_WARNING(ZSCANNER_ELABEL_OVERFLOW);
            fhold; fgoto err_line;
        }
    }
    action _label_exit {
        if (s->dname_tmp_length < MAX_DNAME_LENGTH) {
            (s->dname)[s->item_length_position] = (uint8_t)(s->item_length);
        }
        else {
            SCANNER_WARNING(ZSCANNER_EDNAME_OVERFLOW);
            fhold; fgoto err_line;
        }
    }

    action _label_dec_init {
        if (s->item_length < MAX_LABEL_LENGTH) {
            (s->dname)[s->dname_tmp_length] = 0;
            s->item_length++;
        }
        else {
            SCANNER_WARNING(ZSCANNER_ELABEL_OVERFLOW);
            fhold; fgoto err_line;
        }
    }
    action _label_dec {
        (s->dname)[s->dname_tmp_length] *= 10;
        (s->dname)[s->dname_tmp_length] += digit_to_num[(uint8_t)fc];
    }
    action _label_dec_exit {
        (s->dname)[s->dname_tmp_length] =   // If the char is in upper case.
            ascii_to_lower[(s->dname)[s->dname_tmp_length]];
        s->dname_tmp_length++;
    }

    label_char =
        ( (digit | lower | [\-_/])  $_label_char         # One common char.
        | (upper)                   $_label_upper_char   # One upper-case char.
        | ('\\' . ^(digit | upper)) @_label_char         # One "\x" char.
        | ('\\' . upper)            @_label_upper_char   # One "\X" char.
        | ('\\'                     %_label_dec_init     # Initial "\" char.
           . digit {3}              $_label_dec %_label_dec_exit # "DDD" rest.
          )
        );

    label  = (label_char+ | ('*' $_label_char)) >_label_init %_label_exit;
    labels = (label   . '.')* . label;
    # END

    # BEGIN - Domain name processing.
    action _absolute_dname_exit {
        (s->dname)[s->dname_tmp_length++] = 0;
    }
    action _relative_dname_exit {
        memcpy(s->dname + s->dname_tmp_length,
               s->zone_origin,
               s->zone_origin_length);

        s->dname_tmp_length += s->zone_origin_length;

        if (s->dname_tmp_length >= MAX_DNAME_LENGTH) {
            SCANNER_WARNING(ZSCANNER_EDNAME_OVERFLOW);
            fhold; fgoto err_line;
        }
    }
    action _origin_dname_exit {
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
            SCANNER_WARNING(ZSCANNER_EBAD_DNAME_CHAR);
            fhold; fgoto err_line;
    }

    relative_dname = (labels       ) >_dname_init %_relative_dname_exit;
    absolute_dname = (labels? . '.') >_dname_init %_absolute_dname_exit;

    dname = ( relative_dname
            | absolute_dname
            | '@' %_origin_dname_exit
            ) $!_dname_error;
    # END

    # BEGIN - Common r_data item processing
    action _item_length_init {
        s->item_length_location = rdata_tail++;
    }
    action _item_length_exit {
        s->item_length = rdata_tail - s->item_length_location - 1;

        if (s->item_length <= MAX_ITEM_LENGTH) {
            *(s->item_length_location) = (uint8_t)(s->item_length);
        }
        else {
            SCANNER_WARNING(ZSCANNER_EITEM_OVERFLOW);
            fhold; fgoto err_line;
        }
    }

    action _item_exit {
        ADD_R_DATA_LABEL
    }
    # END

    # BEGIN - Owner processing
    action _r_owner_init {
        s->dname = s->r_owner;
    }
    action _r_owner_exit {
        s->r_owner_length = s->dname_tmp_length;
    }
    action _r_owner_empty_exit {
        if (s->r_owner_length == 0) {
            SCANNER_WARNING(ZSCANNER_EBAD_PREVIOUS_OWNER);
            fhold; fgoto err_line;
        }
    }
    action _r_owner_error {
        s->r_owner_length = 0;
        SCANNER_WARNING(ZSCANNER_EBAD_OWNER);
        fhold; fgoto err_line;
    }

    r_owner = ( dname >_r_owner_init %_r_owner_exit
              | zlen  %_r_owner_empty_exit # Empty owner - use the previous one.
              ) $!_r_owner_error;
    # END

    # BEGIN - Number processing
    action _number_digit {
        // Overflow check: 10*(s->number64) + fc - ASCII_0 <= UINT64_MAX
        if ((s->number64 < (UINT64_MAX / 10)) ||   // Dominant fast check.
            ((s->number64 == (UINT64_MAX / 10)) && // Marginal case.
             (fc <= (UINT64_MAX % 10) + ASCII_0)
            )
           ) {
            s->number64 *= 10;
            s->number64 += digit_to_num[(uint8_t)fc];
        }
        else {
            SCANNER_WARNING(ZSCANNER_ENUMBER64_OVERFLOW);
            fhold; fgoto err_line;
        }
    }

    action _number_init {
        s->number64 = 0;
    }

    number_digit = [0-9] $_number_digit;

    number = number_digit+ >_number_init;

    action _number8_write {
        if (s->number64 <= UINT8_MAX) {
            *rdata_tail = (uint8_t)(s->number64);
            rdata_tail += 1;
        }
        else {
            SCANNER_WARNING(ZSCANNER_ENUMBER8_OVERFLOW);
            fhold; fgoto err_line;
        }
    }

    action _number16_write {
        if (s->number64 <= UINT16_MAX) {
            *((uint16_t *)rdata_tail) = htons((uint16_t)(s->number64));
            rdata_tail += 2;
        }
        else {
            SCANNER_WARNING(ZSCANNER_ENUMBER16_OVERFLOW);
            fhold; fgoto err_line;
        }
    }

    action _number32_write {
        if (s->number64 <= UINT32_MAX) {
            *((uint32_t *)rdata_tail) = htonl((uint32_t)(s->number64));
            rdata_tail += 4;
        }
        else {
            SCANNER_WARNING(ZSCANNER_ENUMBER32_OVERFLOW);
            fhold; fgoto err_line;
        }
    }

    action _type_number_exit {
        if (s->number64 <= UINT16_MAX) {
            s->r_type = (uint16_t)(s->number64);
        }
        else {
            SCANNER_WARNING(ZSCANNER_ENUMBER16_OVERFLOW);
            fhold; fgoto err_line;
        }
    }

    action _length_number_exit {
        if (s->number64 <= UINT16_MAX) {
            s->r_data_length = (uint16_t)(s->number64);
        }
        else {
            SCANNER_WARNING(ZSCANNER_ENUMBER16_OVERFLOW);
            fhold; fgoto err_line;
        }
    }
    number8  = number %_number8_write  %_item_exit;
    number16 = number %_number16_write %_item_exit;
    number32 = number %_number32_write %_item_exit;

    type_number   = number %_type_number_exit;
    length_number = number %_length_number_exit;
    # END

    # BEGIN - Time processing
    time_unit =
        ( 's'i
        | 'm'i ${ if (s->number64 <= (UINT64_MAX / 60)) {
                      s->number64 *= 60;
                  }
                  else {
                      SCANNER_WARNING(ZSCANNER_ENUMBER64_OVERFLOW);
                      fhold; fgoto err_line;
                  }
                }
        | 'h'i ${ if (s->number64 <= (UINT64_MAX / 3600)) {
                      s->number64 *= 3600;
                  }
                  else {
                      SCANNER_WARNING(ZSCANNER_ENUMBER64_OVERFLOW);
                      fhold; fgoto err_line;
                  }
                }
        | 'd'i ${ if (s->number64 <= (UINT64_MAX / 86400)) {
                      s->number64 *= 86400;
                  }
                  else {
                      SCANNER_WARNING(ZSCANNER_ENUMBER64_OVERFLOW);
                      fhold; fgoto err_line;
                  }
                }
        | 'w'i ${ if (s->number64 <= (UINT64_MAX / 604800)) {
                      s->number64 *= 604800;
                  }
                  else {
                      SCANNER_WARNING(ZSCANNER_ENUMBER64_OVERFLOW);
                      fhold; fgoto err_line;
                  }
                }
        );

    time = number . time_unit?;

    time32 = time %_number32_write %_item_exit;
    # END

    # BEGIN - Timestamp processing
    action _timestamp_init {
        s->buffer_length = 0;
    }
    action _timestamp {
        if (s->buffer_length < MAX_RDATA_LENGTH) {
            s->buffer[s->buffer_length++] = fc;
        }
        else {
            SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
            fhold; fgoto err_line;
        }
    }
    action _timestamp_exit {
        s->buffer[s->buffer_length] = 0;

        if (s->buffer_length == 14) { // Date; 14 = len("YYYYMMDDHHmmSS").
            ret = date_to_timestamp(s->buffer, &timestamp);

            if (ret == KNOT_EOK) {
                *((uint32_t *)rdata_tail) = htonl(timestamp);
                rdata_tail += 4;
            }
            else {
                SCANNER_WARNING(ret);
                fhold; fgoto err_line;
            }
        }
        else if (s->buffer_length <= 10) { // Timestamp format.
            errno = 0;
            s->number64 = strtoul((char *)(s->buffer), NULL,  10);

            if (errno == 0) {
                *((uint32_t *)rdata_tail) = htonl((uint32_t)s->number64);
                rdata_tail += 4;
            }
            else {
                SCANNER_WARNING(ZSCANNER_EBAD_TIMESTAMP);
                fhold; fgoto err_line;
            }
        }
        else {
            SCANNER_WARNING(ZSCANNER_EBAD_TIMESTAMP_LENGTH);
            fhold; fgoto err_line;
        }
    }
    action _timestamp_error {
            SCANNER_WARNING(ZSCANNER_EBAD_TIMESTAMP_CHAR);
            fhold; fgoto err_line;
    }

    timestamp = digit+ >_timestamp_init $_timestamp
                %_timestamp_exit %_item_exit $!_timestamp_error;
    # END

    # BEGIN - Text processing
    action _text_char {
        if (rdata_tail <= rdata_stop) {
            *rdata_tail = fc;
            rdata_tail++;
        }
        else {
            SCANNER_WARNING(ZSCANNER_ETEXT_OVERFLOW);
            fhold; fgoto err_line;
        }
    }

    action _text_dec_init {
        if (rdata_tail <= rdata_stop) {
            *rdata_tail = 0;
            s->item_length++;
        }
        else {
            SCANNER_WARNING(ZSCANNER_ETEXT_OVERFLOW);
            fhold; fgoto err_line;
        }
    }
    action _text_dec {
        *rdata_tail *= 10;
        *rdata_tail += digit_to_num[(uint8_t)fc];
    }
    action _text_dec_exit {
        rdata_tail++;
    }

    text_char =
        ( (33..126 - [\\;\"]) $_text_char                # One printable char.
        | ('\\' . ^digit)     @_text_char                # One "\x" char.
        | ('\\'               %_text_dec_init            # Initial "\" char.
           . digit {3}        $_text_dec %_text_dec_exit # "DDD" rest.
          )
        );
    quoted_text_char = text_char | ([ \t;] $_text_char);
    text = ('\"' . quoted_text_char* . '\"') | text_char+;
    text_with_length = text >_item_length_init %_item_length_exit;

    text_item = text_with_length %_item_exit;
    text_array = (text_with_length . (sep . text_with_length)*) %_item_exit;
    # END

    # BEGIN - TTL directives processing
    action _default_ttl_exit {
        if (s->number64 <= UINT32_MAX) {
            s->default_ttl = (uint32_t)(s->number64);
        }
        else {
            SCANNER_ERROR(ZSCANNER_ENUMBER32_OVERFLOW);
            fhold; fgoto err_line;
        }
    }
    action _default_ttl_error {
        SCANNER_ERROR(ZSCANNER_EBAD_TTL);
        fhold; fgoto err_line;
    }

    default_ttl := (sep . time . rest) $!_default_ttl_error
                   %_default_ttl_exit %_ret . newline;

    action _call_default_ttl {
        fhold; fcall default_ttl;
    }
    # END

    # BEGIN - ORIGIN directives processing
    action _zone_origin_init {
        s->dname = s->zone_origin;
    }
    action _zone_origin_exit {
        s->zone_origin_length = s->dname_tmp_length;
    }
    action _zone_origin_error {
        SCANNER_ERROR(ZSCANNER_EBAD_ORIGIN);
        fhold; fgoto err_line;
    }

    zone_origin := (sep . absolute_dname >_zone_origin_init . rest)
                   $!_zone_origin_error %_zone_origin_exit %_ret . newline;

    action _call_zone_origin {
        fhold; fcall zone_origin;
    }
    # END

    # BEGIN - INCLUDE directives processing
    action _incl_filename_init {
        rdata_tail = s->r_data;
    }
    action _incl_filename_exit {
        if (rdata_tail <= rdata_stop) {
            *rdata_tail = 0; // Ending filename string.
            strcpy((char*)(s->include_filename), (char*)(s->r_data));
            rdata_tail = s->r_data; // Initialization of origin if not present!
            *rdata_tail = 0;
        }
        else {
           SCANNER_WARNING(ZSCANNER_ETEXT_OVERFLOW);
           fhold; fgoto err_line;
        }
    }
    action _incl_filename_error {
        SCANNER_ERROR(ZSCANNER_EBAD_INCLUDE_FILENAME);
        fhold; fgoto err_line;
    }

    action _incl_origin_init {
        rdata_tail = s->r_data;
    }
    action _incl_origin_exit {
        if (rdata_tail <= rdata_stop) {
            *rdata_tail = 0; // Ending origin string.
        }
        else {
           SCANNER_WARNING(ZSCANNER_ETEXT_OVERFLOW);
           fhold; fgoto err_line;
        }
    }
    action _incl_origin_error {
        SCANNER_ERROR(ZSCANNER_EBAD_INCLUDE_ORIGIN);
        fhold; fgoto err_line;
    }

    action _include_exit {
        char text_origin[MAX_DNAME_LENGTH];

        // Origin conversion from wire to text form.
        if (s->r_data[0] == 0) { // Use current origin.
            wire_dname_to_text(s->zone_origin,
                               s->zone_origin_length,
                               text_origin);
        } else { // Use specified origin.
            strcpy(text_origin, (char *)(s->r_data));
        }

        if (s->include_filename[0] != '/') { // File name is in relative form.
            // Get absolute path of the current zone file.
            if (realpath(s->file_name, (char*)(s->buffer)) != NULL) {
                char *full_current_zone_file_name = strdup((char*)(s->buffer));

                // Creating full include file name.
                sprintf((char*)(s->buffer), "%s/%s",
                        dirname(full_current_zone_file_name),
                        s->include_filename);

                free(full_current_zone_file_name);
            }
            else {
                SCANNER_ERROR(ZSCANNER_EUNPROCESSED_INCLUDE);
                fhold; fgoto err_line;
            }
        }
        else {
            strcpy((char*)(s->buffer), (char*)(s->include_filename));
        }

        // Create new file loader for included zone file.
        file_loader_t *fl = file_loader_create((char*)(s->buffer),
                                               text_origin,
                                               DEFAULT_CLASS,
                                               DEFAULT_TTL,
                                               s->process_record,
                                               s->process_error);
        if (fl != NULL) {
            // Process included zone file.
            ret = file_loader_process(fl);
            file_loader_free(fl);

            if (ret != 0) {
                SCANNER_ERROR(ZSCANNER_EUNPROCESSED_INCLUDE);
                fhold; fgoto err_line;
            }
        }
        else {
            SCANNER_ERROR(ZSCANNER_EUNOPENED_INCLUDE);
            fhold; fgoto err_line;
        }
    }

    incl := (sep . text >_incl_filename_init %_incl_filename_exit
             $!_incl_filename_error .
             (sep . text >_incl_origin_init %_incl_origin_exit
             $!_incl_origin_error)? . rest) %_include_exit %_ret newline;

    action _call_include {
        fhold; fcall incl;
    }
    # END

    # BEGIN - Directive switch
    action _directive_error {
        SCANNER_ERROR(ZSCANNER_EBAD_DIRECTIVE);
        fhold; fgoto err_line;
    }

    directive = '$' . ( ("TTL"i     %_call_default_ttl . all_wchar)
                      | ("ORIGIN"i  %_call_zone_origin . all_wchar)
                      | ("INCLUDE"i %_call_include     . all_wchar)
                      ) $!_directive_error;
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
        }
        else {
            SCANNER_WARNING(ZSCANNER_ENUMBER32_OVERFLOW);
            fhold; fgoto err_line;
        }
    }

    r_class = "IN"i %_r_class_in_exit;

    r_ttl = time %_r_ttl_exit;
    # END

    # BEGIN - IPv4 and IPv6 address processing
    action _address_init {
        s->buffer_length = 0;
    }

    action _address {
        if (s->buffer_length < MAX_RDATA_LENGTH) {
            s->buffer[s->buffer_length++] = fc;
        }
        else {
            SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
            fhold; fgoto err_line;
        }
    }

    action _address_error {
        SCANNER_WARNING(ZSCANNER_EBAD_ADDRESS_CHAR);
        fhold; fgoto err_line;
    }

    action _ipv4_address_exit {
        s->buffer[s->buffer_length] = 0;

        if (inet_pton(AF_INET, (char *)s->buffer, &addr4) > 0) {
            memcpy(rdata_tail, &(addr4.s_addr), INET4_ADDR_LENGTH);
            rdata_tail += INET4_ADDR_LENGTH;
        }
        else {
            SCANNER_WARNING(ZSCANNER_EBAD_IPV4);
            fhold; fgoto err_line;
        }
    }

    action _ipv6_address_exit {
       s->buffer[s->buffer_length] = 0;

       if (inet_pton(AF_INET6, (char *)s->buffer, &addr6) > 0) {
           memcpy(rdata_tail, &(addr6.s6_addr), INET6_ADDR_LENGTH);
           rdata_tail += INET6_ADDR_LENGTH;
       }
       else {
           SCANNER_WARNING(ZSCANNER_EBAD_IPV6);
           fhold; fgoto err_line;
       }
    }

    ipv4_address = (digit  | '.')+  >_address_init $_address
                   %_ipv4_address_exit %_item_exit $!_address_error;
    ipv6_address = (xdigit | [.:])+ >_address_init $_address
                   %_ipv6_address_exit %_item_exit $!_address_error;
    # END

    # BEGIN - Hexadecimal string array processing.
    action _first_hex_char {
        if (rdata_tail <= rdata_stop) {
            *rdata_tail = first_hex_to_num[(uint8_t)fc];
        }
        else {
           SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
           fhold; fgoto err_line;
        }
    }
    action _second_hex_char {
        *rdata_tail += second_hex_to_num[(uint8_t)fc];
        rdata_tail++;
    }
    action _hex_char_error {
        SCANNER_WARNING(ZSCANNER_EBAD_HEX_CHAR);
        fhold; fgoto err_line;
    }

    hex_char  = (xdigit $_first_hex_char . xdigit $_second_hex_char);

    # Hex array with possibility of inside white spaces and multiline.
    hex_array = (hex_char+ . sep?)+ %_item_exit $!_hex_char_error;

    # Continuous hex array (or "-") with forward length processing.
    salt = (hex_char+ | '-') >_item_length_init %_item_length_exit
           %_item_exit $!_hex_char_error;

#    action _type_data_exit {
 #       if (htons(*(s->r_data_length_position)) != s->r_data_length) {
  #          SCANNER_WARNING(ZSCANNER_EBAD_RDATA_LENGTH);
   #         fhold; fgoto err_line;
    #    }
    #}

    # Hex array or empty with control to forward length statement.
    type_data = hex_array? ;#%_type_data_exit $!_hex_char_error;
    # END

    # BEGIN - Base64 processing (RFC 4648).
    action _first_base64_char {
        if (rdata_tail <= rdata_stop) {
            *rdata_tail = first_base64_to_num[(uint8_t)fc];
        }
        else {
           SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
           fhold; fgoto err_line;
        }
    }
    action _second_base64_char {
        *rdata_tail += second_left_base64_to_num[(uint8_t)fc];
        rdata_tail++;

        if (rdata_tail <= rdata_stop) {
            *rdata_tail = second_right_base64_to_num[(uint8_t)fc];
        }
        else {
           SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
           fhold; fgoto err_line;
        }
    }
    action _third_base64_char {
        *rdata_tail += third_left_base64_to_num[(uint8_t)fc];
        rdata_tail++;

        if (rdata_tail <= rdata_stop) {
            *rdata_tail = third_right_base64_to_num[(uint8_t)fc];
        }
        else {
           SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
           fhold; fgoto err_line;
        }
    }
    action _fourth_base64_char {
        *rdata_tail += fourth_base64_to_num[(uint8_t)fc];
        rdata_tail++;
    }

    action _base64_char_error {
        SCANNER_WARNING(ZSCANNER_EBAD_BASE64_CHAR);
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
    base64 = (base64_quartet+ . sep?)+ %_item_exit $!_base64_char_error;
    # END

    # BEGIN - Base32hex processing (RFC 4648).
    action _first_base32hex_char {
        if (rdata_tail <= rdata_stop) {
            *rdata_tail = first_base32hex_to_num[(uint8_t)fc];
        }
        else {
           SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
           fhold; fgoto err_line;
        }
    }
    action _second_base32hex_char {
        *rdata_tail += second_left_base32hex_to_num[(uint8_t)fc];
        rdata_tail++;

        if (rdata_tail <= rdata_stop) {
            *rdata_tail = second_right_base32hex_to_num[(uint8_t)fc];
        }
        else {
           SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
           fhold; fgoto err_line;
        }
    }
    action _third_base32hex_char {
        *rdata_tail += third_base32hex_to_num[(uint8_t)fc];
    }
    action _fourth_base32hex_char {
        *rdata_tail += fourth_left_base32hex_to_num[(uint8_t)fc];
        rdata_tail++;

        if (rdata_tail <= rdata_stop) {
            *rdata_tail = fourth_right_base32hex_to_num[(uint8_t)fc];
        }
        else {
           SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
           fhold; fgoto err_line;
        }
    }
    action _fifth_base32hex_char {
        *rdata_tail += fifth_left_base32hex_to_num[(uint8_t)fc];
        rdata_tail++;

        if (rdata_tail <= rdata_stop) {
            *rdata_tail = fifth_right_base32hex_to_num[(uint8_t)fc];
        }
        else {
           SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
           fhold; fgoto err_line;
        }
    }
    action _sixth_base32hex_char {
        *rdata_tail += sixth_base32hex_to_num[(uint8_t)fc];
    }
    action _seventh_base32hex_char {
        *rdata_tail += seventh_left_base32hex_to_num[(uint8_t)fc];
        rdata_tail++;

        if (rdata_tail <= rdata_stop) {
            *rdata_tail = seventh_right_base32hex_to_num[(uint8_t)fc];
        }
        else {
           SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
           fhold; fgoto err_line;
        }
    }
    action _eighth_base32hex_char {
        *rdata_tail += eighth_base32hex_to_num[(uint8_t)fc];
        rdata_tail++;
    }

    action _base32hex_char_error {
        SCANNER_WARNING(ZSCANNER_EBAD_BASE32HEX_CHAR);
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
           %_item_exit $!_base32hex_char_error;
    # END

    # BEGIN - Type processing.
    action _type_exit {
        rdata_tail += 2;
    }
    action _type_error {
        SCANNER_WARNING(ZSCANNER_EUNSUPPORTED_TYPE);
        fhold; fgoto err_line;
    }

    type_num =
        ( "A"i          %{ TYPE_NUM(KNOT_RRTYPE_A); }
        | "NS"i         %{ TYPE_NUM(KNOT_RRTYPE_NS); }
        | "CNAME"i      %{ TYPE_NUM(KNOT_RRTYPE_CNAME); }
        | "SOA"i        %{ TYPE_NUM(KNOT_RRTYPE_SOA); }
        | "WKS"i        %{ TYPE_NUM(KNOT_RRTYPE_WKS); }
        | "PTR"i        %{ TYPE_NUM(KNOT_RRTYPE_PTR); }
        | "HINFO"i      %{ TYPE_NUM(KNOT_RRTYPE_HINFO); }
        | "MINFO"i      %{ TYPE_NUM(KNOT_RRTYPE_MINFO); }
        | "MX"i         %{ TYPE_NUM(KNOT_RRTYPE_MX); }
        | "TXT"i        %{ TYPE_NUM(KNOT_RRTYPE_TXT); }
        | "RP"i         %{ TYPE_NUM(KNOT_RRTYPE_RP); }
        | "AFSDB"i      %{ TYPE_NUM(KNOT_RRTYPE_AFSDB); }
        | "X25"i        %{ TYPE_NUM(KNOT_RRTYPE_X25); }
        | "ISDN"i       %{ TYPE_NUM(KNOT_RRTYPE_ISDN); }
        | "RT"i         %{ TYPE_NUM(KNOT_RRTYPE_RT); }
        | "NSAP"i       %{ TYPE_NUM(KNOT_RRTYPE_NSAP); }
        | "SIG"i        %{ TYPE_NUM(KNOT_RRTYPE_SIG); }
        | "KEY"i        %{ TYPE_NUM(KNOT_RRTYPE_KEY); }
        | "PX"i         %{ TYPE_NUM(KNOT_RRTYPE_PX); }
        | "AAAA"i       %{ TYPE_NUM(KNOT_RRTYPE_AAAA); }
        | "LOC"i        %{ TYPE_NUM(KNOT_RRTYPE_LOC); }
        | "SRV"i        %{ TYPE_NUM(KNOT_RRTYPE_SRV); }
        | "NAPTR"i      %{ TYPE_NUM(KNOT_RRTYPE_NAPTR); }
        | "KX"i         %{ TYPE_NUM(KNOT_RRTYPE_KX); }
        | "CERT"i       %{ TYPE_NUM(KNOT_RRTYPE_CERT); }
        | "DNAME"i      %{ TYPE_NUM(KNOT_RRTYPE_DNAME); }
        | "OPT"i        %{ TYPE_NUM(KNOT_RRTYPE_OPT); }
        | "APL"i        %{ TYPE_NUM(KNOT_RRTYPE_APL); }
        | "DS"i         %{ TYPE_NUM(KNOT_RRTYPE_DS); }
        | "SSHFP"i      %{ TYPE_NUM(KNOT_RRTYPE_SSHFP); }
        | "IPSECKEY"i   %{ TYPE_NUM(KNOT_RRTYPE_IPSECKEY); }
        | "RRSIG"i      %{ TYPE_NUM(KNOT_RRTYPE_RRSIG); }
        | "NSEC"i       %{ TYPE_NUM(KNOT_RRTYPE_NSEC); }
        | "DNSKEY"i     %{ TYPE_NUM(KNOT_RRTYPE_DNSKEY); }
        | "DHCID"i      %{ TYPE_NUM(KNOT_RRTYPE_DHCID); }
        | "NSEC3"i      %{ TYPE_NUM(KNOT_RRTYPE_NSEC3); }
        | "NSEC3PARAM"i %{ TYPE_NUM(KNOT_RRTYPE_NSEC3PARAM); }
        | "TLSA"i       %{ TYPE_NUM(KNOT_RRTYPE_TLSA); }
        | "SPF"i        %{ TYPE_NUM(KNOT_RRTYPE_SPF); }
        | "TYPE"i       . number16 # TYPE12345
        ) %_type_exit %_item_exit $!_type_error;
    # END

    # BEGIN - Bitmap processing
    action _type_bitmap_exit {
        if (s->number64 <= UINT16_MAX) {
            WINDOW_ADD_BIT(s->number64);
        }
        else {
            SCANNER_WARNING(ZSCANNER_ENUMBER16_OVERFLOW);
            fhold; fgoto err_line;
        }
    }

    # TYPE0-65535.
    type_bitmap = number %_type_bitmap_exit;

    type_bit =
        ( "A"i          %{ WINDOW_ADD_BIT(KNOT_RRTYPE_A); }
        | "NS"i         %{ WINDOW_ADD_BIT(KNOT_RRTYPE_NS); }
        | "CNAME"i      %{ WINDOW_ADD_BIT(KNOT_RRTYPE_CNAME); }
        | "SOA"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_SOA); }
        | "WKS"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_WKS); }
        | "PTR"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_PTR); }
        | "HINFO"i      %{ WINDOW_ADD_BIT(KNOT_RRTYPE_HINFO); }
        | "MINFO"i      %{ WINDOW_ADD_BIT(KNOT_RRTYPE_MINFO); }
        | "MX"i         %{ WINDOW_ADD_BIT(KNOT_RRTYPE_MX); }
        | "TXT"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_TXT); }
        | "RP"i         %{ WINDOW_ADD_BIT(KNOT_RRTYPE_RP); }
        | "AFSDB"i      %{ WINDOW_ADD_BIT(KNOT_RRTYPE_AFSDB); }
        | "X25"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_X25); }
        | "ISDN"i       %{ WINDOW_ADD_BIT(KNOT_RRTYPE_ISDN); }
        | "RT"i         %{ WINDOW_ADD_BIT(KNOT_RRTYPE_RT); }
        | "NSAP"i       %{ WINDOW_ADD_BIT(KNOT_RRTYPE_NSAP); }
        | "SIG"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_SIG); }
        | "KEY"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_KEY); }
        | "PX"i         %{ WINDOW_ADD_BIT(KNOT_RRTYPE_PX); }
        | "AAAA"i       %{ WINDOW_ADD_BIT(KNOT_RRTYPE_AAAA); }
        | "LOC"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_LOC); }
        | "SRV"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_SRV); }
        | "NAPTR"i      %{ WINDOW_ADD_BIT(KNOT_RRTYPE_NAPTR); }
        | "KX"i         %{ WINDOW_ADD_BIT(KNOT_RRTYPE_KX); }
        | "CERT"i       %{ WINDOW_ADD_BIT(KNOT_RRTYPE_CERT); }
        | "DNAME"i      %{ WINDOW_ADD_BIT(KNOT_RRTYPE_DNAME); }
        | "OPT"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_OPT); }
        | "APL"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_APL); }
        | "DS"i         %{ WINDOW_ADD_BIT(KNOT_RRTYPE_DS); }
        | "SSHFP"i      %{ WINDOW_ADD_BIT(KNOT_RRTYPE_SSHFP); }
        | "IPSECKEY"i   %{ WINDOW_ADD_BIT(KNOT_RRTYPE_IPSECKEY); }
        | "RRSIG"i      %{ WINDOW_ADD_BIT(KNOT_RRTYPE_RRSIG); }
        | "NSEC"i       %{ WINDOW_ADD_BIT(KNOT_RRTYPE_NSEC); }
        | "DNSKEY"i     %{ WINDOW_ADD_BIT(KNOT_RRTYPE_DNSKEY); }
        | "DHCID"i      %{ WINDOW_ADD_BIT(KNOT_RRTYPE_DHCID); }
        | "NSEC3"i      %{ WINDOW_ADD_BIT(KNOT_RRTYPE_NSEC3); }
        | "NSEC3PARAM"i %{ WINDOW_ADD_BIT(KNOT_RRTYPE_NSEC3PARAM); }
        | "TLSA"i       %{ WINDOW_ADD_BIT(KNOT_RRTYPE_TLSA); }
        | "SPF"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_SPF); }
        | "TYPE"i . type_bitmap # Special types TYPE0-TYPE65535
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
                }
                else {
                   SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
                   fhold; fgoto err_line;
                }
            }
        }
    }
    action _bitmap_error {
        SCANNER_WARNING(ZSCANNER_EBAD_BITMAP);
        fhold; fgoto err_line;
    }

    # Blank bitmap is allowed too.
    bitmap := (sep? | (sep . type_bit)* . sep?) >_bitmap_init
              %_bitmap_exit %_item_exit %_ret $!_bitmap_error . end_wchar;

    action _call_bitmap {
        fhold; fcall bitmap;
    }
    # END

    # BEGIN - domain name in record data processing
    action _r_dname_init {
        s->dname = rdata_tail;
    }
    action _r_dname_exit {
        rdata_tail += s->dname_tmp_length;
    }

    r_dname = dname >_r_dname_init %_r_dname_exit %_item_exit;
    # END

    # BEGIN - Gateway
    action _fc_write {
        *rdata_tail = digit_to_num[(uint8_t)fc];
        rdata_tail++;
        ADD_R_DATA_LABEL
    }

    gateway = ( ('0' $_fc_write . sep . number8 . sep . '.')
              | ('1' $_fc_write . sep . number8 . sep . ipv4_address)
              | ('2' $_fc_write . sep . number8 . sep . ipv6_address)
              | ('3' $_fc_write . sep . number8 . sep . r_dname)
              );
    # END

    # BEGIN - Auxiliary functions which call smaller state machines
    action _data_a {
        s->r_type = KNOT_RRTYPE_A;
        fhold; fcall data_a;
    }
    action _data_ns {
        s->r_type = KNOT_RRTYPE_NS;
        fhold; fcall data_ns;
    }
    action _data_cname { // Same as NS.
        s->r_type = KNOT_RRTYPE_CNAME;
        fhold; fcall data_ns;
    }
    action _data_soa {
        s->r_type = KNOT_RRTYPE_SOA;
        fhold; fcall data_soa;
    }
    action _data_ptr { // Same as NS.
        s->r_type = KNOT_RRTYPE_PTR;
        fhold; fcall data_ns;
    }
    action _data_mx {
        s->r_type = KNOT_RRTYPE_MX;
        fhold; fcall data_mx;
    }
    action _data_txt {
        s->r_type = KNOT_RRTYPE_TXT;
        fhold; fcall data_txt;
    }
    action _data_rp {
        s->r_type = KNOT_RRTYPE_RP;
        fhold; fcall data_rp;
    }
    action _data_aaaa {
        s->r_type = KNOT_RRTYPE_AAAA;
        fhold; fcall data_aaaa;
    }
    action _data_srv {
        s->r_type = KNOT_RRTYPE_SRV;
        fhold; fcall data_srv;
    }
    action _data_naptr {
        s->r_type = KNOT_RRTYPE_NAPTR;
        fhold; fcall data_naptr;
    }
    action _data_dname { // Same as NS.
        s->r_type = KNOT_RRTYPE_DNAME;
        fhold; fcall data_ns;
    }
    action _data_ds {
        s->r_type = KNOT_RRTYPE_DS;
        fhold; fcall data_ds;
    }
    action _data_sshfp {
        s->r_type = KNOT_RRTYPE_SSHFP;
        fhold; fcall data_sshfp;
    }
    action _data_ipseckey {
        s->r_type = KNOT_RRTYPE_IPSECKEY;
        fhold; fcall data_ipseckey;
    }
    action _data_rrsig {
        s->r_type = KNOT_RRTYPE_RRSIG;
        fhold; fcall data_rrsig;
    }
    action _data_nsec {
        s->r_type = KNOT_RRTYPE_NSEC;
        fhold; fcall data_nsec;
    }
    action _data_dnskey {
        s->r_type = KNOT_RRTYPE_DNSKEY;
        fhold; fcall data_dnskey;
    }
    action _data_dhcid {
        s->r_type = KNOT_RRTYPE_DHCID;
        fhold; fcall data_dhcid;
    }
    action _data_nsec3 {
        s->r_type = KNOT_RRTYPE_NSEC3;
        fhold; fcall data_nsec3;
    }
    action _data_nsec3param {
        s->r_type = KNOT_RRTYPE_NSEC3PARAM;
        fhold; fcall data_nsec3param;
    }
    action _data_tlsa {
        s->r_type = KNOT_RRTYPE_TLSA;
        fhold; fcall data_tlsa;
    }
    action _data_spf { // Same as TXT.
        s->r_type = KNOT_RRTYPE_SPF;
        fhold; fcall data_txt;
    }
    action _data_type { // TYPE12345
        fhold; fcall data_type;
    }
    # END

    # BEGIN - Smaller state machines
    action _r_data_error {
        SCANNER_WARNING(ZSCANNER_EBAD_RDATA);
        fhold; fgoto err_line;
    }

    data_a :=
        ( sep . ipv4_address )
        $!_r_data_error
        %_ret . all_wchar;

    data_ns :=
        ( sep . r_dname )
        $!_r_data_error
        %_ret . all_wchar;

    data_soa :=
        ( sep . r_dname . sep . r_dname . sep . number32 . sep . time32 .
          sep . time32 . sep . time32 . sep . time32 )
        $!_r_data_error
        %_ret . all_wchar;

    data_mx :=
        ( sep . number16 . sep . r_dname )
        $!_r_data_error
        %_ret . all_wchar;

    data_txt :=
        ( sep . text_array )
        $!_r_data_error
        %_ret . end_wchar;

    data_rp :=
        ( sep . r_dname . sep . r_dname )
        $!_r_data_error
        %_ret . all_wchar;

    data_aaaa :=
        ( sep . ipv6_address )
        $!_r_data_error
        %_ret . all_wchar;

    data_srv :=
        ( sep . number16 . sep . number16 . sep . number16 . sep . r_dname )
        $!_r_data_error
        %_ret . all_wchar;

    data_naptr :=
        ( sep . number16 . sep . number16 . sep . text_item . sep .
          text_item . sep . text_item . sep . r_dname )
        $!_r_data_error
        %_ret . all_wchar;

    data_ds :=
        ( sep . number16 . sep . number8 . sep . number8 . sep . hex_array )
        $!_r_data_error
        %_ret . end_wchar;

    data_sshfp :=
        ( sep . number8 . sep . number8 . sep . hex_array )
        $!_r_data_error
        %_ret . end_wchar;

    data_ipseckey :=
        ( sep . number8 . sep . gateway . sep . base64 )
        $!_r_data_error
        %_ret . end_wchar;

    data_rrsig :=
        ( sep . type_num . sep . number8 . sep . number8 . sep . number32 .
          sep . timestamp . sep . timestamp . sep . number16 . sep . r_dname .
          sep . base64 )
        $!_r_data_error
        %_ret . end_wchar;

    data_nsec :=
        ( sep . r_dname )
        $!_r_data_error
        %_call_bitmap . all_wchar # Bitmap is different machine!
        %_ret . all_wchar;

    data_dnskey :=
        ( sep . number16 . sep . number8 . sep . number8 . sep . base64 )
        $!_r_data_error
        %_ret . end_wchar;

    data_dhcid :=
        ( sep . base64 )
        $!_r_data_error
        %_ret . end_wchar;

    data_nsec3 :=
        ( sep . number8 . sep . number8 . sep . number16 . sep . salt .
          sep . hash )
        $!_r_data_error
        %_call_bitmap . all_wchar # Bitmap is different machine!
        %_ret . all_wchar;

    data_nsec3param :=
        ( sep . number8 . sep . number8 . sep . number16 . sep . salt )
        $!_r_data_error
        %_ret . all_wchar;

    data_tlsa :=
        ( sep . number8 . sep . number8 . sep . number8 . sep . hex_array )
        $!_r_data_error
        %_ret . end_wchar;

    data_type :=
        ( sep . "\\#" . sep .
          ( ('0'                             %_ret . all_wchar)
          | (length_number . sep . type_data %_ret . end_wchar)
          )
        )
        $!_r_data_error;
    # END

    # Record type switch to appropriate smaller state machines.
    action _r_data_init {
        s->r_data_items[0] = 0;
        s->r_data_items_count = 0;
        rdata_tail = s->r_data;
    }

    action _r_type_error {
        SCANNER_WARNING(ZSCANNER_EUNSUPPORTED_TYPE);
        fhold; fgoto err_line;
    }

    # Temporary action!!
    action _data_ { }

    r_type_r_data =
        ( "A"i                  %_data_a
        | "NS"i                 %_data_ns
        | "CNAME"i              %_data_cname
        | "SOA"i                %_data_soa
        | "WKS"i                %_data_
        | "PTR"i                %_data_ptr
        | "HINFO"i              %_data_
        | "MINFO"i              %_data_
        | "MX"i                 %_data_mx
        | "TXT"i                %_data_txt
        | "RP"i                 %_data_rp
        | "AFSDB"i              %_data_
        | "X25"i                %_data_
        | "ISDN"i               %_data_
        | "RT"i                 %_data_
        | "NSAP"i               %_data_
        | "SIG"i                %_data_
        | "KEY"i                %_data_
        | "PX"i                 %_data_
        | "AAAA"i               %_data_aaaa
        | "LOC"i                %_data_
        | "SRV"i                %_data_srv
        | "NAPTR"i              %_data_naptr
        | "KX"i                 %_data_
        | "CERT"i               %_data_
        | "DNAME"i              %_data_dname
        | "OPT"i                %_data_
        | "APL"i                %_data_
        | "DS"i                 %_data_ds
        | "SSHFP"i              %_data_sshfp
        | "IPSECKEY"i           %_data_ipseckey
        | "RRSIG"i              %_data_rrsig
        | "NSEC"i               %_data_nsec
        | "DNSKEY"i             %_data_dnskey
        | "DHCID"i              %_data_dhcid
        | "NSEC3"i              %_data_nsec3
        | "NSEC3PARAM"i         %_data_nsec3param
        | "TLSA"i               %_data_tlsa
        | "SPF"i                %_data_spf
        | "TYPE"i . type_number %_data_type
        ) >_r_data_init $!_r_type_error . all_wchar;

    action _record_exit {
        s->r_data_length = (uint16_t)(rdata_tail - s->r_data);
        s->process_record(s);
    }

    # Resource record.
    record =
        r_owner . sep .
        ( (r_class . sep . ((r_ttl   . sep) | (zlen %_default_r_ttl_exit  )))
        | (r_ttl   . sep . ((r_class . sep) | (zlen %_default_r_class_exit)))
        | zlen %_default_r_class_exit %_default_r_ttl_exit
        ) $!_r_type_error .
        r_type_r_data .
        rest %_record_exit .
        newline;

    # Blank spaces with comments.
    blank = rest . newline;

    # Main processing loop.
    main := (record | directive | blank)*;
}%%

