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
        (s->dname)[s->dname_tmp_length] = (s->dname)[s->dname_tmp_length];
        s->dname_tmp_length++;
    }

    label_char =
        ( (alnum | [\-_/]) $_label_char                 # One common char.
        | ('\\' . ^digit)  @_label_char                 # One "\x" char.
        | ('\\'            %_label_dec_init             # Initial "\" char.
           . digit {3}     $_label_dec %_label_dec_exit # "DDD" rest.
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

    dname_ := ( relative_dname
              | absolute_dname
              | '@' %_origin_dname_exit
              ) $!_dname_error %_ret . all_wchar;
    dname = (alnum | [\-_/\\] | [*.@]) ${ fhold; fcall dname_; }; 
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

    number_digit = [0-9] $_number_digit;

    action _number_init {
        s->number64 = 0;
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
        }
        else if (s->decimal_counter <= s->decimals &&
                 s->number64_tmp < UINT32_MAX) {
            s->number64 *= pow(10, s->decimals - s->decimal_counter);
            s->number64 += s->number64_tmp * pow(10, s->decimals);
        }
        else {
            SCANNER_WARNING(ZSCANNER_EFLOAT_OVERFLOW);
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
        }
        else {
            SCANNER_WARNING(ZSCANNER_ENUMBER8_OVERFLOW);
            fhold; fgoto err_line;
        }
    }
    action _num16_write {
        if (s->number64 <= UINT16_MAX) {
            *((uint16_t *)rdata_tail) = htons((uint16_t)(s->number64));
            rdata_tail += 2;
        }
        else {
            SCANNER_WARNING(ZSCANNER_ENUMBER16_OVERFLOW);
            fhold; fgoto err_line;
        }
    }
    action _num32_write {
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
    num8  = number %_num8_write  %_item_exit;
    num16 = number %_num16_write %_item_exit;
    num32 = number %_num32_write %_item_exit;

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

    time32 = time %_num32_write %_item_exit;
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
            *(rdata_tail++) = fc;
        }
        else {
            SCANNER_WARNING(ZSCANNER_ETEXT_OVERFLOW);
            fhold; fgoto err_line;
        }
    }
    action _text_error {
        SCANNER_ERROR(ZSCANNER_EBAD_TEXT);
        fhold; fgoto err_line;
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
    quoted_text_char =
        ( text_char
        | ([ \t;] | [\n] when { s->multiline }) $_text_char
        );

    # Text string machine instantiation (for smaller code).
    text_ := (('\"' . quoted_text_char* . '\"') | text_char+)
             $!_text_error %_ret . all_wchar;
    text = ^all_wchar ${ fhold; fcall text_; };

    # Text string with forward 1-byte length.
    text_with_length = text >_item_length_init %_item_length_exit;

    # One text string as one rdata item.
    text_item = text_with_length %_item_exit;

    # Text string array as one rdata item.
    text_array = (text_with_length . (sep . text_with_length)* . sep?)
                 %_item_exit;
    # END

    # BEGIN - TTL directive processing
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
        SCANNER_ERROR(ZSCANNER_EBAD_ORIGIN);
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

    include_file_ := (sep . text >_incl_filename_init %_incl_filename_exit
                      $!_incl_filename_error .
                      (sep . text >_incl_origin_init %_incl_origin_exit
                      $!_incl_origin_error)? . rest
                     ) %_include_exit %_ret newline;
    include_file = all_wchar ${ fhold; fcall include_file_; };
    # END

    # BEGIN - Directive switch
    action _directive_error {
        SCANNER_ERROR(ZSCANNER_EBAD_DIRECTIVE);
        fhold; fgoto err_line;
    }

    directive = '$' . ( ("TTL"i     . default_ttl)
                      | ("ORIGIN"i  . zone_origin)
                      | ("INCLUDE"i . include_file)
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

    # BEGIN - domain name in record data processing
    action _r_dname_init {
        s->dname = rdata_tail;
    }
    action _r_dname_exit {
        rdata_tail += s->dname_tmp_length;
    }

    r_dname = dname >_r_dname_init %_r_dname_exit %_item_exit;
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
            SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
            fhold; fgoto err_line;
        }
    }
    action _addr_error {
        SCANNER_WARNING(ZSCANNER_EBAD_ADDRESS_CHAR);
        fhold; fgoto err_line;
    }

    action _ipv4_addr_exit {
        s->buffer[s->buffer_length] = 0;

        if (inet_pton(AF_INET, (char *)s->buffer, &addr4) <= 0) {
            SCANNER_WARNING(ZSCANNER_EBAD_IPV4);
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
           SCANNER_WARNING(ZSCANNER_EBAD_IPV6);
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
    ipv4_addr_write = ipv4_addr %_ipv4_addr_write %_item_exit;
    ipv6_addr_write = ipv6_addr %_ipv6_addr_write %_item_exit;
    # END

    # BEGIN - Gateway
    action _write_0 {
        *(rdata_tail++) = 0;
    }
    action _write_1 {
        *(rdata_tail++) = 1;
    }
    action _write_2 {
        *(rdata_tail++) = 2;
    }
    action _write_3 {
        *(rdata_tail++) = 3;
    }
    action _gateway_error {
        SCANNER_WARNING(ZSCANNER_EBAD_GATEWAY);
        fhold; fgoto err_line;
    }

    gateway =
        ( ('0' $_write_0 %_item_exit . sep . num8 . sep . '.')
        | ('1' $_write_1 %_item_exit . sep . num8 . sep . ipv4_addr_write)
        | ('2' $_write_2 %_item_exit . sep . num8 . sep . ipv6_addr_write)
        | ('3' $_write_3 %_item_exit . sep . num8 . sep . r_dname)
        ) $!_gateway_error;
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
        if (s->number64 <= UINT8_MAX) {
            s->apl.prefix_length = (uint8_t)(s->number64);
        }
        else {
            SCANNER_WARNING(ZSCANNER_ENUMBER8_OVERFLOW);
            fhold; fgoto err_line;
        }
    }
    action _apl_exit {
        // Write address family.
        *((uint16_t *)rdata_tail) = htons(s->apl.addr_family);
        rdata_tail += 2;
        ADD_R_DATA_LABEL
        // Write prefix length in bites.
        *(rdata_tail) = s->apl.prefix_length;
        rdata_tail += 1;
        ADD_R_DATA_LABEL
        // Computed maximal prefix length in bytes (real can be smaller).
        s->number64 = (s->apl.prefix_length + 7) / 8;
        if (s->number64 > 127) { // At most 7 bits.
            SCANNER_WARNING(ZSCANNER_EBAD_APL);
            fhold; fgoto err_line;
        }
        // Copy address to buffer.
        switch (s->apl.addr_family) {
            case 1:
                memcpy(s->buffer, &(addr4.s_addr), INET4_ADDR_LENGTH);
                break;
            case 2:
                memcpy(s->buffer, &(addr6.s6_addr), INET6_ADDR_LENGTH);
                break;
            default:
                SCANNER_WARNING(ZSCANNER_EBAD_APL);
                fhold; fgoto err_line;
        }
        // Find real prefix (without trailing zeroes).
        while (s->number64 > 0 ) {
            if ((s->buffer[s->number64 - 1] & 255) != 0) {
                // Apply mask on last byte if not precise prefix.
                // (Bind does't do this).
                s->buffer[s->number64 - 1] &=
                    ((uint8_t)255 << (8 - s->apl.prefix_length % 8));
                break;
            }
            s->number64--;
        }
        // Write negation flag + prefix length in bytes.
        *(rdata_tail) = (uint8_t)(s->number64) + s->apl.excl_flag;
        rdata_tail += 1;
        ADD_R_DATA_LABEL
        // Write address prefix.
        memcpy(rdata_tail, s->buffer, s->number64);
        rdata_tail += s->number64;
        ADD_R_DATA_LABEL
    }
    action _apl_error {
        SCANNER_WARNING(ZSCANNER_EBAD_APL);
        fhold; fgoto err_line;
    }

    apl = ('!'? $_apl_excl_flag .
           ( ('1' $_apl_addr_1 . ':' . ipv4_addr . '/' . number
              %_apl_prefix_length)
           | ('2' $_apl_addr_2 . ':' . ipv6_addr . '/' . number
              %_apl_prefix_length)
           )
          ) >_apl_init %_apl_exit $!_apl_error;

    apl_array = apl . (sep . apl)* . sep?;
    # END

    # BEGIN - Hexadecimal string array processing
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
    type_data = hex_array ;#%_type_data_exit $!_hex_char_error;
    # END

    # BEGIN - Base64 processing (RFC 4648)
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
        *(rdata_tail++) += second_left_base64_to_num[(uint8_t)fc];

        if (rdata_tail <= rdata_stop) {
            *rdata_tail = second_right_base64_to_num[(uint8_t)fc];
        }
        else {
           SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
           fhold; fgoto err_line;
        }
    }
    action _third_base64_char {
        *(rdata_tail++) += third_left_base64_to_num[(uint8_t)fc];

        if (rdata_tail <= rdata_stop) {
            *rdata_tail = third_right_base64_to_num[(uint8_t)fc];
        }
        else {
           SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
           fhold; fgoto err_line;
        }
    }
    action _fourth_base64_char {
        *(rdata_tail++) += fourth_base64_to_num[(uint8_t)fc];
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
    base64_ := (base64_quartet+ . sep?)+ %_item_exit $!_base64_char_error
               %_ret . end_wchar;
    base64 = base64_char ${ fhold; fcall base64_; };
    # END

    # BEGIN - Base32hex processing (RFC 4648)
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
        *(rdata_tail++) += second_left_base32hex_to_num[(uint8_t)fc];

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
        *(rdata_tail++) += fourth_left_base32hex_to_num[(uint8_t)fc];

        if (rdata_tail <= rdata_stop) {
            *rdata_tail = fourth_right_base32hex_to_num[(uint8_t)fc];
        }
        else {
           SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
           fhold; fgoto err_line;
        }
    }
    action _fifth_base32hex_char {
        *(rdata_tail++) += fifth_left_base32hex_to_num[(uint8_t)fc];

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
        *(rdata_tail++) += seventh_left_base32hex_to_num[(uint8_t)fc];

        if (rdata_tail <= rdata_stop) {
            *rdata_tail = seventh_right_base32hex_to_num[(uint8_t)fc];
        }
        else {
           SCANNER_WARNING(ZSCANNER_ERDATA_OVERFLOW);
           fhold; fgoto err_line;
        }
    }
    action _eighth_base32hex_char {
        *(rdata_tail++) += eighth_base32hex_to_num[(uint8_t)fc];
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

    # BEGIN - Type processing
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
        | "PTR"i        %{ TYPE_NUM(KNOT_RRTYPE_PTR); }
        | "HINFO"i      %{ TYPE_NUM(KNOT_RRTYPE_HINFO); }
        | "MINFO"i      %{ TYPE_NUM(KNOT_RRTYPE_MINFO); }
        | "MX"i         %{ TYPE_NUM(KNOT_RRTYPE_MX); }
        | "TXT"i        %{ TYPE_NUM(KNOT_RRTYPE_TXT); }
        | "RP"i         %{ TYPE_NUM(KNOT_RRTYPE_RP); }
        | "AFSDB"i      %{ TYPE_NUM(KNOT_RRTYPE_AFSDB); }
        | "RT"i         %{ TYPE_NUM(KNOT_RRTYPE_RT); }
        | "KEY"i        %{ TYPE_NUM(KNOT_RRTYPE_KEY); }
        | "AAAA"i       %{ TYPE_NUM(KNOT_RRTYPE_AAAA); }
        | "LOC"i        %{ TYPE_NUM(KNOT_RRTYPE_LOC); }
        | "SRV"i        %{ TYPE_NUM(KNOT_RRTYPE_SRV); }
        | "NAPTR"i      %{ TYPE_NUM(KNOT_RRTYPE_NAPTR); }
        | "KX"i         %{ TYPE_NUM(KNOT_RRTYPE_KX); }
        | "CERT"i       %{ TYPE_NUM(KNOT_RRTYPE_CERT); }
        | "DNAME"i      %{ TYPE_NUM(KNOT_RRTYPE_DNAME); }
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
        | "TYPE"i       . num16 # TYPE12345
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
        | "PTR"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_PTR); }
        | "HINFO"i      %{ WINDOW_ADD_BIT(KNOT_RRTYPE_HINFO); }
        | "MINFO"i      %{ WINDOW_ADD_BIT(KNOT_RRTYPE_MINFO); }
        | "MX"i         %{ WINDOW_ADD_BIT(KNOT_RRTYPE_MX); }
        | "TXT"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_TXT); }
        | "RP"i         %{ WINDOW_ADD_BIT(KNOT_RRTYPE_RP); }
        | "AFSDB"i      %{ WINDOW_ADD_BIT(KNOT_RRTYPE_AFSDB); }
        | "RT"i         %{ WINDOW_ADD_BIT(KNOT_RRTYPE_RT); }
        | "KEY"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_KEY); }
        | "AAAA"i       %{ WINDOW_ADD_BIT(KNOT_RRTYPE_AAAA); }
        | "LOC"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_LOC); }
        | "SRV"i        %{ WINDOW_ADD_BIT(KNOT_RRTYPE_SRV); }
        | "NAPTR"i      %{ WINDOW_ADD_BIT(KNOT_RRTYPE_NAPTR); }
        | "KX"i         %{ WINDOW_ADD_BIT(KNOT_RRTYPE_KX); }
        | "CERT"i       %{ WINDOW_ADD_BIT(KNOT_RRTYPE_CERT); }
        | "DNAME"i      %{ WINDOW_ADD_BIT(KNOT_RRTYPE_DNAME); }
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
    bitmap_ := ((sep . type_bit)* . sep?) >_bitmap_init
               %_bitmap_exit %_item_exit %_ret $!_bitmap_error . end_wchar;
    bitmap = all_wchar ${ fhold; fcall bitmap_; };
    # END

    # BEGIN - Location processing
    action _d1_exit {
        if (s->number64 <= 90) {
            s->loc.d1 = (uint32_t)(s->number64);
        }
        else {
            SCANNER_WARNING(ZSCANNER_EBAD_LOC_DATA);
            fhold; fgoto err_line;
        }
    }
    action _d2_exit {
        if (s->number64 <= 180) {
            s->loc.d2 = (uint32_t)(s->number64);
        }
        else {
            SCANNER_WARNING(ZSCANNER_EBAD_LOC_DATA);
            fhold; fgoto err_line;
        }
    }
    action _m1_exit {
        if (s->number64 <= 59) {
            s->loc.m1 = (uint32_t)(s->number64);
        }
        else {
            SCANNER_WARNING(ZSCANNER_EBAD_LOC_DATA);
            fhold; fgoto err_line;
        }
    }
    action _m2_exit {
        if (s->number64 <= 59) {
            s->loc.m2 = (uint32_t)(s->number64);
        }
        else {
            SCANNER_WARNING(ZSCANNER_EBAD_LOC_DATA);
            fhold; fgoto err_line;
        }
    }
    action _s1_exit {
        if (s->number64 <= 59999) {
            s->loc.s1 = (uint32_t)(s->number64);
        }
        else {
            SCANNER_WARNING(ZSCANNER_EBAD_LOC_DATA);
            fhold; fgoto err_line;
        }
    }
    action _s2_exit {
        if (s->number64 <= 59999) {
            s->loc.s2 = (uint32_t)(s->number64);
        }
        else {
            SCANNER_WARNING(ZSCANNER_EBAD_LOC_DATA);
            fhold; fgoto err_line;
        }
    }
    action _alt_exit {
        if ((s->loc.alt_sign ==  1 && s->number64 <= 4284967295) ||
            (s->loc.alt_sign == -1 && s->number64 <=   10000000))
        {
            s->loc.alt = (uint32_t)(s->number64);
        }
        else {
            SCANNER_WARNING(ZSCANNER_EBAD_LOC_DATA);
            fhold; fgoto err_line;
        }
    }
    action _siz_exit {
        if (s->number64 <= 9000000000) {
            s->loc.siz = (uint32_t)(s->number64);
        }
        else {
            SCANNER_WARNING(ZSCANNER_EBAD_LOC_DATA);
            fhold; fgoto err_line;
        }
    }
    action _hp_exit {
        if (s->number64 <= 9000000000) {
            s->loc.hp = (uint32_t)(s->number64);
        }
        else {
            SCANNER_WARNING(ZSCANNER_EBAD_LOC_DATA);
            fhold; fgoto err_line;
        }
    }
    action _vp_exit {
        if (s->number64 <= 9000000000) {
            s->loc.vp = (uint32_t)(s->number64);
        }
        else {
            SCANNER_WARNING(ZSCANNER_EBAD_LOC_DATA);
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
        ADD_R_DATA_LABEL
        // Write size.
        *(rdata_tail) = loc64to8(s->loc.siz);
        rdata_tail += 1;
        ADD_R_DATA_LABEL
        // Write horizontal precision.
        *(rdata_tail) = loc64to8(s->loc.hp);
        rdata_tail += 1;
        ADD_R_DATA_LABEL
        // Write vertical precision.
        *(rdata_tail) = loc64to8(s->loc.vp);
        rdata_tail += 1;
        ADD_R_DATA_LABEL
        // Write latitude.
        *((uint32_t *)rdata_tail) = htonl(LOC_LAT_ZERO + s->loc.lat_sign *
            (3600000 * s->loc.d1 + 60000 * s->loc.m1 + s->loc.s1));
        rdata_tail += 4;
        ADD_R_DATA_LABEL
        // Write longitude.
        *((uint32_t *)rdata_tail) = htonl(LOC_LONG_ZERO + s->loc.long_sign *
            (3600000 * s->loc.d2 + 60000 * s->loc.m2 + s->loc.s2));
        rdata_tail += 4;
        ADD_R_DATA_LABEL
        // Write altitude.
        *((uint32_t *)rdata_tail) = htonl(LOC_ALT_ZERO + s->loc.alt_sign *
            (s->loc.alt));
        rdata_tail += 4;
        ADD_R_DATA_LABEL
    }
    action _loc_error {
        SCANNER_WARNING(ZSCANNER_EBAD_LOC_DATA);
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
        SCANNER_WARNING(ZSCANNER_EBAD_HEX_RDATA);
        fhold; fgoto err_line;
    }

    hex_r_data_ :=
        (sep . length_number . sep . type_data)
        $!_hex_r_data_error %_ret . end_wchar;
    hex_r_data = "\\#" @{ fcall hex_r_data_; };

    unknown_hex_r_data_ :=
        (sep .
         ( ('0'                             %_ret . all_wchar)
         | (length_number . sep . type_data %_ret . end_wchar)
         )
        ) $!_hex_r_data_error;
    unknown_hex_r_data = "\\#" @{ fcall unknown_hex_r_data_; };
    # END

    # BEGIN - Rdata processing
    action _r_data_init {
        s->r_data_items[0] = 0;
        s->r_data_items_count = 0;
        rdata_tail = s->r_data;
    }
    action _r_data_error {
        SCANNER_WARNING(ZSCANNER_EBAD_RDATA);
        fhold; fgoto err_line;
    }
    action _r_type_error {
        SCANNER_WARNING(ZSCANNER_EUNSUPPORTED_TYPE);
        fhold; fgoto err_line;
    }

    action _r_data_a {
        s->r_type = KNOT_RRTYPE_A;
        fhold; fcall r_data_a;
    }
    action _r_data_ns {
        s->r_type = KNOT_RRTYPE_NS;
        fhold; fcall r_data_ns;
    }
    action _r_data_cname {
        s->r_type = KNOT_RRTYPE_CNAME;
        fhold; fcall r_data_ns; // Same as NS.
    }
    action _r_data_soa {
        s->r_type = KNOT_RRTYPE_SOA;
        fhold; fcall r_data_soa;
    }
    action _r_data_ptr {
        s->r_type = KNOT_RRTYPE_PTR;
        fhold; fcall r_data_ns; // Same as NS.
    }
    action _r_data_hinfo {
        s->r_type = KNOT_RRTYPE_HINFO;
        fhold; fcall r_data_hinfo;
    }
    action _r_data_minfo {
        s->r_type = KNOT_RRTYPE_MINFO;
        fhold; fcall r_data_minfo;
    }
    action _r_data_mx {
        s->r_type = KNOT_RRTYPE_MX;
        fhold; fcall r_data_mx;
    }
    action _r_data_txt {
        s->r_type = KNOT_RRTYPE_TXT;
        fhold; fcall r_data_txt;
    }
    action _r_data_rp {
        s->r_type = KNOT_RRTYPE_RP;
        fhold; fcall r_data_rp;
    }
    action _r_data_afsdb {
        s->r_type = KNOT_RRTYPE_AFSDB;
        fhold; fcall r_data_mx; // Same as MX.
    }
    action _r_data_rt {
        s->r_type = KNOT_RRTYPE_RT;
        fhold; fcall r_data_mx; // Same as MX.
    }
    action _r_data_key {
        s->r_type = KNOT_RRTYPE_KEY;
        fhold; fcall r_data_dnskey; // Same as DNSKEY.
    }
    action _r_data_aaaa {
        s->r_type = KNOT_RRTYPE_AAAA;
        fhold; fcall r_data_aaaa;
    }
    action _r_data_loc {
        s->r_type = KNOT_RRTYPE_LOC;
        fhold; fcall r_data_loc;
    }
    action _r_data_srv {
        s->r_type = KNOT_RRTYPE_SRV;
        fhold; fcall r_data_srv;
    }
    action _r_data_naptr {
        s->r_type = KNOT_RRTYPE_NAPTR;
        fhold; fcall r_data_naptr;
    }
    action _r_data_kx {
        s->r_type = KNOT_RRTYPE_KX;
        fhold; fcall r_data_mx; // Same as MX.
    }
    action _r_data_cert {
        s->r_type = KNOT_RRTYPE_CERT;
        fhold; fcall r_data_cert;
    }
    action _r_data_dname {
        s->r_type = KNOT_RRTYPE_DNAME;
        fhold; fcall r_data_ns; // Same as NS.
    }
    action _r_data_apl {
        s->r_type = KNOT_RRTYPE_APL;
        fhold; fcall r_data_apl;
    }
    action _r_data_ds {
        s->r_type = KNOT_RRTYPE_DS;
        fhold; fcall r_data_ds;
    }
    action _r_data_sshfp {
        s->r_type = KNOT_RRTYPE_SSHFP;
        fhold; fcall r_data_sshfp;
    }
    action _r_data_ipseckey {
        s->r_type = KNOT_RRTYPE_IPSECKEY;
        fhold; fcall r_data_ipseckey;
    }
    action _r_data_rrsig {
        s->r_type = KNOT_RRTYPE_RRSIG;
        fhold; fcall r_data_rrsig;
    }
    action _r_data_nsec {
        s->r_type = KNOT_RRTYPE_NSEC;
        fhold; fcall r_data_nsec;
    }
    action _r_data_dnskey {
        s->r_type = KNOT_RRTYPE_DNSKEY;
        fhold; fcall r_data_dnskey;
    }
    action _r_data_dhcid {
        s->r_type = KNOT_RRTYPE_DHCID;
        fhold; fcall r_data_dhcid;
    }
    action _r_data_nsec3 {
        s->r_type = KNOT_RRTYPE_NSEC3;
        fhold; fcall r_data_nsec3;
    }
    action _r_data_nsec3param {
        s->r_type = KNOT_RRTYPE_NSEC3PARAM;
        fhold; fcall r_data_nsec3param;
    }
    action _r_data_tlsa {
        s->r_type = KNOT_RRTYPE_TLSA;
        fhold; fcall r_data_tlsa;
    }
    action _r_data_spf {
        s->r_type = KNOT_RRTYPE_SPF;
        fhold; fcall r_data_txt; // Same as TXT.
    }
    action _r_data_type { // TYPE12345
        fhold; fcall r_data_type;
    }

    r_data_a :=
        (sep .
         ( hex_r_data
         | ipv4_addr_write
         )
        ) $!_r_data_error %_ret . all_wchar;

    r_data_ns :=
        (sep .
         ( hex_r_data
         | r_dname
         )
        ) $!_r_data_error %_ret . all_wchar;

    r_data_soa :=
        (sep . 
         ( hex_r_data
         | r_dname . sep . r_dname . sep . num32 . sep . time32 . sep .
           time32 . sep . time32 . sep . time32
         )
        ) $!_r_data_error %_ret . all_wchar;

    r_data_hinfo :=
        (sep .
         ( hex_r_data
         | text_item . sep . text_item
         )
        ) $!_r_data_error %_ret . all_wchar;

    r_data_minfo :=
        (sep .
         ( hex_r_data
         | r_dname . sep . r_dname
         )
        ) $!_r_data_error %_ret . all_wchar;

    r_data_mx :=
        (sep .
         ( hex_r_data
         | num16 . sep . r_dname
         )
        ) $!_r_data_error %_ret . all_wchar;

    r_data_txt :=
        (sep .
         ( hex_r_data
         | text_array
         )
        ) $!_r_data_error %_ret . end_wchar;

    r_data_rp :=
        (sep .
         ( hex_r_data
         | r_dname . sep . r_dname
         )
        ) $!_r_data_error %_ret . all_wchar;

    r_data_aaaa :=
        (sep .
         ( hex_r_data
         | ipv6_addr_write
         )
        ) $!_r_data_error %_ret . all_wchar;

    r_data_loc :=
        (sep .
         ( hex_r_data
         | loc
         )
        ) $!_r_data_error %_ret . end_wchar;

    r_data_srv :=
        (sep .
         ( hex_r_data
         | num16 . sep . num16 . sep . num16 . sep . r_dname
         )
        ) $!_r_data_error %_ret . all_wchar;

    r_data_naptr :=
        (sep .
         ( hex_r_data
         | num16 . sep . num16 . sep . text_item . sep . text_item . sep .
           text_item . sep . r_dname
         )
        ) $!_r_data_error %_ret . all_wchar;

    r_data_cert :=
        (sep .
         ( hex_r_data
         | num16 . sep . num16 . sep . num8 . sep . base64
         )
        ) $!_r_data_error %_ret . end_wchar;

    r_data_apl :=
        (sep .
         ( hex_r_data
         | apl_array
         )
        ) $!_r_data_error %_ret . end_wchar;

    r_data_ds :=
        (sep .
         ( hex_r_data
         | num16 . sep . num8 . sep . num8 . sep . hex_array
         )
        ) $!_r_data_error %_ret . end_wchar;

    r_data_sshfp :=
        (sep .
         ( hex_r_data
         | num8 . sep . num8 . sep . hex_array
         )
        ) $!_r_data_error %_ret . end_wchar;

    r_data_ipseckey :=
        (sep .
         ( hex_r_data
         | num8 . sep . gateway . sep . base64
         )
        ) $!_r_data_error %_ret . end_wchar;

    r_data_rrsig :=
        (sep .
         ( hex_r_data
         | type_num . sep . num8 . sep . num8 . sep . num32 . sep .
           timestamp . sep . timestamp . sep . num16 . sep . r_dname .
           sep . base64
         )
        ) $!_r_data_error %_ret . end_wchar;

    r_data_nsec :=
        (sep .
         ( hex_r_data
         | r_dname . bitmap
         )
        ) $!_r_data_error %_ret . all_wchar;

    r_data_dnskey :=
        (sep .
         ( hex_r_data
         | num16 . sep . num8 . sep . num8 . sep . base64
         )
        ) $!_r_data_error %_ret . end_wchar;

    r_data_dhcid :=
        (sep .
         ( hex_r_data
         | base64
         )
        ) $!_r_data_error %_ret . end_wchar;

    r_data_nsec3 :=
        (sep .
         ( hex_r_data
         | num8 . sep . num8 . sep . num16 . sep . salt . sep . hash . bitmap
         )
        ) $!_r_data_error %_ret . all_wchar;

    r_data_nsec3param :=
        (sep .
         ( hex_r_data
         | num8 . sep . num8 . sep . num16 . sep . salt
         )
        ) $!_r_data_error %_ret . all_wchar;

    r_data_tlsa :=
        (sep .
         ( hex_r_data
         | num8 . sep . num8 . sep . num8 . sep . hex_array
         )
        ) $!_r_data_error %_ret . end_wchar;

    r_data_type :=
        (sep . unknown_hex_r_data)
        $!_r_data_error %_ret . all_wchar;

    r_type_r_data =
        ( "A"i                  %_r_data_a
        | "NS"i                 %_r_data_ns
        | "CNAME"i              %_r_data_cname
        | "SOA"i                %_r_data_soa
        | "PTR"i                %_r_data_ptr
        | "HINFO"i              %_r_data_hinfo
        | "MINFO"i              %_r_data_minfo
        | "MX"i                 %_r_data_mx
        | "TXT"i                %_r_data_txt
        | "RP"i                 %_r_data_rp
        | "AFSDB"i              %_r_data_afsdb
        | "RT"i                 %_r_data_rt
        | "KEY"i                %_r_data_key
        | "AAAA"i               %_r_data_aaaa
        | "LOC"i                %_r_data_loc
        | "SRV"i                %_r_data_srv
        | "NAPTR"i              %_r_data_naptr
        | "KX"i                 %_r_data_kx
        | "CERT"i               %_r_data_cert
        | "DNAME"i              %_r_data_dname
        | "APL"i                %_r_data_apl
        | "DS"i                 %_r_data_ds
        | "SSHFP"i              %_r_data_sshfp
        | "IPSECKEY"i           %_r_data_ipseckey
        | "RRSIG"i              %_r_data_rrsig
        | "NSEC"i               %_r_data_nsec
        | "DNSKEY"i             %_r_data_dnskey
        | "DHCID"i              %_r_data_dhcid
        | "NSEC3"i              %_r_data_nsec3
        | "NSEC3PARAM"i         %_r_data_nsec3param
        | "TLSA"i               %_r_data_tlsa
        | "SPF"i                %_r_data_spf
        | "TYPE"i . type_number %_r_data_type
        ) >_r_data_init $!_r_type_error . all_wchar;
    # END

    # BEGIN - Top level processing
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
    # END
}%%

