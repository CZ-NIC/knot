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

#include "common/base32hex.h"
#include "libknot/errcode.h"

#include <stdlib.h>			// malloc
#include <stdint.h>			// uint8_t
#include <stdio.h>

/*! \brief Maximal length of binary input to Base32hex encoding. */
#define MAX_BIN_DATA_LEN	((INT32_MAX / 8) * 5)

/*! \brief Base32hex padding character. */
const uint8_t base32hex_pad = '=';
/*! \brief Base32hex alphabet. */
const uint8_t base32hex_enc[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

/*! \brief Indicates bad Base32hex character. */
#define KO	255
/*! \brief Indicates Base32hex padding character. */
#define PD	 32

/*! \brief Transformation and validation table for decoding Base32hex. */
const uint8_t base32hex_dec[256] = {
	[  0] = KO, [ 43] = KO, ['V'] = 31, [129] = KO, [172] = KO, [215] = KO,
	[  1] = KO, [ 44] = KO, ['W'] = KO, [130] = KO, [173] = KO, [216] = KO,
	[  2] = KO, [ 45] = KO, ['X'] = KO, [131] = KO, [174] = KO, [217] = KO,
	[  3] = KO, [ 46] = KO, ['Y'] = KO, [132] = KO, [175] = KO, [218] = KO,
	[  4] = KO, [ 47] = KO, ['Z'] = KO, [133] = KO, [176] = KO, [219] = KO,
	[  5] = KO, ['0'] =  0, [ 91] = KO, [134] = KO, [177] = KO, [220] = KO,
	[  6] = KO, ['1'] =  1, [ 92] = KO, [135] = KO, [178] = KO, [221] = KO,
	[  7] = KO, ['2'] =  2, [ 93] = KO, [136] = KO, [179] = KO, [222] = KO,
	[  8] = KO, ['3'] =  3, [ 94] = KO, [137] = KO, [180] = KO, [223] = KO,
	[  9] = KO, ['4'] =  4, [ 95] = KO, [138] = KO, [181] = KO, [224] = KO,
	[ 10] = KO, ['5'] =  5, [ 96] = KO, [139] = KO, [182] = KO, [225] = KO,
	[ 11] = KO, ['6'] =  6, ['a'] = 10, [140] = KO, [183] = KO, [226] = KO,
	[ 12] = KO, ['7'] =  7, ['b'] = 11, [141] = KO, [184] = KO, [227] = KO,
	[ 13] = KO, ['8'] =  8, ['c'] = 12, [142] = KO, [185] = KO, [228] = KO,
	[ 14] = KO, ['9'] =  9, ['d'] = 13, [143] = KO, [186] = KO, [229] = KO,
	[ 15] = KO, [ 58] = KO, ['e'] = 14, [144] = KO, [187] = KO, [230] = KO,
	[ 16] = KO, [ 59] = KO, ['f'] = 15, [145] = KO, [188] = KO, [231] = KO,
	[ 17] = KO, [ 60] = KO, ['g'] = 16, [146] = KO, [189] = KO, [232] = KO,
	[ 18] = KO, ['='] = PD, ['h'] = 17, [147] = KO, [190] = KO, [233] = KO,
	[ 19] = KO, [ 62] = KO, ['i'] = 18, [148] = KO, [191] = KO, [234] = KO,
	[ 20] = KO, [ 63] = KO, ['j'] = 19, [149] = KO, [192] = KO, [235] = KO,
	[ 21] = KO, [ 64] = KO, ['k'] = 20, [150] = KO, [193] = KO, [236] = KO,
	[ 22] = KO, ['A'] = 10, ['l'] = 21, [151] = KO, [194] = KO, [237] = KO,
	[ 23] = KO, ['B'] = 11, ['m'] = 22, [152] = KO, [195] = KO, [238] = KO,
	[ 24] = KO, ['C'] = 12, ['n'] = 23, [153] = KO, [196] = KO, [239] = KO,
	[ 25] = KO, ['D'] = 13, ['o'] = 24, [154] = KO, [197] = KO, [240] = KO,
	[ 26] = KO, ['E'] = 14, ['p'] = 25, [155] = KO, [198] = KO, [241] = KO,
	[ 27] = KO, ['F'] = 15, ['q'] = 26, [156] = KO, [199] = KO, [242] = KO,
	[ 28] = KO, ['G'] = 16, ['r'] = 27, [157] = KO, [200] = KO, [243] = KO,
	[ 29] = KO, ['H'] = 17, ['s'] = 28, [158] = KO, [201] = KO, [244] = KO,
	[ 30] = KO, ['I'] = 18, ['t'] = 29, [159] = KO, [202] = KO, [245] = KO,
	[ 31] = KO, ['J'] = 19, ['u'] = 30, [160] = KO, [203] = KO, [246] = KO,
	[ 32] = KO, ['K'] = 20, ['v'] = 31, [161] = KO, [204] = KO, [247] = KO,
	[ 33] = KO, ['L'] = 21, ['w'] = KO, [162] = KO, [205] = KO, [248] = KO,
	[ 34] = KO, ['M'] = 22, ['x'] = KO, [163] = KO, [206] = KO, [249] = KO,
	[ 35] = KO, ['N'] = 23, ['y'] = KO, [164] = KO, [207] = KO, [250] = KO,
	[ 36] = KO, ['O'] = 24, ['z'] = KO, [165] = KO, [208] = KO, [251] = KO,
	[ 37] = KO, ['P'] = 25, [123] = KO, [166] = KO, [209] = KO, [252] = KO,
	[ 38] = KO, ['Q'] = 26, [124] = KO, [167] = KO, [210] = KO, [253] = KO,
	[ 39] = KO, ['R'] = 27, [125] = KO, [168] = KO, [211] = KO, [254] = KO,
	[ 40] = KO, ['S'] = 28, [126] = KO, [169] = KO, [212] = KO, [255] = KO,
	[ 41] = KO, ['T'] = 29, [127] = KO, [170] = KO, [213] = KO,
	[ 42] = KO, ['U'] = 30, [128] = KO, [171] = KO, [214] = KO,
};

int32_t base32hex_encode(const uint8_t  *in,
                         const uint32_t in_len,
                         uint8_t        *out,
                         const uint32_t out_len)
{
	uint8_t		rest_len = in_len % 5;
	const uint8_t	*data = in;
	const uint8_t	*stop = in + in_len - rest_len;
	uint8_t		*text = out;
	uint8_t		num;

	// Checking inputs.
	if (in == NULL || out == NULL) {
		return KNOT_EINVAL;
	}
	if (in_len > MAX_BIN_DATA_LEN || out_len < ((in_len + 4) / 5) * 8) {
		return KNOT_ERANGE;
	}

	// Encoding loop takes 5 bytes and creates 8 characters.
	while (data < stop) {
		// Computing 1. Base32hex character.
		num = *data >> 3;
		*text++ = base32hex_enc[num];

		// Computing 2. Base32hex character.
		num = (*data++ & 0x07) << 2;
		num += *data >> 6;
		*text++ = base32hex_enc[num];

		// Computing 3. Base32hex character.
		num = (*data & 0x3E) >> 1;
		*text++ = base32hex_enc[num];

		// Computing 4. Base32hex character.
		num = (*data++ & 0x01) << 4;
		num += *data >> 4;
		*text++ = base32hex_enc[num];

		// Computing 5. Base32hex character.
		num = (*data++ & 0x0F) << 1;
		num += *data >> 7;
		*text++ = base32hex_enc[num];

		// Computing 6. Base32hex character.
		num = (*data & 0x7C) >> 2;
		*text++ = base32hex_enc[num];

		// Computing 7. Base32hex character.
		num = (*data++ & 0x03) << 3;
		num += *data >> 5;
		*text++ = base32hex_enc[num];

		// Computing 8. Base32hex character.
		num = *data++ & 0x1F;
		*text++ = base32hex_enc[num];
	}

	// Processing of padding, if any.
	switch (rest_len) {
	// Input data has 4-byte last block => 1-char padding.
	case 4:
		// Computing 1. Base32hex character.
		num = *data >> 3;
		*text++ = base32hex_enc[num];

		// Computing 2. Base32hex character.
		num = (*data++ & 0x07) << 2;
		num += *data >> 6;
		*text++ = base32hex_enc[num];

		// Computing 3. Base32hex character.
		num = (*data & 0x3E) >> 1;
		*text++ = base32hex_enc[num];

		// Computing 4. Base32hex character.
		num = (*data++ & 0x01) << 4;
		num += *data >> 4;
		*text++ = base32hex_enc[num];

		// Computing 5. Base32hex character.
		num = (*data++ & 0x0F) << 1;
		num += *data >> 7;
		*text++ = base32hex_enc[num];

		// Computing 6. Base32hex character.
		num = (*data & 0x7C) >> 2;
		*text++ = base32hex_enc[num];

		// Computing 7. Base32hex character.
		num = (*data++ & 0x03) << 3;
		*text++ = base32hex_enc[num];

		// 1 padding character.
		*text++ = base32hex_pad;

		break;
	// Input data has 3-byte last block => 3-char padding.
	case 3:
		// Computing 1. Base32hex character.
		num = *data >> 3;
		*text++ = base32hex_enc[num];

		// Computing 2. Base32hex character.
		num = (*data++ & 0x07) << 2;
		num += *data >> 6;
		*text++ = base32hex_enc[num];

		// Computing 3. Base32hex character.
		num = (*data & 0x3E) >> 1;
		*text++ = base32hex_enc[num];

		// Computing 4. Base32hex character.
		num = (*data++ & 0x01) << 4;
		num += *data >> 4;
		*text++ = base32hex_enc[num];

		// Computing 5. Base32hex character.
		num = (*data++ & 0x0F) << 1;
		*text++ = base32hex_enc[num];

		// 3 padding characters.
		*text++ = base32hex_pad;
		*text++ = base32hex_pad;
		*text++ = base32hex_pad;

		break;
	// Input data has 2-byte last block => 4-char padding.
	case 2:
		// Computing 1. Base32hex character.
		num = *data >> 3;
		*text++ = base32hex_enc[num];

		// Computing 2. Base32hex character.
		num = (*data++ & 0x07) << 2;
		num += *data >> 6;
		*text++ = base32hex_enc[num];

		// Computing 3. Base32hex character.
		num = (*data & 0x3E) >> 1;
		*text++ = base32hex_enc[num];

		// Computing 4. Base32hex character.
		num = (*data++ & 0x01) << 4;
		*text++ = base32hex_enc[num];

		// 4 padding characters.
		*text++ = base32hex_pad;
		*text++ = base32hex_pad;
		*text++ = base32hex_pad;
		*text++ = base32hex_pad;

		break;
	// Input data has 1-byte last block => 6-char padding.
	case 1:
		// Computing 1. Base32hex character.
		num = *data >> 3;
		*text++ = base32hex_enc[num];

		// Computing 2. Base32hex character.
		num = (*data++ & 0x07) << 2;
		*text++ = base32hex_enc[num];

		// 6 padding characters.
		*text++ = base32hex_pad;
		*text++ = base32hex_pad;
		*text++ = base32hex_pad;
		*text++ = base32hex_pad;
		*text++ = base32hex_pad;
		*text++ = base32hex_pad;

		break;
	}

	return (text - out);
}

int32_t base32hex_encode_alloc(const uint8_t  *in,
                               const uint32_t in_len,
                               uint8_t        **out)
{
	// Checking inputs.
	if (out == NULL) {
		return KNOT_EINVAL;
	}
	if (in_len > MAX_BIN_DATA_LEN) {
		return KNOT_ERANGE;
	}

	// Compute output buffer length.
	uint32_t out_len = ((in_len + 4) / 5) * 8;

	// Allocate output buffer.
	*out = malloc(out_len);
	if (*out == NULL) {
		return KNOT_ENOMEM;
	}

	// Encode data.
	int32_t ret = base32hex_encode(in, in_len, *out, out_len);
	if (ret < 0) {
		free(*out);
	}

	return ret;
}

int32_t base32hex_decode(const uint8_t  *in,
                         const uint32_t in_len,
                         uint8_t        *out,
                         const uint32_t out_len)
{
	const uint8_t	*data = in;
	const uint8_t	*stop = in + in_len;
	uint8_t		*bin = out;
	uint8_t		pad_len = 0;
	uint8_t		c1, c2, c3, c4, c5, c6, c7, c8;

	// Checking inputs.
	if (in == NULL || out == NULL) {
		return KNOT_EINVAL;
	}
	if (in_len > INT32_MAX || out_len < ((in_len + 7) / 8) * 5) {
		return KNOT_ERANGE;
	}
	if ((in_len % 8) != 0) {
		return KNOT_BASE32HEX_ESIZE;
	}

	// Decoding loop takes 8 characters and creates 5 bytes.
	while (data < stop) {
		// Filling and transforming 8 Base32hex chars.
		c1 = base32hex_dec[*data++];
		c2 = base32hex_dec[*data++];
		c3 = base32hex_dec[*data++];
		c4 = base32hex_dec[*data++];
		c5 = base32hex_dec[*data++];
		c6 = base32hex_dec[*data++];
		c7 = base32hex_dec[*data++];
		c8 = base32hex_dec[*data++];

		// Check 8. char if is bad or padding.
		if (c8 >= PD) {
			if (c8 == PD && pad_len == 0) {
				pad_len = 1;
			} else {
				return KNOT_BASE32HEX_ECHAR;
			}
		}

		// Check 7. char if is bad or padding (if so, 6. must be too).
		if (c7 >= PD) {
			if (c7 == PD && c6 == PD && pad_len == 1) {
				pad_len = 3;
			} else {
				return KNOT_BASE32HEX_ECHAR;
			}
		}

		// Check 6. char if is bad or padding.
		if (c6 >= PD) {
			if (!(c6 == PD && pad_len == 3)) {
				return KNOT_BASE32HEX_ECHAR;
			}
		}

		// Check 5. char if is bad or padding.
		if (c5 >= PD) {
			if (c5 == PD && pad_len == 3) {
				pad_len = 4;
			} else {
				return KNOT_BASE32HEX_ECHAR;
			}
		}

		// Check 4. char if is bad or padding (if so, 3. must be too).
		if (c4 >= PD) {
			if (c4 == PD && c3 == PD && pad_len == 4) {
				pad_len = 6;
			} else {
				return KNOT_BASE32HEX_ECHAR;
			}
		}

		// Check 3. char if is bad or padding.
		if (c3 >= PD) {
			if (!(c3 == PD && pad_len == 6)) {
				return KNOT_BASE32HEX_ECHAR;
			}
		}

		// 1. and 2. chars must not be padding.
		if (c2 >= PD || c1 >= PD) {
			return KNOT_BASE32HEX_ECHAR;
		}

		// Computing of output data based on padding length.
		switch (pad_len) {
		// No padding => output has 5 bytess.
		case 0:
			*bin++ = (c1 << 3) + (c2 >> 2);
			*bin++ = (c2 << 6) + (c3 << 1) + (c4 >> 4);
			*bin++ = (c4 << 4) + (c5 >> 1);
			*bin++ = (c5 << 7) + (c6 << 2) + (c7 >> 3);
			*bin++ = (c7 << 5) + c8;
			break;
		// 1-char padding => output has 4 bytes.
		case 1:
			*bin++ = (c1 << 3) + (c2 >> 2);
			*bin++ = (c2 << 6) + (c3 << 1) + (c4 >> 4);
			*bin++ = (c4 << 4) + (c5 >> 1);
			*bin++ = (c5 << 7) + (c6 << 2) + (c7 >> 3);
			break;
		// 3-char padding => output has 3 bytes.
		case 3:
			*bin++ = (c1 << 3) + (c2 >> 2);
			*bin++ = (c2 << 6) + (c3 << 1) + (c4 >> 4);
			*bin++ = (c4 << 4) + (c5 >> 1);
			break;
		// 4-char padding => output has 2 bytes.
		case 4:
			*bin++ = (c1 << 3) + (c2 >> 2);
			*bin++ = (c2 << 6) + (c3 << 1) + (c4 >> 4);
			break;
		// 6-char padding => output has 1 byte.
		case 6:
			*bin++ = (c1 << 3) + (c2 >> 2);
			break;
		}
	}

	return (bin - out);
}

int32_t base32hex_decode_alloc(const uint8_t  *in,
                               const uint32_t in_len,
                               uint8_t        **out)
{
	// Checking inputs.
	if (out == NULL) {
		return KNOT_EINVAL;
	}

	// Compute output buffer length.
	uint32_t out_len = ((in_len + 7) / 8) * 5;

	// Allocate output buffer.
	*out = malloc(out_len);
	if (*out == NULL) {
		return KNOT_ENOMEM;
	}

	// Decode data.
	int32_t ret = base32hex_decode(in, in_len, *out, out_len);
	if (ret < 0) {
		free(*out);
	}

	return ret;
}

int32_t base32hex_encode_no_padding(const uint8_t  *in,
                                    const uint32_t in_len,
                                    uint8_t        *out,
                                    const uint32_t out_len)
{
    uint8_t		rest_len = in_len % 5;
    const uint8_t	*data = in;
    const uint8_t	*stop = in + in_len - rest_len;
    uint8_t		*text = out;
    uint8_t		num;
    
    // Checking inputs.
    if (in == NULL || out == NULL) {
        return KNOT_EINVAL;
    }
    if (in_len > MAX_BIN_DATA_LEN || out_len < ((in_len + 4) / 5) * 8) {
        return KNOT_ERANGE;
    }
    
    // Encoding loop takes 5 bytes and creates 8 characters.
    while (data < stop) {
        // Computing 1. Base32hex character.
        num = *data >> 3;
        *text++ = base32hex_enc[num];
        
        // Computing 2. Base32hex character.
        num = (*data++ & 0x07) << 2;
        num += *data >> 6;
        *text++ = base32hex_enc[num];
        
        // Computing 3. Base32hex character.
        num = (*data & 0x3E) >> 1;
        *text++ = base32hex_enc[num];
        
        // Computing 4. Base32hex character.
        num = (*data++ & 0x01) << 4;
        num += *data >> 4;
        *text++ = base32hex_enc[num];
        
        // Computing 5. Base32hex character.
        num = (*data++ & 0x0F) << 1;
        num += *data >> 7;
        *text++ = base32hex_enc[num];
        
        // Computing 6. Base32hex character.
        num = (*data & 0x7C) >> 2;
        *text++ = base32hex_enc[num];
        
        // Computing 7. Base32hex character.
        num = (*data++ & 0x03) << 3;
        num += *data >> 5;
        *text++ = base32hex_enc[num];
        
        // Computing 8. Base32hex character.
        num = *data++ & 0x1F;
        *text++ = base32hex_enc[num];
    }
    
    // Input data has 2-byte last block => 4-char padding.

    // Computing 1. Base32hex character.
    num = *data >> 3;
    *text++ = base32hex_enc[num];
    
    // Computing 2. Base32hex character.
    num = (*data++ & 0x07) << 2;
    num += *data >> 6;
    *text++ = base32hex_enc[num];
    
    // Computing 3. Base32hex character.
    num = (*data & 0x3E) >> 1;
    *text++ = base32hex_enc[num];
    
    // Computing 4. Base32hex character.
    num = (*data++ & 0x01) << 4;
    *text++ = base32hex_enc[num];
    
    // 4 padding characters.
    //*text++ = base32hex_pad;
    //*text++ = base32hex_pad;
    //*text++ = base32hex_pad;
    //*text++ = base32hex_pad;
    
    return (text - out);
}

int32_t base32hex_decode_no_padding(const uint8_t  *in,
                         const uint32_t in_len,
                         uint8_t        *out,
                         const uint32_t out_len)
{
    const uint8_t	*data = in;
    const uint8_t	*stop = in + in_len - 4;
    uint8_t		*bin = out;
    uint8_t		pad_len = 0;
    uint8_t		c1, c2, c3, c4, c5, c6, c7, c8;
    
    // Checking inputs.
    if (in == NULL || out == NULL) {
        return KNOT_EINVAL;
    }
    /*if (in_len > INT32_MAX || out_len < ((in_len + 7) / 8) * 5) {
        printf("NOT RANGE\n");
        return KNOT_ERANGE;
    }
    if ((in_len % 8) != 0) {
        printf("NOT DIVISIBLE\n");
        return KNOT_BASE32HEX_ESIZE;
    }
    */
    // Decoding loop takes 8 characters and creates 5 bytes.
    while (data < stop) {
        // Filling and transforming 8 Base32hex chars.
        c1 = base32hex_dec[*data++];
        c2 = base32hex_dec[*data++];
        c3 = base32hex_dec[*data++];
        c4 = base32hex_dec[*data++];
        c5 = base32hex_dec[*data++];
        c6 = base32hex_dec[*data++];
        c7 = base32hex_dec[*data++];
        c8 = base32hex_dec[*data++];
        
        // Check 8. char if is bad or padding.
        if (c8 >= PD) {
            if (c8 == PD && pad_len == 0) {
                pad_len = 1;
            } else {
                return KNOT_BASE32HEX_ECHAR;
            }
        }
        
        // Check 7. char if is bad or padding (if so, 6. must be too).
        if (c7 >= PD) {
            if (c7 == PD && c6 == PD && pad_len == 1) {
                pad_len = 3;
            } else {
                return KNOT_BASE32HEX_ECHAR;
            }
        }
        
        // Check 6. char if is bad or padding.
        if (c6 >= PD) {
            if (!(c6 == PD && pad_len == 3)) {
                return KNOT_BASE32HEX_ECHAR;
            }
        }
        
        // Check 5. char if is bad or padding.
        if (c5 >= PD) {
            if (c5 == PD && pad_len == 3) {
                pad_len = 4;
            } else {
                return KNOT_BASE32HEX_ECHAR;
            }
        }
        
        // Check 4. char if is bad or padding (if so, 3. must be too).
        if (c4 >= PD) {
            if (c4 == PD && c3 == PD && pad_len == 4) {
                pad_len = 6;
            } else {
                return KNOT_BASE32HEX_ECHAR;
            }
        }
        
        // Check 3. char if is bad or padding.
        if (c3 >= PD) {
            if (!(c3 == PD && pad_len == 6)) {
                return KNOT_BASE32HEX_ECHAR;
            }
        }
        
        // 1. and 2. chars must not be padding.
        if (c2 >= PD || c1 >= PD) {
            return KNOT_BASE32HEX_ECHAR;
        }
    
        *bin++ = (c1 << 3) + (c2 >> 2);
        *bin++ = (c2 << 6) + (c3 << 1) + (c4 >> 4);
        *bin++ = (c4 << 4) + (c5 >> 1);
        *bin++ = (c5 << 7) + (c6 << 2) + (c7 >> 3);
        *bin++ = (c7 << 5) + c8;
    }
    c1 = base32hex_dec[*data++];
    c2 = base32hex_dec[*data++];
    c3 = base32hex_dec[*data++];
    c4 = base32hex_dec[*data++];
    *bin++ = (c1 << 3) + (c2 >> 2);
    *bin++ = (c2 << 6) + (c3 << 1) + (c4 >> 4);
    return (bin - out);
}


