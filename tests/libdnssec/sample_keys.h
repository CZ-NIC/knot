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

#pragma once

#include <binary.h>

typedef struct key_parameters {
	// DNSSEC fields
	uint8_t *name;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;
	dnssec_binary_t public_key;

	// DNSSEC wire format
	dnssec_binary_t rdata;

	// Hashes
	const char *key_id;
	uint16_t keytag;
	dnssec_binary_t ds_sha1;
	dnssec_binary_t ds_sha256;
	dnssec_binary_t ds_sha384;

	// Key information
	unsigned bit_size;

	// Private key in PEM
	dnssec_binary_t pem;
} key_parameters_t;

/*

RSA-SHA-256

rsa.    IN      DNSKEY  256 3 8 AwEAAaqwL+O6GcCPkRZjoObfIJHcHPwQQY9mnAg6kROea2gsyRJOAwBNQPCfXoPtmrU0BiZ0aGBVTVPAvZh+HJRu9NEfTNDPK2HSyHdSucjY1qs6WAub6oWHJuLBxMesftpnUwoLnVZyN+pOblUZUMsvxP3PlS+mA+E6NyQX0F/fcfGL
rsa.    IN      DS      37335 8 1 2ABEFAAB07A900F8CB5B266FC930EEBEF51766F6
rsa.    IN      DS      37335 8 2 30226484F230814C08C6DD9E2DF6E7A3DB860C2552A418CBF70D0FEE94DFA15F
rsa.    IN      DS      37335 8 4 978E0F7766096E131E3E90C50B63DBD825E7428E864BC5A3D32F3135A3786F0CDC6A070B6B8D760190F0F572B03CA4C0

Modulus: qrAv47oZwI+RFmOg5t8gkdwc/BBBj2acCDqRE55raCzJEk4DAE1A8J9eg+2atTQGJnRoYFVNU8C9mH4clG700R9M0M8rYdLId1K5yNjWqzpYC5vqhYcm4sHEx6x+2mdTCgudVnI36k5uVRlQyy/E/c+VL6YD4To3JBfQX99x8Ys=
PublicExponent: AQAB
PrivateExponent: NGDSoVBHfMbRoAw8oPxRk1D3eAZJCAdV1FSclmej0BkGLt7PnvUV+4D8UQHF2ts3E+/e48jpbM0VoUj53jbaWx1ULVmQ1cpJY0XLsRUmaQdOwEnSgXjtQy2htlth8RinB+LnVG8eUS9jWnEEikfvCLH0ptkOa/u6GKFUMj+Q95k=
Prime1: 4ZZj/YD5xvjxEuE0uR0KedsZeGT6iHqwtmJuLNuhFaeXIw5vXXZmg88U/lIo2t0DESYTbfXglw0eu62MwWb+5w==
Prime2: wbMU0wM6MYaDs4FfEeuTXT14P3cXZOFGikJPWiIUGoMGvDgYzxdiFoHzGdLkapsPizTqBKMtYQ9CYQa8g1cXvQ==
Exponent1: ywKuZVqGbdtmB9mHuvc5kEPuffxRwjS3hsq538CfDH/PcYryCagdxYy8lcqWXa/7rJkZbyGQxh7Wg4tBWmM4DQ==
Exponent2: L8MYv29sSgoBL6IW7zRHghZGMGANRLLH0g/HwVHl4yOr5X1voKEDbslcSGHYMPFLQ+goTDxwVB6PH52pnjk7gQ==
Coefficient: USHiV/UQkTz3BlxZc1IAiUQv9/Ba8wtHWSVp+YqPhxt1sfdiyUMXtlA4f6WAKAGMraoRw4wIcYr+N6Wx+wwXZw==

-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKqwL+O6GcCPkRZj
oObfIJHcHPwQQY9mnAg6kROea2gsyRJOAwBNQPCfXoPtmrU0BiZ0aGBVTVPAvZh+
HJRu9NEfTNDPK2HSyHdSucjY1qs6WAub6oWHJuLBxMesftpnUwoLnVZyN+pOblUZ
UMsvxP3PlS+mA+E6NyQX0F/fcfGLAgMBAAECgYA0YNKhUEd8xtGgDDyg/FGTUPd4
BkkIB1XUVJyWZ6PQGQYu3s+e9RX7gPxRAcXa2zcT797jyOlszRWhSPneNtpbHVQt
WZDVykljRcuxFSZpB07ASdKBeO1DLaG2W2HxGKcH4udUbx5RL2NacQSKR+8IsfSm
2Q5r+7oYoVQyP5D3mQJBAOGWY/2A+cb48RLhNLkdCnnbGXhk+oh6sLZibizboRWn
lyMOb112ZoPPFP5SKNrdAxEmE2314JcNHrutjMFm/ucCQQDBsxTTAzoxhoOzgV8R
65NdPXg/dxdk4UaKQk9aIhQagwa8OBjPF2IWgfMZ0uRqmw+LNOoEoy1hD0JhBryD
Vxe9AkEAywKuZVqGbdtmB9mHuvc5kEPuffxRwjS3hsq538CfDH/PcYryCagdxYy8
lcqWXa/7rJkZbyGQxh7Wg4tBWmM4DQJAL8MYv29sSgoBL6IW7zRHghZGMGANRLLH
0g/HwVHl4yOr5X1voKEDbslcSGHYMPFLQ+goTDxwVB6PH52pnjk7gQJAUSHiV/UQ
kTz3BlxZc1IAiUQv9/Ba8wtHWSVp+YqPhxt1sfdiyUMXtlA4f6WAKAGMraoRw4wI
cYr+N6Wx+wwXZw==
-----END PRIVATE KEY-----

*/

static const key_parameters_t SAMPLE_RSA_KEY = {
	.name = (uint8_t *)"\x03""rsa",
	.flags = 256,
	.protocol = 3,
	.algorithm = 8,
	.public_key = { .size = 132, .data = (uint8_t []) {
		0x03, 0x01, 0x00, 0x01, 0xaa, 0xb0, 0x2f, 0xe3, 0xba, 0x19,
		0xc0, 0x8f, 0x91, 0x16, 0x63, 0xa0, 0xe6, 0xdf, 0x20, 0x91,
		0xdc, 0x1c, 0xfc, 0x10, 0x41, 0x8f, 0x66, 0x9c, 0x08, 0x3a,
		0x91, 0x13, 0x9e, 0x6b, 0x68, 0x2c, 0xc9, 0x12, 0x4e, 0x03,
		0x00, 0x4d, 0x40, 0xf0, 0x9f, 0x5e, 0x83, 0xed, 0x9a, 0xb5,
		0x34, 0x06, 0x26, 0x74, 0x68, 0x60, 0x55, 0x4d, 0x53, 0xc0,
		0xbd, 0x98, 0x7e, 0x1c, 0x94, 0x6e, 0xf4, 0xd1, 0x1f, 0x4c,
		0xd0, 0xcf, 0x2b, 0x61, 0xd2, 0xc8, 0x77, 0x52, 0xb9, 0xc8,
		0xd8, 0xd6, 0xab, 0x3a, 0x58, 0x0b, 0x9b, 0xea, 0x85, 0x87,
		0x26, 0xe2, 0xc1, 0xc4, 0xc7, 0xac, 0x7e, 0xda, 0x67, 0x53,
		0x0a, 0x0b, 0x9d, 0x56, 0x72, 0x37, 0xea, 0x4e, 0x6e, 0x55,
		0x19, 0x50, 0xcb, 0x2f, 0xc4, 0xfd, 0xcf, 0x95, 0x2f, 0xa6,
		0x03, 0xe1, 0x3a, 0x37, 0x24, 0x17, 0xd0, 0x5f, 0xdf, 0x71,
		0xf1, 0x8b,
	}},
	.rdata = { .size = 136, .data = (uint8_t []) {
		0x01, 0x00, 0x03, 0x08,
		0x03, 0x01, 0x00, 0x01, 0xaa, 0xb0, 0x2f, 0xe3, 0xba, 0x19,
		0xc0, 0x8f, 0x91, 0x16, 0x63, 0xa0, 0xe6, 0xdf, 0x20, 0x91,
		0xdc, 0x1c, 0xfc, 0x10, 0x41, 0x8f, 0x66, 0x9c, 0x08, 0x3a,
		0x91, 0x13, 0x9e, 0x6b, 0x68, 0x2c, 0xc9, 0x12, 0x4e, 0x03,
		0x00, 0x4d, 0x40, 0xf0, 0x9f, 0x5e, 0x83, 0xed, 0x9a, 0xb5,
		0x34, 0x06, 0x26, 0x74, 0x68, 0x60, 0x55, 0x4d, 0x53, 0xc0,
		0xbd, 0x98, 0x7e, 0x1c, 0x94, 0x6e, 0xf4, 0xd1, 0x1f, 0x4c,
		0xd0, 0xcf, 0x2b, 0x61, 0xd2, 0xc8, 0x77, 0x52, 0xb9, 0xc8,
		0xd8, 0xd6, 0xab, 0x3a, 0x58, 0x0b, 0x9b, 0xea, 0x85, 0x87,
		0x26, 0xe2, 0xc1, 0xc4, 0xc7, 0xac, 0x7e, 0xda, 0x67, 0x53,
		0x0a, 0x0b, 0x9d, 0x56, 0x72, 0x37, 0xea, 0x4e, 0x6e, 0x55,
		0x19, 0x50, 0xcb, 0x2f, 0xc4, 0xfd, 0xcf, 0x95, 0x2f, 0xa6,
		0x03, 0xe1, 0x3a, 0x37, 0x24, 0x17, 0xd0, 0x5f, 0xdf, 0x71,
		0xf1, 0x8b,
	}},
	.key_id = "76f0d6c093d8328bc7f0e25bd8cde5575bad9b44",
	.keytag = 37335,
	.ds_sha1 = { .size = 24, .data = (uint8_t []) {
		0x91, 0xd7, 0x08, 0x01,
		0x2a, 0xbe, 0xfa, 0xab, 0x07, 0xa9, 0x00, 0xf8, 0xcb, 0x5b,
		0x26, 0x6f, 0xc9, 0x30, 0xee, 0xbe, 0xf5, 0x17, 0x66, 0xf6,
	}},
	.ds_sha256 = { .size = 36, .data = (uint8_t []) {
		0x91, 0xd7, 0x08, 0x02,
		0x30, 0x22, 0x64, 0x84, 0xf2, 0x30, 0x81, 0x4c, 0x08, 0xc6,
		0xdd, 0x9e, 0x2d, 0xf6, 0xe7, 0xa3, 0xdb, 0x86, 0x0c, 0x25,
		0x52, 0xa4, 0x18, 0xcb, 0xf7, 0x0d, 0x0f, 0xee, 0x94, 0xdf,
		0xa1, 0x5f,
	}},
	.ds_sha384 = { .size = 52, .data = (uint8_t []) {
		0x91, 0xd7, 0x08, 0x04,
		0x97, 0x8e, 0x0f, 0x77, 0x66, 0x09, 0x6e, 0x13, 0x1e, 0x3e,
		0x90, 0xc5, 0x0b, 0x63, 0xdb, 0xd8, 0x25, 0xe7, 0x42, 0x8e,
		0x86, 0x4b, 0xc5, 0xa3, 0xd3, 0x2f, 0x31, 0x35, 0xa3, 0x78,
		0x6f, 0x0c, 0xdc, 0x6a, 0x07, 0x0b, 0x6b, 0x8d, 0x76, 0x01,
		0x90, 0xf0, 0xf5, 0x72, 0xb0, 0x3c, 0xa4, 0xc0,
	}},
	.bit_size = 1024,
	.pem = { .size = 916, .data = (uint8_t []) {
		0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e,
		0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b,
		0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49,
		0x49, 0x43, 0x64, 0x67, 0x49, 0x42, 0x41, 0x44, 0x41, 0x4e,
		0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47, 0x39, 0x77,
		0x30, 0x42, 0x41, 0x51, 0x45, 0x46, 0x41, 0x41, 0x53, 0x43,
		0x41, 0x6d, 0x41, 0x77, 0x67, 0x67, 0x4a, 0x63, 0x41, 0x67,
		0x45, 0x41, 0x41, 0x6f, 0x47, 0x42, 0x41, 0x4b, 0x71, 0x77,
		0x4c, 0x2b, 0x4f, 0x36, 0x47, 0x63, 0x43, 0x50, 0x6b, 0x52,
		0x5a, 0x6a, 0x0a, 0x6f, 0x4f, 0x62, 0x66, 0x49, 0x4a, 0x48,
		0x63, 0x48, 0x50, 0x77, 0x51, 0x51, 0x59, 0x39, 0x6d, 0x6e,
		0x41, 0x67, 0x36, 0x6b, 0x52, 0x4f, 0x65, 0x61, 0x32, 0x67,
		0x73, 0x79, 0x52, 0x4a, 0x4f, 0x41, 0x77, 0x42, 0x4e, 0x51,
		0x50, 0x43, 0x66, 0x58, 0x6f, 0x50, 0x74, 0x6d, 0x72, 0x55,
		0x30, 0x42, 0x69, 0x5a, 0x30, 0x61, 0x47, 0x42, 0x56, 0x54,
		0x56, 0x50, 0x41, 0x76, 0x5a, 0x68, 0x2b, 0x0a, 0x48, 0x4a,
		0x52, 0x75, 0x39, 0x4e, 0x45, 0x66, 0x54, 0x4e, 0x44, 0x50,
		0x4b, 0x32, 0x48, 0x53, 0x79, 0x48, 0x64, 0x53, 0x75, 0x63,
		0x6a, 0x59, 0x31, 0x71, 0x73, 0x36, 0x57, 0x41, 0x75, 0x62,
		0x36, 0x6f, 0x57, 0x48, 0x4a, 0x75, 0x4c, 0x42, 0x78, 0x4d,
		0x65, 0x73, 0x66, 0x74, 0x70, 0x6e, 0x55, 0x77, 0x6f, 0x4c,
		0x6e, 0x56, 0x5a, 0x79, 0x4e, 0x2b, 0x70, 0x4f, 0x62, 0x6c,
		0x55, 0x5a, 0x0a, 0x55, 0x4d, 0x73, 0x76, 0x78, 0x50, 0x33,
		0x50, 0x6c, 0x53, 0x2b, 0x6d, 0x41, 0x2b, 0x45, 0x36, 0x4e,
		0x79, 0x51, 0x58, 0x30, 0x46, 0x2f, 0x66, 0x63, 0x66, 0x47,
		0x4c, 0x41, 0x67, 0x4d, 0x42, 0x41, 0x41, 0x45, 0x43, 0x67,
		0x59, 0x41, 0x30, 0x59, 0x4e, 0x4b, 0x68, 0x55, 0x45, 0x64,
		0x38, 0x78, 0x74, 0x47, 0x67, 0x44, 0x44, 0x79, 0x67, 0x2f,
		0x46, 0x47, 0x54, 0x55, 0x50, 0x64, 0x34, 0x0a, 0x42, 0x6b,
		0x6b, 0x49, 0x42, 0x31, 0x58, 0x55, 0x56, 0x4a, 0x79, 0x57,
		0x5a, 0x36, 0x50, 0x51, 0x47, 0x51, 0x59, 0x75, 0x33, 0x73,
		0x2b, 0x65, 0x39, 0x52, 0x58, 0x37, 0x67, 0x50, 0x78, 0x52,
		0x41, 0x63, 0x58, 0x61, 0x32, 0x7a, 0x63, 0x54, 0x37, 0x39,
		0x37, 0x6a, 0x79, 0x4f, 0x6c, 0x73, 0x7a, 0x52, 0x57, 0x68,
		0x53, 0x50, 0x6e, 0x65, 0x4e, 0x74, 0x70, 0x62, 0x48, 0x56,
		0x51, 0x74, 0x0a, 0x57, 0x5a, 0x44, 0x56, 0x79, 0x6b, 0x6c,
		0x6a, 0x52, 0x63, 0x75, 0x78, 0x46, 0x53, 0x5a, 0x70, 0x42,
		0x30, 0x37, 0x41, 0x53, 0x64, 0x4b, 0x42, 0x65, 0x4f, 0x31,
		0x44, 0x4c, 0x61, 0x47, 0x32, 0x57, 0x32, 0x48, 0x78, 0x47,
		0x4b, 0x63, 0x48, 0x34, 0x75, 0x64, 0x55, 0x62, 0x78, 0x35,
		0x52, 0x4c, 0x32, 0x4e, 0x61, 0x63, 0x51, 0x53, 0x4b, 0x52,
		0x2b, 0x38, 0x49, 0x73, 0x66, 0x53, 0x6d, 0x0a, 0x32, 0x51,
		0x35, 0x72, 0x2b, 0x37, 0x6f, 0x59, 0x6f, 0x56, 0x51, 0x79,
		0x50, 0x35, 0x44, 0x33, 0x6d, 0x51, 0x4a, 0x42, 0x41, 0x4f,
		0x47, 0x57, 0x59, 0x2f, 0x32, 0x41, 0x2b, 0x63, 0x62, 0x34,
		0x38, 0x52, 0x4c, 0x68, 0x4e, 0x4c, 0x6b, 0x64, 0x43, 0x6e,
		0x6e, 0x62, 0x47, 0x58, 0x68, 0x6b, 0x2b, 0x6f, 0x68, 0x36,
		0x73, 0x4c, 0x5a, 0x69, 0x62, 0x69, 0x7a, 0x62, 0x6f, 0x52,
		0x57, 0x6e, 0x0a, 0x6c, 0x79, 0x4d, 0x4f, 0x62, 0x31, 0x31,
		0x32, 0x5a, 0x6f, 0x50, 0x50, 0x46, 0x50, 0x35, 0x53, 0x4b,
		0x4e, 0x72, 0x64, 0x41, 0x78, 0x45, 0x6d, 0x45, 0x32, 0x33,
		0x31, 0x34, 0x4a, 0x63, 0x4e, 0x48, 0x72, 0x75, 0x74, 0x6a,
		0x4d, 0x46, 0x6d, 0x2f, 0x75, 0x63, 0x43, 0x51, 0x51, 0x44,
		0x42, 0x73, 0x78, 0x54, 0x54, 0x41, 0x7a, 0x6f, 0x78, 0x68,
		0x6f, 0x4f, 0x7a, 0x67, 0x56, 0x38, 0x52, 0x0a, 0x36, 0x35,
		0x4e, 0x64, 0x50, 0x58, 0x67, 0x2f, 0x64, 0x78, 0x64, 0x6b,
		0x34, 0x55, 0x61, 0x4b, 0x51, 0x6b, 0x39, 0x61, 0x49, 0x68,
		0x51, 0x61, 0x67, 0x77, 0x61, 0x38, 0x4f, 0x42, 0x6a, 0x50,
		0x46, 0x32, 0x49, 0x57, 0x67, 0x66, 0x4d, 0x5a, 0x30, 0x75,
		0x52, 0x71, 0x6d, 0x77, 0x2b, 0x4c, 0x4e, 0x4f, 0x6f, 0x45,
		0x6f, 0x79, 0x31, 0x68, 0x44, 0x30, 0x4a, 0x68, 0x42, 0x72,
		0x79, 0x44, 0x0a, 0x56, 0x78, 0x65, 0x39, 0x41, 0x6b, 0x45,
		0x41, 0x79, 0x77, 0x4b, 0x75, 0x5a, 0x56, 0x71, 0x47, 0x62,
		0x64, 0x74, 0x6d, 0x42, 0x39, 0x6d, 0x48, 0x75, 0x76, 0x63,
		0x35, 0x6b, 0x45, 0x50, 0x75, 0x66, 0x66, 0x78, 0x52, 0x77,
		0x6a, 0x53, 0x33, 0x68, 0x73, 0x71, 0x35, 0x33, 0x38, 0x43,
		0x66, 0x44, 0x48, 0x2f, 0x50, 0x63, 0x59, 0x72, 0x79, 0x43,
		0x61, 0x67, 0x64, 0x78, 0x59, 0x79, 0x38, 0x0a, 0x6c, 0x63,
		0x71, 0x57, 0x58, 0x61, 0x2f, 0x37, 0x72, 0x4a, 0x6b, 0x5a,
		0x62, 0x79, 0x47, 0x51, 0x78, 0x68, 0x37, 0x57, 0x67, 0x34,
		0x74, 0x42, 0x57, 0x6d, 0x4d, 0x34, 0x44, 0x51, 0x4a, 0x41,
		0x4c, 0x38, 0x4d, 0x59, 0x76, 0x32, 0x39, 0x73, 0x53, 0x67,
		0x6f, 0x42, 0x4c, 0x36, 0x49, 0x57, 0x37, 0x7a, 0x52, 0x48,
		0x67, 0x68, 0x5a, 0x47, 0x4d, 0x47, 0x41, 0x4e, 0x52, 0x4c,
		0x4c, 0x48, 0x0a, 0x30, 0x67, 0x2f, 0x48, 0x77, 0x56, 0x48,
		0x6c, 0x34, 0x79, 0x4f, 0x72, 0x35, 0x58, 0x31, 0x76, 0x6f,
		0x4b, 0x45, 0x44, 0x62, 0x73, 0x6c, 0x63, 0x53, 0x47, 0x48,
		0x59, 0x4d, 0x50, 0x46, 0x4c, 0x51, 0x2b, 0x67, 0x6f, 0x54,
		0x44, 0x78, 0x77, 0x56, 0x42, 0x36, 0x50, 0x48, 0x35, 0x32,
		0x70, 0x6e, 0x6a, 0x6b, 0x37, 0x67, 0x51, 0x4a, 0x41, 0x55,
		0x53, 0x48, 0x69, 0x56, 0x2f, 0x55, 0x51, 0x0a, 0x6b, 0x54,
		0x7a, 0x33, 0x42, 0x6c, 0x78, 0x5a, 0x63, 0x31, 0x49, 0x41,
		0x69, 0x55, 0x51, 0x76, 0x39, 0x2f, 0x42, 0x61, 0x38, 0x77,
		0x74, 0x48, 0x57, 0x53, 0x56, 0x70, 0x2b, 0x59, 0x71, 0x50,
		0x68, 0x78, 0x74, 0x31, 0x73, 0x66, 0x64, 0x69, 0x79, 0x55,
		0x4d, 0x58, 0x74, 0x6c, 0x41, 0x34, 0x66, 0x36, 0x57, 0x41,
		0x4b, 0x41, 0x47, 0x4d, 0x72, 0x61, 0x6f, 0x52, 0x77, 0x34,
		0x77, 0x49, 0x0a, 0x63, 0x59, 0x72, 0x2b, 0x4e, 0x36, 0x57,
		0x78, 0x2b, 0x77, 0x77, 0x58, 0x5a, 0x77, 0x3d, 0x3d, 0x0a,
		0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x50,
		0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59,
		0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a,
	}},
};

/*

ECDSA-P256-SHA256

ecdsa.  IN      DNSKEY  256 3 13 8uD7C4THTM/w7uhryRSToeE/jKT78/p853RX0L5EwrZrSLBubLPiBw7g bvUP6SsIga5ZQ4CSAxNmYA/gZsuXzA==
ecdsa.  IN      DS      5345 13 1 954103ac7c43810ce9f414e80f30ab1cbe49b236
ecdsa.  IN      DS      5345 13 2 bac2107036e735b50f85006ce409a19a3438cab272e70769ebda032239a3d0ca
ecdsa.  IN      DS      5345 13 4 a0ac6790483872be72a258314200a88ab75cdd70f66a18a09f0f414c074df0989fdb1df0e67d82d4312cda67b93a76c1

PrivateKey: iyLIPdk3DOIxVmmSYlmTstbtUPiVlEyDX46psyCwNVQ=

-----BEGIN PRIVATE KEY-----
MIGUAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHoweAIBAQQhAIsiyD3ZNwziMVZp
kmJZk7LW7VD4lZRMg1+OqbMgsDVUoAoGCCqGSM49AwEHoUQDQgAE8uD7C4THTM/w
7uhryRSToeE/jKT78/p853RX0L5EwrZrSLBubLPiBw7gbvUP6SsIga5ZQ4CSAxNm
YA/gZsuXzA==
-----END PRIVATE KEY-----

*/

static const key_parameters_t SAMPLE_ECDSA_KEY = {
	.name = (uint8_t *)"\x05""ecdsa",
	.flags = 256,
	.protocol = 3,
	.algorithm = 13,
	.public_key = { .size = 64, .data = (uint8_t []) {
		0xf2, 0xe0, 0xfb, 0x0b, 0x84, 0xc7, 0x4c, 0xcf, 0xf0, 0xee,
		0xe8, 0x6b, 0xc9, 0x14, 0x93, 0xa1, 0xe1, 0x3f, 0x8c, 0xa4,
		0xfb, 0xf3, 0xfa, 0x7c, 0xe7, 0x74, 0x57, 0xd0, 0xbe, 0x44,
		0xc2, 0xb6, 0x6b, 0x48, 0xb0, 0x6e, 0x6c, 0xb3, 0xe2, 0x07,
		0x0e, 0xe0, 0x6e, 0xf5, 0x0f, 0xe9, 0x2b, 0x08, 0x81, 0xae,
		0x59, 0x43, 0x80, 0x92, 0x03, 0x13, 0x66, 0x60, 0x0f, 0xe0,
		0x66, 0xcb, 0x97, 0xcc,
	}},
	.rdata = { .size = 68, .data = (uint8_t []) {
		0x01, 0x00, 0x03, 0x0d,
		0xf2, 0xe0, 0xfb, 0x0b, 0x84, 0xc7, 0x4c, 0xcf, 0xf0, 0xee,
		0xe8, 0x6b, 0xc9, 0x14, 0x93, 0xa1, 0xe1, 0x3f, 0x8c, 0xa4,
		0xfb, 0xf3, 0xfa, 0x7c, 0xe7, 0x74, 0x57, 0xd0, 0xbe, 0x44,
		0xc2, 0xb6, 0x6b, 0x48, 0xb0, 0x6e, 0x6c, 0xb3, 0xe2, 0x07,
		0x0e, 0xe0, 0x6e, 0xf5, 0x0f, 0xe9, 0x2b, 0x08, 0x81, 0xae,
		0x59, 0x43, 0x80, 0x92, 0x03, 0x13, 0x66, 0x60, 0x0f, 0xe0,
		0x66, 0xcb, 0x97, 0xcc,
	}},
	.keytag = 5345,
	.key_id = "47fd10011e76cc6741af586041eae5519465fc8d",
	.ds_sha1 = { .size = 24, .data = (uint8_t []) {
		0x14, 0xe1, 0x0d, 0x01,
		0x95, 0x41, 0x03, 0xac, 0x7c, 0x43, 0x81, 0x0c, 0xe9, 0xf4,
		0x14, 0xe8, 0x0f, 0x30, 0xab, 0x1c, 0xbe, 0x49, 0xb2, 0x36,
	}},
	.ds_sha256 = { .size = 36, .data = (uint8_t []) {
		0x14, 0xe1, 0x0d, 0x02,
		0xba, 0xc2, 0x10, 0x70, 0x36, 0xe7, 0x35, 0xb5, 0x0f, 0x85,
		0x00, 0x6c, 0xe4, 0x09, 0xa1, 0x9a, 0x34, 0x38, 0xca, 0xb2,
		0x72, 0xe7, 0x07, 0x69, 0xeb, 0xda, 0x03, 0x22, 0x39, 0xa3,
		0xd0, 0xca,
	}},
	.ds_sha384 = { .size = 52, .data = (uint8_t []) {
		0x14, 0xe1, 0x0d, 0x04,
		0xa0, 0xac, 0x67, 0x90, 0x48, 0x38, 0x72, 0xbe, 0x72, 0xa2,
		0x58, 0x31, 0x42, 0x00, 0xa8, 0x8a, 0xb7, 0x5c, 0xdd, 0x70,
		0xf6, 0x6a, 0x18, 0xa0, 0x9f, 0x0f, 0x41, 0x4c, 0x07, 0x4d,
		0xf0, 0x98, 0x9f, 0xdb, 0x1d, 0xf0, 0xe6, 0x7d, 0x82, 0xd4,
		0x31, 0x2c, 0xda, 0x67, 0xb9, 0x3a, 0x76, 0xc1,
	}},
	.bit_size = 256,
	.pem = { .size = 262, .data = (uint8_t []) {
		0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e,
		0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b,
		0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49,
		0x47, 0x55, 0x41, 0x67, 0x45, 0x41, 0x4d, 0x42, 0x4d, 0x47,
		0x42, 0x79, 0x71, 0x47, 0x53, 0x4d, 0x34, 0x39, 0x41, 0x67,
		0x45, 0x47, 0x43, 0x43, 0x71, 0x47, 0x53, 0x4d, 0x34, 0x39,
		0x41, 0x77, 0x45, 0x48, 0x42, 0x48, 0x6f, 0x77, 0x65, 0x41,
		0x49, 0x42, 0x41, 0x51, 0x51, 0x68, 0x41, 0x49, 0x73, 0x69,
		0x79, 0x44, 0x33, 0x5a, 0x4e, 0x77, 0x7a, 0x69, 0x4d, 0x56,
		0x5a, 0x70, 0x0a, 0x6b, 0x6d, 0x4a, 0x5a, 0x6b, 0x37, 0x4c,
		0x57, 0x37, 0x56, 0x44, 0x34, 0x6c, 0x5a, 0x52, 0x4d, 0x67,
		0x31, 0x2b, 0x4f, 0x71, 0x62, 0x4d, 0x67, 0x73, 0x44, 0x56,
		0x55, 0x6f, 0x41, 0x6f, 0x47, 0x43, 0x43, 0x71, 0x47, 0x53,
		0x4d, 0x34, 0x39, 0x41, 0x77, 0x45, 0x48, 0x6f, 0x55, 0x51,
		0x44, 0x51, 0x67, 0x41, 0x45, 0x38, 0x75, 0x44, 0x37, 0x43,
		0x34, 0x54, 0x48, 0x54, 0x4d, 0x2f, 0x77, 0x0a, 0x37, 0x75,
		0x68, 0x72, 0x79, 0x52, 0x53, 0x54, 0x6f, 0x65, 0x45, 0x2f,
		0x6a, 0x4b, 0x54, 0x37, 0x38, 0x2f, 0x70, 0x38, 0x35, 0x33,
		0x52, 0x58, 0x30, 0x4c, 0x35, 0x45, 0x77, 0x72, 0x5a, 0x72,
		0x53, 0x4c, 0x42, 0x75, 0x62, 0x4c, 0x50, 0x69, 0x42, 0x77,
		0x37, 0x67, 0x62, 0x76, 0x55, 0x50, 0x36, 0x53, 0x73, 0x49,
		0x67, 0x61, 0x35, 0x5a, 0x51, 0x34, 0x43, 0x53, 0x41, 0x78,
		0x4e, 0x6d, 0x0a, 0x59, 0x41, 0x2f, 0x67, 0x5a, 0x73, 0x75,
		0x58, 0x7a, 0x41, 0x3d, 0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d,
		0x2d, 0x45, 0x4e, 0x44, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41,
		0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d,
		0x2d, 0x0a,
	}},
};

/*
 * Private-key-format: v1.2
 * Algorithm: 15 (ED25519)
 * PrivateKey: ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=
 *
 * example.com. 3600 IN DNSKEY 256 3 15 (
 *              l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4= )
 *
 * example.com. 3600 IN DS 3612 15 2 (
 *              3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79
 *              a304b )
 *
 * example.com. 3600 IN MX 10 mail.example.com.
 *
 * example.com. 3600 IN RRSIG MX 15 2 3600 (
 *              1440021600 1438207200 3613 example.com. (
 *              oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3f
 *              x8A4M3e23mRZ9VrbpMngwcrqNAg== )
 */

static const key_parameters_t SAMPLE_ED25519_KEY = {
	.name = (uint8_t *)"\x07""ed25519",
	.flags = 256,
	.protocol = 3,
	.algorithm = 15,
	.public_key = { .size = 32, .data = (uint8_t []) {
			0x97, 0x4d, 0x96, 0xa2, 0x2d, 0x22, 0x4b, 0xc0, 0x1a, 0xdb, 0x91, 0x50,
			0x91, 0x47, 0x7d, 0x44, 0xcc, 0xd9, 0x1c, 0x9a, 0x41, 0xa1, 0x14, 0x30,
			0x01, 0x01, 0x17, 0xd5, 0x2c, 0x59, 0x24, 0x0e,
		}},
	.rdata = { .size = 36, .data = (uint8_t []) {
			0x01, 0x00, 0x03, 0x0f,
			0x97, 0x4d, 0x96, 0xa2, 0x2d, 0x22, 0x4b, 0xc0, 0x1a, 0xdb, 0x91, 0x50,
			0x91, 0x47, 0x7d, 0x44, 0xcc, 0xd9, 0x1c, 0x9a, 0x41, 0xa1, 0x14, 0x30,
			0x01, 0x01, 0x17, 0xd5, 0x2c, 0x59, 0x24, 0x0e,
	}},
	.keytag = 3612,
	.key_id = "bea75b99fb22ee1a68106ad6399e4acc43eb9929",
	.ds_sha1 = { .size = 24, .data = (uint8_t []) {
			0x0e, 0x1c, 0x0f, 0x01,
			0x50, 0x12, 0x49, 0x72, 0x1e, 0x1f, 0x09, 0xa7, 0x9d, 0x30, 0xd5, 0xc6,
			0xc4, 0xdc, 0xa1, 0xdc, 0x1d, 0xa4, 0xed, 0x5d,
	}},
	.ds_sha256 = { .size = 36, .data = (uint8_t []) {
			0x0e, 0x1c, 0x0f, 0x02,
			0x1b, 0x1c, 0x87, 0x66, 0xb2, 0xa9, 0x65, 0x66, 0xff, 0x19, 0x6f, 0x77,
			0xc0, 0xc4, 0x19, 0x4a, 0xf8, 0x6a, 0xaa, 0x10, 0x9c, 0x53, 0x46, 0xff,
			0x60, 0x23, 0x1a, 0x27, 0xd2, 0xb0, 0x7a, 0xc0,
	}},
	.ds_sha384 = { .size = 52, .data = (uint8_t []) {
			0x0e, 0x1c, 0x0f, 0x04,
			0xd1, 0x18, 0x31, 0x15, 0x3a, 0xf4, 0x98, 0x5e, 0xfb, 0xd0, 0xae, 0x79,
			0x2c, 0x96, 0x7e, 0xb4, 0xaf, 0xf3, 0xc3, 0x54, 0x88, 0xdb, 0x95, 0xf7,
			0xe2, 0xf8, 0x5d, 0xce, 0xc7, 0x4a, 0xe8, 0xf5, 0x9f, 0x9a, 0x72, 0x64,
			0x17, 0x98, 0xc9, 0x1c, 0x67, 0xc6, 0x75, 0xdb, 0x1d, 0x71, 0x0c, 0x18,
	}},
	.bit_size = 256,
	.pem = { .size = 119, .data = (uint8_t []) {
			0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50,
			0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d,
			0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x43, 0x34, 0x43, 0x41, 0x51, 0x41, 0x77,
			0x42, 0x51, 0x59, 0x44, 0x4b, 0x32, 0x56, 0x77, 0x42, 0x43, 0x49, 0x45,
			0x49, 0x44, 0x67, 0x79, 0x4d, 0x6a, 0x59, 0x77, 0x4d, 0x7a, 0x67, 0x30,
			0x4e, 0x6a, 0x49, 0x34, 0x4d, 0x44, 0x67, 0x77, 0x4d, 0x54, 0x49, 0x79,
			0x4e, 0x6a, 0x51, 0x31, 0x4d, 0x54, 0x6b, 0x77, 0x4d, 0x6a, 0x41, 0x30,
			0x4d, 0x54, 0x51, 0x79, 0x4d, 0x6a, 0x59, 0x79, 0x0a, 0x2d, 0x2d, 0x2d,
			0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54,
			0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a
	}},
};
