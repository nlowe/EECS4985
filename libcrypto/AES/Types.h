/*
 * Copyright (c) 2016 Nathan Lowe
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Types.h - Type Definitions for AES
 */
#pragma once
#include <cstdint>

/** A 192-bit key for AES */
typedef struct
{
	int8_t b[24];
	int8_t& operator[](size_t idx) { return b[idx]; }
} aes_key_192_t;

/** A 256-bit key for AES */
typedef struct
{
	int8_t b[32];
	int8_t& operator[](size_t idx) { return b[idx]; }
} aes_key_256_t;

/** A single block that AES operates on (4x4 byte array) */
typedef struct aes_block_t
{
	int8_t b[16];

	aes_block_t()
	{
	}

	aes_block_t(aes_key_192_t k)
	{
		b[0]  = k[0];  b[1]  = k[1];  b[2]  = k[2];  b[3]  = k[3];
		b[4]  = k[4];  b[5]  = k[5];  b[6]  = k[6];  b[7]  = k[7];
		b[8]  = k[8];  b[9]  = k[9];  b[10] = k[10]; b[11] = k[11];
		b[12] = k[12]; b[13] = k[13]; b[14] = k[14]; b[15] = k[15];
	}

	aes_block_t(aes_key_256_t k)
	{
		b[0]  = k[0];  b[1]  = k[1];  b[2]  = k[2];  b[3]  = k[3];
		b[4]  = k[4];  b[5]  = k[5];  b[6]  = k[6];  b[7]  = k[7];
		b[8]  = k[8];  b[9]  = k[9];  b[10] = k[10]; b[11] = k[11];
		b[12] = k[12]; b[13] = k[13]; b[14] = k[14]; b[15] = k[15];
	}

	int8_t& operator[](size_t idx) { return b[idx]; }
	aes_block_t operator^=(aes_block_t other) const
	{
		aes_block_t result;

		result[0]  = b[0]  ^ other.b[0];  result[1]  = b[1]  ^ other.b[1];  result[2]  = b[2]  ^ other.b[2];  result[3]  = b[3]  ^ other.b[3];
		result[4]  = b[4]  ^ other.b[4];  result[5]  = b[5]  ^ other.b[5];  result[6]  = b[6]  ^ other.b[6];  result[7]  = b[7]  ^ other.b[7];
		result[8]  = b[8]  ^ other.b[8];  result[9]  = b[9]  ^ other.b[9];  result[10] = b[10] ^ other.b[10]; result[11] = b[11] ^ other.b[11];
		result[12] = b[12] ^ other.b[12]; result[13] = b[13] ^ other.b[13]; result[14] = b[14] ^ other.b[14]; result[15] = b[15] ^ other.b[15];

		return result;
	}

	void operator^=(aes_block_t other)
	{
		b[0]  ^= other.b[0];  b[1]  ^= other.b[1];  b[2]  ^= other.b[2];  b[3]  ^= other.b[3];
		b[4]  ^= other.b[4];  b[5]  ^= other.b[5];  b[6]  ^= other.b[6];  b[7]  ^= other.b[7];
		b[8]  ^= other.b[8];  b[9]  ^= other.b[9];  b[10] ^= other.b[10]; b[11] ^= other.b[11];
		b[12] ^= other.b[12]; b[13] ^= other.b[13]; b[14] ^= other.b[14]; b[15] ^= other.b[15];
	}
} aes_block_t;

/** A 128-bit key for AES */
typedef aes_block_t aes_key_128_t;