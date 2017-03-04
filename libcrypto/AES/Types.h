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

namespace libcrypto
{
	namespace aes
	{
		/** A 192-bit key for AES */
		typedef struct
		{
			uint8_t b[4][6]{ 0 };
			uint8_t* operator[](size_t idx) { return b[idx]; }
		} aes_key_192_t;

		/** A 256-bit key for AES */
		typedef struct
		{
			uint8_t b[4][8]{ 0 };
			uint8_t* operator[](size_t idx) { return b[idx]; }
		} aes_key_256_t;

		/** A single block that AES operates on (4x4 byte array) */
		typedef struct aes_block_t
		{
			uint8_t b[4][4]{ 0 };

			aes_block_t()
			{
			}

			aes_block_t(aes_block_t& other)
			{
				b[0][0] = other.b[0][0]; b[0][1] = other.b[0][1]; b[0][2] = other.b[0][2]; b[0][3] = other.b[0][3];
				b[1][0] = other.b[1][0]; b[1][1] = other.b[1][1]; b[1][2] = other.b[1][2]; b[1][3] = other.b[1][3];
				b[2][0] = other.b[2][0]; b[2][1] = other.b[2][1]; b[2][2] = other.b[2][2]; b[2][3] = other.b[2][3];
				b[3][0] = other.b[3][0]; b[3][1] = other.b[3][1]; b[3][2] = other.b[3][2]; b[3][3] = other.b[3][3];
			}

			explicit aes_block_t(aes_key_192_t& k)
			{
				b[0][0] = k[0][0];  b[0][1]  = k[0][1];  b[0][2]  = k[0][2];  b[0][3]  = k[0][3];
				b[1][0] = k[1][0];  b[1][1]  = k[1][1];  b[1][2]  = k[1][2];  b[1][3]  = k[1][3];
				b[2][0] = k[2][0];  b[2][1]  = k[2][1];  b[2][2]  = k[2][2];  b[2][3]  = k[2][3];
				b[3][0] = k[3][0];  b[3][1]  = k[3][1];  b[3][2]  = k[3][2];  b[3][3]  = k[3][3];
			}

			explicit aes_block_t(aes_key_256_t& k)
			{
				b[0][0] = k[0][0];  b[0][1]  = k[0][1];  b[0][2]  = k[0][2];  b[0][3]  = k[0][3];
				b[1][0] = k[1][0];  b[1][1]  = k[1][1];  b[1][2]  = k[1][2];  b[1][3]  = k[1][3];
				b[2][0] = k[2][0];  b[2][1]  = k[2][1];  b[2][2]  = k[2][2];  b[2][3]  = k[2][3];
				b[3][0] = k[3][0];  b[3][1]  = k[3][1];  b[3][2]  = k[3][2];  b[3][3]  = k[3][3];
			}

			aes_block_t& operator=(aes_block_t& other)
			{
				b[0][0] = other.b[0][0]; b[0][1] = other.b[0][1]; b[0][2] = other.b[0][2]; b[0][3] = other.b[0][3];
				b[1][0] = other.b[1][0]; b[1][1] = other.b[1][1]; b[1][2] = other.b[1][2]; b[1][3] = other.b[1][3];
				b[2][0] = other.b[2][0]; b[2][1] = other.b[2][1]; b[2][2] = other.b[2][2]; b[2][3] = other.b[2][3];
				b[3][0] = other.b[3][0]; b[3][1] = other.b[3][1]; b[3][2] = other.b[3][2]; b[3][3] = other.b[3][3];

				return *this;
			}
			aes_block_t& operator=(aes_key_192_t& other)
			{
				b[0][0] = other.b[0][0]; b[0][1] = other.b[0][1]; b[0][2] = other.b[0][2]; b[0][3] = other.b[0][3];
				b[1][0] = other.b[1][0]; b[1][1] = other.b[1][1]; b[1][2] = other.b[1][2]; b[1][3] = other.b[1][3];
				b[2][0] = other.b[2][0]; b[2][1] = other.b[2][1]; b[2][2] = other.b[2][2]; b[2][3] = other.b[2][3];
				b[3][0] = other.b[3][0]; b[3][1] = other.b[3][1]; b[3][2] = other.b[3][2]; b[3][3] = other.b[3][3];

				return *this;
			}
			aes_block_t& operator=(aes_key_256_t& other)
			{
				b[0][0] = other.b[0][0]; b[0][1] = other.b[0][1]; b[0][2] = other.b[0][2]; b[0][3] = other.b[0][3];
				b[1][0] = other.b[1][0]; b[1][1] = other.b[1][1]; b[1][2] = other.b[1][2]; b[1][3] = other.b[1][3];
				b[2][0] = other.b[2][0]; b[2][1] = other.b[2][1]; b[2][2] = other.b[2][2]; b[2][3] = other.b[2][3];
				b[3][0] = other.b[3][0]; b[3][1] = other.b[3][1]; b[3][2] = other.b[3][2]; b[3][3] = other.b[3][3];

				return *this;
			}
			uint8_t* operator[](size_t idx) { return b[idx]; }
			aes_block_t operator^(aes_block_t& other) const
			{
				aes_block_t result;

				result[0][0] = b[0][0] ^ other.b[0][0]; result[0][1] = b[0][1] ^ other.b[0][1]; result[0][2] = b[0][2] ^ other.b[0][2]; result[0][3] = b[0][3] ^ other.b[0][3];
				result[1][0] = b[1][0] ^ other.b[1][0]; result[1][1] = b[1][1] ^ other.b[1][1]; result[1][2] = b[1][2] ^ other.b[1][2]; result[1][3] = b[1][3] ^ other.b[1][3];
				result[2][0] = b[2][0] ^ other.b[2][0]; result[2][1] = b[2][1] ^ other.b[2][1]; result[2][2] = b[2][2] ^ other.b[2][2]; result[2][3] = b[2][3] ^ other.b[2][3];
				result[3][0] = b[3][0] ^ other.b[3][0]; result[3][1] = b[3][1] ^ other.b[3][1]; result[3][2] = b[3][2] ^ other.b[3][2]; result[3][3] = b[3][3] ^ other.b[3][3];

				return result;
			}

			aes_block_t& operator^=(aes_block_t& other)
			{
				b[0][0] ^= other.b[0][0]; b[0][1] ^= other.b[0][1]; b[0][2] ^= other.b[0][2]; b[0][3] ^= other.b[0][3];
				b[1][0] ^= other.b[1][0]; b[1][1] ^= other.b[1][1]; b[1][2] ^= other.b[1][2]; b[1][3] ^= other.b[1][3];
				b[2][0] ^= other.b[2][0]; b[2][1] ^= other.b[2][1]; b[2][2] ^= other.b[2][2]; b[2][3] ^= other.b[2][3];
				b[3][0] ^= other.b[3][0]; b[3][1] ^= other.b[3][1]; b[3][2] ^= other.b[3][2]; b[3][3] ^= other.b[3][3];

				return *this;
			}
		} aes_block_t;

		/** A 128-bit key for AES */
		typedef aes_block_t aes_key_128_t;
	}
}
