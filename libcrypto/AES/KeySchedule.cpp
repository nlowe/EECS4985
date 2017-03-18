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
 * KeySchedule.cpp - Key Schedule Implementation for AES
 */
#include "KeySchedule.h"
#include "../export.h"
#include "AES.h"
#include "Boxes.h"

namespace libcrypto
{
	namespace aes
	{
		LIBCRYPTO_PUB aes_key_schedule_t BuildSchedule(aes_key_128_t key)
		{
			aes_key_schedule_t result;
			uint8_t w[(AES_ROUNDS_128 + 1) * 4][4]{ 0 };

			// The first 4 words come from the key
			result[0][0][0] = w[0][0] = key[0][0]; result[0][1][0] = w[0][1] = key[1][0]; result[0][2][0] = w[0][2] = key[2][0]; result[0][3][0] = w[0][3] = key[3][0];
			result[0][0][1] = w[1][0] = key[0][1]; result[0][1][1] = w[1][1] = key[1][1]; result[0][2][1] = w[1][2] = key[2][1]; result[0][3][1] = w[1][3] = key[3][1];
			result[0][0][2] = w[2][0] = key[0][2]; result[0][1][2] = w[2][1] = key[1][2]; result[0][2][2] = w[2][2] = key[2][2]; result[0][3][2] = w[2][3] = key[3][2];
			result[0][0][3] = w[3][0] = key[0][3]; result[0][1][3] = w[3][1] = key[1][3]; result[0][2][3] = w[3][2] = key[2][3]; result[0][3][3] = w[3][3] = key[3][3];

			auto r = 0;
			for(auto i = AES_WORDS_128; i < (AES_ROUNDS_128 + 1) * 4; i++)
			{
				if(i % AES_WORDS_128 == 0)
				{
					// shift up the rightmost column of the previous key
					// substitute all bytes
					// xor the first byte with the RCON
					// Then proceed as normal
					w[i][0] = s[w[i - 1][1]] ^ RCON[r++] ^ w[i - AES_WORDS_128][0];
					w[i][1] = s[w[i - 1][2]] ^ w[i - AES_WORDS_128][1];
					w[i][2] = s[w[i - 1][3]] ^ w[i - AES_WORDS_128][2];
					w[i][3] = s[w[i - 1][0]] ^ w[i - AES_WORDS_128][3];
				}
				else
				{
					// Otherwise this word is the previous word xor with the same word index in the previous round
					w[i][0] = w[i - 1][0] ^ w[i - AES_WORDS_128][0];
					w[i][1] = w[i - 1][1] ^ w[i - AES_WORDS_128][1];
					w[i][2] = w[i - 1][2] ^ w[i - AES_WORDS_128][2];
					w[i][3] = w[i - 1][3] ^ w[i - AES_WORDS_128][3];
				}

				// Populate this word in the key schedule
				result[i / 4][0][i % 4] = w[i][0];
				result[i / 4][1][i % 4] = w[i][1];
				result[i / 4][2][i % 4] = w[i][2];
				result[i / 4][3][i % 4] = w[i][3];
			}

			return result;
		}

		LIBCRYPTO_PUB aes_key_schedule_t BuildSchedule(aes_key_192_t key)
		{
			aes_key_schedule_t result;
			uint8_t w[(AES_ROUNDS_192 + 1) * 4][4]{ 0 };

			// The first 6 words come from the key
			result[0][0][0] = w[0][0] = key[0][0]; result[0][1][0] = w[0][1] = key[1][0]; result[0][2][0] = w[0][2] = key[2][0]; result[0][3][0] = w[0][3] = key[3][0];
			result[0][0][1] = w[1][0] = key[0][1]; result[0][1][1] = w[1][1] = key[1][1]; result[0][2][1] = w[1][2] = key[2][1]; result[0][3][1] = w[1][3] = key[3][1];
			result[0][0][2] = w[2][0] = key[0][2]; result[0][1][2] = w[2][1] = key[1][2]; result[0][2][2] = w[2][2] = key[2][2]; result[0][3][2] = w[2][3] = key[3][2];
			result[0][0][3] = w[3][0] = key[0][3]; result[0][1][3] = w[3][1] = key[1][3]; result[0][2][3] = w[3][2] = key[2][3]; result[0][3][3] = w[3][3] = key[3][3];
			result[1][0][0] = w[4][0] = key[0][4]; result[1][1][0] = w[4][1] = key[1][4]; result[1][2][0] = w[4][2] = key[2][4]; result[1][3][0] = w[4][3] = key[3][4];
			result[1][0][1] = w[5][0] = key[0][5]; result[1][1][1] = w[5][1] = key[1][5]; result[1][2][1] = w[5][2] = key[2][5]; result[1][3][1] = w[5][3] = key[3][5];

			auto r = 0;
			for(auto i = AES_WORDS_192; i < (AES_ROUNDS_192 + 1) * 4; i++)
			{
				if(i % AES_WORDS_192 == 0)
				{
					// shift up the rightmost column of the previous key
					// substitute all bytes
					// xor the first byte with the RCON
					// Then proceed as normal
					w[i][0] = s[w[i - 1][1]] ^ RCON[r++] ^ w[i - AES_WORDS_192][0];
					w[i][1] = s[w[i - 1][2]] ^ w[i - AES_WORDS_192][1];
					w[i][2] = s[w[i - 1][3]] ^ w[i - AES_WORDS_192][2];
					w[i][3] = s[w[i - 1][0]] ^ w[i - AES_WORDS_192][3];
				}
				else
				{
					// Otherwise this word is the previous word xor with the same word index in the previous round
					w[i][0] = w[i - 1][0] ^ w[i - AES_WORDS_192][0];
					w[i][1] = w[i - 1][1] ^ w[i - AES_WORDS_192][1];
					w[i][2] = w[i - 1][2] ^ w[i - AES_WORDS_192][2];
					w[i][3] = w[i - 1][3] ^ w[i - AES_WORDS_192][3];
				}

				// Populate this word in the key schedule
				result[i / 4][0][i % 4] = w[i][0];
				result[i / 4][1][i % 4] = w[i][1];
				result[i / 4][2][i % 4] = w[i][2];
				result[i / 4][3][i % 4] = w[i][3];
			}

			return result;
		}

		LIBCRYPTO_PUB aes_key_schedule_t BuildSchedule(aes_key_256_t key)
		{
			aes_key_schedule_t result;
			uint8_t w[(AES_ROUNDS_256 + 1) * 4][4]{ 0 };

			// The first 8 words come from the key
			result[0][0][0] = w[0][0] = key[0][0]; result[0][1][0] = w[0][1] = key[1][0]; result[0][2][0] = w[0][2] = key[2][0]; result[0][3][0] = w[0][3] = key[3][0];
			result[0][0][1] = w[1][0] = key[0][1]; result[0][1][1] = w[1][1] = key[1][1]; result[0][2][1] = w[1][2] = key[2][1]; result[0][3][1] = w[1][3] = key[3][1];
			result[0][0][2] = w[2][0] = key[0][2]; result[0][1][2] = w[2][1] = key[1][2]; result[0][2][2] = w[2][2] = key[2][2]; result[0][3][2] = w[2][3] = key[3][2];
			result[0][0][3] = w[3][0] = key[0][3]; result[0][1][3] = w[3][1] = key[1][3]; result[0][2][3] = w[3][2] = key[2][3]; result[0][3][3] = w[3][3] = key[3][3];
			result[1][0][0] = w[4][0] = key[0][4]; result[1][1][0] = w[4][1] = key[1][4]; result[1][2][0] = w[4][2] = key[2][4]; result[1][3][0] = w[4][3] = key[3][4];
			result[1][0][1] = w[5][0] = key[0][5]; result[1][1][1] = w[5][1] = key[1][5]; result[1][2][1] = w[5][2] = key[2][5]; result[1][3][1] = w[5][3] = key[3][5];
			result[1][0][2] = w[6][0] = key[0][6]; result[1][1][2] = w[6][1] = key[1][6]; result[1][2][2] = w[6][2] = key[2][6]; result[1][3][2] = w[6][3] = key[3][6];
			result[1][0][3] = w[7][0] = key[0][7]; result[1][1][3] = w[7][1] = key[1][7]; result[1][2][3] = w[7][2] = key[2][7]; result[1][3][3] = w[7][3] = key[3][7];

			auto r = 0;
			for(auto i = AES_WORDS_256; i < (AES_ROUNDS_256 + 1) * 4; i++)
			{
				if(i % AES_WORDS_256 == 0)
				{
					// shift up the rightmost column of the previous key
					// substitute all bytes
					// xor the first byte with the RCON
					// Then proceed as normal
					w[i][0] = s[w[i - 1][1]] ^ RCON[r++] ^ w[i - AES_WORDS_256][0];
					w[i][1] = s[w[i - 1][2]] ^ w[i - AES_WORDS_256][1];
					w[i][2] = s[w[i - 1][3]] ^ w[i - AES_WORDS_256][2];
					w[i][3] = s[w[i - 1][0]] ^ w[i - AES_WORDS_256][3];
				}
				else if((i - 4) % 8 == 0)
				{
					// The 5th word in each segment runs the previous word through the s-box before xor'ing
					w[i][0] = s[w[i - 1][0]] ^ w[i - AES_WORDS_256][0];
					w[i][1] = s[w[i - 1][1]] ^ w[i - AES_WORDS_256][1];
					w[i][2] = s[w[i - 1][2]] ^ w[i - AES_WORDS_256][2];
					w[i][3] = s[w[i - 1][3]] ^ w[i - AES_WORDS_256][3];
				}
				else
				{
					// Otherwise this word is the previous word xor with the same word index in the previous round
					w[i][0] = w[i - 1][0] ^ w[i - AES_WORDS_256][0];
					w[i][1] = w[i - 1][1] ^ w[i - AES_WORDS_256][1];
					w[i][2] = w[i - 1][2] ^ w[i - AES_WORDS_256][2];
					w[i][3] = w[i - 1][3] ^ w[i - AES_WORDS_256][3];
				}

				// Populate this word in the key schedule
				result[i / 4][0][i % 4] = w[i][0];
				result[i / 4][1][i % 4] = w[i][1];
				result[i / 4][2][i % 4] = w[i][2];
				result[i / 4][3][i % 4] = w[i][3];
			}

			return result;
		}
	}
}
