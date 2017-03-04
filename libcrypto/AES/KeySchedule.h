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
 * KeySchedule.h - Key Schedule Generation for AES
 */
#pragma once
#include "../libcrypto.h"
#include "Boxes.h"

namespace libcrypto
{
	namespace aes
	{
		const uint8_t RCON[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D };

		typedef struct
		{
			aes_block_t keys[15];
			aes_block_t& operator[](size_t idx) { return keys[idx]; }
		} aes_key_schedule_t;

		inline aes_key_schedule_t BuildSchedule(aes_key_128_t key)
		{
			// The first key is as-is
			aes_key_schedule_t result;
			result[0] = key;
			
			for(auto i = 1; i < AES_ROUNDS_128 + 1; i++)
			{
				// shift up the rightmost column of the previous key
				// substitute all bytes
				// xor the first byte with the RCON
				uint8_t t[4];
				t[0] = s[result[i - 1][1][3]] ^ RCON[i - 1];
				t[1] = s[result[i - 1][2][3]];
				t[2] = s[result[i - 1][3][3]];
				t[3] = s[result[i - 1][0][3]];

				// The first column of this round key is t xor the first column of the previous round key
				result[i][0][0] = t[0] ^ result[i - 1][0][0];
				result[i][1][0] = t[1] ^ result[i - 1][1][0];
				result[i][2][0] = t[2] ^ result[i - 1][2][0];
				result[i][3][0] = t[3] ^ result[i - 1][3][0];

				// The second column of this round key is the previous column xor the second column of the previous round key
				result[i][0][1] = result[i][0][0] ^ result[i - 1][0][1];
				result[i][1][1] = result[i][1][0] ^ result[i - 1][1][1];
				result[i][2][1] = result[i][2][0] ^ result[i - 1][2][1];
				result[i][3][1] = result[i][3][0] ^ result[i - 1][3][1];

				// The third column of this round key is the previous column xor the third column of the previous round key
				result[i][0][2] = result[i][0][1] ^ result[i - 1][0][2];
				result[i][1][2] = result[i][1][1] ^ result[i - 1][1][2];
				result[i][2][2] = result[i][2][1] ^ result[i - 1][2][2];
				result[i][3][2] = result[i][3][1] ^ result[i - 1][3][2];

				// The fourth column of this round key is the previous column xor the fourth column of the previous round key
				result[i][0][3] = result[i][0][2] ^ result[i - 1][0][3];
				result[i][1][3] = result[i][1][2] ^ result[i - 1][1][3];
				result[i][2][3] = result[i][2][2] ^ result[i - 1][2][3];
				result[i][3][3] = result[i][3][2] ^ result[i - 1][3][3];
			}

			return result;
		}

		inline aes_key_schedule_t BuildSchedule(Action action, aes_key_192_t key)
		{
			aes_key_schedule_t result;
			result[action == ENCRYPT ? 0 : AES_ROUNDS_192] = key;

			// The last two columns in the 192 bit key are scratch work, extra bytes are discarded in the last round key
			uint8_t t1[] = {
				key[0][5],
				key[1][5],
				key[2][5],
				key[3][5]
			};
			uint8_t t2[] = {
				key[0][4],
				key[1][4],
				key[2][4],
				key[3][4]
			};

			for(auto i = 1; i < AES_ROUNDS_192 + 1; i++)
			{
				// shift up the rightmost column of the previous key
				// substitute all bytes
				// xor the first byte with the RCON
				uint8_t t[4];
				t[0] = s[t2[1]] ^ RCON[i - 1];
				t[1] = s[t2[2]];
				t[2] = s[t2[3]];
				t[3] = s[t2[0]];

				// The first column of this round key is t xor the first column of the previous round key
				result[action == ENCRYPT ? i : 12 - i][0][0] = t[0] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][0][0];
				result[action == ENCRYPT ? i : 12 - i][1][0] = t[1] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][1][0];
				result[action == ENCRYPT ? i : 12 - i][2][0] = t[2] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][2][0];
				result[action == ENCRYPT ? i : 12 - i][3][0] = t[3] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][3][0];

				// The second column of this round key is the previous column xor the second column of the previous round key
				result[action == ENCRYPT ? i : 12 - i][0][1] = result[action == ENCRYPT ? i : 12 - i][0][0] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][0][1];
				result[action == ENCRYPT ? i : 12 - i][1][1] = result[action == ENCRYPT ? i : 12 - i][1][0] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][1][1];
				result[action == ENCRYPT ? i : 12 - i][2][1] = result[action == ENCRYPT ? i : 12 - i][2][0] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][2][1];
				result[action == ENCRYPT ? i : 12 - i][3][1] = result[action == ENCRYPT ? i : 12 - i][3][0] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][3][1];

				// The third column of this round key is the previous column xor the third column of the previous round key
				result[action == ENCRYPT ? i : 12 - i][0][2] = result[action == ENCRYPT ? i : 12 - i][0][1] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][0][2];
				result[action == ENCRYPT ? i : 12 - i][1][2] = result[action == ENCRYPT ? i : 12 - i][1][1] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][1][2];
				result[action == ENCRYPT ? i : 12 - i][2][2] = result[action == ENCRYPT ? i : 12 - i][2][1] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][2][2];
				result[action == ENCRYPT ? i : 12 - i][3][2] = result[action == ENCRYPT ? i : 12 - i][3][1] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][3][2];

				// The fourth column of this round key is the previous column xor the fourth column of the previous round key
				result[action == ENCRYPT ? i : 12 - i][0][3] = result[action == ENCRYPT ? i : 12 - i][0][2] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][0][3];
				result[action == ENCRYPT ? i : 12 - i][1][3] = result[action == ENCRYPT ? i : 12 - i][1][2] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][1][3];
				result[action == ENCRYPT ? i : 12 - i][2][3] = result[action == ENCRYPT ? i : 12 - i][2][2] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][2][3];
				result[action == ENCRYPT ? i : 12 - i][3][3] = result[action == ENCRYPT ? i : 12 - i][3][2] ^ result[action == ENCRYPT ? i - 1 : 12 - i + 1][3][3];

				// TODO: XOR scratch
			}

			return result;
		}

		inline aes_key_schedule_t BuildSchedule(Action action, aes_key_256_t key)
		{
			aes_key_schedule_t result;
			result[action == ENCRYPT ? 0 : AES_ROUNDS_256] = key;
			for(auto i = 1; i < AES_ROUNDS_256 + 1; i++)
			{
				//TODO: Implement
			}

			return result;
		}
	}
}
