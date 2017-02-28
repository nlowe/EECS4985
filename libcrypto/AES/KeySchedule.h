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
		const int8_t RCON[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D };

		typedef struct
		{
			aes_block_t keys[14];
			aes_block_t& operator[](size_t idx) { return keys[idx]; }
		} aes_key_schedule_t;
		
		inline void shiftColumn(aes_key_128_t& key, size_t num)
		{
			auto tmp = key[num];
			key[num] = key[4 + num];
			key[4 + num] = key[8 + num];
			key[8 + num] = key[12 + num];
			key[12 + num] = tmp;
		}

		inline aes_key_schedule_t BuildSchedule(Action action, aes_key_128_t key)
		{
			aes_key_schedule_t result;
			result[action == ENCRYPT ? 0 : 9] = key;
			
			int8_t t[4];
			for(auto i = 1; i < 10; i++)
			{
				t[0] = s[key[7]] ^ RCON[i-1];
				t[1] = s[key[11]];
				t[2] = s[key[15]];
				t[3] = s[key[3]];

				result[action == ENCRYPT ? i : 8 - i][0]  = t[0] ^ result[action == ENCRYPT ? i - 1 : 8 - i + 1][0];
				result[action == ENCRYPT ? i : 8 - i][4]  = t[1] ^ result[action == ENCRYPT ? i - 1 : 8 - i + 1][4];
				result[action == ENCRYPT ? i : 8 - i][8]  = t[2] ^ result[action == ENCRYPT ? i - 1 : 8 - i + 1][8];
				result[action == ENCRYPT ? i : 8 - i][12] = t[3] ^ result[action == ENCRYPT ? i - 1 : 8 - i + 1][12];
			}

			return result;
		}

		inline aes_key_schedule_t BuildSchedule(Action action, aes_key_192_t key)
		{
			aes_key_schedule_t result;
			result[action == ENCRYPT ? 0 : 11] = key;
			for(auto i = 1; i < 12; i++)
			{
				
			}

			return result;
		}

		inline aes_key_schedule_t BuildSchedule(Action action, aes_key_256_t key)
		{
			aes_key_schedule_t result;
			result[action == ENCRYPT ? 0 : 13] = key;
			for(auto i = 1; i < 14; i++)
			{
				
			}

			return result;
		}
	}
}
