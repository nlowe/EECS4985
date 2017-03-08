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
#include "Types.h"
#include "../export.h"

#define AES_WORDS_128 4
#define AES_WORDS_192 6
#define AES_WORDS_256 8

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

		LIBCRYPTO_PUB aes_key_schedule_t BuildSchedule(aes_key_128_t key);

		LIBCRYPTO_PUB aes_key_schedule_t BuildSchedule(aes_key_192_t key);

		LIBCRYPTO_PUB aes_key_schedule_t BuildSchedule(aes_key_256_t key);
	}
}
