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
 * libcrypto.h - Public interface for libcrypto
 */

#pragma once
#include <cstdint>
#include <random>

namespace libcrypto
{
	/**
	 * The mode of operation for ciphers
	 */
	enum Mode
	{
		ECB,
		CBC,
		UNKNOWN_MODE
	};

	/**
	 * The action to perform on the specified buffer
	 */
	enum Action
	{
		ENCRYPT,
		DECRYPT,
		UNKNOWN_ACTION
	};

	/**
	 * Create a random 32-bit integer
	 */
	inline uint64_t Random32()
	{
		std::random_device rd;
		std::mt19937_64 gen(rd());

		std::uniform_int_distribution<uint32_t> half;
		return half(gen) | 0ull;
	}

	/**
	 * Create a random 64-bit integer
	 */
	inline uint64_t Random64()
	{
		std::random_device rd;
		std::mt19937_64 gen(rd());

		std::uniform_int_distribution<uint64_t> full;
		return full(gen);
	}

	/**
	 * Pack the specified 64-bit integer into the buffer starting at the specified offset, accounting for endianness
	 */
	inline void buffStuff64(char* buff, size_t offset, uint64_t block)
	{
		buff[offset]     = block >> 56 & 0xFF;
		buff[offset + 1] = block >> 48 & 0xFF;
		buff[offset + 2] = block >> 40 & 0xFF;
		buff[offset + 3] = block >> 32 & 0xFF;
		buff[offset + 4] = block >> 24 & 0xFF;
		buff[offset + 5] = block >> 16 & 0xFF;
		buff[offset + 6] = block >>  8 & 0xFF;
		buff[offset + 7] = block       & 0xFF;
	}

	const int SUCCESS = 0;
	const int ERR_MODE = -2;
	const int ERR_ACTION = -3;
	const int ERR_BAD_INPUT = -4;
	const int ERR_TOO_BIG = -5;
	const int ERR_BAD_OUTPUT = -6;
	const int ERR_KEY_TOO_WEAK = -7;
	const int ERR_SIZE = -8;
	const int ERR_NOT_IMPLEMENTED = -9;
}
