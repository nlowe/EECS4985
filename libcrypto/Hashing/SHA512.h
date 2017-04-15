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
 * SHA512.h - Public interface for calculating SHA512 digests
 */

#pragma once
#include <string>
#include "../export.h"

#define SHA512_BLOCK_SIZE_BYTES 128

namespace libcrypto
{
	namespace hashing
	{
		namespace SHA512
		{
			/** Compute the 8-byte SHA512 digest for the buffer of the specified length */
			LIBCRYPTO_PUB char* ComputeHash(const char* buff, size_t len);
			/** Compute the 8-byte SHA512 digest for the specified string */
			LIBCRYPTO_PUB char* ComputeHash(std::string str);
			/** Compute the partial hash using the previous state. The size of the buffer must be a multiple of 128 bytes */
			LIBCRYPTO_PUB void ComputePartialHash(char* previous, const char* buff, size_t len, bool initialBlock, size_t* totalLength);
		}
	}
}
