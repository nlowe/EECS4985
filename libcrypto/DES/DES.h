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
 * DES.h - API for the DES algorithm
 */
#pragma once
#include "Boxes.h"
#include "../export.h"

#define DES_BLOCK_SIZE_BYTES 8

 // Enforce weak keys by default
#if !defined(NOENFORCE_WEAK_KEYS) && !defined(WARN_WEAK_KEYS)
#define ENFORCE_NO_WEAK_KEYS 1
#endif

 // Enforce Semi-Weak keys by default
#if !defined(NOENFORCE_SEMI_WEAK_KEYS) && !defined(WARN_SEMI_WEAK_KEYS)
#define ENFORCE_NO_SEMI_WEAK_KEYS 1
#endif

 // Warn on possibly weak keys by default
#if !defined(NOENFORCE_POSSIBLY_WEAK_KEYS) && !defined(ENFORCE_NO_POSSIBLY_WEAK_KEYS)
#define WARN_POSSIBLY_WEAK_KEYS 1
#endif

namespace libcrypto
{
	namespace des
	{
		/** The Strength of a DES key */
		enum KeyStrength { WEAK, SEMI_WEAK, POSSIBLY_WEAK, NOT_WEAK };

		/**
		 * Check the strength of the provided key
		 */
		LIBCRYPTO_PUB KeyStrength CheckKey(uint64_t key);

		/**
		 * Encrypt the buffer of the specified length using the provided key in ECB mode. The buffer must be a multiple of 8 bytes
		 */
		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, uint64_t key);
		/**
		 * Encrypt the buffer of the specified length using the provided key and initialization vector in CBC mode. The buffer must be a multiple of 8 bytes
		 */
		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, uint64_t key, uint64_t IV);

		/**
		 * Encrypt the buffer of the specified length using the provided key in ECB mode. The buffer must be a multiple of 8 bytes
		 */
		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, uint64_t key);
		/**
		 * Encrypt the buffer of the specified length using the provided key and initialization vector in CBC mode. The buffer must be a multiple of 8 bytes
		 */
		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, uint64_t key, uint64_t IV);
	}
}
