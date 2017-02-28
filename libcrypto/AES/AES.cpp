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
 * aes.cpp - Implementation of the AES algorithm
 */
#include "AES.h"
#include "KeySchedule.h"
#include "../libcrypto.h"

namespace libcrypto
{
	namespace aes
	{
		typedef struct
		{
			Action Action;
			aes_key_schedule_t RoundKeys;
			size_t BlockCount;
		} Context;

		Context* __mk_ctx(Action action, size_t len, int& result)
		{
			if(len % 16 != 0)
			{
				result = ERR_BAD_INPUT;
				return nullptr;
			}

			auto ctx = new Context();

			ctx->Action = action;
			ctx->BlockCount = len / 16;

			return ctx;
		}

		// Create an AES context for 128-bit keys
		Context* init(Action action, size_t len, aes_key_128_t key, int& result)
		{
			auto ctx = __mk_ctx(action, len, result);
			if (ctx == nullptr) return nullptr;

			ctx->RoundKeys = BuildSchedule(action, key);
			return ctx;
		}

		// Create an AES context for 192-bit keys
		Context* init(Action action, size_t len, aes_key_192_t key, int& result)
		{
			auto ctx = __mk_ctx(action, len, result);
			if (ctx == nullptr) return nullptr;

			ctx->RoundKeys = BuildSchedule(action, key);
			return ctx;
		}

		// Create an AES context for 256-bit keys
		Context* init(Action action, size_t len, aes_key_256_t key, int& result)
		{
			auto ctx = __mk_ctx(action, len, result);
			if (ctx == nullptr) return nullptr;

			ctx->RoundKeys = BuildSchedule(action, key);
			return ctx;
		}

		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, aes_key_128_t key)
		{
			return ERR_NOT_IMPLEMENTED;
		}

		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, aes_key_128_t key, aes_block_t IV)
		{
			return ERR_NOT_IMPLEMENTED;
		}

		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, aes_key_128_t key)
		{
			return ERR_NOT_IMPLEMENTED;
		}

		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, aes_key_128_t key, aes_block_t IV)
		{
			return ERR_NOT_IMPLEMENTED;
		}

		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, aes_key_192_t key)
		{
			return ERR_NOT_IMPLEMENTED;
		}

		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, aes_key_192_t key, aes_block_t IV)
		{
			return ERR_NOT_IMPLEMENTED;
		}

		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, aes_key_192_t key)
		{
			return ERR_NOT_IMPLEMENTED;
		}

		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, aes_key_192_t key, aes_block_t IV)
		{
			return ERR_NOT_IMPLEMENTED;
		}

		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, aes_key_256_t key)
		{
			return ERR_NOT_IMPLEMENTED;
		}

		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, aes_key_256_t key, aes_block_t IV)
		{
			return ERR_NOT_IMPLEMENTED;
		}

		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, aes_key_256_t key)
		{
			return ERR_NOT_IMPLEMENTED;
		}

		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, aes_key_256_t key, aes_block_t IV)
		{
			return ERR_NOT_IMPLEMENTED;
		}
	}
}

