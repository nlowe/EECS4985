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
 * AES128.cpp - Implementation of the AES algorithm with 128-bit keys
 */
#include "AES.h"
#include "KeySchedule.h"
#include "../libcrypto.h"
#include "Shared.h"

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

		// Create an AES context for 128-bit keys
		Context* init(Action action, size_t len, aes_key_128_t key, int& result)
		{
			if(len % AES_BLOCK_SIZE != 0)
			{
				result = ERR_BAD_INPUT;
				return nullptr;
			}

			auto ctx = new Context();

			ctx->Action = action;
			ctx->BlockCount = len / AES_BLOCK_SIZE;

			ctx->RoundKeys = BuildSchedule(action, key);
			return ctx;
		}

		inline void transform_block_128(aes_block_t& block, Context* ctx)
		{
			for(auto i = 0; i < AES_ROUNDS_128 - 1; i++)
			{
				SubBytes(block);
				ShiftRows(block);
				MixColumns(block);
				block ^= ctx->RoundKeys[i];
			}

			SubBytes(block);
			ShiftRows(block);
			block ^= ctx->RoundKeys[AES_ROUNDS_128 - 1];
		}

		inline void inverse_transform_block_128(aes_block_t& block, Context* ctx)
		{
			InvSubBytes(block);
			InvShiftRows(block);
			block ^= ctx->RoundKeys[0];

			for(auto i = 1; i < AES_ROUNDS_128; i++)
			{
				InvSubBytes(block);
				InvShiftRows(block);
				InvMixColumns(block);
				block ^= ctx->RoundKeys[i];
			}
		}

		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, aes_key_128_t key)
		{
			int result;
			auto ctx = init(ENCRYPT, len, key, result);
			if (ctx == nullptr) return result;

			for(auto i = 0; i < len; i+= AES_BLOCK_SIZE)
			{
				auto block = make_block(data, i);
				transform_block_128(block, ctx);
				buffstuff(data, i, block);
			}

			delete ctx;
			return ERR_NOT_IMPLEMENTED;
		}

		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, aes_key_128_t key, aes_block_t IV)
		{
			int result;
			auto ctx = init(ENCRYPT, len, key, result);
			if (ctx == nullptr) return result;

			auto previousBlock = IV;

			for(auto i = 0; i < len; i+= AES_BLOCK_SIZE)
			{
				auto block = make_block(data, i) ^ previousBlock;
				transform_block_128(block, ctx);
				previousBlock = block;
				buffstuff(data, i, block);
			}

			delete ctx;
			return ERR_NOT_IMPLEMENTED;
		}

		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, aes_key_128_t key)
		{
			int result;
			auto ctx = init(ENCRYPT, len, key, result);
			if (ctx == nullptr) return result;

			for(auto i = 0; i < len; i+= AES_BLOCK_SIZE)
			{
				auto block = make_block(data, i);
				inverse_transform_block_128(block, ctx);
				buffstuff(data, i, block);
			}

			delete ctx;
			return ERR_NOT_IMPLEMENTED;
		}

		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, aes_key_128_t key, aes_block_t IV)
		{
			int result;
			auto ctx = init(ENCRYPT, len, key, result);
			if (ctx == nullptr) return result;

			auto previousBlock = IV;

			for(auto i = 0; i < len; i+= AES_BLOCK_SIZE)
			{
				auto block = make_block(data, i);
				auto ciphertext = block;
				inverse_transform_block_128(block, ctx);
				block ^= previousBlock;
				previousBlock = ciphertext;
				buffstuff(data, i, block);
			}

			delete ctx;
			return ERR_NOT_IMPLEMENTED;
		}
	}
}

