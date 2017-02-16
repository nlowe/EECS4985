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
 * DES.cpp - Implementation of the DES algorithm
 */

#include "../libcrypto.h"
#include "../Util.h"
#include "DES.h"
#include "Math.h"
#include <iostream>

namespace libcrypto
{
	namespace des
	{
		int encrypt_file_impl(std::string, std::string, uint64_t, Optional<uint64_t>);
		int decrypt_file_impl(std::string, std::string, uint64_t, Optional<uint64_t>);

		/**
		 * A struct containing the context for DES
		 */
		typedef struct
		{
			Action Action;
			uint64_t RoundKeys[16];
			uint64_t* blocks;
			size_t blockCount;
		} Context;

		/**
		* Runs the specified block through the substitution boxes
		*/
		inline uint64_t substitute(uint64_t in)
		{
			return S0[extract6(in, 1)] |
				S1[extract6(in, 2)] |
				S2[extract6(in, 3)] |
				S3[extract6(in, 4)] |
				S4[extract6(in, 5)] |
				S5[extract6(in, 6)] |
				S6[extract6(in, 7)] |
				S7[extract6(in, 8)];
		}

		/**
		 * Transforms the block using the specified key schedule
		 */
		uint64_t TransformBlock(Context* ctx, uint64_t block)
		{
			// Perform the initial permutation on the plaintext
			auto permutedBlock = InitialBlockPermutation(block);

			// Split the plaintext into 32 bit left and right halves
			uint64_t left, right;

			// Perform the initial permutation
			split64(permutedBlock, left, right);

			// 16 fistel rounds
			for(auto i = 0; i < 16; i++)
			{
				// Expand and permute the right half of the block to 48 bits
				auto expandedRightHalf = BlockPE32To48(right);

				// XOR with the round key
				// Important note: The correct round key (different order for encrypt vs. decyrpt) is taken care of when initializing the DES Context
				auto roundKey = ctx->RoundKeys[i];
				expandedRightHalf ^= roundKey;

				// Substitute via S-Boxes
				auto substituted = substitute(expandedRightHalf);

				// Perform the final permutation
				auto ciphertext = BlockP32(substituted);

				// XOR with the left half
				ciphertext ^= left;

				// Swap the half-blocks for the next round
				left = right;
				right = ciphertext;
			}

			auto finalBlock = join64(right, left);
			return FinalBlockPermutation(finalBlock);
		}

		/**
		 * Check the key against known weak, semi-weak, and potentially weak keys
		 */
		int __check_key_internal(uint64_t key)
		{
			auto strength = CheckKey(key);

#if !defined(NOENFORCE_WEAK_KEYS)
			if(strength == WEAK)
			{
				std::cerr << "WARNING: Weak Key specified" << std::endl;
#if defined(ENFORCE_NO_WEAK_KEYS)
				std::cerr << "Recompile with WARN_WEAK_KEYS or NOENFORCE_WEAK_KEYS to allow weak keys" << std::endl;
				return ERR_KEY_TOO_WEAK;
#endif
			}
#endif

#if !defined(NOENFORCE_SEMI_WEAK_KEYS)
			if(strength == SEMI_WEAK)
			{
				std::cerr << "WARNING: Semi-Weak Key specified" << std::endl;
#if defined(ENFORCE_NO_SEMI_WEAK_KEYS)
				std::cerr << "Recompile with WARN_SEMI_WEAK_KEYS or NOENFORCE_SEMI_WEAK_KEYS to allow semi-weak keys" << std::endl;
				return ERR_KEY_TOO_WEAK;
#endif
			}
#endif

#if !defined(NOENFORCE_POSSIBLY_WEAK_KEYS)
			if(strength == POSSIBLY_WEAK)
			{
				std::cerr << "WARNING: Possibly-weak Key specified" << std::endl;
#if defined(ENFORCE_NO_POSSIBLY_WEAK_KEYS)
				std::cerr << "Recompile with WARN_POSSIBLY_WEAK_KEYS or NOENFORCE_POSSIBLY_WEAK_KEYS to allow possibly-weak keys" << std::endl;
				return ERR_KEY_TOO_WEAK;
#endif
			}
#endif

			return SUCCESS;
		}

		/**
		 * Check the size to ensure it is a multiple of 8 bytes
		 */
		inline bool checkSize(size_t len)
		{
			if(len % 8 != 0)
			{
				std::cerr << "Input must be a multiple of 8 bytes (got " << len << " bytes)" << std::endl;
				return false;
			}

			return true;
		}

		/**
		 * Initialize the DES Context using the specified key
		 */
		Context* init(uint64_t key, char* data, size_t len, libcrypto::Action action, int& result)
		{
			// Check for valid input sizes
			if (!checkSize(len))
			{
				result = ERR_SIZE;
				return nullptr;
			}

			// Check the key strength (if enabled at compilation time)
			auto keyCheck = __check_key_internal(key);
			if (keyCheck != SUCCESS)
			{
				result = keyCheck;
				return nullptr;
			}

			auto ctx = new Context;
			ctx->Action = action;

			// Initialize the key
			//   1. Compress and Permute the key into 56 bits
			//   2. Split the key into two 28 bit halves
			uint64_t keyLeft, keyRight;
			split56(KeyPC64To56(key), keyLeft, keyRight);

			for(auto i = 0; i < 16; i++)
			{
				rotL28(keyLeft, RotationSchedule[i]);
				rotL28(keyRight, RotationSchedule[i]);

				ctx->RoundKeys[action == ENCRYPT ? i : 15-i] = KeyPC56To48(join56(keyLeft, keyRight));
			}

			ctx->blocks = reinterpret_cast<uint64_t*>(data);
			ctx->blockCount = len / 8;

			result = SUCCESS;
			return ctx;
		}

		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, uint64_t key)
		{
			// Initialize the crypto context
			int initStatus;
			auto ctx = init(key, data, len, ENCRYPT, initStatus);
			if (initStatus != SUCCESS) return initStatus;

			// Encrypt all the things
			size_t i = 0;
			while(i < ctx->blockCount)
			{
				auto block = _byteswap_uint64(ctx->blocks[i]);
				auto encrypted = TransformBlock(ctx, block);
				ctx->blocks[i++] = _byteswap_uint64(encrypted);
			}

			// Free the crypto context and return success
			delete ctx;
			return SUCCESS;
		}

		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, uint64_t key, uint64_t iv)
		{
			// Initialize the crypto context
			int initStatus;
			auto ctx = init(key, data, len, ENCRYPT, initStatus);
			if (initStatus != SUCCESS) return initStatus;

			auto previousBlock = iv;

			// Encrypt all the things
			size_t i = 0;
			while(i < ctx->blockCount)
			{
				auto block = _byteswap_uint64(ctx->blocks[i]);
				block ^= previousBlock;
				auto encrypted = TransformBlock(ctx, block);
				previousBlock = encrypted;
				ctx->blocks[i++] = _byteswap_uint64(encrypted);
			}

			// Free the crypto context and return success
			delete ctx;
			return SUCCESS;
		}

		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, uint64_t key)
		{
			// Initialize the crypto context
			int initStatus;
			auto ctx = init(key, data, len, DECRYPT, initStatus);
			if (initStatus != SUCCESS) return initStatus;

			// Decrypt all the things
			size_t i = 0;
			while(i < ctx->blockCount)
			{
				auto block = _byteswap_uint64(ctx->blocks[i]);
				auto decrypted = TransformBlock(ctx, block);
				ctx->blocks[i++] = _byteswap_uint64(decrypted);
			}

			// Free the crypto context and return success
			delete ctx;
			return SUCCESS;
		}

		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, uint64_t key, uint64_t iv)
		{
			// Initialize the crypto context
			int initStatus;
			auto ctx = init(key, data, len, DECRYPT, initStatus);
			if (initStatus != SUCCESS) return initStatus;

			auto previousBlock = iv;

			// Decrypt all the things
			size_t i = 0;
			while(i < ctx->blockCount)
			{
				auto block = _byteswap_uint64(ctx->blocks[i]);
				auto decrypted = TransformBlock(ctx, block);
				decrypted ^= previousBlock;
				previousBlock = block;
				ctx->blocks[i++] = _byteswap_uint64(decrypted);
			}

			// Free the crypto context and return success
			delete ctx;
			return SUCCESS;
		}
	}
}
