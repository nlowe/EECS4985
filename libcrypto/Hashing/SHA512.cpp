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
 * SHA512.cpp - Implementation of SHA2 for 512-bit digests
 */

#include <stdexcept>
#include "SHA512.h"
#include "constants.h"
#include "../libcrypto.h"

/** The number of internal rounds performed on each block of data */
#define SHA512_ROUNDS_PER_BLOCK 80

namespace libcrypto
{
	namespace hashing
	{
		namespace SHA512
		{
			/** The state used across rounds of the hash */
			typedef struct
			{
				uint64_t a = 0x6a09e667f3bcc908;
				uint64_t b = 0xbb67ae8584caa73b;
				uint64_t c = 0x3c6ef372fe94f82b;
				uint64_t d = 0xa54ff53a5f1d36f1;
				uint64_t e = 0x510e527fade682d1;
				uint64_t f = 0x9b05688c2b3e6c1f;
				uint64_t g = 0x1f83d9abfb41bd6b;
				uint64_t h = 0x5be0cd19137e2179;

				uint64_t W[SHA512_ROUNDS_PER_BLOCK] = { 0 };
			}State;

			/** A 1024-bit block that SHA512 Operates on */
			typedef struct
			{
				uint64_t& operator[](size_t idx) { return M[idx]; }
				uint64_t M[16] = { 0 };
			}MessageBlock;

			/** Choose Functipn: Bit i is selected from y if it is set in x, otherwise it is selected from z */
			inline uint64_t ch(uint64_t x, uint64_t y, uint64_t z)
			{
				return (x & y) ^ (~x & z);
			}

			/** Majority Function: Bit i is set if it is set in at least two of three inputs */
			inline uint64_t maj(uint64_t x, uint64_t y, uint64_t z)
			{
				return (x & y) ^ (x & z) ^ (y & z);
			}

			/** Right-rotate x by the specified amount */
			inline uint64_t rotr(uint64_t x, uint8_t n)
			{
				return x >> n | x << (64 - n);
			}

			/** Big-Sigma 0 from FIPS 1SHA512_ROUNDS_PER_BLOCK-4 */
			inline uint64_t SIGMA0(uint64_t x)
			{
				return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
			}

			/** Big-Sigma 0 from FIPS 1SHA512_ROUNDS_PER_BLOCK-4 */
			inline uint64_t SIGMA1(uint64_t x)
			{
				return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
			}

			/** Little-Sigma 0 from FIPS 1SHA512_ROUNDS_PER_BLOCK-4 */
			inline uint64_t sigma0(uint64_t x)
			{
				return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
			}

			/** Little-Sigma 1 from FIPS 1SHA512_ROUNDS_PER_BLOCK-4 */
			inline uint64_t sigma1(uint64_t x)
			{
				return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
			}

			/** Generate the word schedule for the round from the specified message block */
			inline void GenSchedule(State* state, MessageBlock M)
			{
				for(auto t = 0; t < 16; t++)
				{
					state->W[t] = M[t];
				}
				for(auto t = 16; t < SHA512_ROUNDS_PER_BLOCK; t++)
				{
					state->W[t] = sigma1(state->W[t - 2]) + state->W[t - 7] + sigma0(state->W[t - 15]) + state->W[t - 16];
				}
			}

			/** Perform an iteration of SHA512 on the specified message block */
			inline void round(State* state, MessageBlock M)
			{
				auto a = state->a;
				auto b = state->b;
				auto c = state->c;
				auto d = state->d;
				auto e = state->e;
				auto f = state->f;
				auto g = state->g;
				auto h = state->h;

				GenSchedule(state, M);

				for(auto t = 0; t < SHA512_ROUNDS_PER_BLOCK; t++)
				{
					auto t1 = h + SIGMA1(e) + ch(e, f, g) + K[t] + state->W[t];
					auto t2 = SIGMA0(a) + maj(a, b, c);
					h = g;
					g = f;
					f = e;
					e = d + t1;
					d = c;
					c = b;
					b = a;
					a = t1 + t2;
				}

				state->a += a;
				state->b += b;
				state->c += c;
				state->d += d;
				state->e += e;
				state->f += f;
				state->g += g;
				state->h += h;
			}

			/** Extract and pad up to 1024 bits from the buffer. If less than 112 bytes were extracted, the length field is appended after padding */
			MessageBlock ExtractAndPadBlock(const char* buff, size_t off, size_t len, size_t* realLen = nullptr)
			{
				MessageBlock result;

				// Extract as many bytes from the buffer into the block that we can
				uint64_t i = 0;
				for(; i < SHA512_BLOCK_SIZE_BYTES && (off + i) < len; i++)
				{
					result[i / 8] |= (0ull | (0xff & buff[off + i])) << ((7 - i) << 3);
				}
				// If we ran out of bytes, insert padding
				if (i < SHA512_BLOCK_SIZE_BYTES)
				{
					// A '1' bit after the message followed by zeroes
					result[i / 8] |= (0ull | 0x80) << ((7 - (i % 8)) << 3);
					if(len - off < 112)
					{
						// with the length we extracted at the end
						result[15] = (realLen != nullptr ? *realLen : len) << 3;
					}
				}

				return result;
			}

			LIBCRYPTO_PUB char* ComputeHash(const char* buff, size_t len)
			{
				auto state = new State();
				auto blocks = len / SHA512_BLOCK_SIZE_BYTES + (len % SHA512_BLOCK_SIZE_BYTES != 0 ? 1 : 0);

				if(len == 0 || (len == 1 && buff[0] == 0))
				{
					// Special case for empty string
					MessageBlock M;
					M[0] = 1ull << 63;
					round(state, M);
				}
				else
				{
					for(auto i = 0; i < blocks; i++)
					{
						auto M = ExtractAndPadBlock(buff, i * SHA512_BLOCK_SIZE_BYTES, len);
						round(state, M);
					}

					// Final padding comes after
					if(len % SHA512_BLOCK_SIZE_BYTES == 0)
					{
						// If we're exactly a multiple of 128 bytes, the first byte of the padding block needs to be set
						MessageBlock M;
						M[0] = 1ull << 63;
						M[15] = len << 3;
						round(state, M);
					}
					else if(len - (blocks - 1) * SHA512_BLOCK_SIZE_BYTES >= 112)
					{
						// Otherwise the padding bit was already set, just append the length
						MessageBlock M;
						M[15] = len << 3;
						round(state, M);
					}

				}

				
				auto result = new char[64]{ 0 };

				libcrypto::buffStuff64(result,  0, state->a);
				libcrypto::buffStuff64(result,  8, state->b);
				libcrypto::buffStuff64(result, 16, state->c);
				libcrypto::buffStuff64(result, 24, state->d);
				libcrypto::buffStuff64(result, 32, state->e);
				libcrypto::buffStuff64(result, 40, state->f);
				libcrypto::buffStuff64(result, 48, state->g);
				libcrypto::buffStuff64(result, 56, state->h);

				delete state;
				return result;
			}

			LIBCRYPTO_PUB char* ComputeHash(std::string str)
			{
				return ComputeHash(str.c_str(), str.length());
			}

			LIBCRYPTO_PUB void ComputePartialHash(char* prev, const char* buff, size_t len, bool initialBlock, size_t* totalLength)
			{
				if (totalLength == nullptr && len % SHA512_BLOCK_SIZE_BYTES != 0) throw std::length_error("Non-final input block must be a multiple of 128 bytes");

				auto blocks = len / SHA512_BLOCK_SIZE_BYTES + (totalLength != nullptr && len % SHA512_BLOCK_SIZE_BYTES != 0 ? 1 : 0);

				auto state = new State();
				auto previousState = reinterpret_cast<uint64_t*>(prev);

				if(!initialBlock)
				{
					state->a = _byteswap_uint64(previousState[0]);
					state->b = _byteswap_uint64(previousState[1]);
					state->c = _byteswap_uint64(previousState[2]);
					state->d = _byteswap_uint64(previousState[3]);
					state->e = _byteswap_uint64(previousState[4]);
					state->f = _byteswap_uint64(previousState[5]);
					state->g = _byteswap_uint64(previousState[6]);
					state->h = _byteswap_uint64(previousState[7]);
				}

				for(auto i = 0; i < blocks; i++)
				{
					auto M = ExtractAndPadBlock(buff, i * SHA512_BLOCK_SIZE_BYTES, len, totalLength);
					round(state, M);
				}

				if(totalLength != nullptr)
				{
					// Final padding comes after
					if(len % SHA512_BLOCK_SIZE_BYTES == 0)
					{
						// If we're exactly a multiple of 128 bytes, the first byte of the padding block needs to be set
						MessageBlock M;
						M[0] = 1ull << 63;
						M[15] = *totalLength << 3;
						round(state, M);
					}
					else if(len - (blocks - 1) * SHA512_BLOCK_SIZE_BYTES >= 112)
					{
						// Otherwise the padding bit was already set, just append the length
						MessageBlock M;
						M[15] = *totalLength << 3;
						round(state, M);
					}
				}

				previousState[0] = _byteswap_uint64(state->a);
				previousState[1] = _byteswap_uint64(state->b);
				previousState[2] = _byteswap_uint64(state->c);
				previousState[3] = _byteswap_uint64(state->d);
				previousState[4] = _byteswap_uint64(state->e);
				previousState[5] = _byteswap_uint64(state->f);
				previousState[6] = _byteswap_uint64(state->g);
				previousState[7] = _byteswap_uint64(state->h);

				delete state;
			}
		}
	}
}
