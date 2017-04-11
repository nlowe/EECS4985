#include "SHA512.h"
#include "constants.h"
#include "../libcrypto.h"

namespace libcrypto
{
	namespace hashing
	{
		namespace SHA512
		{
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

				uint64_t W[80] = { 0 };
			}State;

			typedef struct
			{
				uint64_t& operator[](size_t idx) { return M[idx]; }
				uint64_t M[16] = { 0 };
			}MessageBlock;

			inline uint64_t ch(uint64_t x, uint64_t y, uint64_t z)
			{
				return (x & y) ^ (~x & z);
			}

			inline uint64_t maj(uint64_t x, uint64_t y, uint64_t z)
			{
				return (x & y) ^ (x & z) ^ (y & z);
			}

			inline uint64_t rotr(uint64_t x, uint8_t n)
			{
				return x >> n | x << (64 - n);
			}

			inline uint64_t SIGMA0(uint64_t x)
			{
				return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
			}

			inline uint64_t SIGMA1(uint64_t x)
			{
				return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
			}

			inline uint64_t sigma0(uint64_t x)
			{
				return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
			}

			inline uint64_t sigma1(uint64_t x)
			{
				return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
			}

			inline void GenSchedule(State* state, MessageBlock M)
			{
				for(auto t = 0; t < 16; t++)
				{
					state->W[t] = M[t];
				}
				for(auto t = 16; t < 80; t++)
				{
					state->W[t] = sigma1(state->W[t - 2]) + state->W[t - 7] + sigma0(state->W[t - 15]) + state->W[t - 16];
				}
			}

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

				for(auto t = 0; t <= 79; t++)
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

			MessageBlock ExtractAndPadBlock(const char* buff, size_t off, size_t len)
			{
				MessageBlock result;

				// Extract as many bytes from the buffer into the block that we can
				uint64_t i = 0;
				for(; i < 128 && (off + i) < len; i++)
				{
					result[i / 8] |= (0ull | (0xff & buff[off + i])) << ((7 - i) << 3);
				}
				// If we ran out of bytes, insert padding
				if (i < 128)
				{
					// A '1' bit after the message followed by zeroes
					result[i / 8] |= (0ull | 0x80) << ((7 - (i % 8)) << 3);
					if(len - off < 112)
					{
						// with the length we extracted at the end
						result[15] = len << 3;
					}
				}

				return result;
			}

			LIBCRYPTO_PUB char* ComputeHash(const char* buff, size_t len)
			{
				// TODO Padding
				auto state = new State();
				auto blocks = len / 128 + (len % 128 != 0 ? 1 : 0);

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
						auto M = ExtractAndPadBlock(buff, i * 128, len);
						round(state, M);
					}

					// Final padding comes after
					if(len % 128 == 0)
					{
						// If we're exactly a multiple of 128 bytes, the first byte of the padding block needs to be set
						MessageBlock M;
						M[0] = 1ull << 63;
						M[15] = len << 3;
						round(state, M);
					}
					else if(len - (blocks - 1) * 128 >= 112)
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
		}
	}
}
