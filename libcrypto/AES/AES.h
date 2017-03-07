/*
 * Copyright (c) 2016 Nathan Lowe
 *
 * Permission is hereby granted; free of charge; to any person obtaining a copy
 * of this software and associated documentation files (the "Software"); to deal
 * in the Software without restriction; including without limitation the rights
 * to use; copy; modify; merge; publish; distribute; sublicense; and/or sell
 * copies of the Software; and to permit persons to whom the Software is
 * furnished to do so; subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS"; WITHOUT WARRANTY OF ANY KIND; EXPRESS OR
 * IMPLIED; INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY;
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM; DAMAGES OR OTHER
 * LIABILITY; WHETHER IN AN ACTION OF CONTRACT; TORT OR OTHERWISE; ARISING FROM;
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * AES.h - API for the AES algorithm
 */
#pragma once
#include "../export.h"
#include "Types.h"
#include <iomanip>

#define AES_BLOCK_SIZE 16
#define AES_ROUNDS_128 10
#define AES_ROUNDS_192 12
#define AES_ROUNDS_256 14

namespace libcrypto
{
	namespace aes
	{
		inline void print_block(aes_block_t& block)
		{
			printf("%02x %02x %02x %02x\n", block[0][0], block[0][1], block[0][2], block[0][3]);
			printf("%02x %02x %02x %02x\n", block[1][0], block[1][1], block[1][2], block[1][3]);
			printf("%02x %02x %02x %02x\n", block[2][0], block[2][1], block[2][2], block[2][3]);
			printf("%02x %02x %02x %02x\n", block[3][0], block[3][1], block[3][2], block[3][3]);
		}

		inline void buffstuff(char* buff, size_t off, aes_block_t& block)
		{
			buff[off + 0] = block[0][0]; buff[off + 4] = block[0][1]; buff[off +  8] = block[0][2]; buff[off + 12] = block[0][3];
			buff[off + 1] = block[1][0]; buff[off + 5] = block[1][1]; buff[off +  9] = block[1][2]; buff[off + 13] = block[1][3];
			buff[off + 2] = block[2][0]; buff[off + 6] = block[2][1]; buff[off + 10] = block[2][2]; buff[off + 14] = block[2][3];
			buff[off + 3] = block[3][0]; buff[off + 7] = block[3][1]; buff[off + 11] = block[3][2]; buff[off + 15] = block[3][3];
		}

		inline aes_block_t make_block(char* buff, size_t offset)
		{
			aes_block_t block;

			block[0][0] = buff[offset];     block[0][1] = buff[offset + 4]; block[0][2] = buff[offset + 8];  block[0][3] = buff[offset + 12];
			block[1][0] = buff[offset + 1]; block[1][1] = buff[offset + 5]; block[1][2] = buff[offset + 9];  block[1][3] = buff[offset + 13];
			block[2][0] = buff[offset + 2]; block[2][1] = buff[offset + 6]; block[2][2] = buff[offset + 10]; block[2][3] = buff[offset + 14];
			block[3][0] = buff[offset + 3]; block[3][1] = buff[offset + 7]; block[3][2] = buff[offset + 11]; block[3][3] = buff[offset + 15];

			return block;
		}

		inline aes_key_192_t make_key_192(char* buff)
		{
			aes_key_192_t k;

			k[0][0] = buff[0]; k[0][1] = buff[4]; k[0][2] = buff[8];  k[0][3] = buff[12]; k[0][4] = buff[16]; k[0][5] = buff[20];
			k[1][0] = buff[1]; k[1][1] = buff[5]; k[1][2] = buff[9];  k[1][3] = buff[13]; k[1][4] = buff[17]; k[1][5] = buff[21];
			k[2][0] = buff[2]; k[2][1] = buff[6]; k[2][2] = buff[10]; k[2][3] = buff[14]; k[2][4] = buff[18]; k[2][5] = buff[22];
			k[3][0] = buff[3]; k[3][1] = buff[7]; k[3][2] = buff[11]; k[3][3] = buff[15]; k[3][4] = buff[19]; k[3][5] = buff[23];

			return k;
		}

		inline aes_key_256_t make_key_256(char* buff)
		{
			aes_key_256_t k;

			k[0][0] = buff[0]; k[0][1] = buff[4]; k[0][2] = buff[8];  k[0][3] = buff[12]; k[0][4] = buff[16]; k[0][5] = buff[20]; k[0][6] = buff[24]; k[0][7] = buff[28];
			k[1][0] = buff[1]; k[1][1] = buff[5]; k[1][2] = buff[9];  k[1][3] = buff[13]; k[1][4] = buff[17]; k[1][5] = buff[21]; k[1][6] = buff[25]; k[1][7] = buff[29];
			k[2][0] = buff[2]; k[2][1] = buff[6]; k[2][2] = buff[10]; k[2][3] = buff[14]; k[2][4] = buff[18]; k[2][5] = buff[22]; k[2][6] = buff[26]; k[2][7] = buff[30];
			k[3][0] = buff[3]; k[3][1] = buff[7]; k[3][2] = buff[11]; k[3][3] = buff[15]; k[3][4] = buff[19]; k[3][5] = buff[23]; k[3][6] = buff[27]; k[3][7] = buff[31];

			return k;
		}

		inline aes_block_t random_block()
		{
			aes_block_t result;

			result[0][0] = rand() & 0xFF; result[0][1] = rand() & 0xFF; result[0][2] = rand() & 0xFF; result[0][3] = rand() & 0xFF;
			result[1][0] = rand() & 0xFF; result[1][1] = rand() & 0xFF; result[1][2] = rand() & 0xFF; result[1][3] = rand() & 0xFF;
			result[2][0] = rand() & 0xFF; result[2][1] = rand() & 0xFF; result[2][2] = rand() & 0xFF; result[2][3] = rand() & 0xFF;
			result[3][0] = rand() & 0xFF; result[3][1] = rand() & 0xFF; result[3][2] = rand() & 0xFF; result[3][3] = rand() & 0xFF;
			
			return result;
		}

		/**
		 * Encrypt the buffer of the specified length using the provided key in ECB mode. The buffer must be a multiple of 16 bytes
		 */
		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, aes_key_128_t key);
		/**
		 * Encrypt the buffer of the specified length using the provided key and initialization vector in CBC mode. The buffer must be a multiple of 16 bytes
		 */
		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, aes_key_128_t key, aes_block_t IV);

		/**
		 * Encrypt the buffer of the specified length using the provided key in ECB mode. The buffer must be a multiple of 16 bytes
		 */
		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, aes_key_128_t key);
		/**
		 * Encrypt the buffer of the specified length using the provided key and initialization vector in CBC mode. The buffer must be a multiple of 16 bytes
		 */
		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, aes_key_128_t key, aes_block_t IV);

		/**
		 * Encrypt the buffer of the specified length using the provided key in ECB mode. The buffer must be a multiple of 16 bytes
		 */
		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, aes_key_192_t key);
		/**
		 * Encrypt the buffer of the specified length using the provided key and initialization vector in CBC mode. The buffer must be a multiple of 16 bytes
		 */
		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, aes_key_192_t key, aes_block_t IV);

		/**
		 * Encrypt the buffer of the specified length using the provided key in ECB mode. The buffer must be a multiple of 16 bytes
		 */
		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, aes_key_192_t key);
		/**
		 * Encrypt the buffer of the specified length using the provided key and initialization vector in CBC mode. The buffer must be a multiple of 16 bytes
		 */
		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, aes_key_192_t key, aes_block_t IV);

		/**
		 * Encrypt the buffer of the specified length using the provided key in ECB mode. The buffer must be a multiple of 16 bytes
		 */
		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, aes_key_256_t key);
		/**
		 * Encrypt the buffer of the specified length using the provided key and initialization vector in CBC mode. The buffer must be a multiple of 16 bytes
		 */
		LIBCRYPTO_PUB int Encrypt(char* data, size_t len, aes_key_256_t key, aes_block_t IV);

		/**
		 * Encrypt the buffer of the specified length using the provided key in ECB mode. The buffer must be a multiple of 16 bytes
		 */
		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, aes_key_256_t key);
		/**
		 * Encrypt the buffer of the specified length using the provided key and initialization vector in CBC mode. The buffer must be a multiple of 16 bytes
		 */
		LIBCRYPTO_PUB int Decrypt(char* data, size_t len, aes_key_256_t key, aes_block_t IV);
	}
}
