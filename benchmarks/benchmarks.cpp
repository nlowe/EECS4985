/*
 * Copyright (c) 2017 Nathan Lowe
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
 * benchmarks.cpp - A simple application that benchmarks the speed of various algorithms
 *   provided by libcrypto
 */

#include "stdafx.h"
#include "../libcrypto/DES/DES.h"
#include <random>
#include <iostream>
#include <ctime>
#include <chrono>
#include "../libcrypto/AES/AES.h"


/** The minimum size in bytes to benchmark for DES */
#define DES_MIN_SIZE 128
/** The maximum size in bytes to benchmark for DES */
#define DES_MAX_SIZE 128 * 1024 * 1024 // 128MB
/** The step in bytes for each benchmark for DES */
#define DES_STEP_SIZE (DES_MAX_SIZE - DES_MIN_SIZE)/31 // 31 data points

#define AES_MIN_SIZE 128
#define AES_MAX_SIZE 128 * 1024 * 1024
#define AES_STEP_SIZE (AES_MAX_SIZE - AES_MIN_SIZE)/31 // 15 data points


/**
 * Fill the specified buffer with random bytes
 */
void fillbuff(std::mt19937_64& random, char* buff, size_t len)
{

	uint64_t bytes = 0;
	for(auto i = 0; i < len; i++)
	{
		if (i % 8 == 0) bytes = random();
		buff[i] = bytes & 0xFF;
		bytes >>= 8;
	}
}

/**
 * Benchmark the performance of DES (both ECB and CBC Mode)
 */
void benchmarkDES()
{
	std::cout << std::endl << std::endl << "Benchmarking DES" << std::endl << "----------------" << std::endl;
	std::cout << "Initializing data" << std::endl;
	std::mt19937_64 random;
	auto buff = new char[DES_MAX_SIZE];
	fillbuff(random, buff, DES_MAX_SIZE);

	std::cout << "bytes\tECB Encrypt\tECB Decrypt\tCBC Encrypt\tCBC Decrypt" << std::endl;
	for(auto i = DES_MIN_SIZE; i <= DES_MAX_SIZE; i += DES_STEP_SIZE)
	{
		auto key = random();
		auto iv = random();

		auto ecb_enc_start = std::chrono::high_resolution_clock::now();
		libcrypto::des::Encrypt(buff, i, key);
		auto ecb_enc_end = std::chrono::high_resolution_clock::now();

		auto ecb_dec_start = std::chrono::high_resolution_clock::now();
		libcrypto::des::Decrypt(buff, i, key);
		auto ecb_dec_end = std::chrono::high_resolution_clock::now();

		auto cbc_enc_start = std::chrono::high_resolution_clock::now();
		libcrypto::des::Encrypt(buff, i, key, iv);
		auto cbc_enc_end = std::chrono::high_resolution_clock::now();

		auto cbc_dec_start = std::chrono::high_resolution_clock::now();
		libcrypto::des::Decrypt(buff, i, key, iv);
		auto cbc_dec_end = std::chrono::high_resolution_clock::now();

		std::chrono::duration<double, std::milli> ecb_enc = ecb_enc_end - ecb_enc_start;
		std::chrono::duration<double, std::milli> ecb_dec = ecb_dec_end - ecb_dec_start;
		std::chrono::duration<double, std::milli> cbc_enc = cbc_enc_end - cbc_enc_start;
		std::chrono::duration<double, std::milli> cbc_dec = cbc_dec_end - cbc_dec_start;

		std::cout << i << "\t" << ecb_enc.count() << "\t" << ecb_dec.count() << "\t" << cbc_enc.count() << "\t" << cbc_dec.count() << std::endl;
	}

	delete[] buff;
}

/** 
 * Benchmark AES with 128-bit keys (both ECB and CBC Mode)
 */
void benchmarkAES128()
{
	std::cout << std::endl << std::endl << "Benchmarking AES with 128-bit keys" << std::endl << "----------------" << std::endl;
	std::cout << "Initializing data" << std::endl;
	std::mt19937_64 random;
	auto buff = new char[AES_MAX_SIZE];
	fillbuff(random, buff, AES_MAX_SIZE);

	std::cout << "bytes\tECB Encrypt\tECB Decrypt\tCBC Encrypt\tCBC Decrypt" << std::endl;
	for(auto i = AES_MIN_SIZE; i <= AES_MAX_SIZE; i += AES_STEP_SIZE)
	{
		char keybuff[16]{ 0 };
		char ivbuff[16]{ 0 };

		fillbuff(random, keybuff, 16);
		fillbuff(random, ivbuff, 16);

		auto key = libcrypto::aes::make_block(keybuff, 0);
		auto iv = libcrypto::aes::make_block(ivbuff, 0);

		auto ecb_enc_start = std::chrono::high_resolution_clock::now();
		libcrypto::aes::Encrypt(buff, i, key);
		auto ecb_enc_end = std::chrono::high_resolution_clock::now();

		auto ecb_dec_start = std::chrono::high_resolution_clock::now();
		libcrypto::aes::Decrypt(buff, i, key);
		auto ecb_dec_end = std::chrono::high_resolution_clock::now();

		auto cbc_enc_start = std::chrono::high_resolution_clock::now();
		libcrypto::aes::Encrypt(buff, i, key, iv);
		auto cbc_enc_end = std::chrono::high_resolution_clock::now();

		auto cbc_dec_start = std::chrono::high_resolution_clock::now();
		libcrypto::aes::Decrypt(buff, i, key, iv);
		auto cbc_dec_end = std::chrono::high_resolution_clock::now();

		std::chrono::duration<double, std::milli> ecb_enc = ecb_enc_end - ecb_enc_start;
		std::chrono::duration<double, std::milli> ecb_dec = ecb_dec_end - ecb_dec_start;
		std::chrono::duration<double, std::milli> cbc_enc = cbc_enc_end - cbc_enc_start;
		std::chrono::duration<double, std::milli> cbc_dec = cbc_dec_end - cbc_dec_start;

		std::cout << i << "\t" << ecb_enc.count() << "\t" << ecb_dec.count() << "\t" << cbc_enc.count() << "\t" << cbc_dec.count() << std::endl;
	}

	delete[] buff;
}

/** 
* Benchmark AES with 192-bit keys (both ECB and CBC Mode)
*/
void benchmarkAES192()
{
	std::cout << std::endl << std::endl << "Benchmarking AES with 192-bit keys" << std::endl << "----------------" << std::endl;
	std::cout << "Initializing data" << std::endl;
	std::mt19937_64 random;
	auto buff = new char[AES_MAX_SIZE];
	fillbuff(random, buff, AES_MAX_SIZE);

	std::cout << "bytes\tECB Encrypt\tECB Decrypt\tCBC Encrypt\tCBC Decrypt" << std::endl;
	for(auto i = AES_MIN_SIZE; i <= AES_MAX_SIZE; i += AES_STEP_SIZE)
	{
		char keybuff[24]{ 0 };
		char ivbuff[16]{ 0 };

		fillbuff(random, keybuff, 24);
		fillbuff(random, ivbuff, 16);

		auto key = libcrypto::aes::make_key_192(keybuff);
		auto iv = libcrypto::aes::make_block(ivbuff, 0);

		auto ecb_enc_start = std::chrono::high_resolution_clock::now();
		libcrypto::aes::Encrypt(buff, i, key);
		auto ecb_enc_end = std::chrono::high_resolution_clock::now();

		auto ecb_dec_start = std::chrono::high_resolution_clock::now();
		libcrypto::aes::Decrypt(buff, i, key);
		auto ecb_dec_end = std::chrono::high_resolution_clock::now();

		auto cbc_enc_start = std::chrono::high_resolution_clock::now();
		libcrypto::aes::Encrypt(buff, i, key, iv);
		auto cbc_enc_end = std::chrono::high_resolution_clock::now();

		auto cbc_dec_start = std::chrono::high_resolution_clock::now();
		libcrypto::aes::Decrypt(buff, i, key, iv);
		auto cbc_dec_end = std::chrono::high_resolution_clock::now();

		std::chrono::duration<double, std::milli> ecb_enc = ecb_enc_end - ecb_enc_start;
		std::chrono::duration<double, std::milli> ecb_dec = ecb_dec_end - ecb_dec_start;
		std::chrono::duration<double, std::milli> cbc_enc = cbc_enc_end - cbc_enc_start;
		std::chrono::duration<double, std::milli> cbc_dec = cbc_dec_end - cbc_dec_start;

		std::cout << i << "\t" << ecb_enc.count() << "\t" << ecb_dec.count() << "\t" << cbc_enc.count() << "\t" << cbc_dec.count() << std::endl;
	}

	delete[] buff;
}

/** 
* Benchmark AES with 256-bit keys (both ECB and CBC Mode)
*/
void benchmarkAES256()
{
	std::cout << std::endl << std::endl << "Benchmarking AES with 256-bit keys" << std::endl << "----------------" << std::endl;
	std::cout << "Initializing data" << std::endl;
	std::mt19937_64 random;
	auto buff = new char[AES_MAX_SIZE];
	fillbuff(random, buff, AES_MAX_SIZE);

	std::cout << "bytes\tECB Encrypt\tECB Decrypt\tCBC Encrypt\tCBC Decrypt" << std::endl;
	for(auto i = AES_MIN_SIZE; i <= AES_MAX_SIZE; i += AES_STEP_SIZE)
	{
		char keybuff[32]{ 0 };
		char ivbuff[16]{ 0 };

		fillbuff(random, keybuff, 32);
		fillbuff(random, ivbuff, 16);

		auto key = libcrypto::aes::make_key_256(keybuff);
		auto iv = libcrypto::aes::make_block(ivbuff, 0);

		auto ecb_enc_start = std::chrono::high_resolution_clock::now();
		libcrypto::aes::Encrypt(buff, i, key);
		auto ecb_enc_end = std::chrono::high_resolution_clock::now();

		auto ecb_dec_start = std::chrono::high_resolution_clock::now();
		libcrypto::aes::Decrypt(buff, i, key);
		auto ecb_dec_end = std::chrono::high_resolution_clock::now();

		auto cbc_enc_start = std::chrono::high_resolution_clock::now();
		libcrypto::aes::Encrypt(buff, i, key, iv);
		auto cbc_enc_end = std::chrono::high_resolution_clock::now();

		auto cbc_dec_start = std::chrono::high_resolution_clock::now();
		libcrypto::aes::Decrypt(buff, i, key, iv);
		auto cbc_dec_end = std::chrono::high_resolution_clock::now();

		std::chrono::duration<double, std::milli> ecb_enc = ecb_enc_end - ecb_enc_start;
		std::chrono::duration<double, std::milli> ecb_dec = ecb_dec_end - ecb_dec_start;
		std::chrono::duration<double, std::milli> cbc_enc = cbc_enc_end - cbc_enc_start;
		std::chrono::duration<double, std::milli> cbc_dec = cbc_dec_end - cbc_dec_start;

		std::cout << i << "\t" << ecb_enc.count() << "\t" << ecb_dec.count() << "\t" << cbc_enc.count() << "\t" << cbc_dec.count() << std::endl;
	}

	delete[] buff;
}

int main(int argc, char* argv[])
{
	srand(time(nullptr));

	for(auto i = 0; i < argc; i++)
	{
		std::string arg(argv[i]);
		if(arg == "des")
		{
			benchmarkDES();
		}
		else if(arg == "aes128")
		{
			benchmarkAES128();
		}
		else if(arg == "aes192")
		{
			benchmarkAES192();
		}
		else if(arg == "aes256")
		{
			benchmarkAES256();
		}
	}

    return 0;
}

