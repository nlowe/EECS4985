// benchmarks.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../libcrypto/DES/DES.h"
#include <random>
#include <iostream>
#include <ctime>
#include <chrono>

#define DES_MIN_SIZE 128
#define DES_MAX_SIZE 128 * 1024 * 1024 // 124MB
#define DES_STEP_SIZE (DES_MAX_SIZE - DES_MIN_SIZE)/31 // 31 data points

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
	}

    return 0;
}

