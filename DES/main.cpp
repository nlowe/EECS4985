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
 * main.cpp - A simple application that uses libcrypto to encrypt and decrypt files with DES
 */

#include "stdafx.h"
#include "../libcrypto/libcrypto.h"
#include "../libcrypto/DES/DES.h"
#include <iostream>
#include <fstream>
#include <ctime>
#include "opts.h"
#include "../libcrypto/Mask.h"
#include <chrono>

// Forward-declare so main is at the top as per project spec
void printHelp();

int main(int argc, char* argv[])
{
	// Seed the RNG
	srand(static_cast<unsigned int>(time(nullptr)));

	// Parse Options
	Options opts(argc, argv);

	if(opts.Errors)
	{
		printHelp();
		return -1;
	}

	std::ifstream reader;
	std::ofstream writer;

	// Open the input file for read in binary mode
	reader.open(opts.Input, std::ios::binary | std::ios::ate | std::ios::in);
	if(!reader.good())
	{
		std::cerr << "unable to open file for read: " << opts.Input << std::endl;
		return -1;
	}

	// How big is it?
	size_t len = reader.tellg();
	if (len > MASK31)
	{
		std::cerr << "Input file too large according to spec. Must be less than 2GiB" << std::endl;
		return -1;
	}

	// Seek to the start of the file
	reader.seekg(0, std::ios::beg);
	// Open the output file for write in binary mode
	writer.open(opts.Output, std::ios::binary | std::ios::out);

	if(!writer.good())
	{
		std::cerr << "Unable to open file for write: " << opts.Output << std::endl;
		reader.close();
		return -1;
	}

	char* buff;

	if(opts.Action == libcrypto::Action::ENCRYPT)
	{
		auto headerBlock = libcrypto::Random32() << 31 | len;
		auto needsPadding = len % 8 != 0;
		auto buffSize = len + 1 + (needsPadding ? 8 : 0);
		buff = new char[buffSize]{ 0 };

		// Include the length of the file so we can determine how much padding we used when decrypting
		buff[0] = headerBlock >> 28 & 0xFF;
		buff[1] = headerBlock >> 24 & 0xFF;
		buff[2] = headerBlock >> 20 & 0xFF;
		buff[3] = headerBlock >> 16 & 0xFF;
		buff[4] = headerBlock >> 12 & 0xFF;
		buff[5] = headerBlock >> 8 & 0xFF;
		buff[6] = headerBlock >> 4 & 0xFF;
		buff[7] = headerBlock & 0xFF;

		if(needsPadding)
		{
			auto padding = libcrypto::Random64();
			buff[len/8 + 0] = padding >> 28 & 0xFF;
			buff[len/8 + 1] = padding >> 24 & 0xFF;
			buff[len/8 + 2] = padding >> 20 & 0xFF;
			buff[len/8 + 3] = padding >> 16 & 0xFF;
			buff[len/8 + 4] = padding >> 12 & 0xFF;
			buff[len/8 + 5] = padding >> 8 & 0xFF;
			buff[len/8 + 6] = padding >> 4 & 0xFF;
			buff[len/8 + 7] = padding & 0xFF;
		}

		reader.read(buff + 8, len);
		reader.close();

		auto start = std::chrono::high_resolution_clock::now();
		int result;
		if(opts.Mode == libcrypto::Mode::ECB)
		{
			result = libcrypto::des::Encrypt(buff, buffSize, opts.Key);
		}
		else
		{
			result = libcrypto::des::Encrypt(buff, buffSize, opts.Key, opts.IV.GetValue());
		}
		auto end = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double, std::milli> duration = end - start;

		if(result == libcrypto::SUCCESS)
		{
			writer.write(buff, buffSize);
		}

		delete[] buff;

		if(result != libcrypto::SUCCESS)
		{
			std::cerr << "DES Failed with result " << result << std::endl;
		}
		else
		{
			std::cout << "Encrypted " << buffSize << " bytes in " << duration.count() << "ms" << std::endl;
		}
	}
	else if(opts.Action == libcrypto::Action::DECRYPT)
	{
		
	}
	else
	{
		return -1;
	}
}

void printHelp()
{
	std::cout << "DES <action> <key> <mode> <in> <out>" << std::endl << std::endl;

	std::cout << "\tAction: -e: encrypt, -d: decrypt" << std::endl;
	std::cout << "\tKey:    an 8-byte hex or ascii sequence (16 hex digits or 8 characters)" << std::endl;
	std::cout << "\t        Non-hex literals should be surrounded in single quotes" << std::endl;
	std::cout << "\t        If the key contains spaces, surround additionally with double quotes" << std::endl;
	std::cout << "\tMode:   CBC or ECB" << std::endl;
	std::cout << "\tIn:     The path to the input file" << std::endl;
	std::cout << "\tOut:    The path to the output file" << std::endl;
}

