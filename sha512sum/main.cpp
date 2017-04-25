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
 * main.cpp - Calculate SHA512 hashes for strings and files
 */

#include "stdafx.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include "../libcrypto/Hashing/SHA512.h"

/** The size of the buffer for computing hashes on large files (16k) */
#define BUFFER_SIZE SHA512_BLOCK_SIZE_BYTES * 128

/** Print the specified digest in the format required by the project spec (8-byte chunks) */
void printHash(char* digest)
{
	for(auto i = 0; i < SHA512_DIGEST_SIZE_BYTES; i++)
	{
		printf("%02x", digest[i] & 0xff);
		if (i % 8 == 7) printf(" ");
	}
}

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "syntax: sha512sum <file>" << std::endl;
		return -1;
	}

	std::ifstream reader;
	reader.open(argv[1], std::ios::binary | std::ios::in);
	if(!reader.good())
	{
		std::cerr << "Unable to open file for read: " << argv[1] << std::endl;
		return -2;
	}

	auto start = std::chrono::high_resolution_clock::now();

	auto buff = new char[BUFFER_SIZE];

	// Process the file in BUFFER_SIZE chunks
	auto firstBlock = true;
	auto digest = new char[SHA512_DIGEST_SIZE_BYTES];
	size_t totalLength = 0;
	while(!reader.eof())
	{
		// Try to read BUFFER_SIZE bytes and get the actual number of bytes read
		auto len = reader.read(buff, BUFFER_SIZE).gcount();
		totalLength += len;

		// Compute the partial has for the block
		libcrypto::hashing::SHA512::ComputePartialHash(digest, buff, len, firstBlock, len != BUFFER_SIZE ? &totalLength : nullptr);
		firstBlock = false;
	}

	std::chrono::duration<double> duration = std::chrono::high_resolution_clock::now() - start;

	// Print the hash and statistics
	printHash(digest);
	std::cout << " - " << argv[1] << " (" << std::fixed << std::setprecision(3) << duration.count() << "s)" << std::endl;

	// Cleanup
	delete[] digest;
	delete[] buff;

    return 0;
}
