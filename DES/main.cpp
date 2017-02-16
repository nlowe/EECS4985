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
#include "opts.h"
#include "../libcrypto/libcrypto.h"
#include "../libcrypto/Mask.h"
#include "../libcrypto/DES/DES.h"
#include <iostream>
#include <fstream>
#include <chrono>

// Forward-declare so main is at the top as per project spec
void printHelp();

int main(int argc, char* argv[])
{
	// Seed the RNG
	srand(static_cast<unsigned int>(time(nullptr)));

	// Parse Options
	Options opts(argc, argv);

	// Parse errors?
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
		// Create the first block containing the length of the file for padding purposes
		auto headerBlock = libcrypto::Random32() << 32 | len;
		auto needsPadding = len % 8 != 0;
		auto buffSize = len + 8 + (needsPadding ? 8 - (len % 8) : 0);
		buff = new char[buffSize]{ 0 };

		// Include the length of the file so we can determine how much padding we used when decrypting
		libcrypto::buffStuff64(buff, 0, headerBlock);

		// If we need padding, fill the last block with random data (it will be overwritten when we read the file)
		if(needsPadding)
		{
			auto padding = libcrypto::Random64();
			libcrypto::buffStuff64(buff, len / 8, padding);
		}

		// Record the start time and read the file
		auto ioStart = std::chrono::high_resolution_clock::now();
		reader.read(buff + 8, len);
		reader.close();

		// Hand off the buffer to the crypto library and record the runtime
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

		// If encryption was a success, write the buffer to the output file
		if(result == libcrypto::SUCCESS)
		{
			writer.write(buff, buffSize);
		}
		writer.close();

		// Clean up
		delete[] buff;
		auto ioEnd = std::chrono::high_resolution_clock::now();

		std::chrono::duration<double, std::milli> ioTime = ioEnd - ioStart - duration;

		// Tell the user what happened
		if(result != libcrypto::SUCCESS)
		{
			std::cerr << "DES Failed with result " << result << std::endl;
		}
		else
		{
			std::cout << "Encrypted " << buffSize << " bytes in " << duration.count() << "ms (+" << ioTime.count() << "ms i/o)" << std::endl;
		}
	}
	else if(opts.Action == libcrypto::Action::DECRYPT)
	{
		// Valid files are a multiple of 8 bytes
		if(len % 8 != 0)
		{
			std::cerr << "Input file not a multiple of 8 bytes. The file is corrupt, not complete, or is not a DES Encrypted file" << std::endl;
			reader.close();
			return -1;
		}

		// Record the start time and read the file
		auto ioStart = std::chrono::high_resolution_clock::now();
		buff = new char[len];
		reader.read(buff, len);
		reader.close();

		// Hand off the buffer to the crypto library and record the runtime
		auto start = std::chrono::high_resolution_clock::now();
		int result;
		if(opts.Mode == libcrypto::Mode::ECB)
		{
			result = libcrypto::des::Decrypt(buff, len, opts.Key);
		}
		else
		{
			result = libcrypto::des::Decrypt(buff, len, opts.Key, opts.IV.GetValue());
		}
		auto end = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double, std::milli> duration = end - start;

		// Read the original length from the decrypted file
		auto originalLength = _byteswap_uint64(reinterpret_cast<uint64_t*>(buff)[0]) & MASK32;

		// If we didn't decrypt the file successfully, warn the user
		if(originalLength > MASK31)
		{
			std::cerr << "Decrypted length too large. The file is corrupted or is not a DES file" << std::endl;
			writer.close();
			delete[] buff;

			return -1;
		}

		// If we decrypted the file successfully, write the buffer (excluding the header and padding)
		if(result == libcrypto::SUCCESS)
		{
			writer.write(buff + 8, originalLength);
		}
		writer.close();
		
		// Cleanup
		delete[] buff;
		auto ioEnd = std::chrono::high_resolution_clock::now();

		std::chrono::duration<double, std::milli> ioTime = ioEnd - ioStart - duration;

		// Tell the user what happened
		if(result != libcrypto::SUCCESS)
		{
			std::cerr << "DES Failed with result " << result << std::endl;
		}
		else
		{
			std::cout << "Decrypted " << len << " bytes in " << duration.count() << "ms (+" << ioTime.count() << "ms i/o)" << std::endl;
		}
	}
	else
	{
		return -1;
	}
}

/**
 * Prints the syntax and help for the program
 */
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

