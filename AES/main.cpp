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
 * main.cpp - A simple application that uses libcrypto to encrypt and decrypt files with AES
 */

#include "stdafx.h"
#include <chrono>
#include <iostream>
#include <fstream>
#include "opts.h"
#include "../libcrypto/Mask.h"
#include "../libcrypto/AES/AES.h"

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
		auto headerBlock = libcrypto::aes::random_block();
		headerBlock[0][3] = (len >> 24) & 0xFF;
		headerBlock[1][3] = (len >> 16) & 0xFF;
		headerBlock[2][3] = (len >>  8) & 0xFF;
		headerBlock[3][3] = len & 0xFF;

		auto needsPadding = len % 16 != 0;
		auto buffSize = len + 16 + (needsPadding ? 16 - (len % 16) : 0);
		buff = new char[buffSize]{ 0 };

		// Include the length of the file so we can determine how much padding we used when decrypting
		libcrypto::aes::buffstuff(buff, 0, headerBlock);

		// If we need padding, fill the last block with random data (it will be overwritten when we read the file)
		if (needsPadding)
		{
			auto padding = libcrypto::aes::random_block();
			libcrypto::aes::buffstuff(buff, buffSize - 16, padding);
		}

		// Record the start time and read the file
		auto ioStart = std::chrono::high_resolution_clock::now();
		reader.read(buff + 16, len);
		reader.close();

		// Hand off the buffer to the crypto library and record the runtime
		auto start = std::chrono::high_resolution_clock::now();
		int result;
		if(opts.Mode == libcrypto::Mode::ECB)
		{
			if(opts.has128BitKey)
			{
				result = libcrypto::aes::Encrypt(buff, buffSize, opts.k128);
			}
			else if(opts.has192BitKey)
			{
				result = libcrypto::aes::Encrypt(buff, buffSize, opts.k192);
			}
			else
			{
				result = libcrypto::aes::Encrypt(buff, buffSize, opts.k256);
			}
		}
		else
		{
			// Create a random IV, encrypt it, and write it to the file
			auto IV = libcrypto::aes::random_block();
			char ivbuff[16]{ 0 };
			libcrypto::aes::buffstuff(ivbuff, 0, IV);

			// Encrypt using the key and IV
			if(opts.has128BitKey)
			{
				libcrypto::aes::Encrypt(ivbuff, 16, opts.k128);
				result = libcrypto::aes::Encrypt(buff, buffSize, opts.k128, IV);
			}
			else if(opts.has192BitKey)
			{
				libcrypto::aes::Encrypt(ivbuff, 16, opts.k192);
				result = libcrypto::aes::Encrypt(buff, buffSize, opts.k192, IV);
			}
			else
			{
				libcrypto::aes::Encrypt(ivbuff, 16, opts.k256);
				result = libcrypto::aes::Encrypt(buff, buffSize, opts.k256, IV);
			}
			writer.write(ivbuff, 16);
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
			std::cerr << "AES Failed with result " << result << std::endl;
		}
		else
		{
			std::cout << "Encrypted " << buffSize << " bytes in " << duration.count() << "ms (+" << ioTime.count() << "ms i/o)" << std::endl;
		}
	}
	else if(opts.Action == libcrypto::Action::DECRYPT)
	{
		// Valid files are a multiple of 16 bytes
		if(len % 16 != 0)
		{
			std::cerr << "Input file not a multiple of 16 bytes. The file is corrupt, not complete, or is not an AES Encrypted file" << std::endl;
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
			if(opts.has128BitKey)
			{
				result = libcrypto::aes::Decrypt(buff, len, opts.k128);
			}
			else if(opts.has192BitKey)
			{
				result = libcrypto::aes::Decrypt(buff, len, opts.k192);
			}
			else
			{
				result = libcrypto::aes::Decrypt(buff, len, opts.k256);
			}
		}
		else
		{
			// Decrypt the IV, then the rest of the file
			if(opts.has128BitKey)
			{
				libcrypto::aes::Decrypt(buff, 16, opts.k128);

				auto IV = libcrypto::aes::make_block(buff, 0);
				buff += 16;
				len -= 16;

				result = libcrypto::aes::Decrypt(buff, len, opts.k128, IV);
			}
			else if(opts.has192BitKey)
			{
				libcrypto::aes::Decrypt(buff, 16, opts.k192);

				auto IV = libcrypto::aes::make_block(buff, 0);
				buff += 16;
				len -= 16;

				result = libcrypto::aes::Decrypt(buff, len, opts.k192, IV);
			}
			else
			{
				libcrypto::aes::Decrypt(buff, 16, opts.k256);

				auto IV = libcrypto::aes::make_block(buff, 0);
				buff += 16;
				len -= 16;

				result = libcrypto::aes::Decrypt(buff, len, opts.k256, IV);
			}
		}
		auto end = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double, std::milli> duration = end - start;

		auto originalLength = (buff[12] | 0ull) << 24 | (buff[13] | 0ull) << 16 | (buff[14] | 0ull) << 8 | buff[15];
		// If we didn't decrypt the file successfully, warn the user
		if(originalLength > MASK31 || originalLength > len)
		{
			std::cerr << "Decrypted length too large (" << originalLength << " bytes). The file is corrupted or is not an AES file" << std::endl;
			writer.close();
			if (opts.Mode == libcrypto::Mode::CBC) buff -= 16;
			delete[] buff;

			return -1;
		}

		// If we decrypted the file successfully, write the buffer (excluding the header and padding)
		if(result == libcrypto::SUCCESS)
		{
			writer.write(buff + 16, originalLength);
		}
		writer.close();

		// Cleanup
		if (opts.Mode == libcrypto::Mode::CBC) buff -= 16;
		delete[] buff;
		auto ioEnd = std::chrono::high_resolution_clock::now();

		std::chrono::duration<double, std::milli> ioTime = ioEnd - ioStart - duration;

		// Tell the user what happened
		if(result != libcrypto::SUCCESS)
		{
			std::cerr << "AES Failed with result " << result << std::endl;
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

    return 0;
}

/**
 * Prints the syntax and help for the program
 */
void printHelp()
{
	std::cout << "AES <action> <key> <mode> <in> <out>" << std::endl << std::endl;

	std::cout << "\tAction: -e: encrypt, -d: decrypt" << std::endl;
	std::cout << "\tKey:    an 16, 24, or 32 byte hex or ascii sequence" << std::endl;
	std::cout << "\t        Non-hex literals should be surrounded in single quotes" << std::endl;
	std::cout << "\t        If the key contains spaces, surround additionally with double quotes" << std::endl;
	std::cout << "\tMode:   CBC or ECB" << std::endl;
	std::cout << "\tIn:     The path to the input file" << std::endl;
	std::cout << "\tOut:    The path to the output file" << std::endl;
}

