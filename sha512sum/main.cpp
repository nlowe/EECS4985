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
#include "../libcrypto/Hashing/SHA512.h"

void printHelp();
void hashFile(char* path);
void printHash(char* digest);

int main(int argc, char* argv[])
{
	if(argc < 1 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1] ,"/?") == 0)
	{
		printHelp();
		return -1;
	}

	if(strcmp(argv[1], "-t") == 0)
	{
		std::string str;
		for(auto i = 2; i < argc; i++)
		{
			str += std::string(argv[i]);
		}

		auto digest = libcrypto::hashing::SHA512::ComputeHash(str);

		printHash(digest);
		std::cout << " - " << std::endl;

		delete[] digest;
	}
	else
	{
		for(auto i = 1; i < argc; i++)
		{
			hashFile(argv[i]);
		}
	}

    return 0;
}

void hashFile(char* path)
{
	std::ifstream reader;
	reader.open(path, std::ios::binary | std::ios::ate | std::ios::in);
	if(!reader.good())
	{
		std::cerr << "Unable to open file for read: " << path << std::endl;
		return;
	}

	size_t len = reader.tellg();
	reader.seekg(0, std::ios::beg);

	auto buff = new char[len] { 0 };
	reader.read(buff, len);
	reader.close();

	auto digest = libcrypto::hashing::SHA512::ComputeHash(buff, len);

	printHash(digest);
	std::cout << " - " << path << std::endl;

	delete[] digest;
	delete[] buff;
}

void printHash(char* digest)
{
	for(auto i = 0; i < 64; i++)
	{
		printf("%02x", digest[i] & 0xff);
	}
}

void printHelp()
{
	std::cout << "syntax: sha512sum <file [file2] [file3]...> | -t <string>" << std::endl;
}
