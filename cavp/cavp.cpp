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
 * cavp.cpp - A program to test various algorithms against NIST Test Vectors
 */
#include "stdafx.h"
#include "ValidationTests.h"
#include "../libcrypto/libcrypto.h"
#include "../libcrypto/AES/AES.h"

/** Convert the specified hex string buffer into a buffer of bytes*/
void fromHex(char* src, char*& dst)
{
	auto j = 0;
	for(auto i = 0; i < strlen(src); i += 2)
	{
		char tmp[]{ src[i], src[i + 1] };
		dst[j++] = static_cast<char>(strtol(tmp, nullptr, 16));
	}
}

int main(int argc, char* argv[])
{
	if(argc < 6 || argc > 7)
	{
		printf("Incorrect number of arguments (got %llu). Syntax: cavp <aes128|aes192|aes256> <e|d> <key> <data> <expected> [iv]\n", argc);
		return -1;
	}

	auto key = new char[strlen(argv[3]) / 2]{ 0 };
	fromHex(argv[3], key);
	auto data = new char[strlen(argv[4]) / 2]{ 0 };
	fromHex(argv[4], data);
	auto expected = new char[strlen(argv[4]) / 2]{ 0 };
	fromHex(argv[5], expected);

	char* iv = nullptr;
	if (argc == 7)
	{
		iv = new char[16]{ 0 };
		fromHex(argv[6], iv);
	}

	auto result = 0;
	if(strcmp(argv[1], "aes128") == 0)
	{
		if(argv[2][0] == 'e')
		{
			if (argc == 6) result =  aes_encrypt_ecb_128(key, data, expected, strlen(argv[4])/2);
			else result =  aes_encrypt_cbc_128(key, iv, data, expected, strlen(argv[4])/2);
		}
		else
		{
			if (argc == 6) result =  aes_decrypt_ecb_128(key, data, expected, strlen(argv[4])/2);
			else result =  aes_decrypt_cbc_128(key, iv, data, expected, strlen(argv[4])/2);
		}
	}
	else if(strcmp(argv[1], "aes192") == 0)
	{
		if(argv[2][0] == 'e')
		{
			if (argc == 6) result =  aes_encrypt_ecb_192(key, data, expected, strlen(argv[4])/2);
			else result =  aes_encrypt_cbc_192(key, iv, data, expected, strlen(argv[4])/2);
		}
		else
		{
			if (argc == 6) result =  aes_decrypt_ecb_192(key, data, expected, strlen(argv[4])/2);
			else result =  aes_decrypt_cbc_192(key, iv, data, expected, strlen(argv[4])/2);
		}
	}
	else if(strcmp(argv[1], "aes256") == 0)
	{
		if(argv[2][0] == 'e')
		{
			if (argc == 6) result =  aes_encrypt_ecb_256(key, data, expected, strlen(argv[4])/2);
			else result =  aes_encrypt_cbc_256(key, iv, data, expected, strlen(argv[4])/2);
		}
		else
		{
			if (argc == 6) result =  aes_decrypt_ecb_256(key, data, expected, strlen(argv[4])/2);
			else result =  aes_decrypt_cbc_256(key, iv, data, expected, strlen(argv[4])/2);
		}
	}
	else
	{
		printf("Unknown algorithm\n");
		result =  -1;
	}

	delete[] key;
	delete[] data;
	if (iv != nullptr) delete[] iv;

	return result;;
}

