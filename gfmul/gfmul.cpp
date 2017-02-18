/**
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
 * gfmul.cpp - Print partial multiplication tables for 7th order polynomials under GF(2^8)
 */

#include "stdafx.h"
#include <cstdint>
#include <iostream>
#include <iomanip>

/** The modulus polynomial we use */
#define GF_MOD 0b00011011

/**
 * Multiplication of 7th order polynomials under GF(2^8) using the specified modulus
 */
uint8_t gfmul(int8_t a, int8_t b, int8_t modulus)
{
	// Short-circuit if we're multiplying by zero
	if (a == 0 || b == 0) return 0;

	// In general, multipy the previous "polynomial" by "x" (shift previous left one)
	// If the result would be an 8th order polynomial, xor with the modulus
	// NOTE: We're exploiting an implementation detail of the MSVC++ compiler:
	//           left shifts of signed values propogates the sign bit. This lets
	//           us easily create a mask to select the modulus, eliminating a branch.
	int8_t b1 = ((b >> 8) & modulus) ^ (b << 1);
	int8_t b2 = ((b1 >> 8) & modulus) ^ (b1 << 1);
	int8_t b3 = ((b2 >> 8) & modulus) ^ (b2 << 1);
	int8_t b4 = ((b3 >> 8) & modulus) ^ (b3 << 1);
	int8_t b5 = ((b4 >> 8) & modulus) ^ (b4 << 1);
	int8_t b6 = ((b5 >> 8) & modulus) ^ (b5 << 1);
	int8_t b7 = ((b6 >> 8) & modulus) ^ (b6 << 1);

	// "Add" (via xor) the terms we're interested in
	return uint8_t(a & (1 << 0) ? b  : 0) ^
		   uint8_t(a & (1 << 1) ? b1 : 0) ^
		   uint8_t(a & (1 << 2) ? b2 : 0) ^
		   uint8_t(a & (1 << 3) ? b3 : 0) ^
		   uint8_t(a & (1 << 4) ? b4 : 0) ^
		   uint8_t(a & (1 << 5) ? b5 : 0) ^
		   uint8_t(a & (1 << 6) ? b6 : 0) ^
		   uint8_t(a & (1 << 7) ? b7 : 0);
}

int main()
{
	for(auto a = 0; a < 16; a++)
	{
		std::cout << "//Table for " << std::dec << a << std::endl;
		for(auto b = 0; b < 256; b++)
		{
			std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << int(gfmul(a, b, GF_MOD));
			if (b != 255) std::cout << ",";
			if ((b + 1) % 32 == 0) std::cout << std::endl;
			else std::cout << " ";
		}

		std::cout << std::endl;
	}

	return 0;
}

