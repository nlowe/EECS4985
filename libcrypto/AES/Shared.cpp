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
 * Shared.cpp - Implementation of shared functions across AES subtypes
 */
#include "Shared.h"
#include "GaloisMul.h"
#include "Boxes.h"

namespace libcrypto
{
	namespace aes
	{
		inline void SubBytes(aes_block_t& block)
		{
			block[0] = s[block[0]];
			block[1] = s[block[1]];
			block[2] = s[block[2]];
			block[3] = s[block[3]];
			block[4] = s[block[4]];
			block[5] = s[block[5]];
			block[6] = s[block[6]];
			block[7] = s[block[7]];
			block[8] = s[block[8]];
			block[9] = s[block[9]];
			block[10] = s[block[10]];
			block[11] = s[block[11]];
			block[12] = s[block[12]];
			block[13] = s[block[13]];
			block[14] = s[block[14]];
			block[15] = s[block[15]];
		}

		inline void InvSubBytes(aes_block_t& block)
		{
			block[0] = si[block[0]];
			block[1] = si[block[1]];
			block[2] = si[block[2]];
			block[3] = si[block[3]];
			block[4] = si[block[4]];
			block[5] = si[block[5]];
			block[6] = si[block[6]];
			block[7] = si[block[7]];
			block[8] = si[block[8]];
			block[9] = si[block[9]];
			block[10] = si[block[10]];
			block[11] = si[block[11]];
			block[12] = si[block[12]];
			block[13] = si[block[13]];
			block[14] = si[block[14]];
			block[15] = si[block[15]];
		}

		inline void ShiftRows(aes_block_t& block)
		{
			// Row 0 is not shifted
			// Row 1 << 1
			auto tmp = block[4];
			block[4] = block[5];
			block[5] = block[6];
			block[6] = block[7];
			block[7] = tmp;

			// Row 2 << 2
			tmp = block[8];
			auto tmp2 = block[9];
			block[8] = block[10];
			block[9] = block[11];
			block[10] = tmp;
			block[11] = tmp2;
			
			// Row 3 << 3
			tmp = block[15];
			block[15] = block[14];
			block[14] = block[13];
			block[13] = block[12];
			block[12] = tmp;
		}

		inline void InvShiftRows(aes_block_t& block)
		{
			// Row 0 is not shifted
			// Row 1 >> 1
			auto tmp = block[3];
			block[3] = block[2];
			block[2] = block[1];
			block[1] = block[0];
			block[0] = tmp;

			// Row 2 >> 2
			tmp = block[7];
			auto tmp2 = block[6];
			block[7] = block[5];
			block[6] = block[4];
			block[5] = tmp;
			block[4] = tmp2;

			// Row 3 >> 3
			tmp = block[12];
			block[12] = block[13];
			block[13] = block[14];
			block[14] = block[15];
			block[15] = tmp;
		}

		inline void MixColumns(aes_block_t& block)
		{
			// Column 1 (0,4,8,12)
			block[0]  = gfmul2[block[0]] ^ gfmul3[block[4]] ^        block[8]  ^        block[12];
			block[4]  =        block[0]  ^ gfmul2[block[4]] ^ gfmul3[block[8]] ^        block[12];
			block[8]  =        block[0]  ^        block[4]  ^ gfmul2[block[8]] ^ gfmul3[block[12]];
			block[12] = gfmul3[block[0]] ^        block[4]  ^        block[8]  ^ gfmul2[block[12]];

			// Column 2 (1,5,9,13)
			block[1]  = gfmul2[block[1]] ^ gfmul3[block[5]] ^        block[9]  ^        block[13];
			block[5]  =        block[1]  ^ gfmul2[block[5]] ^ gfmul3[block[9]] ^        block[13];
			block[9]  =        block[1]  ^        block[5]  ^ gfmul2[block[9]] ^ gfmul3[block[13]];
			block[13] = gfmul3[block[1]] ^        block[5]  ^        block[9]  ^ gfmul2[block[13]];

			// Column 3 (2,6,10,14)
			block[2]  = gfmul2[block[2]] ^ gfmul3[block[6]] ^        block[10]  ^        block[14];
			block[6]  =        block[2]  ^ gfmul2[block[6]] ^ gfmul3[block[10]] ^        block[14];
			block[10] =        block[2]  ^        block[6]  ^ gfmul2[block[10]] ^ gfmul3[block[14]];
			block[14] = gfmul3[block[2]] ^        block[6]  ^        block[10]  ^ gfmul2[block[14]];

			// Column 4 (3,7,11,15)
			block[3]  = gfmul2[block[3]] ^ gfmul3[block[7]] ^        block[11]  ^        block[15];
			block[7]  =        block[3]  ^ gfmul2[block[7]] ^ gfmul3[block[11]] ^        block[15];
			block[11] =        block[3]  ^        block[7]  ^ gfmul2[block[11]] ^ gfmul3[block[15]];
			block[15] = gfmul3[block[3]] ^        block[7]  ^        block[11]  ^ gfmul2[block[15]];
		}
		
		inline void InvMixColumns(aes_block_t& block)
		{
			// Column 1 (0,4,8,12)
			block[0]  = gfmul14[block[0]] ^ gfmul11[block[4]] ^ gfmul13[block[8]] ^  gfmul9[block[12]];
			block[4]  =  gfmul9[block[0]] ^ gfmul14[block[4]] ^ gfmul11[block[8]] ^ gfmul13[block[12]];
			block[8]  = gfmul13[block[0]] ^  gfmul9[block[4]] ^ gfmul14[block[8]] ^ gfmul11[block[12]];
			block[12] = gfmul11[block[0]] ^ gfmul13[block[4]] ^  gfmul9[block[8]] ^ gfmul14[block[12]];

			// Column 2 (1,5,9,13)
			block[1]  = gfmul14[block[1]] ^ gfmul11[block[5]] ^ gfmul13[block[9]] ^  gfmul9[block[13]];
			block[5]  =  gfmul9[block[1]] ^ gfmul14[block[5]] ^ gfmul11[block[9]] ^ gfmul13[block[13]];
			block[9]  = gfmul13[block[1]] ^  gfmul9[block[5]] ^ gfmul14[block[9]] ^ gfmul11[block[13]];
			block[13] = gfmul11[block[1]] ^ gfmul13[block[5]] ^  gfmul9[block[9]] ^ gfmul14[block[13]];

			// Column 3 (2,6,10,14)
			block[2]  = gfmul14[block[2]] ^ gfmul11[block[6]] ^ gfmul13[block[10]] ^  gfmul9[block[14]];
			block[6]  =  gfmul9[block[2]] ^ gfmul14[block[6]] ^ gfmul11[block[10]] ^ gfmul13[block[14]];
			block[10] = gfmul13[block[2]] ^  gfmul9[block[6]] ^ gfmul14[block[10]] ^ gfmul11[block[14]];
			block[14] = gfmul11[block[2]] ^ gfmul13[block[6]] ^  gfmul9[block[10]] ^ gfmul14[block[14]];

			// Column 4 (3,7,11,15)
			block[3]  = gfmul14[block[3]] ^ gfmul11[block[7]] ^ gfmul13[block[11]] ^  gfmul9[block[15]];
			block[7]  =  gfmul9[block[3]] ^ gfmul14[block[7]] ^ gfmul11[block[11]] ^ gfmul13[block[15]];
			block[11] = gfmul13[block[3]] ^  gfmul9[block[7]] ^ gfmul14[block[11]] ^ gfmul11[block[15]];
			block[15] = gfmul11[block[3]] ^ gfmul13[block[7]] ^  gfmul9[block[11]] ^ gfmul14[block[15]];
		}
	}
}