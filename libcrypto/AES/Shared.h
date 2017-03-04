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
 * Shared.h - Shared functions across sub-types of AES
 */
#pragma once
#include "AES.h"
#include "GaloisMul.h"
#include "Boxes.h"

namespace libcrypto
{
	namespace aes
	{
		inline void buffstuff(char* buff, size_t off, aes_block_t& block)
		{
			buff[off + 0] = block[0][0]; buff[off + 4] = block[0][1]; buff[off +  8] = block[0][2]; buff[off + 12] = block[0][3];
			buff[off + 1] = block[1][0]; buff[off + 5] = block[1][1]; buff[off +  9] = block[1][2]; buff[off + 13] = block[1][3];
			buff[off + 2] = block[2][0]; buff[off + 6] = block[2][1]; buff[off + 10] = block[2][2]; buff[off + 14] = block[2][3];
			buff[off + 3] = block[3][0]; buff[off + 7] = block[3][1]; buff[off + 11] = block[3][2]; buff[off + 15] = block[3][3];
		}

		inline void SubBytes(aes_block_t& block)
		{
			block[0][0] = s[block[0][0]]; block[0][1] = s[block[0][1]]; block[0][2] = s[block[0][2]]; block[0][3] = s[block[0][3]];
			block[1][0] = s[block[1][0]]; block[1][1] = s[block[1][1]]; block[1][2] = s[block[1][2]]; block[1][3] = s[block[1][3]];
			block[2][0] = s[block[2][0]]; block[2][1] = s[block[2][1]]; block[2][2] = s[block[2][2]]; block[2][3] = s[block[2][3]];
			block[3][0] = s[block[3][0]]; block[3][1] = s[block[3][1]]; block[3][2] = s[block[3][2]]; block[3][3] = s[block[3][3]];
		}

		inline void InvSubBytes(aes_block_t& block)
		{
			block[0][0] = si[block[0][0]]; block[0][1] = si[block[0][1]]; block[0][2] = si[block[0][2]]; block[0][3] = si[block[0][3]];
			block[1][0] = si[block[1][0]]; block[1][1] = si[block[1][1]]; block[1][2] = si[block[1][2]]; block[1][3] = si[block[1][3]];
			block[2][0] = si[block[2][0]]; block[2][1] = si[block[2][1]]; block[2][2] = si[block[2][2]]; block[2][3] = si[block[2][3]];
			block[3][0] = si[block[3][0]]; block[3][1] = si[block[3][1]]; block[3][2] = si[block[3][2]]; block[3][3] = si[block[3][3]];
		}

		inline void ShiftRows(aes_block_t& block)
		{
			// Row 0 is not shifted
			// Row 1 << 1
			auto tmp    = block[1][0];
			block[1][0] = block[1][1];
			block[1][1] = block[1][2];
			block[1][2] = block[1][3];
			block[1][3] = tmp;

			// Row 2 << 2
			     tmp    = block[2][0];
			auto tmp2   = block[2][1];
			block[2][0] = block[2][2];
			block[2][1] = block[2][3];
			block[2][2] = tmp;
			block[2][3] = tmp2;
			
			// Row 3 << 3 (or 3 >> 1)
			        tmp = block[3][3];
			block[3][3] = block[3][2];
			block[3][2] = block[3][1];
			block[3][1] = block[3][0];
			block[3][0] = tmp;
		}

		inline void InvShiftRows(aes_block_t& block)
		{
			// Row 0 is not shifted
			// Row 1 >> 1
			auto tmp    = block[1][3];
			block[1][3] = block[1][2];
			block[1][2] = block[1][1];
			block[1][1] = block[1][0];
			block[1][0] = tmp;

			// Row 2 >> 2
			     tmp    = block[2][3];
			auto tmp2   = block[2][2];
			block[2][3] = block[2][1];
			block[2][2] = block[2][0];
			block[2][1] = tmp;
			block[2][0] = tmp2;

			// Row 3 >> 3 (or 3 << 1)
			     tmp    = block[3][0];
			block[3][0] = block[3][1];
			block[3][1] = block[3][2];
			block[3][2] = block[3][3];
			block[3][3] = tmp;
		}

		inline void MixColumns(aes_block_t& block)
		{
			aes_block_t tmp;

			// Column 1
			tmp[0][0] = gfmul2[block[0][0]] ^ gfmul3[block[1][0]] ^        block[2][0]  ^        block[3][0];
			tmp[1][0] =        block[0][0]  ^ gfmul2[block[1][0]] ^ gfmul3[block[2][0]] ^        block[3][0];
			tmp[2][0] =        block[0][0]  ^        block[1][0]  ^ gfmul2[block[2][0]] ^ gfmul3[block[3][0]];
			tmp[3][0] = gfmul3[block[0][0]] ^        block[1][0]  ^        block[2][0]  ^ gfmul2[block[3][0]];

			// Column 2
			tmp[0][1] = gfmul2[block[0][1]] ^ gfmul3[block[1][1]] ^        block[2][1]  ^        block[3][1];
			tmp[1][1] =        block[0][1]  ^ gfmul2[block[1][1]] ^ gfmul3[block[2][1]] ^        block[3][1];
			tmp[2][1] =        block[0][1]  ^        block[1][1]  ^ gfmul2[block[2][1]] ^ gfmul3[block[3][1]];
			tmp[3][1] = gfmul3[block[0][1]] ^        block[1][1]  ^        block[2][1]  ^ gfmul2[block[3][1]];

			// Column 3
			tmp[0][2] = gfmul2[block[0][2]] ^ gfmul3[block[1][2]] ^        block[2][2]  ^        block[3][2];
			tmp[1][2] =        block[0][2]  ^ gfmul2[block[1][2]] ^ gfmul3[block[2][2]] ^        block[3][2];
			tmp[2][2] =        block[0][2]  ^        block[1][2]  ^ gfmul2[block[2][2]] ^ gfmul3[block[3][2]];
			tmp[3][2] = gfmul3[block[0][2]] ^        block[1][2]  ^        block[2][2]  ^ gfmul2[block[3][2]];

			// Column 4
			tmp[0][3] = gfmul2[block[0][3]] ^ gfmul3[block[1][3]] ^        block[2][3]  ^        block[3][3];
			tmp[1][3] =        block[0][3]  ^ gfmul2[block[1][3]] ^ gfmul3[block[2][3]] ^        block[3][3];
			tmp[2][3] =        block[0][3]  ^        block[1][3]  ^ gfmul2[block[2][3]] ^ gfmul3[block[3][3]];
			tmp[3][3] = gfmul3[block[0][3]] ^        block[1][3]  ^        block[2][3]  ^ gfmul2[block[3][3]];

			block = tmp;
		}
		
		inline void InvMixColumns(aes_block_t& block)
		{
			aes_block_t tmp;

			// Column 1
			tmp[0][0] = gfmul14[block[0][0]] ^ gfmul11[block[1][0]] ^ gfmul13[block[2][0]] ^ gfmul09[block[3][0]];
			tmp[1][0] = gfmul09[block[0][0]] ^ gfmul14[block[1][0]] ^ gfmul11[block[2][0]] ^ gfmul13[block[3][0]];
			tmp[2][0] = gfmul13[block[0][0]] ^ gfmul09[block[1][0]] ^ gfmul14[block[2][0]] ^ gfmul11[block[3][0]];
			tmp[3][0] = gfmul11[block[0][0]] ^ gfmul13[block[1][0]] ^ gfmul09[block[2][0]] ^ gfmul14[block[3][0]];

			// Column 2
			tmp[0][1] = gfmul14[block[0][1]] ^ gfmul11[block[1][1]] ^ gfmul13[block[2][1]] ^ gfmul09[block[3][1]];
			tmp[1][1] = gfmul09[block[0][1]] ^ gfmul14[block[1][1]] ^ gfmul11[block[2][1]] ^ gfmul13[block[3][1]];
			tmp[2][1] = gfmul13[block[0][1]] ^ gfmul09[block[1][1]] ^ gfmul14[block[2][1]] ^ gfmul11[block[3][1]];
			tmp[3][1] = gfmul11[block[0][1]] ^ gfmul13[block[1][1]] ^ gfmul09[block[2][1]] ^ gfmul14[block[3][1]];

			// Column 3
			tmp[0][2] = gfmul14[block[0][2]] ^ gfmul11[block[1][2]] ^ gfmul13[block[2][2]] ^ gfmul09[block[3][2]];
			tmp[1][2] = gfmul09[block[0][2]] ^ gfmul14[block[1][2]] ^ gfmul11[block[2][2]] ^ gfmul13[block[3][2]];
			tmp[2][2] = gfmul13[block[0][2]] ^ gfmul09[block[1][2]] ^ gfmul14[block[2][2]] ^ gfmul11[block[3][2]];
			tmp[3][2] = gfmul11[block[0][2]] ^ gfmul13[block[1][2]] ^ gfmul09[block[2][2]] ^ gfmul14[block[3][2]];

			// Column 4
			tmp[0][3] = gfmul14[block[0][3]] ^ gfmul11[block[1][3]] ^ gfmul13[block[2][3]] ^ gfmul09[block[3][3]];
			tmp[1][3] = gfmul09[block[0][3]] ^ gfmul14[block[1][3]] ^ gfmul11[block[2][3]] ^ gfmul13[block[3][3]];
			tmp[2][3] = gfmul13[block[0][3]] ^ gfmul09[block[1][3]] ^ gfmul14[block[2][3]] ^ gfmul11[block[3][3]];
			tmp[3][3] = gfmul11[block[0][3]] ^ gfmul13[block[1][3]] ^ gfmul09[block[2][3]] ^ gfmul14[block[3][3]];

			block = tmp;
		}
	}
}

