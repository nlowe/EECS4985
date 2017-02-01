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
 * Boxes.h - S and P boxes for DES ECB mode
 */

#pragma once
#include <cstdint>

/**
 * The compression P-Box used to compress the 64 bit key into a 56 bit permutation
 *
 * Usage: KeyPC64To56[i] = k: output bit i is the k'th bit of the key
 */
const uint8_t KeyPC64To56[] = {
	57, 49, 41, 33, 25, 17, 9,
	1,  58, 50, 42, 34, 26, 18,
	10, 2,  59, 51, 43, 35, 27,
	19, 11, 3,  60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7,  62, 54, 46, 38, 30, 22,
	14, 6,  61, 53, 45, 37, 29,
	21, 13, 5,  28, 20, 12, 4 
};

inline uint64_t KeyPC64To56_unrolled(uint64_t in)
{
	uint64_t out = 0;

	out |= ((in >> (64 - 4)) & 1) << 0;
	out |= ((in >> (64 - 12)) & 1) << 1;
	out |= ((in >> (64 - 20)) & 1) << 2;
	out |= ((in >> (64 - 28)) & 1) << 3;
	out |= ((in >> (64 - 5)) & 1) << 4;
	out |= ((in >> (64 - 13)) & 1) << 5;
	out |= ((in >> (64 - 21)) & 1) << 6;
	out |= ((in >> (64 - 29)) & 1) << 7;
	out |= ((in >> (64 - 37)) & 1) << 8;
	out |= ((in >> (64 - 45)) & 1) << 9;
	out |= ((in >> (64 - 53)) & 1) << 10;
	out |= ((in >> (64 - 61)) & 1) << 11;
	out |= ((in >> (64 - 6)) & 1) << 12;
	out |= ((in >> (64 - 14)) & 1) << 13;
	out |= ((in >> (64 - 22)) & 1) << 14;
	out |= ((in >> (64 - 30)) & 1) << 15;
	out |= ((in >> (64 - 38)) & 1) << 16;
	out |= ((in >> (64 - 46)) & 1) << 17;
	out |= ((in >> (64 - 54)) & 1) << 18;
	out |= ((in >> (64 - 62)) & 1) << 19;
	out |= ((in >> (64 - 7)) & 1) << 20;
	out |= ((in >> (64 - 15)) & 1) << 21;
	out |= ((in >> (64 - 23)) & 1) << 22;
	out |= ((in >> (64 - 31)) & 1) << 23;
	out |= ((in >> (64 - 39)) & 1) << 24;
	out |= ((in >> (64 - 47)) & 1) << 25;
	out |= ((in >> (64 - 55)) & 1) << 26;
	out |= ((in >> (64 - 63)) & 1) << 27;
	out |= ((in >> (64 - 36)) & 1) << 28;
	out |= ((in >> (64 - 44)) & 1) << 29;
	out |= ((in >> (64 - 52)) & 1) << 30;
	out |= ((in >> (64 - 60)) & 1) << 31;
	out |= ((in >> (64 - 3)) & 1) << 32;
	out |= ((in >> (64 - 11)) & 1) << 33;
	out |= ((in >> (64 - 19)) & 1) << 34;
	out |= ((in >> (64 - 27)) & 1) << 35;
	out |= ((in >> (64 - 35)) & 1) << 36;
	out |= ((in >> (64 - 43)) & 1) << 37;
	out |= ((in >> (64 - 51)) & 1) << 38;
	out |= ((in >> (64 - 59)) & 1) << 39;
	out |= ((in >> (64 - 2)) & 1) << 40;
	out |= ((in >> (64 - 10)) & 1) << 41;
	out |= ((in >> (64 - 18)) & 1) << 42;
	out |= ((in >> (64 - 26)) & 1) << 43;
	out |= ((in >> (64 - 34)) & 1) << 44;
	out |= ((in >> (64 - 42)) & 1) << 45;
	out |= ((in >> (64 - 50)) & 1) << 46;
	out |= ((in >> (64 - 58)) & 1) << 47;
	out |= ((in >> (64 - 1)) & 1) << 48;
	out |= ((in >> (64 - 9)) & 1) << 49;
	out |= ((in >> (64 - 17)) & 1) << 50;
	out |= ((in >> (64 - 25)) & 1) << 51;
	out |= ((in >> (64 - 33)) & 1) << 52;
	out |= ((in >> (64 - 41)) & 1) << 53;
	out |= ((in >> (64 - 49)) & 1) << 54;
	out |= ((in >> (64 - 57)) & 1) << 55;

	return out;
}

/**
* The compression P-Box used to compress the 56 bit key into a 48 bit permutation
*
* Usage: KeyPC56To48[i] = k: output bit i is the k'th bit of the key
*/
const uint8_t KeyPC56To48[] = {
	14, 17, 11, 24, 1,  5,
	3,  28, 15, 6,  21, 10,
	23, 19, 12, 4,  26, 8,
	16, 7,  27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

inline uint64_t KeyPC56To48_unrolled(uint64_t in)
{
	uint64_t out = 0;

	out |= ((in >> (56 - 32)) & 1) << 0;
	out |= ((in >> (56 - 29)) & 1) << 1;
	out |= ((in >> (56 - 36)) & 1) << 2;
	out |= ((in >> (56 - 50)) & 1) << 3;
	out |= ((in >> (56 - 42)) & 1) << 4;
	out |= ((in >> (56 - 46)) & 1) << 5;
	out |= ((in >> (56 - 53)) & 1) << 6;
	out |= ((in >> (56 - 34)) & 1) << 7;
	out |= ((in >> (56 - 56)) & 1) << 8;
	out |= ((in >> (56 - 39)) & 1) << 9;
	out |= ((in >> (56 - 49)) & 1) << 10;
	out |= ((in >> (56 - 44)) & 1) << 11;
	out |= ((in >> (56 - 48)) & 1) << 12;
	out |= ((in >> (56 - 33)) & 1) << 13;
	out |= ((in >> (56 - 45)) & 1) << 14;
	out |= ((in >> (56 - 51)) & 1) << 15;
	out |= ((in >> (56 - 40)) & 1) << 16;
	out |= ((in >> (56 - 30)) & 1) << 17;
	out |= ((in >> (56 - 55)) & 1) << 18;
	out |= ((in >> (56 - 47)) & 1) << 19;
	out |= ((in >> (56 - 37)) & 1) << 20;
	out |= ((in >> (56 - 31)) & 1) << 21;
	out |= ((in >> (56 - 52)) & 1) << 22;
	out |= ((in >> (56 - 41)) & 1) << 23;
	out |= ((in >> (56 - 2)) & 1) << 24;
	out |= ((in >> (56 - 13)) & 1) << 25;
	out |= ((in >> (56 - 20)) & 1) << 26;
	out |= ((in >> (56 - 27)) & 1) << 27;
	out |= ((in >> (56 - 7)) & 1) << 28;
	out |= ((in >> (56 - 16)) & 1) << 29;
	out |= ((in >> (56 - 8)) & 1) << 30;
	out |= ((in >> (56 - 26)) & 1) << 31;
	out |= ((in >> (56 - 4)) & 1) << 32;
	out |= ((in >> (56 - 12)) & 1) << 33;
	out |= ((in >> (56 - 19)) & 1) << 34;
	out |= ((in >> (56 - 23)) & 1) << 35;
	out |= ((in >> (56 - 10)) & 1) << 36;
	out |= ((in >> (56 - 21)) & 1) << 37;
	out |= ((in >> (56 - 6)) & 1) << 38;
	out |= ((in >> (56 - 15)) & 1) << 39;
	out |= ((in >> (56 - 28)) & 1) << 40;
	out |= ((in >> (56 - 3)) & 1) << 41;
	out |= ((in >> (56 - 5)) & 1) << 42;
	out |= ((in >> (56 - 1)) & 1) << 43;
	out |= ((in >> (56 - 24)) & 1) << 44;
	out |= ((in >> (56 - 11)) & 1) << 45;
	out |= ((in >> (56 - 17)) & 1) << 46;
	out |= ((in >> (56 - 14)) & 1) << 47;

	return out;
}

/**
 * The rotation schedule for computing keys for each round. 
 *
 * Usage: Rotate each half of the key by RotationSchedule[roundNumber] bits
 */
const uint8_t RotationSchedule[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

/**
 * The inital permutation table run on the input block
 *
 * Usage: InitialBlockPermutation[i] = k: output bit i is the k'th bit of the input
 */
const uint8_t InitalBlockPermutation[] = {
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9,  1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

inline uint64_t InitialBlockPermutation_unrolled(uint64_t in)
{
	uint64_t out = 0;

	out |= ((in >> (64 - 7)) & 1) << 0;
	out |= ((in >> (64 - 15)) & 1) << 1;
	out |= ((in >> (64 - 23)) & 1) << 2;
	out |= ((in >> (64 - 31)) & 1) << 3;
	out |= ((in >> (64 - 39)) & 1) << 4;
	out |= ((in >> (64 - 47)) & 1) << 5;
	out |= ((in >> (64 - 55)) & 1) << 6;
	out |= ((in >> (64 - 63)) & 1) << 7;
	out |= ((in >> (64 - 5)) & 1) << 8;
	out |= ((in >> (64 - 13)) & 1) << 9;
	out |= ((in >> (64 - 21)) & 1) << 10;
	out |= ((in >> (64 - 29)) & 1) << 11;
	out |= ((in >> (64 - 37)) & 1) << 12;
	out |= ((in >> (64 - 45)) & 1) << 13;
	out |= ((in >> (64 - 53)) & 1) << 14;
	out |= ((in >> (64 - 61)) & 1) << 15;
	out |= ((in >> (64 - 3)) & 1) << 16;
	out |= ((in >> (64 - 11)) & 1) << 17;
	out |= ((in >> (64 - 19)) & 1) << 18;
	out |= ((in >> (64 - 27)) & 1) << 19;
	out |= ((in >> (64 - 35)) & 1) << 20;
	out |= ((in >> (64 - 43)) & 1) << 21;
	out |= ((in >> (64 - 51)) & 1) << 22;
	out |= ((in >> (64 - 59)) & 1) << 23;
	out |= ((in >> (64 - 1)) & 1) << 24;
	out |= ((in >> (64 - 9)) & 1) << 25;
	out |= ((in >> (64 - 17)) & 1) << 26;
	out |= ((in >> (64 - 25)) & 1) << 27;
	out |= ((in >> (64 - 33)) & 1) << 28;
	out |= ((in >> (64 - 41)) & 1) << 29;
	out |= ((in >> (64 - 49)) & 1) << 30;
	out |= ((in >> (64 - 57)) & 1) << 31;
	out |= ((in >> (64 - 8)) & 1) << 32;
	out |= ((in >> (64 - 16)) & 1) << 33;
	out |= ((in >> (64 - 24)) & 1) << 34;
	out |= ((in >> (64 - 32)) & 1) << 35;
	out |= ((in >> (64 - 40)) & 1) << 36;
	out |= ((in >> (64 - 48)) & 1) << 37;
	out |= ((in >> (64 - 56)) & 1) << 38;
	out |= ((in >> (64 - 64)) & 1) << 39;
	out |= ((in >> (64 - 6)) & 1) << 40;
	out |= ((in >> (64 - 14)) & 1) << 41;
	out |= ((in >> (64 - 22)) & 1) << 42;
	out |= ((in >> (64 - 30)) & 1) << 43;
	out |= ((in >> (64 - 38)) & 1) << 44;
	out |= ((in >> (64 - 46)) & 1) << 45;
	out |= ((in >> (64 - 54)) & 1) << 46;
	out |= ((in >> (64 - 62)) & 1) << 47;
	out |= ((in >> (64 - 4)) & 1) << 48;
	out |= ((in >> (64 - 12)) & 1) << 49;
	out |= ((in >> (64 - 20)) & 1) << 50;
	out |= ((in >> (64 - 28)) & 1) << 51;
	out |= ((in >> (64 - 36)) & 1) << 52;
	out |= ((in >> (64 - 44)) & 1) << 53;
	out |= ((in >> (64 - 52)) & 1) << 54;
	out |= ((in >> (64 - 60)) & 1) << 55;
	out |= ((in >> (64 - 2)) & 1) << 56;
	out |= ((in >> (64 - 10)) & 1) << 57;
	out |= ((in >> (64 - 18)) & 1) << 58;
	out |= ((in >> (64 - 26)) & 1) << 59;
	out |= ((in >> (64 - 34)) & 1) << 60;
	out |= ((in >> (64 - 42)) & 1) << 61;
	out |= ((in >> (64 - 50)) & 1) << 62;
	out |= ((in >> (64 - 58)) & 1) << 63;


	return out;
}

/**
 * The expansion permutation table that is run on the right half of the block in a fistel round
 *
 * Usage: BlockPE32To48[i] = k: output bit i is the k'th bit of the input
 */
const uint8_t BlockPE32To48[] = {
	32, 1,  2,  3,  4,  5,
	4,  5,  6,  7,  8,  9,
	8,  9,  10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1
};

inline uint64_t BlockPE32To48_unrolled(uint64_t in)
{
	uint64_t out = 0;

	out |= ((in >> (32 - 1)) & 1) << 0;
	out |= ((in >> (32 - 32)) & 1) << 1;
	out |= ((in >> (32 - 31)) & 1) << 2;
	out |= ((in >> (32 - 30)) & 1) << 3;
	out |= ((in >> (32 - 29)) & 1) << 4;
	out |= ((in >> (32 - 28)) & 1) << 5;
	out |= ((in >> (32 - 29)) & 1) << 6;
	out |= ((in >> (32 - 28)) & 1) << 7;
	out |= ((in >> (32 - 27)) & 1) << 8;
	out |= ((in >> (32 - 26)) & 1) << 9;
	out |= ((in >> (32 - 25)) & 1) << 10;
	out |= ((in >> (32 - 24)) & 1) << 11;
	out |= ((in >> (32 - 25)) & 1) << 12;
	out |= ((in >> (32 - 24)) & 1) << 13;
	out |= ((in >> (32 - 23)) & 1) << 14;
	out |= ((in >> (32 - 22)) & 1) << 15;
	out |= ((in >> (32 - 21)) & 1) << 16;
	out |= ((in >> (32 - 20)) & 1) << 17;
	out |= ((in >> (32 - 21)) & 1) << 18;
	out |= ((in >> (32 - 20)) & 1) << 19;
	out |= ((in >> (32 - 19)) & 1) << 20;
	out |= ((in >> (32 - 18)) & 1) << 21;
	out |= ((in >> (32 - 17)) & 1) << 22;
	out |= ((in >> (32 - 16)) & 1) << 23;
	out |= ((in >> (32 - 17)) & 1) << 24;
	out |= ((in >> (32 - 16)) & 1) << 25;
	out |= ((in >> (32 - 15)) & 1) << 26;
	out |= ((in >> (32 - 14)) & 1) << 27;
	out |= ((in >> (32 - 13)) & 1) << 28;
	out |= ((in >> (32 - 12)) & 1) << 29;
	out |= ((in >> (32 - 13)) & 1) << 30;
	out |= ((in >> (32 - 12)) & 1) << 31;
	out |= ((in >> (32 - 11)) & 1) << 32;
	out |= ((in >> (32 - 10)) & 1) << 33;
	out |= ((in >> (32 - 9)) & 1) << 34;
	out |= ((in >> (32 - 8)) & 1) << 35;
	out |= ((in >> (32 - 9)) & 1) << 36;
	out |= ((in >> (32 - 8)) & 1) << 37;
	out |= ((in >> (32 - 7)) & 1) << 38;
	out |= ((in >> (32 - 6)) & 1) << 39;
	out |= ((in >> (32 - 5)) & 1) << 40;
	out |= ((in >> (32 - 4)) & 1) << 41;
	out |= ((in >> (32 - 5)) & 1) << 42;
	out |= ((in >> (32 - 4)) & 1) << 43;
	out |= ((in >> (32 - 3)) & 1) << 44;
	out |= ((in >> (32 - 2)) & 1) << 45;
	out |= ((in >> (32 - 1)) & 1) << 46;
	out |= ((in >> (32 - 32)) & 1) << 47;

	return out;
}

/**
 * The final permutation table run on the ciphertext block
 *
 * Usage: FinalBlockPermutation[i] = k: output bit i is the k'th bit of the input
 */
const uint8_t FinalBlockPermutation[] = {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9,  49, 17, 57, 25
};

inline uint64_t FinalBlockPermutation_unrolled(uint64_t in)
{
	uint64_t out = 0;

	out |= ((in >> (64 - 25)) & 1) << 0;
	out |= ((in >> (64 - 57)) & 1) << 1;
	out |= ((in >> (64 - 17)) & 1) << 2;
	out |= ((in >> (64 - 49)) & 1) << 3;
	out |= ((in >> (64 - 9)) & 1) << 4;
	out |= ((in >> (64 - 41)) & 1) << 5;
	out |= ((in >> (64 - 1)) & 1) << 6;
	out |= ((in >> (64 - 33)) & 1) << 7;
	out |= ((in >> (64 - 26)) & 1) << 8;
	out |= ((in >> (64 - 58)) & 1) << 9;
	out |= ((in >> (64 - 18)) & 1) << 10;
	out |= ((in >> (64 - 50)) & 1) << 11;
	out |= ((in >> (64 - 10)) & 1) << 12;
	out |= ((in >> (64 - 42)) & 1) << 13;
	out |= ((in >> (64 - 2)) & 1) << 14;
	out |= ((in >> (64 - 34)) & 1) << 15;
	out |= ((in >> (64 - 27)) & 1) << 16;
	out |= ((in >> (64 - 59)) & 1) << 17;
	out |= ((in >> (64 - 19)) & 1) << 18;
	out |= ((in >> (64 - 51)) & 1) << 19;
	out |= ((in >> (64 - 11)) & 1) << 20;
	out |= ((in >> (64 - 43)) & 1) << 21;
	out |= ((in >> (64 - 3)) & 1) << 22;
	out |= ((in >> (64 - 35)) & 1) << 23;
	out |= ((in >> (64 - 28)) & 1) << 24;
	out |= ((in >> (64 - 60)) & 1) << 25;
	out |= ((in >> (64 - 20)) & 1) << 26;
	out |= ((in >> (64 - 52)) & 1) << 27;
	out |= ((in >> (64 - 12)) & 1) << 28;
	out |= ((in >> (64 - 44)) & 1) << 29;
	out |= ((in >> (64 - 4)) & 1) << 30;
	out |= ((in >> (64 - 36)) & 1) << 31;
	out |= ((in >> (64 - 29)) & 1) << 32;
	out |= ((in >> (64 - 61)) & 1) << 33;
	out |= ((in >> (64 - 21)) & 1) << 34;
	out |= ((in >> (64 - 53)) & 1) << 35;
	out |= ((in >> (64 - 13)) & 1) << 36;
	out |= ((in >> (64 - 45)) & 1) << 37;
	out |= ((in >> (64 - 5)) & 1) << 38;
	out |= ((in >> (64 - 37)) & 1) << 39;
	out |= ((in >> (64 - 30)) & 1) << 40;
	out |= ((in >> (64 - 62)) & 1) << 41;
	out |= ((in >> (64 - 22)) & 1) << 42;
	out |= ((in >> (64 - 54)) & 1) << 43;
	out |= ((in >> (64 - 14)) & 1) << 44;
	out |= ((in >> (64 - 46)) & 1) << 45;
	out |= ((in >> (64 - 6)) & 1) << 46;
	out |= ((in >> (64 - 38)) & 1) << 47;
	out |= ((in >> (64 - 31)) & 1) << 48;
	out |= ((in >> (64 - 63)) & 1) << 49;
	out |= ((in >> (64 - 23)) & 1) << 50;
	out |= ((in >> (64 - 55)) & 1) << 51;
	out |= ((in >> (64 - 15)) & 1) << 52;
	out |= ((in >> (64 - 47)) & 1) << 53;
	out |= ((in >> (64 - 7)) & 1) << 54;
	out |= ((in >> (64 - 39)) & 1) << 55;
	out |= ((in >> (64 - 32)) & 1) << 56;
	out |= ((in >> (64 - 64)) & 1) << 57;
	out |= ((in >> (64 - 24)) & 1) << 58;
	out |= ((in >> (64 - 56)) & 1) << 59;
	out |= ((in >> (64 - 16)) & 1) << 60;
	out |= ((in >> (64 - 48)) & 1) << 61;
	out |= ((in >> (64 - 8)) & 1) << 62;
	out |= ((in >> (64 - 40)) & 1) << 63;

	return out;
}

/**
 * The first Substitution Box
 *
 * Usage: compute R and C where
 *    * R is the two-bit number composed of the MSB then LSB of the input
 *    * C is the four bit number composed of the middle 4 bits of the input
 * S1[(R << 4) + C] is the value to substitute
 */
const uint8_t S0[] = 
{
	14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
	0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
	4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
	15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
};

/**
 * The second Substitution Box
 *
 * Usage: compute R and C where
 *    * R is the two-bit number composed of the MSB then LSB of the input
 *    * C is the four bit number composed of the middle 4 bits of the input
 * S1[(R << 4) + C] is the value to substitute
 */
const uint8_t S1[] = 
{
		15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
};

/**
 * The third Substitution Box
 *
 * Usage: compute R and C where
 *    * R is the two-bit number composed of the MSB then LSB of the input
 *    * C is the four bit number composed of the middle 4 bits of the input
 * S1[(R << 4) + C] is the value to substitute
 */
const uint8_t S2[] = {
		10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
};

/**
 * The fourth Substitution Box
 *
 * Usage: compute R and C where
 *    * R is the two-bit number composed of the MSB then LSB of the input
 *    * C is the four bit number composed of the middle 4 bits of the input
 * S1[(R << 4) + C] is the value to substitute
 */
const uint8_t S3[] = {
		7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
};

/**
 * The fifth Substitution Box
 *
 * Usage: compute R and C where
 *    * R is the two-bit number composed of the MSB then LSB of the input
 *    * C is the four bit number composed of the middle 4 bits of the input
 * S1[(R << 4) + C] is the value to substitute
 */
const uint8_t S4[] = {
		2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
};

/**
 * The sixth Substitution Box
 *
 * Usage: compute R and C where
 *    * R is the two-bit number composed of the MSB then LSB of the input
 *    * C is the four bit number composed of the middle 4 bits of the input
 * S1[(R << 4) + C] is the value to substitute
 */
const uint8_t S5[] = {
		12, 1,  10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9,  14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4,  3,  2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
};

/**
 * The seventh Substitution Box
 *
 * Usage: compute R and C where
 *    * R is the two-bit number composed of the MSB then LSB of the input
 *    * C is the four bit number composed of the middle 4 bits of the input
 * S1[(R << 4) + C] is the value to substitute
 */
const uint8_t S6[] = {
		4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
};

/**
 * The eight and final Substitution Box
 *
 * Usage: compute R and C where
 *    * R is the two-bit number composed of the MSB then LSB of the input
 *    * C is the four bit number composed of the middle 4 bits of the input
 * S1[(R << 4) + C] is the value to substitute
 */
const uint8_t S7[] = {
		13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
};

/**
 * The straight P-Box used to mix the block in the fistel round
 *
 * Usage: BlockP32[i] = k: output bit i is the k'th bit of the input
 */
const uint8_t BlockP32[] = {
	16, 7, 20, 21, 
	29, 12, 28, 17, 
	1, 15, 23, 26, 
	5, 18, 31, 10, 
	2, 8, 24, 14, 
	32, 27, 3, 9, 
	19, 13, 30, 6, 
	22, 11, 4, 25
};

inline uint64_t BlockP32_unrolled(uint64_t in)
{
	uint64_t out = 0;

	out |= ((in >> (32 - 25)) & 1) << 0;
	out |= ((in >> (32 - 4)) & 1) << 1;
	out |= ((in >> (32 - 11)) & 1) << 2;
	out |= ((in >> (32 - 22)) & 1) << 3;
	out |= ((in >> (32 - 6)) & 1) << 4;
	out |= ((in >> (32 - 30)) & 1) << 5;
	out |= ((in >> (32 - 13)) & 1) << 6;
	out |= ((in >> (32 - 19)) & 1) << 7;
	out |= ((in >> (32 - 9)) & 1) << 8;
	out |= ((in >> (32 - 3)) & 1) << 9;
	out |= ((in >> (32 - 27)) & 1) << 10;
	out |= ((in >> (32 - 32)) & 1) << 11;
	out |= ((in >> (32 - 14)) & 1) << 12;
	out |= ((in >> (32 - 24)) & 1) << 13;
	out |= ((in >> (32 - 8)) & 1) << 14;
	out |= ((in >> (32 - 2)) & 1) << 15;
	out |= ((in >> (32 - 10)) & 1) << 16;
	out |= ((in >> (32 - 31)) & 1) << 17;
	out |= ((in >> (32 - 18)) & 1) << 18;
	out |= ((in >> (32 - 5)) & 1) << 19;
	out |= ((in >> (32 - 26)) & 1) << 20;
	out |= ((in >> (32 - 23)) & 1) << 21;
	out |= ((in >> (32 - 15)) & 1) << 22;
	out |= ((in >> (32 - 1)) & 1) << 23;
	out |= ((in >> (32 - 17)) & 1) << 24;
	out |= ((in >> (32 - 28)) & 1) << 25;
	out |= ((in >> (32 - 12)) & 1) << 26;
	out |= ((in >> (32 - 29)) & 1) << 27;
	out |= ((in >> (32 - 21)) & 1) << 28;
	out |= ((in >> (32 - 20)) & 1) << 29;
	out |= ((in >> (32 - 7)) & 1) << 30;
	out |= ((in >> (32 - 16)) & 1) << 31;

	return out;
}