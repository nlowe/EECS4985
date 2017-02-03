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
 * The compression permutation used to compress the 64 bit key into a 56 bit permutation
 */
inline uint64_t KeyPC64To56(uint64_t in)
{
	uint64_t out = 0;

	out |= ((in >> 60) & 1) <<  0;
	out |= ((in >> 52) & 1) <<  1;
	out |= ((in >> 44) & 1) <<  2;
	out |= ((in >> 36) & 1) <<  3;
	out |= ((in >> 59) & 1) <<  4;
	out |= ((in >> 51) & 1) <<  5;
	out |= ((in >> 43) & 1) <<  6;
	out |= ((in >> 35) & 1) <<  7;
	out |= ((in >> 27) & 1) <<  8;
	out |= ((in >> 19) & 1) <<  9;
	out |= ((in >> 11) & 1) << 10;
	out |= ((in >>  3) & 1) << 11;
	out |= ((in >> 58) & 1) << 12;
	out |= ((in >> 50) & 1) << 13;
	out |= ((in >> 42) & 1) << 14;
	out |= ((in >> 34) & 1) << 15;
	out |= ((in >> 26) & 1) << 16;
	out |= ((in >> 18) & 1) << 17;
	out |= ((in >> 10) & 1) << 18;
	out |= ((in >>  2) & 1) << 19;
	out |= ((in >> 57) & 1) << 20;
	out |= ((in >> 49) & 1) << 21;
	out |= ((in >> 41) & 1) << 22;
	out |= ((in >> 33) & 1) << 23;
	out |= ((in >> 25) & 1) << 24;
	out |= ((in >> 17) & 1) << 25;
	out |= ((in >>  9) & 1) << 26;
	out |= ((in >>  1) & 1) << 27;
	out |= ((in >> 28) & 1) << 28;
	out |= ((in >> 20) & 1) << 29;
	out |= ((in >> 12) & 1) << 30;
	out |= ((in >>  4) & 1) << 31;
	out |= ((in >> 61) & 1) << 32;
	out |= ((in >> 53) & 1) << 33;
	out |= ((in >> 45) & 1) << 34;
	out |= ((in >> 37) & 1) << 35;
	out |= ((in >> 29) & 1) << 36;
	out |= ((in >> 21) & 1) << 37;
	out |= ((in >> 13) & 1) << 38;
	out |= ((in >>  5) & 1) << 39;
	out |= ((in >> 62) & 1) << 40;
	out |= ((in >> 54) & 1) << 41;
	out |= ((in >> 46) & 1) << 42;
	out |= ((in >> 38) & 1) << 43;
	out |= ((in >> 30) & 1) << 44;
	out |= ((in >> 22) & 1) << 45;
	out |= ((in >> 14) & 1) << 46;
	out |= ((in >>  6) & 1) << 47;
	out |= ((in >> 63) & 1) << 48;
	out |= ((in >> 55) & 1) << 49;
	out |= ((in >> 47) & 1) << 50;
	out |= ((in >> 39) & 1) << 51;
	out |= ((in >> 31) & 1) << 52;
	out |= ((in >> 23) & 1) << 53;
	out |= ((in >> 15) & 1) << 54;
	out |= ((in >>  7) & 1) << 55;

	return out;
}

/**
* The compression permutation used to compress the 56 bit key into a 48 bit permutation
*/
inline uint64_t KeyPC56To48(uint64_t in)
{
	uint64_t out = 0;

	out |= ((in >> 24) & 1) <<  0;
	out |= ((in >> 27) & 1) <<  1;
	out |= ((in >> 20) & 1) <<  2;
	out |= ((in >>  6) & 1) <<  3;
	out |= ((in >> 14) & 1) <<  4;
	out |= ((in >> 10) & 1) <<  5;
	out |= ((in >>  3) & 1) <<  6;
	out |= ((in >> 22) & 1) <<  7;
	out |= ((in >>  0) & 1) <<  8;
	out |= ((in >> 17) & 1) <<  9;
	out |= ((in >>  7) & 1) << 10;
	out |= ((in >> 12) & 1) << 11;
	out |= ((in >>  8) & 1) << 12;
	out |= ((in >> 23) & 1) << 13;
	out |= ((in >> 11) & 1) << 14;
	out |= ((in >>  5) & 1) << 15;
	out |= ((in >> 16) & 1) << 16;
	out |= ((in >> 26) & 1) << 17;
	out |= ((in >>  1) & 1) << 18;
	out |= ((in >>  9) & 1) << 19;
	out |= ((in >> 19) & 1) << 20;
	out |= ((in >> 25) & 1) << 21;
	out |= ((in >>  4) & 1) << 22;
	out |= ((in >> 15) & 1) << 23;
	out |= ((in >> 54) & 1) << 24;
	out |= ((in >> 43) & 1) << 25;
	out |= ((in >> 36) & 1) << 26;
	out |= ((in >> 29) & 1) << 27;
	out |= ((in >> 49) & 1) << 28;
	out |= ((in >> 40) & 1) << 29;
	out |= ((in >> 48) & 1) << 30;
	out |= ((in >> 30) & 1) << 31;
	out |= ((in >> 52) & 1) << 32;
	out |= ((in >> 44) & 1) << 33;
	out |= ((in >> 37) & 1) << 34;
	out |= ((in >> 33) & 1) << 35;
	out |= ((in >> 46) & 1) << 36;
	out |= ((in >> 35) & 1) << 37;
	out |= ((in >> 50) & 1) << 38;
	out |= ((in >> 41) & 1) << 39;
	out |= ((in >> 28) & 1) << 40;
	out |= ((in >> 53) & 1) << 41;
	out |= ((in >> 51) & 1) << 42;
	out |= ((in >> 55) & 1) << 43;
	out |= ((in >> 32) & 1) << 44;
	out |= ((in >> 45) & 1) << 45;
	out |= ((in >> 39) & 1) << 46;
	out |= ((in >> 42) & 1) << 47;

	return out;
}

/**
 * The rotation schedule for computing keys for each round. 
 *
 * Usage: Rotate each half of the key by RotationSchedule[roundNumber] bits
 */
const uint8_t RotationSchedule[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

/**
 * The inital permutation run on the input block
 */
inline uint64_t InitialBlockPermutation(uint64_t in)
{
	uint64_t out = 0;

	out |= ((in >> 57) & 1) <<  0;
	out |= ((in >> 49) & 1) <<  1;
	out |= ((in >> 41) & 1) <<  2;
	out |= ((in >> 33) & 1) <<  3;
	out |= ((in >> 25) & 1) <<  4;
	out |= ((in >> 17) & 1) <<  5;
	out |= ((in >>  9) & 1) <<  6;
	out |= ((in >>  1) & 1) <<  7;
	out |= ((in >> 59) & 1) <<  8;
	out |= ((in >> 51) & 1) <<  9;
	out |= ((in >> 43) & 1) << 10;
	out |= ((in >> 35) & 1) << 11;
	out |= ((in >> 27) & 1) << 12;
	out |= ((in >> 19) & 1) << 13;
	out |= ((in >> 11) & 1) << 14;
	out |= ((in >>  3) & 1) << 15;
	out |= ((in >> 61) & 1) << 16;
	out |= ((in >> 53) & 1) << 17;
	out |= ((in >> 45) & 1) << 18;
	out |= ((in >> 37) & 1) << 19;
	out |= ((in >> 29) & 1) << 20;
	out |= ((in >> 21) & 1) << 21;
	out |= ((in >> 13) & 1) << 22;
	out |= ((in >>  5) & 1) << 23;
	out |= ((in >> 63) & 1) << 24;
	out |= ((in >> 55) & 1) << 25;
	out |= ((in >> 47) & 1) << 26;
	out |= ((in >> 39) & 1) << 27;
	out |= ((in >> 31) & 1) << 28;
	out |= ((in >> 23) & 1) << 29;
	out |= ((in >> 15) & 1) << 30;
	out |= ((in >>  7) & 1) << 31;
	out |= ((in >> 56) & 1) << 32;
	out |= ((in >> 48) & 1) << 33;
	out |= ((in >> 40) & 1) << 34;
	out |= ((in >> 32) & 1) << 35;
	out |= ((in >> 24) & 1) << 36;
	out |= ((in >> 16) & 1) << 37;
	out |= ((in >>  8) & 1) << 38;
	out |= ((in >>  0) & 1) << 39;
	out |= ((in >> 58) & 1) << 40;
	out |= ((in >> 50) & 1) << 41;
	out |= ((in >> 42) & 1) << 42;
	out |= ((in >> 34) & 1) << 43;
	out |= ((in >> 26) & 1) << 44;
	out |= ((in >> 18) & 1) << 45;
	out |= ((in >> 10) & 1) << 46;
	out |= ((in >>  2) & 1) << 47;
	out |= ((in >> 60) & 1) << 48;
	out |= ((in >> 52) & 1) << 49;
	out |= ((in >> 44) & 1) << 50;
	out |= ((in >> 36) & 1) << 51;
	out |= ((in >> 28) & 1) << 52;
	out |= ((in >> 20) & 1) << 53;
	out |= ((in >> 12) & 1) << 54;
	out |= ((in >>  4) & 1) << 55;
	out |= ((in >> 62) & 1) << 56;
	out |= ((in >> 54) & 1) << 57;
	out |= ((in >> 46) & 1) << 58;
	out |= ((in >> 38) & 1) << 59;
	out |= ((in >> 30) & 1) << 60;
	out |= ((in >> 22) & 1) << 61;
	out |= ((in >> 14) & 1) << 62;
	out |= ((in >>  6) & 1) << 63;

	return out;
}

/**
 * The 32-48 expansion permutation that is run on the right half of the block in a fistel round
 */
inline uint64_t BlockPE32To48(uint64_t in)
{
	uint64_t out = 0;

	out |= ((in >> 31) & 1) <<  0;
	out |= ((in >>  0) & 1) <<  1;
	out |= ((in >>  1) & 1) <<  2;
	out |= ((in >>  2) & 1) <<  3;
	out |= ((in >>  3) & 1) <<  4;
	out |= ((in >>  4) & 1) <<  5;
	out |= ((in >>  3) & 1) <<  6;
	out |= ((in >>  4) & 1) <<  7;
	out |= ((in >>  5) & 1) <<  8;
	out |= ((in >>  6) & 1) <<  9;
	out |= ((in >>  7) & 1) << 10;
	out |= ((in >>  8) & 1) << 11;
	out |= ((in >>  7) & 1) << 12;
	out |= ((in >>  8) & 1) << 13;
	out |= ((in >>  9) & 1) << 14;
	out |= ((in >> 10) & 1) << 15;
	out |= ((in >> 11) & 1) << 16;
	out |= ((in >> 12) & 1) << 17;
	out |= ((in >> 11) & 1) << 18;
	out |= ((in >> 12) & 1) << 19;
	out |= ((in >> 13) & 1) << 20;
	out |= ((in >> 14) & 1) << 21;
	out |= ((in >> 15) & 1) << 22;
	out |= ((in >> 16) & 1) << 23;
	out |= ((in >> 15) & 1) << 24;
	out |= ((in >> 16) & 1) << 25;
	out |= ((in >> 17) & 1) << 26;
	out |= ((in >> 18) & 1) << 27;
	out |= ((in >> 19) & 1) << 28;
	out |= ((in >> 20) & 1) << 29;
	out |= ((in >> 19) & 1) << 30;
	out |= ((in >> 20) & 1) << 31;
	out |= ((in >> 21) & 1) << 32;
	out |= ((in >> 22) & 1) << 33;
	out |= ((in >> 23) & 1) << 34;
	out |= ((in >> 24) & 1) << 35;
	out |= ((in >> 23) & 1) << 36;
	out |= ((in >> 24) & 1) << 37;
	out |= ((in >> 25) & 1) << 38;
	out |= ((in >> 26) & 1) << 39;
	out |= ((in >> 27) & 1) << 40;
	out |= ((in >> 28) & 1) << 41;
	out |= ((in >> 27) & 1) << 42;
	out |= ((in >> 28) & 1) << 43;
	out |= ((in >> 29) & 1) << 44;
	out |= ((in >> 30) & 1) << 45;
	out |= ((in >> 31) & 1) << 46;
	out |= ((in >>  0) & 1) << 47;

	return out;
}

/**
 * The final permutation to run on the ciphertext block
 */
inline uint64_t FinalBlockPermutation(uint64_t in)
{
	uint64_t out = 0;

	out |= ((in >> 39) & 1) <<  0;
	out |= ((in >>  7) & 1) <<  1;
	out |= ((in >> 47) & 1) <<  2;
	out |= ((in >> 15) & 1) <<  3;
	out |= ((in >> 55) & 1) <<  4;
	out |= ((in >> 23) & 1) <<  5;
	out |= ((in >> 63) & 1) <<  6;
	out |= ((in >> 31) & 1) <<  7;
	out |= ((in >> 38) & 1) <<  8;
	out |= ((in >>  6) & 1) <<  9;
	out |= ((in >> 46) & 1) << 10;
	out |= ((in >> 14) & 1) << 11;
	out |= ((in >> 54) & 1) << 12;
	out |= ((in >> 22) & 1) << 13;
	out |= ((in >> 62) & 1) << 14;
	out |= ((in >> 30) & 1) << 15;
	out |= ((in >> 37) & 1) << 16;
	out |= ((in >>  5) & 1) << 17;
	out |= ((in >> 45) & 1) << 18;
	out |= ((in >> 13) & 1) << 19;
	out |= ((in >> 53) & 1) << 20;
	out |= ((in >> 21) & 1) << 21;
	out |= ((in >> 61) & 1) << 22;
	out |= ((in >> 29) & 1) << 23;
	out |= ((in >> 36) & 1) << 24;
	out |= ((in >>  4) & 1) << 25;
	out |= ((in >> 44) & 1) << 26;
	out |= ((in >> 12) & 1) << 27;
	out |= ((in >> 52) & 1) << 28;
	out |= ((in >> 20) & 1) << 29;
	out |= ((in >> 60) & 1) << 30;
	out |= ((in >> 28) & 1) << 31;
	out |= ((in >> 35) & 1) << 32;
	out |= ((in >>  3) & 1) << 33;
	out |= ((in >> 43) & 1) << 34;
	out |= ((in >> 11) & 1) << 35;
	out |= ((in >> 51) & 1) << 36;
	out |= ((in >> 19) & 1) << 37;
	out |= ((in >> 59) & 1) << 38;
	out |= ((in >> 27) & 1) << 39;
	out |= ((in >> 34) & 1) << 40;
	out |= ((in >>  2) & 1) << 41;
	out |= ((in >> 42) & 1) << 42;
	out |= ((in >> 10) & 1) << 43;
	out |= ((in >> 50) & 1) << 44;
	out |= ((in >> 18) & 1) << 45;
	out |= ((in >> 58) & 1) << 46;
	out |= ((in >> 26) & 1) << 47;
	out |= ((in >> 33) & 1) << 48;
	out |= ((in >>  1) & 1) << 49;
	out |= ((in >> 41) & 1) << 50;
	out |= ((in >>  9) & 1) << 51;
	out |= ((in >> 49) & 1) << 52;
	out |= ((in >> 17) & 1) << 53;
	out |= ((in >> 57) & 1) << 54;
	out |= ((in >> 25) & 1) << 55;
	out |= ((in >> 32) & 1) << 56;
	out |= ((in >>  0) & 1) << 57;
	out |= ((in >> 40) & 1) << 58;
	out |= ((in >>  8) & 1) << 59;
	out |= ((in >> 48) & 1) << 60;
	out |= ((in >> 16) & 1) << 61;
	out |= ((in >> 56) & 1) << 62;
	out |= ((in >> 24) & 1) << 63;

	return out;
}

/**
 * The first substitution box (pre-sorted and pre-shifted)
 */
const uint64_t S0[] =
{
	14 << 28,  0 << 28,  4 << 28, 15 << 28, 13 << 28,  7 << 28,  1 << 28,  4 << 28,  2 << 28, 14 << 28, 15 << 28,  2 << 28, 11 << 28, 13 << 28,  8 << 28,  1 << 28,
	 3 << 28, 10 << 28, 10 << 28,  6 << 28,  6 << 28, 12 << 28, 12 << 28, 11 << 28,  5 << 28,  9 << 28,  9 << 28,  5 << 28,  0 << 28,  3 << 28,  7 << 28,  8 << 28,
	 4 << 28, 15 << 28,  1 << 28, 12 << 28, 14 << 28,  8 << 28,  8 << 28,  2 << 28, 13 << 28,  4 << 28,  6 << 28,  9 << 28,  2 << 28,  1 << 28, 11 << 28,  7 << 28,
	15 << 28,  5 << 28, 12 << 28, 11 << 28,  9 << 28,  3 << 28,  7 << 28, 14 << 28,  3 << 28, 10 << 28, 10 << 28,  0 << 28,  5 << 28,  6 << 28,  0 << 28, 13 << 28
};

/**
 * The second substitution box (pre-sorted and pre-shifted)
 */
const uint64_t S1[] =
{
	15 << 24,  3 << 24,  1 << 24, 13 << 24,  8 << 24,  4 << 24, 14 << 24,  7 << 24,  6 << 24, 15 << 24, 11 << 24,  2 << 24,  3 << 24,  8 << 24,  4 << 24, 14 << 24,
	 9 << 24, 12 << 24,  7 << 24,  0 << 24,  2 << 24,  1 << 24, 13 << 24, 10 << 24, 12 << 24,  6 << 24,  0 << 24,  9 << 24,  5 << 24, 11 << 24, 10 << 24,  5 << 24,
	 0 << 24, 13 << 24, 14 << 24,  8 << 24,  7 << 24, 10 << 24, 11 << 24,  1 << 24, 10 << 24,  3 << 24,  4 << 24, 15 << 24, 13 << 24,  4 << 24,  1 << 24,  2 << 24,
	 5 << 24, 11 << 24,  8 << 24,  6 << 24, 12 << 24,  7 << 24,  6 << 24, 12 << 24,  9 << 24,  0 << 24,  3 << 24,  5 << 24,  2 << 24, 14 << 24, 15 << 24,  9 << 24
};

/**
 * The third substitution box (pre-sorted and pre-shifted)
 */
const uint64_t S2[] =
{
	10 << 20, 13 << 20,  0 << 20,  7 << 20,  9 << 20,  0 << 20, 14 << 20,  9 << 20,  6 << 20,  3 << 20,  3 << 20,  4 << 20, 15 << 20,  6 << 20,  5 << 20, 10 << 20,
	 1 << 20,  2 << 20, 13 << 20,  8 << 20, 12 << 20,  5 << 20,  7 << 20, 14 << 20, 11 << 20, 12 << 20,  4 << 20, 11 << 20,  2 << 20, 15 << 20,  8 << 20,  1 << 20,
	13 << 20,  1 << 20,  6 << 20, 10 << 20,  4 << 20, 13 << 20,  9 << 20,  0 << 20,  8 << 20,  6 << 20, 15 << 20,  9 << 20,  3 << 20,  8 << 20,  0 << 20,  7 << 20,
	11 << 20,  4 << 20,  1 << 20, 15 << 20,  2 << 20, 14 << 20, 12 << 20,  3 << 20,  5 << 20, 11 << 20, 10 << 20,  5 << 20, 14 << 20,  2 << 20,  7 << 20, 12 << 20
};

/**
 * The fourth substitution box (pre-sorted and pre-shifted)
 */
const uint64_t S3[] =
{
	 7 << 16, 13 << 16, 13 << 16,  8 << 16, 14 << 16, 11 << 16,  3 << 16,  5 << 16,  0 << 16,  6 << 16,  6 << 16, 15 << 16,  9 << 16,  0 << 16, 10 << 16,  3 << 16,
	 1 << 16,  4 << 16,  2 << 16,  7 << 16,  8 << 16,  2 << 16,  5 << 16, 12 << 16, 11 << 16,  1 << 16, 12 << 16, 10 << 16,  4 << 16, 14 << 16, 15 << 16,  9 << 16,
	10 << 16,  3 << 16,  6 << 16, 15 << 16,  9 << 16,  0 << 16,  0 << 16,  6 << 16, 12 << 16, 10 << 16, 11 << 16,  1 << 16,  7 << 16, 13 << 16, 13 << 16,  8 << 16,
	15 << 16,  9 << 16,  1 << 16,  4 << 16,  3 << 16,  5 << 16, 14 << 16, 11 << 16,  5 << 16, 12 << 16,  2 << 16,  7 << 16,  8 << 16,  2 << 16,  4 << 16, 14 << 16
};

/**
 * The fifth substitution box (pre-sorted and pre-shifted)
 */
const uint64_t S4[] =
{
	 2 << 12, 14 << 12, 12 << 12, 11 << 12,  4 << 12,  2 << 12,  1 << 12, 12 << 12,  7 << 12,  4 << 12, 10 << 12,  7 << 12, 11 << 12, 13 << 12,  6 << 12,  1 << 12,
	 8 << 12,  5 << 12,  5 << 12,  0 << 12,  3 << 12, 15 << 12, 15 << 12, 10 << 12, 13 << 12,  3 << 12,  0 << 12,  9 << 12, 14 << 12,  8 << 12,  9 << 12,  6 << 12,
	 4 << 12, 11 << 12,  2 << 12,  8 << 12,  1 << 12, 12 << 12, 11 << 12,  7 << 12, 10 << 12,  1 << 12, 13 << 12, 14 << 12,  7 << 12,  2 << 12,  8 << 12, 13 << 12,
	15 << 12,  6 << 12,  9 << 12, 15 << 12, 12 << 12,  0 << 12,  5 << 12,  9 << 12,  6 << 12, 10 << 12,  3 << 12,  4 << 12,  0 << 12,  5 << 12, 14 << 12,  3 << 12
};

/**
 * The sixth substitution box (pre-sorted and pre-shifted)
 */
const uint64_t S5[] =
{
	12 <<  8, 10 <<  8,  1 <<  8, 15 <<  8, 10 <<  8,  4 <<  8, 15 <<  8,  2 <<  8,  9 <<  8,  7 <<  8,  2 <<  8, 12 <<  8,  6 <<  8,  9 <<  8,  8 <<  8,  5 <<  8,
	 0 <<  8,  6 <<  8, 13 <<  8,  1 <<  8,  3 <<  8, 13 <<  8,  4 <<  8, 14 <<  8, 14 <<  8,  0 <<  8,  7 <<  8, 11 <<  8,  5 <<  8,  3 <<  8, 11 <<  8,  8 <<  8,
	 9 <<  8,  4 <<  8, 14 <<  8,  3 <<  8, 15 <<  8,  2 <<  8,  5 <<  8, 12 <<  8,  2 <<  8,  9 <<  8,  8 <<  8,  5 <<  8, 12 <<  8, 15 <<  8,  3 <<  8, 10 <<  8,
	 7 <<  8, 11 <<  8,  0 <<  8, 14 <<  8,  4 <<  8,  1 <<  8, 10 <<  8,  7 <<  8,  1 <<  8,  6 <<  8, 13 <<  8,  0 <<  8, 11 <<  8,  8 <<  8,  6 <<  8, 13 <<  8
};

/**
 * The seventh substitution box (pre-sorted and pre-shifted)
 */
const uint64_t S6[] =
{
	 4 <<  4, 13 <<  4, 11 <<  4,  0 <<  4,  2 <<  4, 11 <<  4, 14 <<  4,  7 <<  4, 15 <<  4,  4 <<  4,  0 <<  4,  9 <<  4,  8 <<  4,  1 <<  4, 13 <<  4, 10 <<  4,
	 3 <<  4, 14 <<  4, 12 <<  4,  3 <<  4,  9 <<  4,  5 <<  4,  7 <<  4, 12 <<  4,  5 <<  4,  2 <<  4, 10 <<  4, 15 <<  4,  6 <<  4,  8 <<  4,  1 <<  4,  6 <<  4,
	 1 <<  4,  6 <<  4,  4 <<  4, 11 <<  4, 11 <<  4, 13 <<  4, 13 <<  4,  8 <<  4, 12 <<  4,  1 <<  4,  3 <<  4,  4 <<  4,  7 <<  4, 10 <<  4, 14 <<  4,  7 <<  4,
	10 <<  4,  9 <<  4, 15 <<  4,  5 <<  4,  6 <<  4,  0 <<  4,  8 <<  4, 15 <<  4,  0 <<  4, 14 <<  4,  5 <<  4,  2 <<  4,  9 <<  4,  3 <<  4,  2 <<  4, 12 <<  4
};

/**
 * The final substitution box (pre-sorted)
 */
const uint64_t S7[] =
{
	13,  1,  2, 15,  8, 13,  4,  8,  6, 10, 15,  3, 11,  7,  1,  4,
	10, 12,  9,  5,  3,  6, 14, 11,  5,  0,  0, 14, 12,  9,  7,  2,
	 7,  2, 11,  1,  4, 14,  1,  7,  9,  4, 12, 10, 14,  8,  2, 13,
	 0, 15,  6, 12, 10,  9, 13,  0, 15,  3,  3,  5,  5,  6,  8, 11
};

/**
 * The straight 32-32 permutation to mix the half-block in the fistel round
 */
inline uint64_t BlockP32(uint64_t in)
{
	uint64_t out = 0;

	out |= ((in >>  7) & 1) <<  0;
	out |= ((in >> 28) & 1) <<  1;
	out |= ((in >> 21) & 1) <<  2;
	out |= ((in >> 10) & 1) <<  3;
	out |= ((in >> 26) & 1) <<  4;
	out |= ((in >>  2) & 1) <<  5;
	out |= ((in >> 19) & 1) <<  6;
	out |= ((in >> 13) & 1) <<  7;
	out |= ((in >> 23) & 1) <<  8;
	out |= ((in >> 29) & 1) <<  9;
	out |= ((in >>  5) & 1) << 10;
	out |= ((in >>  0) & 1) << 11;
	out |= ((in >> 18) & 1) << 12;
	out |= ((in >>  8) & 1) << 13;
	out |= ((in >> 24) & 1) << 14;
	out |= ((in >> 30) & 1) << 15;
	out |= ((in >> 22) & 1) << 16;
	out |= ((in >>  1) & 1) << 17;
	out |= ((in >> 14) & 1) << 18;
	out |= ((in >> 27) & 1) << 19;
	out |= ((in >>  6) & 1) << 20;
	out |= ((in >>  9) & 1) << 21;
	out |= ((in >> 17) & 1) << 22;
	out |= ((in >> 31) & 1) << 23;
	out |= ((in >> 15) & 1) << 24;
	out |= ((in >>  4) & 1) << 25;
	out |= ((in >> 20) & 1) << 26;
	out |= ((in >>  3) & 1) << 27;
	out |= ((in >> 11) & 1) << 28;
	out |= ((in >> 12) & 1) << 29;
	out |= ((in >> 25) & 1) << 30;
	out |= ((in >> 16) & 1) << 31;

	return out;
}