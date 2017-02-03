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