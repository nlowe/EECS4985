/*
 * Copyright (c) 2016 Nathan Lowe
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software, associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software,, to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice, this permission notice shall be included in all
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
 * WeakKeys.cpp - Implementation for checking for weak, semi-weak,, possibly-weak keys
 */

#include <cstdint>

#include "DES.h"

namespace libcrypto
{
	namespace des
	{

		/** The number of weak keys */
		#define NUM_WEAK_KEYS 4
		/** The number of semi-weak keys */
		#define NUM_SEMI_WEAK_KEYS 16
		/** The number of possibly-weak keys */
		#define NUM_POSSIBLY_WEAK_KEYS 48

		/** The list of weak keys */
		const uint64_t WEAK_KEYS[] = { 0x0101010101010101, 0x1F1F1F1F0E0E0E0E, 0xE0E0E0E0F1F1F1F1, 0xFEFEFEFEFEFEFEFE };

		/** The list of semi-weak keys */
		const uint64_t SEMI_WEAK_KEYS[] = {
			0x01FE01FE01FE01FE, 0xFE01FE01FE01FE01,
			0x1FE01FE00EF10EF1, 0xE01FE01FF10EF10E,
			0x01E001E001F101F1, 0xE001E001F101F101,
			0x1FFE1FFE0EFE0EFE, 0xFE1FFE1FFE0EFE0E,
			0x011F011F010E010E, 0x1F011F010E010E01,
			0xE0FEE0FEF1FEF1FE, 0xFEE0FEE0FEF1FEF1
		};

		/** The list of possibly weak keys */
		const uint64_t POSSIBLY_WEAK_KEYS[] = {
			0x1F1F01010E0E0101, 0xFEE01F01FEF10E01, 0xFE1FE001FE0EF101, 0x1FE0FE010EF1FE01,
			0xE00101E0F10101F1, 0xE0011FFEF1010EFE, 0x0101E0E00101F1F1, 0x0101FEFE0101FEFE,
			0x011F1F01010E0E01, 0xE0FE1F01F1FE0E01, 0xE01FFE01F10EFE01, 0x01FEFE0101FEFE01,
			0xFE1F01E0FE0E01F1, 0xFE1F1FFEFE0E0EFE, 0x1F1FE0E00E0EF1F1, 0x1F1FFEFE0E0EFEFE,
			0x1F01011F0E01010E, 0xFEE0011FFEF1010E, 0xFE01E01FFE01F10E, 0x1FE0E01F0EF1F10E,
			0xFE011FE0FE010EF1, 0x1FFE01E00EFE01F1, 0x1F01FEE00E01FEF1, 0xFEFEE0E0FEFEF1F1,
			0x01011F1F01010E0E, 0xE0FE011FF1FE010E, 0xE001FE1FF101FE0E, 0x01FEE01F01FEF10E,
			0xE01F1FE0F10E0EF1, 0x01FE1FE001FE0EF1, 0x011FFEE0010EFEF1, 0xE0FEFEE0F1FEFEF1,
			0xE0E00101F1F10101, 0xE0E01F1FF1F10E0E, 0x01E0E00101F1F101, 0x01E0FE1F01F1FE0E,
			0xFE0101FEFE0101FE, 0x1FE001FE0EF101FE, 0x1F01E0FE0E01F1FE, 0xFEE0E0FEFEF1F1FE,
			0xFEFE0101FEFE0101, 0xFEFE1F1FFEFE0E0E, 0x1FFEE0010EFEF001, 0x1FFEFE1F0EFEFE0E,
			0xE01F01FEF10E01FE, 0x01E01FFE01F10EFE, 0x011FE0FE010EF1FE, 0xE0E0FEFEF1F1FEFE
		};

		/**
		 * Returns true iff the specified key is a weak key
		 */
		inline bool isWeakKey(uint64_t key)
		{
			for(auto i = 0; i < NUM_WEAK_KEYS; i++)
			{
				if (key == WEAK_KEYS[i]) return true;
			}

			return false;
		}

		/**
		 * Returns true iff the specified key is a semi-weak key
		 */
		inline bool isSemiWeakKey(uint64_t key)
		{
			for(auto i = 0; i < NUM_SEMI_WEAK_KEYS; i++)
			{
				if (key == SEMI_WEAK_KEYS[i]) return true;
			}

			return false;
		}

		/**
		 * Returns true iff the specified key is a semi-weak key
		 */
		inline bool isPossiblyWeakKey(uint64_t key)
		{
			for(auto i = 0; i < NUM_POSSIBLY_WEAK_KEYS; i++)
			{
				if (key == POSSIBLY_WEAK_KEYS[i]) return true;
			}

			return false;
		}

		LIBCRYPTO_PUB KeyStrength CheckKey(uint64_t key)
		{
			if(isWeakKey(key))
			{
				return WEAK;
			}

			if(isSemiWeakKey(key))
			{
				return SEMI_WEAK;
			}

			if(isPossiblyWeakKey(key))
			{
				return POSSIBLY_WEAK;
			}

			return NOT_WEAK;
		}
	}
}
