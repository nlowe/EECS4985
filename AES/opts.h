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
 * opts.h - Command Line Options
 */

#pragma once
#include <string>
#include <algorithm>
#include <iostream>
#include <regex>
#include "../libcrypto/libcrypto.h"
#include "../libcrypto/AES/Types.h"

#define REGEX_HEX "^([0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64})$"

/**
 * A class for parsing command-line options
 */
class Options
{
private:
	bool parseKey(std::string key)
	{
		auto raw = key.c_str();

		if(std::regex_match(key, std::regex(REGEX_HEX)))
		{
			if(key.length() == 32)
			{
				// 128-bit hex string
			}
			else if(key.length() == 48)
			{
				// 192-bit hex string
			}
			else
			{
				// 256-bit hex string
			}
		}
		else if (key.length() == 16)
		{
			// 16 ascii characters
			k128[0][0] = raw[0]; k128[0][1] = raw[4]; k128[0][2] = raw[8];  k128[0][3] = raw[12];
			k128[1][0] = raw[1]; k128[1][1] = raw[5]; k128[1][2] = raw[9];  k128[1][3] = raw[13];
			k128[2][0] = raw[2]; k128[2][1] = raw[6]; k128[2][2] = raw[10]; k128[2][3] = raw[14];
			k128[3][0] = raw[3]; k128[3][1] = raw[7]; k128[3][2] = raw[11]; k128[3][3] = raw[15];

			has128BitKey = true;
		}
		else if (key.length() == 24)
		{
			// 24 ascii characters
			k192[0][0] = raw[0]; k192[0][1] = raw[4]; k192[0][2] = raw[8];  k192[0][3] = raw[12]; k192[0][4] = raw[16]; k192[0][5] = raw[20];
			k192[1][0] = raw[1]; k192[1][1] = raw[5]; k192[1][2] = raw[9];  k192[1][3] = raw[13]; k192[1][4] = raw[17]; k192[1][5] = raw[21];
			k192[2][0] = raw[2]; k192[2][1] = raw[6]; k192[2][2] = raw[10]; k192[2][3] = raw[14]; k192[2][4] = raw[18]; k192[2][5] = raw[22];
			k192[3][0] = raw[3]; k192[3][1] = raw[7]; k192[3][2] = raw[11]; k192[3][3] = raw[15]; k192[3][4] = raw[19]; k192[3][5] = raw[23];

			has192BitKey = true;
		}
		else if(key.length() == 32)
		{
			// 32 ascii characters
			k256[0][0] = raw[0]; k256[0][1] = raw[4]; k256[0][2] = raw[8];  k256[0][3] = raw[12]; k256[0][4] = raw[16]; k256[0][5] = raw[20]; k256[0][6] = raw[24]; k256[0][7] = raw[28];
			k256[1][0] = raw[1]; k256[1][1] = raw[5]; k256[1][2] = raw[9];  k256[1][3] = raw[13]; k256[1][4] = raw[17]; k256[1][5] = raw[21]; k256[1][6] = raw[25]; k256[1][7] = raw[29];
			k256[2][0] = raw[2]; k256[2][1] = raw[6]; k256[2][2] = raw[10]; k256[2][3] = raw[14]; k256[2][4] = raw[18]; k256[2][5] = raw[22]; k256[2][6] = raw[26]; k256[2][7] = raw[30];
			k256[3][0] = raw[3]; k256[3][1] = raw[7]; k256[3][2] = raw[11]; k256[3][3] = raw[15]; k256[3][4] = raw[19]; k256[3][5] = raw[23]; k256[3][6] = raw[27]; k256[3][7] = raw[31];
		}
		// The remainder of these are ASCII w/ space, because you totally need an extra set of quotes...
		// Fun Fact: cmd.exe does not recognize arguments surrounded with single quotes as
		//           a single argument (unlike most other shells). I still believe that this
		//           is a user problem and Microsoft should either update their shell, or users
		//           should learn how to provide arguments that contain spaces...but I digress
		// Note: they got it right with powershell, but we still have to support cmd.exe
		else if (key.length() == 18)
		{
			k128[0][0] = raw[1]; k128[0][1] = raw[5]; k128[0][2] = raw[9];  k128[0][3] = raw[13];
			k128[1][0] = raw[2]; k128[1][1] = raw[6]; k128[1][2] = raw[10]; k128[1][3] = raw[14];
			k128[2][0] = raw[3]; k128[2][1] = raw[7]; k128[2][2] = raw[11]; k128[2][3] = raw[15];
			k128[3][0] = raw[4]; k128[3][1] = raw[8]; k128[3][2] = raw[12]; k128[3][3] = raw[16];

			has128BitKey = true;
		}
		else if (key.length() == 26)
		{
			k192[0][0] = raw[1]; k192[0][1] = raw[5]; k192[0][2] = raw[9];  k192[0][3] = raw[13]; k192[0][4] = raw[17]; k192[0][5] = raw[21];
			k192[1][0] = raw[2]; k192[1][1] = raw[6]; k192[1][2] = raw[10]; k192[1][3] = raw[14]; k192[1][4] = raw[18]; k192[1][5] = raw[22];
			k192[2][0] = raw[3]; k192[2][1] = raw[7]; k192[2][2] = raw[11]; k192[2][3] = raw[15]; k192[2][4] = raw[19]; k192[2][5] = raw[23];
			k192[3][0] = raw[4]; k192[3][1] = raw[8]; k192[3][2] = raw[12]; k192[3][3] = raw[16]; k192[3][4] = raw[20]; k192[3][5] = raw[24];

			has192BitKey = true;
		}
		else if(key.length() == 34)
		{
			k256[0][0] = raw[1]; k256[0][1] = raw[5]; k256[0][2] = raw[9];  k256[0][3] = raw[13]; k256[0][4] = raw[17]; k256[0][5] = raw[21]; k256[0][6] = raw[25]; k256[0][7] = raw[29];
			k256[1][0] = raw[2]; k256[1][1] = raw[6]; k256[1][2] = raw[10]; k256[1][3] = raw[14]; k256[1][4] = raw[18]; k256[1][5] = raw[22]; k256[1][6] = raw[26]; k256[1][7] = raw[30];
			k256[2][0] = raw[3]; k256[2][1] = raw[7]; k256[2][2] = raw[11]; k256[2][3] = raw[15]; k256[2][4] = raw[19]; k256[2][5] = raw[23]; k256[2][6] = raw[27]; k256[2][7] = raw[31];
			k256[3][0] = raw[4]; k256[3][1] = raw[8]; k256[3][2] = raw[12]; k256[3][3] = raw[16]; k256[3][4] = raw[20]; k256[3][5] = raw[24]; k256[3][6] = raw[28]; k256[3][7] = raw[32];
		}
		else
		{
			return false;
		}

		return true;
	}
public:
	/** The action to perform */
	libcrypto::Action Action = libcrypto::Action::UNKNOWN_ACTION;
	/** The mode to operate in */
	libcrypto::Mode Mode = libcrypto::Mode::UNKNOWN_MODE;

	/** The key to use */
	libcrypto::aes::aes_key_128_t k128;
	libcrypto::aes::aes_key_192_t k192;
	libcrypto::aes::aes_key_256_t k256;

	/** The path to the input file */
	std::string Input;
	/** The path to the output file */
	std::string Output;

	bool has128BitKey = false;
	bool has192BitKey = false;

	/** Whether or not errors were encountered */
	bool Errors = false;

	/**
	 * Construct the options using the specified arguments
	 */
	Options(int argc, char* argv[])
	{
		if(argc != 6)
		{
			Errors = true;
			return;
		}

		std::string actionFlag(argv[1]);
		std::transform(actionFlag.begin(), actionFlag.end(), actionFlag.begin(), ::tolower);

		if(actionFlag == "-e")
		{
			Action = libcrypto::Action::ENCRYPT;
		}
		else if(actionFlag == "-d")
		{
			Action = libcrypto::Action::DECRYPT;
		}
		else
		{
			std::cerr << "Unknown action " << actionFlag << std::endl;
			Errors = true;
			return;
		}

		std::string key(argv[2]);
		if(!parseKey(key))
		{
			std::cerr << "Malformed Key" << std::endl;
			Errors = true;
			return;
		}

		std::string mode(argv[3]);
		std::transform(mode.begin(), mode.end(), mode.begin(), ::tolower);

		if(mode == "ecb")
		{
			Mode = libcrypto::Mode::ECB;
		}
		else if(mode == "cbc")
		{
			Mode = libcrypto::Mode::CBC;
		}
		else
		{
			std::cerr << "Unrecognized mode: " << mode << std::endl;
			Errors = true;
			return;
		}

		Input = std::string(argv[4]);
		Output = std::string(argv[5]);
	}
};
