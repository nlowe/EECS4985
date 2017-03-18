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
#include "../libcrypto/AES/AES.h"
#include "../libcrypto/AES/Types.h"

/** A regular expression that accepts 32, 48, or 64 hex characters (16, 24, or 32 hex bytes) */
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
				auto j = 0;
				for(auto i = 0; i < 32; i+=2)
				{
					char tmp[]{ raw[i], raw[i + 1] };
					k128[j % 4][j++ / 4] = strtoul(tmp, nullptr, 16) & 0xff;
				}
			}
			else if(key.length() == 48)
			{
				// 192-bit hex string
				auto j = 0;
				for(auto i = 0; i < 48; i+=2)
				{
					char tmp[]{ raw[i], raw[i + 1] };
					k192[j % 4][j++ / 4] = strtoul(tmp, nullptr, 16) & 0xff;
				}
			}
			else
			{
				// 256-bit hex string
				auto j = 0;
				for(auto i = 0; i < 64; i+=2)
				{
					char tmp[]{ raw[i], raw[i + 1] };
					k256[j % 4][j++ / 4] = strtoul(tmp, nullptr, 16) & 0xff;
				}
			}
		}
		else if (key.length() == 16)
		{
			// 16 ascii characters
			auto k = libcrypto::aes::make_block(const_cast<char*>(raw), 0);
			k128 = k;

			has128BitKey = true;
		}
		else if (key.length() == 24)
		{
			// 24 ascii characters
			auto k = libcrypto::aes::make_key_192(const_cast<char*>(raw));
			k192 = k;

			has192BitKey = true;
		}
		else if(key.length() == 32)
		{
			// 32 ascii characters
			auto k = libcrypto::aes::make_key_256(const_cast<char*>(raw));
			k256 = k;
		}
		// The remainder of these are ASCII w/ space, because you totally need an extra set of quotes...
		// Fun Fact: cmd.exe does not recognize arguments surrounded with single quotes as
		//           a single argument (unlike most other shells). I still believe that this
		//           is a user problem and Microsoft should either update their shell, or users
		//           should learn how to provide arguments that contain spaces...but I digress
		// Note: they got it right with powershell, but we still have to support cmd.exe
		else if (key.length() == 18)
		{
			auto k = libcrypto::aes::make_block(const_cast<char*>(raw), 1);
			k128 = k;

			has128BitKey = true;
		}
		else if (key.length() == 26)
		{
			auto k = libcrypto::aes::make_key_192(const_cast<char*>(raw + 1));
			k192 = k;

			has192BitKey = true;
		}
		else if(key.length() == 34)
		{
			auto k = libcrypto::aes::make_key_256(const_cast<char*>(raw + 1));
			k256 = k;
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

	/** True iff a 128-bit key was provided */
	bool has128BitKey = false;
	/** True iff a 192-bit key was provided */
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
