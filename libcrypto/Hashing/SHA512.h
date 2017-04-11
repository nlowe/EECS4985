#pragma once
#include <string>
#include "../export.h"

namespace libcrypto
{
	namespace hashing
	{
		namespace SHA512
		{
			/** Compute the 8-byte SHA512 digest for the buffer of the specified length */
			LIBCRYPTO_PUB char* ComputeHash(const char* buff, size_t len);
			/** Compute the 8-byte SHA512 digest for the specified string */
			LIBCRYPTO_PUB char* ComputeHash(std::string str);
		}
	}
}
