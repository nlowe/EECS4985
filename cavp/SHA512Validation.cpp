#include "stdafx.h"
#include "ValidationTests.h"
#include "../libcrypto/Hashing/SHA512.h"

int sha512_digest(char* message, char* expected, size_t len)
{
	auto digest = libcrypto::hashing::SHA512::ComputeHash(message, len);

	auto result = check(digest, expected, 64) ? 0 : -22;
	delete[] digest;

	return result;
}