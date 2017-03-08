#include "stdafx.h"
#include "ValidationTests.h"
#include "../libcrypto/AES/AES.h"

int aes_encrypt_ecb_192(char* key, char* data, char* expected, size_t len)
{
	auto k = libcrypto::aes::make_key_192(key);
	auto result = libcrypto::aes::Encrypt(data, len, k);

	if(!check(data, expected, len)) return -22;
	return result;
}

int aes_encrypt_cbc_192(char* key, char* iv, char* data, char* expected, size_t len)
{
	auto k = libcrypto::aes::make_key_192(key);
	auto i = libcrypto::aes::make_block(iv, 0);
	auto result = libcrypto::aes::Encrypt(data, len, k, i);

	if(!check(data, expected, len)) return -22;
	return result;
}

int aes_decrypt_ecb_192(char* key, char* data, char* expected, size_t len)
{
	auto k = libcrypto::aes::make_key_192(key);
	auto result = libcrypto::aes::Decrypt(data, len, k);

	if(!check(data, expected, len)) return -22;
	return result;
}

int aes_decrypt_cbc_192(char* key, char* iv, char* data, char* expected, size_t len)
{
	auto k = libcrypto::aes::make_key_192(key);
	auto i = libcrypto::aes::make_block(iv, 0);
	auto result = libcrypto::aes::Decrypt(data, len, k, i);

	if(!check(data, expected, len)) return -22;
	return result;
}