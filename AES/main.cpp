// main.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../libcrypto/AES/AES.h"
#include "../libcrypto/AES/KeySchedule.h"
#include <iostream>

int main()
{
	uint8_t rawKey[16] = {
		0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98
	};
	auto key = libcrypto::aes::make_block(reinterpret_cast<char*>(rawKey), 0);

//	auto schedule = libcrypto::aes::BuildSchedule(key);
//	for(auto i = 0; i <= AES_ROUNDS_128; i++)
//	{
//		std::cout << "KeySchedule[" << i << "]:" << std::endl;
//		libcrypto::aes::print_block(schedule[i]);
//	}

	char data[16] = { 0 };

	libcrypto::aes::Decrypt(data, 16, key);
	
	auto block = libcrypto::aes::make_block(data, 0);
	libcrypto::aes::print_block(block);

    return 0;
}

