// main.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../libcrypto/AES/AES.h"
#include <iostream>
#include "../libcrypto/AES/KeySchedule.h"

void print_block(aes_block_t block)
{
	std::cout << std::hex << +block[0][0] << " " << +block[0][1] << " " << +block[0][2] << " " << +block[0][3] << " " << std::endl;
	std::cout << std::hex << +block[1][0] << " " << +block[1][1] << " " << +block[1][2] << " " << +block[1][3] << " " << std::endl;
	std::cout << std::hex << +block[2][0] << " " << +block[2][1] << " " << +block[2][2] << " " << +block[2][3] << " " << std::endl;
	std::cout << std::hex << +block[3][0] << " " << +block[3][1] << " " << +block[3][2] << " " << +block[3][3] << " " << std::endl;
}

int main()
{
	auto key = libcrypto::aes::make_block("SOME 128 BIT KEY", 0);

	auto schedule = libcrypto::aes::BuildSchedule(libcrypto::Action::ENCRYPT, key);

	print_block(schedule[0]);
	std::cout << "------" << std::endl;
	print_block(schedule[1]);

    return 0;
}

