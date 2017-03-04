// ValidationTests.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "AESValidationTests.h"
#include <iostream>


int main()
{
	std::cout << "Validating AES" << std::endl;
	if(ValidationTests::aes::Validate() > 0)
	{
		std::cerr << "Validation of AES failed" << std::endl;
	}

    return 0;
}

