#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <SHA256.h>
#include <iostream>


char cData[] = {"Hello world This is testing code"};

int main()
{
	SHA256 shaObj;
	
	shaObj.append(cData, strlen( cData ) );
	
	shaObj.finalize();
	
	
	printf("The sum =%s\r\n",  shaObj.hexString().c_str() );
	
	std::cout << shaObj.hexString() << std::endl;



}



