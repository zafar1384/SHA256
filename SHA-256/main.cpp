#include <stdio.h>
#include <sha256.h>
#include <cstring>


char testData[256];



int main()
{
	SHA256 sha256;
	
	strcpy(testData, "Let us test the Binary" );
	
	printf("sha256 =%s\r\n", sha256(testData, strlen(testData)).c_str()  );


}
