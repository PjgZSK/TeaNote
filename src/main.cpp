#include <iostream>
#include <cstdio>
extern "C"
{
}

void printHex(unsigned char* data, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02X", data[i]);
    }
}

int main()
{
    // sha256 test
    unsigned char content[] = "abc";
    unsigned char hash[32];
    std::cout << "Hello, TeaNote!" << std::endl;
    printHex(hash, 32);
    return 0;
}
