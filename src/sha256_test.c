#include "./sha256.h"
#include <stdio.h>
#include <string.h>

int test_sha256(char* str, char* correct_hash)
{
    uint8_t bytes[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, str, strlen(str));
    sha256_final(&ctx, bytes);

    char hash[64];
    for (int i = 0, j = 0; i < 32; i++, j += 2) sprintf(hash + j, "%02x", bytes[i]);
    if (0 != strcmp(hash, correct_hash))
    {
        printf(
            "error, %s 's hash value should be:\n%s\nerror hash:\n%s\n\n",
            str,
            correct_hash,
            hash);
        return -1;
    }
    printf("bingo, %s 's hash value is:\n%s\n\n", str, hash);
    return 0;
}

int main()
{
    // test
    test_sha256(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    test_sha256("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    test_sha256("aaaaaaa", "e46240714b5db3a23eee60479a623efba4d633d27fe4f03c904b9e219a7fbe60");
}
