#ifndef SHA256_HPP
#define SHA256_HPP

typedef char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

typedef struct
{
    uint32_t state[8];
    uint8_t block[64];
    uint8_t blocklen;
    uint64_t bitlen;
} SHA256_CTX;

void sha256_init(SHA256_CTX* ctx);
void sha256_update(SHA256_CTX* ctx, void* data, uint64_t len);
void sha256_final(SHA256_CTX* ctx);

#endif
