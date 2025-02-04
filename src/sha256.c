#include "./sha256.h"
#include <string.h>

static inline uint32_t ror(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
{
    return z ^ (x & (y ^ z));
}

static inline uint32_t mag(uint32_t x, uint32_t y, uint32_t z)
{
    return ((x | y) & z) | (x & y);
}

static inline uint32_t SIGMA0(uint32_t x)
{
    return ror(x, 2) ^ ror(x, 13) ^ ror(x, 22);
}

static inline uint32_t SIGMA1(uint32_t x)
{
    return ror(x, 6) ^ ror(x, 11) ^ ror(x, 25);
}

static inline uint32_t sigma0(uint32_t x)
{
    return ror(x, 7) ^ ror(x, 18) ^ (x >> 3);
}

static inline uint32_t sigma1(uint32_t x)
{
    return ror(x, 17) ^ ror(x, 19) ^ (x >> 10);
}

static const uint32_t sha256k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void sha256_transform(SHA256_CTX* ctx)
{
    uint32_t S[8];
    // printf("H:");
    for (int i = 0; i < 8; i++)
    {
        S[i] = ctx->state[i];
        // printf("%08x ", S[i]);
    }
    // printf("\n");

    uint32_t W[64];
    // printf("W:\n");
    for (int i = 0, j = 0; i < 16; i++, j += 4)
    {
        W[i] = (ctx->block[j] << 24) + (ctx->block[j + 1] << 16) + (ctx->block[j + 2] << 8) +
               ctx->block[j + 3];
        // printf("%i: %08x\n", i, W[i]);
    }
    for (int i = 16; i < 64; i++)
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];

#define a S[0]
#define b S[1]
#define c S[2]
#define d S[3]
#define e S[4]
#define f S[5]
#define g S[6]
#define h S[7]
    for (int i = 0; i < 64; i++)
    {
        uint32_t t1 = h + SIGMA1(e) + ch(e, f, g) + sha256k[i] + W[i];
        uint32_t t2 = SIGMA0(a) + mag(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
        // printf("%i: %08x %08x %08x %08x %08x %08x %08x %08x\n", i, a, b, c, d, e, f, g, h);
    }
#undef a
#undef b
#undef c
#undef d
#undef e
#undef f
#undef g
#undef h

    for (int i = 0; i < 8; i++) ctx->state[i] += S[i];
}

void sha256_init(SHA256_CTX* ctx)
{
    ctx->bitlen = 0;
    ctx->blocklen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX* ctx, void* data, uint64_t len)
{
    uint64_t l = 64 - ctx->blocklen;
    uint64_t pos = 0;
    while (l <= len)
    {
        memcpy(ctx->block + ctx->blocklen, data + pos, l);
        sha256_transform(ctx);
        ctx->bitlen += l * 8;
        pos += l;
        ctx->blocklen = 0;
        l = 64;
    }

    l = len - pos;
    if (l > 0)
    {
        memcpy(ctx->block + ctx->blocklen, data + pos, l);
        ctx->blocklen += (uint8_t)l;
        ctx->bitlen += l * 8;
    }
}

void sha256_final(SHA256_CTX* ctx, uint8_t bytes[])
{
    // padding message
    uint16_t bitlen = ctx->blocklen * 8;
    if (bitlen < 448)
    {
        memset(ctx->block + ctx->blocklen, 0, 64 - ctx->blocklen);
        ctx->block[ctx->blocklen] = 0x80;
    }
    else
    {
        memset(ctx->block + ctx->blocklen, 0, 64 - ctx->blocklen);
        ctx->block[ctx->blocklen] = 0x80;
        sha256_transform(ctx);

        memset(ctx->block, 0, 64);
    }
    ctx->block[56] = (ctx->bitlen >> 56) & 0xFF;
    ctx->block[57] = (ctx->bitlen >> 48) & 0xFF;
    ctx->block[58] = (ctx->bitlen >> 40) & 0xFF;
    ctx->block[59] = (ctx->bitlen >> 32) & 0xFF;
    ctx->block[60] = (ctx->bitlen >> 24) & 0xFF;
    ctx->block[61] = (ctx->bitlen >> 16) & 0xFF;
    ctx->block[62] = (ctx->bitlen >> 8) & 0xFF;
    ctx->block[63] = ctx->bitlen & 0xFF;

    sha256_transform(ctx);

    for (int i = 0, j = 0; i < 8; i++, j += 4)
    {
        uint32_t v = ctx->state[i];
        bytes[j] = (v >> 24) & 0xFF;
        bytes[j + 1] = (v >> 16) & 0xFF;
        bytes[j + 2] = (v >> 8) & 0xFF;
        bytes[j + 3] = v & 0xFF;
    }
}
