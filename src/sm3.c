/*
 * Copyright (c) 2026 dingjing
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "sm3.h"


#define IPAD    0x36
#define OPAD    0x5C

#define GETU16(p) \
    ((uint16_t)(p)[0] <<  8 \
    | (uint16_t)(p)[1])

#define GETU32(p) \
    ((uint32_t)(p)[0] << 24 \
    | (uint32_t)(p)[1] << 16 \
    | (uint32_t)(p)[2] <<  8 \
    | (uint32_t)(p)[3])

#define GETU64(p) \
    ((uint64_t)(p)[0] << 56 \
    | (uint64_t)(p)[1] << 48 \
    | (uint64_t)(p)[2] << 40 \
    | (uint64_t)(p)[3] << 32 \
    | (uint64_t)(p)[4] << 24 \
    | (uint64_t)(p)[5] << 16 \
    | (uint64_t)(p)[6] <<  8 \
    | (uint64_t)(p)[7])


// 注意：PUTU32(buf, val++) 会出错！
#define PUTU16(p,V) \
    ((p)[0] = (uint8_t)((V) >> 8), \
    (p)[1] = (uint8_t)(V))

#define PUTU32(p,V) \
    ((p)[0] = (uint8_t)((V) >> 24), \
    (p)[1] = (uint8_t)((V) >> 16), \
    (p)[2] = (uint8_t)((V) >>  8), \
    (p)[3] = (uint8_t)(V))

#define PUTU64(p,V) \
    ((p)[0] = (uint8_t)((V) >> 56), \
    (p)[1] = (uint8_t)((V) >> 48), \
    (p)[2] = (uint8_t)((V) >> 40), \
    (p)[3] = (uint8_t)((V) >> 32), \
    (p)[4] = (uint8_t)((V) >> 24), \
    (p)[5] = (uint8_t)((V) >> 16), \
    (p)[6] = (uint8_t)((V) >>  8), \
    (p)[7] = (uint8_t)(V))

/* Little Endian R/W */

#define GETU16_LE(p)        (*(const uint16_t *)(p))
#define GETU32_LE(p)        (*(const uint32_t *)(p))
#define GETU64_LE(p)        (*(const uint64_t *)(p))

#define PUTU16_LE(p,V)     *(uint16_t *)(p) = (V)
#define PUTU32_LE(p,V)     *(uint32_t *)(p) = (V)
#define PUTU64_LE(p,V)     *(uint64_t *)(p) = (V)

/* Rotate */

#define ROL32(a,n)          (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))
#define ROL64(a,n)          (((a)<<(n))|((a)>>(64-(n))))

#define ROR32(a,n)          ROL32((a),32-(n))
#define ROR64(a,n)          ROL64(a,64-n)

#define ROTL(x,n)           (((x)<<(n)) | ((x)>>(32-(n))))
#define P0(x)               ((x) ^ ROL32((x), 9) ^ ROL32((x),17))
#define P1(x)               ((x) ^ ROL32((x),15) ^ ROL32((x),23))

#define FF00(x,y,z)         ((x) ^ (y) ^ (z))
#define FF16(x,y,z)         (((x)&(y)) | ((x)&(z)) | ((y)&(z)))
#define GG00(x,y,z)         ((x) ^ (y) ^ (z))
#define GG16(x,y,z)         ((((y)^(z)) & (x)) ^ (z))

#define R(A, B, C, D, E, F, G, H, xx) \
    SS1 = ROL32((ROL32(A, 12) + E + K[j]), 7); \
    SS2 = SS1 ^ ROL32(A, 12); \
    TT1 = FF##xx(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]); \
    TT2 = GG##xx(E, F, G) + H + SS1 + W[j]; \
    B = ROL32(B, 9); \
    H = TT1; \
    F = ROL32(F, 19); \
    D = P0(TT2); \
    j++

#define R8(A, B, C, D, E, F, G, H, xx) \
    R(A, B, C, D, E, F, G, H, xx); \
    R(H, A, B, C, D, E, F, G, xx); \
    R(G, H, A, B, C, D, E, F, xx); \
    R(F, G, H, A, B, C, D, E, xx); \
    R(E, F, G, H, A, B, C, D, xx); \
    R(D, E, F, G, H, A, B, C, xx); \
    R(C, D, E, F, G, H, A, B, xx); \
    R(B, C, D, E, F, G, H, A, xx)


#define T00     0x79cc4519U
#define T16     0x7a879d8aU

#define K0      0x79cc4519U
#define K1      0xf3988a32U
#define K2      0xe7311465U
#define K3      0xce6228cbU
#define K4      0x9cc45197U
#define K5      0x3988a32fU
#define K6      0x7311465eU
#define K7      0xe6228cbcU
#define K8      0xcc451979U
#define K9      0x988a32f3U
#define K10     0x311465e7U
#define K11     0x6228cbceU
#define K12     0xc451979cU
#define K13     0x88a32f39U
#define K14     0x11465e73U
#define K15     0x228cbce6U
#define K16     0x9d8a7a87U
#define K17     0x3b14f50fU
#define K18     0x7629ea1eU
#define K19     0xec53d43cU
#define K20     0xd8a7a879U
#define K21     0xb14f50f3U
#define K22     0x629ea1e7U
#define K23     0xc53d43ceU
#define K24     0x8a7a879dU
#define K25     0x14f50f3bU
#define K26     0x29ea1e76U
#define K27     0x53d43cecU
#define K28     0xa7a879d8U
#define K29     0x4f50f3b1U
#define K30     0x9ea1e762U
#define K31     0x3d43cec5U
#define K32     0x7a879d8aU
#define K33     0xf50f3b14U
#define K34     0xea1e7629U
#define K35     0xd43cec53U
#define K36     0xa879d8a7U
#define K37     0x50f3b14fU
#define K38     0xa1e7629eU
#define K39     0x43cec53dU
#define K40     0x879d8a7aU
#define K41     0x0f3b14f5U
#define K42     0x1e7629eaU
#define K43     0x3cec53d4U
#define K44     0x79d8a7a8U
#define K45     0xf3b14f50U
#define K46     0xe7629ea1U
#define K47     0xcec53d43U
#define K48     0x9d8a7a87U
#define K49     0x3b14f50fU
#define K50     0x7629ea1eU
#define K51     0xec53d43cU
#define K52     0xd8a7a879U
#define K53     0xb14f50f3U
#define K54     0x629ea1e7U
#define K55     0xc53d43ceU
#define K56     0x8a7a879dU
#define K57     0x14f50f3bU
#define K58     0x29ea1e76U
#define K59     0x53d43cecU
#define K60     0xa7a879d8U
#define K61     0x4f50f3b1U
#define K62     0x9ea1e762U
#define K63     0x3d43cec5U

static uint32_t K[64] = {
    K0,  K1,  K2,  K3,  K4,  K5,  K6,  K7,
    K8,  K9,  K10, K11, K12, K13, K14, K15,
    K16, K17, K18, K19, K20, K21, K22, K23,
    K24, K25, K26, K27, K28, K29, K30, K31,
    K32, K33, K34, K35, K36, K37, K38, K39,
    K40, K41, K42, K43, K44, K45, K46, K47,
    K48, K49, K50, K51, K52, K53, K54, K55,
    K56, K57, K58, K59, K60, K61, K62, K63,
    /*
    0x79cc4519U, 0xf3988a32U, 0xe7311465U, 0xce6228cbU,
    0x9cc45197U, 0x3988a32fU, 0x7311465eU, 0xe6228cbcU,
    0xcc451979U, 0x988a32f3U, 0x311465e7U, 0x6228cbceU,
    0xc451979cU, 0x88a32f39U, 0x11465e73U, 0x228cbce6U,
    0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
    0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
    0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
    0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
    0x7a879d8aU, 0xf50f3b14U, 0xea1e7629U, 0xd43cec53U,
    0xa879d8a7U, 0x50f3b14fU, 0xa1e7629eU, 0x43cec53dU,
    0x879d8a7aU, 0x0f3b14f5U, 0x1e7629eaU, 0x3cec53d4U,
    0x79d8a7a8U, 0xf3b14f50U, 0xe7629ea1U, 0xcec53d43U,
    0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
    0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
    0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
    0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
    */
};

static void c_sm3_compress_blocks(uint32_t digest[8], const uint8_t *data, size_t blocks)
{
    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D;
    uint32_t E;
    uint32_t F;
    uint32_t G;
    uint32_t H;
    uint32_t W[68];
    uint32_t SS1, SS2, TT1, TT2;
    int j;

    while (blocks--) {
        A = digest[0];
        B = digest[1];
        C = digest[2];
        D = digest[3];
        E = digest[4];
        F = digest[5];
        G = digest[6];
        H = digest[7];

        for (j = 0; j < 16; j++) {
            W[j] = GETU32(data + j*4);
        }

        for (; j < 68; j++) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROL32(W[j - 3], 15))
                ^ ROL32(W[j - 13], 7) ^ W[j - 6];
        }
        j = 0;

        R8(A, B, C, D, E, F, G, H, 00);
        R8(A, B, C, D, E, F, G, H, 00);
        R8(A, B, C, D, E, F, G, H, 16);
        R8(A, B, C, D, E, F, G, H, 16);
        R8(A, B, C, D, E, F, G, H, 16);
        R8(A, B, C, D, E, F, G, H, 16);
        R8(A, B, C, D, E, F, G, H, 16);
        R8(A, B, C, D, E, F, G, H, 16);

        digest[0] ^= A;
        digest[1] ^= B;
        digest[2] ^= C;
        digest[3] ^= D;
        digest[4] ^= E;
        digest[5] ^= F;
        digest[6] ^= G;
        digest[7] ^= H;

        data += 64;
    }
}

void c_sm3_hmac_init(Sm3HMACContext* ctx, const uint8_t* key, size_t keyLen)
{
    int i;

    if (keyLen <= C_SM3_BLOCK_SIZE) {
        memcpy(ctx->key, key, keyLen);
        memset(ctx->key + keyLen, 0, C_SM3_BLOCK_SIZE - keyLen);
    }
    else {
        c_sm3_init(&ctx->sm3Ctx);
        c_sm3_update(&ctx->sm3Ctx, key, keyLen);
        c_sm3_finish(&ctx->sm3Ctx, ctx->key);
        memset(ctx->key + C_SM3_DIGEST_SIZE, 0, C_SM3_BLOCK_SIZE - C_SM3_DIGEST_SIZE);
    }
    for (i = 0; i < C_SM3_BLOCK_SIZE; i++) {
        ctx->key[i] ^= IPAD;
    }

    c_sm3_init(&ctx->sm3Ctx);
    c_sm3_update(&ctx->sm3Ctx, ctx->key, C_SM3_BLOCK_SIZE);
}

void c_sm3_hmac_update(Sm3HMACContext* ctx, const uint8_t* data, size_t dataLen)
{
    c_sm3_update(&ctx->sm3Ctx, data, dataLen);
}

void c_sm3_hmac_finish(Sm3HMACContext* ctx, uint8_t mac[32])
{
    int i;
    for (i = 0; i < C_SM3_BLOCK_SIZE; i++) {
        ctx->key[i] ^= (IPAD ^ OPAD);
    }

    c_sm3_finish(&ctx->sm3Ctx, mac);
    c_sm3_init(&ctx->sm3Ctx);
    c_sm3_update(&ctx->sm3Ctx, ctx->key, C_SM3_BLOCK_SIZE);
    c_sm3_update(&ctx->sm3Ctx, mac, C_SM3_DIGEST_SIZE);
    c_sm3_finish(&ctx->sm3Ctx, mac);
    memset(ctx, 0, sizeof(*ctx));
}

void c_sm3_hmac(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen, uint8_t mac[32])
{
    Sm3HMACContext ctx;
    c_sm3_hmac_init(&ctx, key, keyLen);
    c_sm3_hmac_update(&ctx, data, dataLen);
    c_sm3_hmac_finish(&ctx, mac);
}

void c_sm3_kdf_init(Sm3KDFContext* ctx, size_t outLen)
{
    c_sm3_init(&ctx->sm3Ctx);
    ctx->outLen = outLen;
}

void c_sm3_kdf_update(Sm3KDFContext* ctx, const uint8_t* data, size_t dataLen)
{
    c_sm3_update(&ctx->sm3Ctx, data, dataLen);
}

void c_sm3_kdf_finish(Sm3KDFContext* ctx, uint8_t* out)
{
    Sm3Context sm3Ctx;
    size_t outlen = ctx->outLen;
    uint8_t counterBE[4];
    uint8_t dgst[C_SM3_DIGEST_SIZE];
    uint32_t counter = 1;
    size_t len;

    while (outlen) {
        PUTU32(counterBE, counter);
        counter++;

        sm3Ctx = ctx->sm3Ctx;
        c_sm3_update(&sm3Ctx, counterBE, sizeof(counterBE));
        c_sm3_finish(&sm3Ctx, dgst);

        len = outlen < C_SM3_DIGEST_SIZE ? outlen : C_SM3_DIGEST_SIZE;
        memcpy(out, dgst, len);
        out += len;
        outlen -= len;
    }

    memset(&sm3Ctx, 0, sizeof(Sm3Context));
    memset(dgst, 0, sizeof(dgst));
}



void c_sm3_init(Sm3Context* ctx)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->digest[0] = 0x7380166F;
    ctx->digest[1] = 0x4914B2B9;
    ctx->digest[2] = 0x172442D7;
    ctx->digest[3] = 0xDA8A0600;
    ctx->digest[4] = 0xA96F30BC;
    ctx->digest[5] = 0x163138AA;
    ctx->digest[6] = 0xE38DEE4D;
    ctx->digest[7] = 0xB0FB0E4E;
}

void c_sm3_update(Sm3Context* ctx, const uint8_t* data, size_t dataLen)
{
    size_t blocks;

    ctx->num &= 0x3f;
    if (ctx->num) {
        size_t left = C_SM3_BLOCK_SIZE - ctx->num;
        if (dataLen < left) {
            memcpy(ctx->block + ctx->num, data, dataLen);
            ctx->num += dataLen;
            return;
        }
        else {
            memcpy(ctx->block + ctx->num, data, left);
            c_sm3_compress_blocks(ctx->digest, ctx->block, 1);
            ctx->nBlocks++;
            data += left;
            dataLen -= left;
        }
    }

    blocks = dataLen / C_SM3_BLOCK_SIZE;
    if (blocks) {
        c_sm3_compress_blocks(ctx->digest, data, blocks);
        ctx->nBlocks += blocks;
        data += C_SM3_BLOCK_SIZE * blocks;
        dataLen -= C_SM3_BLOCK_SIZE * blocks;
    }

    ctx->num = dataLen;
    if (dataLen) {
        memcpy(ctx->block, data, dataLen);
    }
}

void c_sm3_finish(Sm3Context* ctx, uint8_t dGst[32])
{
    int i;

    ctx->num &= 0x3f;
    ctx->block[ctx->num] = 0x80;

    if (ctx->num <= C_SM3_BLOCK_SIZE - 9) {
        memset(ctx->block + ctx->num + 1, 0, C_SM3_BLOCK_SIZE - ctx->num - 9);
    }
    else {
        memset(ctx->block + ctx->num + 1, 0, C_SM3_BLOCK_SIZE - ctx->num - 1);
        c_sm3_compress_blocks(ctx->digest, ctx->block, 1);
        memset(ctx->block, 0, C_SM3_BLOCK_SIZE - 8);
    }
    PUTU32(ctx->block + 56, ctx->nBlocks >> 23);
    PUTU32(ctx->block + 60, (ctx->nBlocks << 9) + (ctx->num << 3));

    c_sm3_compress_blocks(ctx->digest, ctx->block, 1);
    for (i = 0; i < 8; i++) {
        PUTU32(dGst + i*4, ctx->digest[i]);
    }
}

void c_sm3_digest(const uint8_t* data, size_t dataLen, uint8_t dGst[32])
{
    Sm3Context ctx;
    c_sm3_init(&ctx);
    c_sm3_update(&ctx, data, dataLen);
    c_sm3_finish(&ctx, dGst);
    memset(&ctx, 0, sizeof(ctx));
}

