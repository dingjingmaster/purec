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
#ifndef purec_PUREC_AES_H
#define purec_PUREC_AES_H
#include "common.h"


C_BEGIN_EXTERN_C


#ifndef DOS16
#define FULL_UNROLL
#endif

#define AES_MAX_KC  (256/32)  // max key cipher = 8
#define AES_MAX_KB  (256/8)   // max key block =32
#define AES_MAX_NR  14        // max round

#define ENC_MODE_ECB 0
#define ENC_MODE_CBC 1
#define ENC_MODE_CFB 2

enum
{
    AES_BLOCK_SIZE = 16,
    AES_BLOCK_SIZE_SHIFT = 4,
    AES_BLOCK_UINT_SIZE = AES_BLOCK_SIZE/4,
    AES_MAX_ROUNDS = 14,
    MAX_KC = 8,
    MAX_BC = 8,
};


typedef struct AesCtx
{
    uint32_t                enKey[4*(AES_MAX_ROUNDS+1)];    // encrypt key
    uint32_t                deKey[4*(AES_MAX_ROUNDS+1)];    // decrypt key
    uint8_t                 IV[AES_BLOCK_SIZE];             // initialized value
    uint8_t                 nRound;
    uint8_t                 iMode;
} AesContext;


#ifdef BIG_ENDIAN
#define GETU32(pt)          (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ ((uint32_t)(pt)[2] <<  8) ^ ((uint32_t)(pt)[3]))
#define PUTU32(ct, st)      { (ct)[0] = (uint8_t)((st) >> 24); (ct)[1] = (uint8_t)((st) >> 16); (ct)[2] = (uint8_t)((st) >>  8); (ct)[3] = (uint8_t)(st); }
#else
#define GETU32(pt)          (*(uint32_t*)(pt))
#define PUTU32(ct, st)      (*(uint32_t*)(ct) = (st))
#endif

void c_aes_setup            (AesContext* ctx, const uint8_t* aesKey, uint32_t keyLen);
void c_aes_setup_real       (AesContext* ctx, const uint8_t* aesKey, uint32_t keyLen, uint8_t* iv, uint32_t iMode);
void c_aes_encrypt_block    (AesContext* ctx, uint8_t* input, uint8_t* output);
void c_aes_decrypt_block    (AesContext* ctx, uint8_t* input, uint8_t* output);

C_END_EXTERN_C

#endif // purec_PUREC_AES_H