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
#ifndef purec_PUREC_SM_4_H
#define purec_PUREC_SM_4_H
#include "common.h"


C_BEGIN_EXTERN_C

#define SM4_BLOCK_SIZE  16

typedef struct _Sm4Context Sm4Context;


struct _Sm4Context
{
    uint32_t enKey[32]; //encrypt key
    uint32_t deKey[32]; //decrypt key
    uint32_t ulBuf[36]; //used in round
    uint8_t IV[16]; //intialized value
    uint8_t iMode;  //ECB/CBC etc
};

void c_sm4_set_key       (uint32_t SK[32], const uint8_t key[16]);
void c_sm4_one_round     (uint32_t sk[32], uint8_t input[16], uint8_t output[16], Sm4Context* ctx);

void c_sm4_setup         (Sm4Context* ctx, const uint8_t key[16]);
void c_sm4_encrypt_block (Sm4Context* ctx, uint8_t input[16], uint8_t output[16]);
void c_sm4_decrypt_block (Sm4Context* ctx, uint8_t input[16], uint8_t output[16]);

void c_sm4_encrypt       (Sm4Context* ctx, uint8_t* input, uint8_t* output, int length);
void c_sm4_decrypt       (Sm4Context* ctx, uint8_t* input, uint8_t* output, int length);

void c_sm4_encrypt_cbc   (Sm4Context* ctx, uint8_t iv[16], uint8_t* input, uint8_t* output, int length);
void c_sm4_decrypt_cbc   (Sm4Context* ctx, uint8_t iv[16], uint8_t* input, uint8_t* output, int length);


C_END_EXTERN_C

#endif // purec_PUREC_SM_4_H