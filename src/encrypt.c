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
#include "encrypt.h"

#include "aes.h"
#include "rc4.h"
#include "sm4.h"


void c_encrypt_encode_rc4(uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen)
{
    Rc4Context ctx;
    c_rc4_setup(&ctx, key, keyLen);
    c_rc4_crypt(&ctx, buffer, bufLen);
}

void c_encrypt_decode_rc4(uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen)
{
    Rc4Context ctx;
    c_rc4_setup(&ctx, key, keyLen);
    c_rc4_crypt(&ctx, buffer, bufLen);
}

void c_encrypt_encode_sm4(uint8_t* buffer, uint64_t bufLen, const uint8_t* key)
{
    uint64_t i = 0;
    Sm4Context ctx;
    c_sm4_setup(&ctx, key);
    while (bufLen >= SM4_BLOCK_SIZE) {
        c_sm4_encrypt_block(&ctx, buffer, buffer);
        buffer += SM4_BLOCK_SIZE;
        bufLen -= SM4_BLOCK_SIZE;
    }

    for (i = 0; i < bufLen; i++) {
        *buffer++ ^= i;
    }
}

void c_encrypt_decode_sm4(uint8_t* buffer, uint64_t bufLen, const uint8_t* key)
{
    uint64_t i = 0;
    Sm4Context ctx;
    c_sm4_setup(&ctx, key);
    while (bufLen >= SM4_BLOCK_SIZE) {
        c_sm4_decrypt_block(&ctx, buffer, buffer);
        buffer += SM4_BLOCK_SIZE;
        bufLen -= SM4_BLOCK_SIZE;
    }
    for (i = 0; i < bufLen; i++) {
        *buffer++ ^= i;
    }
}

void c_encrypt_encode_aes_ecb(uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen)
{
    c_encrypt_encode_aes_real(buffer, bufLen, key, keyLen, NULL, ENC_MODE_ECB);
}

void c_encrypt_decode_aes_ecb(uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen)
{
    c_encrypt_decode_aes_real(buffer, bufLen, key, keyLen, NULL, ENC_MODE_ECB);
}

void c_encrypt_encode_aes_real(uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen, uint8_t* iv, uint32_t mode)
{
    AesContext ctx;
    uint32_t i, j, groups;
    uint32_t IV[AES_BLOCK_UINT_SIZE];
    uint32_t* inout;
    c_aes_setup_real(&ctx, key, keyLen, iv, mode);
    groups = bufLen >> AES_BLOCK_SIZE_SHIFT;
    memcpy(IV, ctx.IV,AES_BLOCK_SIZE);

    inout = (uint32_t*) buffer;

    if (ENC_MODE_CBC == mode) {
        for (i = 0; i < groups; i++) {
            for (j = 0; j < AES_BLOCK_UINT_SIZE; j++) {
                IV[j] ^= inout[j];
            }
            {
                c_aes_encrypt_block(&ctx,(uint8_t*) IV,(uint8_t*) IV);
            }

            memcpy(inout, IV, AES_BLOCK_SIZE);
            inout += AES_BLOCK_UINT_SIZE;
        }
        buffer = (uint8_t*) inout;
    }
    else if (ENC_MODE_CFB ==  mode) {
        for (i = 0; i < groups; i++) {
            {
                c_aes_decrypt_block(&ctx,(uint8_t*) IV, (uint8_t*) IV);
            }
            for (j = 0; j < AES_BLOCK_UINT_SIZE; j++) {
                IV[j] ^=  inout[j];
            }
            memcpy(inout, IV, AES_BLOCK_SIZE);
            inout += AES_BLOCK_UINT_SIZE;
        }
        buffer = (uint8_t*) inout;
    }
    else {
        //ECB mode, not using the Chain
        for (i = 0; i< groups; i++) {
            {
                c_aes_encrypt_block(&ctx,buffer,buffer);
            }
            buffer += AES_BLOCK_SIZE;
        }
    }
    for (i = 0; i < (bufLen % AES_BLOCK_SIZE); i++) {
        *buffer++ ^= (uint8_t) i;
    }
}

void c_encrypt_decode_aes_real(uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen, uint8_t* iv, uint32_t mode)
{
    AesContext ctx;
    uint32_t i, j, groups;
    uint32_t IV[AES_BLOCK_UINT_SIZE], block[AES_BLOCK_UINT_SIZE];
    uint32_t* inout;
    c_aes_setup_real(&ctx, key, keyLen, iv, mode);
    groups = bufLen >> AES_BLOCK_SIZE_SHIFT;
    memcpy(IV, ctx.IV,AES_BLOCK_SIZE);

    inout = (uint32_t*) buffer;

    if (ENC_MODE_CBC == mode) {
        for (i = 0; i < groups; i++) {
            {
                c_aes_decrypt_block(&ctx,(uint8_t*) inout,(uint8_t*) block);
            }

            for (j = 0; j < AES_BLOCK_UINT_SIZE; j++) {
                block[j] ^=  IV[j];
            }
            memcpy(IV, inout, AES_BLOCK_SIZE);
            memcpy(inout, block, AES_BLOCK_SIZE);
            inout += AES_BLOCK_UINT_SIZE;
        }
        buffer = (uint8_t*) inout;
    }
    else if (ENC_MODE_CFB ==  mode) {
        for (i = 0; i < groups; i++) {
            {
                c_aes_encrypt_block(&ctx,(uint8_t*) IV, (uint8_t*) IV);
            }
            for (j = 0; j < AES_BLOCK_UINT_SIZE; j++) {
                IV[j] ^=  inout[j];
            }
            memcpy(inout, IV, AES_BLOCK_SIZE);
            inout += AES_BLOCK_UINT_SIZE;
        }
        buffer = (uint8_t*) inout;
    }
    else {
        //ECB mode, not using the Chain
        for (i = 0; i< groups; i++) {
            {
                c_aes_decrypt_block(&ctx,buffer,buffer);
            }
            buffer += AES_BLOCK_SIZE;
        }
    }
    for (i = 0; i < (bufLen % AES_BLOCK_SIZE); i++) {
        *buffer++ ^= (uint8_t) i;
    }
}

void c_encrypt_encode_en_rc4(uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen)
{
    Rc4Context ctx;
    c_rc4_setup(&ctx, key, keyLen);
    c_en_rc4_encrypt(&ctx, buffer, bufLen);
}

void c_encrypt_decode_en_rc4(uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen)
{
    Rc4Context ctx;
    c_rc4_setup(&ctx, key, keyLen);
    c_en_rc4_decrypt(&ctx, buffer, bufLen);
}

void c_encrypt_encrypt_buffer(uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen, uint32_t arith)
{
    switch(arith) {
        case C_ENCRYPT_ARITH_RC4: {
            c_encrypt_encode_rc4(buffer, bufLen, key, keyLen);
            break;
        }
        case C_ENCRYPT_ARITH_EN_RC4: {
            c_encrypt_encode_en_rc4(buffer, bufLen, key, keyLen);
            break;
        }
        case C_ENCRYPT_ARITH_AES_ECB: {
            c_encrypt_encode_aes_ecb(buffer, bufLen, key, keyLen);
            break;
        }
        case C_ENCRYPT_ARITH_SM4: {
            c_encrypt_encode_sm4 (buffer, bufLen, key);
            break;
        }
        default: {
            break;
        }
    }
}

void c_encrypt_decrypt_buffer(uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen, uint32_t arith)
{
    switch(arith) {
        case C_ENCRYPT_ARITH_RC4: {
            c_encrypt_decode_rc4(buffer, bufLen, key, keyLen);
            break;
        }
        case C_ENCRYPT_ARITH_EN_RC4: {
            c_encrypt_decode_en_rc4(buffer, bufLen, key, keyLen);
            break;
        }
        case C_ENCRYPT_ARITH_AES: {
            c_encrypt_decode_aes(buffer, bufLen, key, keyLen);
            break;
        }
        case C_ENCRYPT_ARITH_SM4: {
            c_encrypt_decode_sm4 (buffer, bufLen, key);
            break;
        }
        default: {
            break;
        }
    }
}

