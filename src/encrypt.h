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
#ifndef purec_PUREC_ENCRYPT_H
#define purec_PUREC_ENCRYPT_H
#include "common.h"

// FIXME:// AES 算法还不完善

/* 加解密算法 -- start */
#define C_ENCRYPT_ARITH_NONE                        0
#define C_ENCRYPT_ARITH_RC4                         10
#define C_ENCRYPT_ARITH_EN_RC4                      11
#define C_ENCRYPT_ARITH_RC5                         20
#define C_ENCRYPT_ARITH_RC6                         30
// --> 块
#define C_ENCRYPT_ARITH_DES                         40
#define C_ENCRYPT_ARITH_3DES                        41
#define C_ENCRYPT_ARITH_SEAL                        50
#define C_ENCRYPT_ARITH_TEA                         60
#define C_ENCRYPT_ARITH_XXTEA                       61
#define C_ENCRYPT_ARITH_AES_ECB                     70
#define C_ENCRYPT_ARITH_SM4                         80
/* 加解密算法 -- end   */


C_BEGIN_EXTERN_C

/**
 * @brief RC4 加密
 * @param buffer
 * @param bufLen
 * @param key
 * @param keyLen
 */
void        c_encrypt_encode_rc4             (uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen);
/**
 * @brief RC4 解密
 * @param buffer
 * @param bufLen
 * @param key
 * @param keyLen
 */
void        c_encrypt_decode_rc4             (uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen);

/**
 * @brief SM4 加密
 * @param buffer
 * @param bufLen
 * @param key
 */
void        c_encrypt_encode_sm4             (uint8_t* buffer, uint64_t bufLen, const uint8_t* key);
/**
 * @brief SM4 解密
 * @param buffer
 * @param bufLen
 * @param key
 */
void        c_encrypt_decode_sm4             (uint8_t* buffer, uint64_t bufLen, const uint8_t* key);

void        c_encrypt_encode_aes_ecb         (uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen);
void        c_encrypt_decode_aes_ecb         (uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen);

/**
 * @brief 增强的 RC4 加密
 * @param buffer
 * @param bufLen
 * @param key
 * @param keyLen
 */
void        c_encrypt_encode_en_rc4          (uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen);

/**
 * @brief 增强的 RC4 解密
 * @param buffer
 * @param bufLen
 * @param key
 * @param keyLen
 */
void        c_encrypt_decode_en_rc4          (uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen);

/**
 * @brief 使用指定算法加密缓存区
 * @param buffer
 * @param bufLen
 * @param key
 * @param keyLen
 * @param arith
 */
void        c_encrypt_encrypt_buffer         (uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen, uint32_t arith);

/**
 * @brief 使用指定算法解密缓存区
 * @param buffer
 * @param bufLen
 * @param key
 * @param keyLen
 * @param arith
 */
void        c_encrypt_decrypt_buffer         (uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen, uint32_t arith);

void        c_encrypt_encode_aes_real        (uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen, uint8_t* iv, uint32_t mode);
void        c_encrypt_decode_aes_real        (uint8_t* buffer, uint64_t bufLen, const uint8_t* key, uint64_t keyLen, uint8_t* iv, uint32_t mode);


C_END_EXTERN_C

#endif // purec_PUREC_ENCRYPT_H