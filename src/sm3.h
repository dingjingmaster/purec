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
#ifndef purec_PUREC_SM_3_H
#define purec_PUREC_SM_3_H
#include "common.h"

#define C_SM3_IS_BIG_ENDIAN         1

#define C_SM3_DIGEST_SIZE           32
#define C_SM3_BLOCK_SIZE            64
#define C_SM3_STATE_WORDS           8
#define C_SM3_HMAC_SIZE             (C_SM3_DIGEST_SIZE)

C_BEGIN_EXTERN_C

typedef struct
{
    uint32_t        digest[C_SM3_STATE_WORDS];
    uint64_t        nBlocks;
    uint8_t         block[C_SM3_BLOCK_SIZE];
    uint32_t        num;
} Sm3Context;

typedef struct
{
    Sm3Context      sm3Ctx;
    uint8_t         key[C_SM3_BLOCK_SIZE];
} Sm3HMACContext;

typedef struct
{
    Sm3Context      sm3Ctx;
    size_t          outLen;
} Sm3KDFContext;


/**
 * @brief 初始化 SM3(用来计算Hash) 上下文结构
 * @param ctx
 */
void c_sm3_init             (Sm3Context* ctx);

/**
 * @brief 将指定长度的数据添加到 sm3 上下文, 计算hash值
 * @param ctx
 * @param data
 * @param dataLen
 */
void c_sm3_update           (Sm3Context* ctx, const uint8_t* data, size_t dataLen);

/**
 * @brief 完成 hash 值计算, 并返回计算结果
 * @param ctx
 * @param dGst
 */
void c_sm3_finish           (Sm3Context* ctx, uint8_t dGst[C_SM3_DIGEST_SIZE]);

/**
 * @brief 集成hash值计算流程
 * @param data
 * @param dataLen
 * @param dGst
 */
void c_sm3_digest           (const uint8_t* data, size_t dataLen, uint8_t dGst[C_SM3_DIGEST_SIZE]);

/**
 * @brief SM3哈希的核心压缩函数, 用于对512-bit消息块进行压缩并更新哈希状态
 * @param digest
 * @param data
 * @param blocks
 */
void c_sm3_compress_blocks  (uint32_t digest[8], const uint8_t *data, size_t blocks);

/**
 * @brief (HMAC, Hash-based Message Authentication Code), 一种基于hash函数的消息认证码, 初始化并生成 ipad和opad
 * @param ctx
 * @param key
 * @param keyLen
 */
void c_sm3_hmac_init        (Sm3HMACContext* ctx, const uint8_t* key, size_t keyLen);
void c_sm3_hmac_update      (Sm3HMACContext* ctx, const uint8_t* data, size_t dataLen);
void c_sm3_hmac_finish      (Sm3HMACContext* ctx, uint8_t mac[C_SM3_HMAC_SIZE]);
void c_sm3_hmac             (const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen, uint8_t mac[C_SM3_HMAC_SIZE]);

/**
 * @brief KDF(Key Derivation Function, 密钥派生函数);
 * 从一个主密钥/共享密钥(比如:SM2握手得到的Z值)派生出一个指定长度的密钥流/密钥材料(比如:128-bit、256-bit)
 * @param ctx
 * @param outLen
 */
void c_sm3_kdf_init         (Sm3KDFContext* ctx, size_t outLen);
void c_sm3_kdf_update       (Sm3KDFContext* ctx, const uint8_t *data, size_t dataLen);
void c_sm3_kdf_finish       (Sm3KDFContext* ctx, uint8_t *out);


C_END_EXTERN_C

#endif // purec_PUREC_SM_3_H