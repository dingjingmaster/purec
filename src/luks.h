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
#ifndef purec_PUREC_LUKS_H
#define purec_PUREC_LUKS_H
#include "common.h"


#define C_MAX_CIPHER_LEN                    32
#define C_MAX_CIPHER_LEN_STR                "31"
#define C_MAX_KEYFILES                      32
#define C_MAX_KEYRING_LINKS                 2
#define C_MAX_VK_IN_KEYRING                 2
#define C_MAX_CAPI_ONE_LEN                  (2 * C_MAX_CIPHER_LEN)
#define C_MAX_CAPI_ONE_LEN_STR              "63"  /* for sscanf length + '\0' */
#define C_MAX_CAPI_LEN                      144   /* should be enough to fit whole capi string */
#define C_MAX_INTEGRITY_LEN                 64

#define C_LUKS_NUM_KEYS                     8
#define C_LUKS_MAGIC_L                      6
#define C_LUKS_CIPHER_NAME_L                32
#define C_LUKS_CIPHER_MODE_L                32
#define C_LUKS_HASH_SPEC_L                  32
#define C_LUKS_DIGEST_SIZE                  20 // since SHA1
#define C_LUKS_HMAC_SIZE                    32
#define C_LUKS_SALT_SIZE                    32
#define C_UUID_STRING_L                     40


#define C_DEFAULT_DISK_ALIGNMENT            1048576 /* 1MiB */
#define C_DEFAULT_MEM_ALIGNMENT             4096

#define C_CRYPT_PLAIN                       "PLAIN"
#define C_CRYPT_LUKS1                       "LUKS1"     // LUKS version 1 header on-disk
#define C_CRYPT_LUKS2                       "LUKS2"     // LUKS version 2 header on-disk
#define C_CRYPT_LOOP_AES                    "LOOPAES"   // loop-AES compatibility mode
#define C_CRYPT_VERITY                      "VERITY"    // dm-verity mode
#define C_CRYPT_TCRYPT                      "TCRYPT"    // TCRYPT (TrueCrypt-compatible and VeraCrypt-compatible) mode
#define C_CRYPT_INTEGRITY                   "INTEGRITY" // INTEGRITY dm-integrity device
#define C_CRYPT_BITLK                       "BITLK"     // BITLK (BitLocker-compatible mode)
#define C_CRYPT_FVAULT2                     "FVAULT2"   // FVAULT2 (FileVault2-compatible mode)
#define C_CRYPT_LUKS                        NULL        // LUKS any version

C_BEGIN_EXTERN_C

typedef enum
{
    LUKS_KEY_TYPE_LOGON_KEY = 0,
    LUKS_KEY_TYPE_USER_KEY,
    LUKS_KEY_TYPE_BIG_KEY,
    LUKS_KEY_TYPE_TRUSTED_KEY,
    LUKS_KEY_TYPE_ENCRYPTED_KEY,
    LUKS_KEY_TYPE_INVALID_KEY,
} LUKSKeyType;

typedef enum
{
    LUKS_CRYPT_STATUS_INFO_INVALID,
    LUKS_CRYPT_STATUS_INFO_INACTIVE,
    LUKS_CRYPT_STATUS_INFO_ACTIVE,
    LUKS_CRYPT_STATUS_INFO_BUSY,
} LUKSCryptStatusInfo;

typedef int32_t LUKSKeySerial;

typedef struct _LUKSCryptDevice LUKSCryptDevice;

typedef struct _LUKSCryptPbkdfType
{
    const uint8_t*              type;               // PBKDF algorithm
    const uint8_t*              hash;               // Hash algorithm
    uint32_t                    timeMs;             // Requested time cost [milliseconds]
    uint32_t                    iterations;         // Iterations, @e 0 or benchmarked value.
    uint32_t                    maxMemoryKb;        // Requested or benchmarked  memory cost [kilobytes]
    uint32_t                    parallelThreads;    // Requested parallel cost [threads]
    uint32_t                    flags;              // CRYPT_PBKDF* flags
} LUKSCryptPbkdfType;

typedef struct _LUKSCryptParamsPlain
{
    const uint8_t*              hash;
    uint64_t                    offset;
    uint64_t                    skip;
    uint64_t                    size;
    uint32_t                    sectorSize;
} LUKSCryptParamsPlain;

typedef struct _LUKSCryptParamsLoopAes
{
    const char*                 hash;               // key hash function
    uint64_t                    offset;             // offset in sectors
    uint64_t                    skip;               // IV offset / initialization sector
} LUKSCryptParamsParamsLoopAes;

typedef struct _LUKSPhdr
{
    char                        magic[C_LUKS_MAGIC_L];
    uint16_t                    version;
    char                        cipherName[C_LUKS_CIPHER_NAME_L];
    char                        cipherMode[C_LUKS_CIPHER_MODE_L];
    char                        hashSpec[C_LUKS_HASH_SPEC_L];
    uint32_t                    payloadOffset;
    uint32_t                    keyBytes;
    char                        mkDigest[C_LUKS_DIGEST_SIZE];
    char                        mkDigestSalt[C_LUKS_SALT_SIZE];
    uint32_t                    mkDigestIterations;
    char                        uuid[C_UUID_STRING_L];

    struct {
        uint32_t                active;
        uint32_t                passwordIterations;
        char                    passwordSalt[C_LUKS_SALT_SIZE];

        /* parameters used for AF store/load */
        uint32_t                keyMaterialOffset;
        uint32_t                stripes;
    } keyblock[C_LUKS_NUM_KEYS];

    /* Align it to 512 sector size */
    char                        _padding[432];
} LUKSPhdr;

/**
 * @brief 初始化
 * @param cd
 * @param device
 * @return 成功返回0, 失败返回负数
 */
int                     c_luks_crypt_init                   (C_IN_OUT LUKSCryptDevice** cd, C_IN const uint8_t* device);

void                    c_luks_crypt_free                   (C_IN LUKSCryptDevice* cd);

int                     c_luks_crypt_format                 (C_IN LUKSCryptDevice* cd,
                                                             C_IN const uint8_t* type,
                                                             C_IN const uint8_t* cipher,
                                                             C_IN const uint8_t* cipherMode,
                                                             C_IN const uint8_t* uuid,
                                                             C_IN const uint8_t* volumeKey,
                                                             C_IN uint64_t volumeKeySize,
                                                             C_IN void* params);

LUKSCryptStatusInfo     c_luks_crypt_status                 (C_IN LUKSCryptDevice* cd, C_IN const uint8_t* name);

int                     c_luks_crypt_activate_by_volume_key (C_IN LUKSCryptDevice* cd,
                                                             C_IN const uint8_t* name,
                                                             C_IN const uint8_t* volumeKey,
                                                             C_IN uint64_t volumeKeySize,
                                                             C_IN uint32_t flags);

int                     c_luks_crypt_deactivate_by_name     (C_IN LUKSCryptDevice* cd, C_IN const uint8_t* name, C_IN uint32_t flags);

int                     c_luks_crypt_deactivate             (C_IN LUKSCryptDevice* cd, C_IN const uint8_t* name);

C_END_EXTERN_C


#endif // purec_PUREC_LUKS_H