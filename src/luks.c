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
#include "luks.h"


typedef enum
{
    LUKS_LOCK_TYPE_DEV_LOCK_READ = 0,
    LUKS_LOCK_TYPE_DEV_LOCK_WRITE,
} LUKSLockType;

typedef enum
{
    LUKS_LOCK_MODE_DEV_LOCK_FILE = 0,
    LUKS_LOCK_MODE_DEV_LOCK_BDEV,
    LUKS_LOCK_MODE_DEV_LOCK_NAME,
} LUKSLockMode;

typedef struct _LUKSCryptLockHandle
{
    uint32_t                    refCnt;
    int32_t                     flockFd;
    LUKSLockType                type;
    LUKSLockMode                mode;
    union {
        struct {
            dev_t               devno;
        } bdev;
        struct {
            char*               name;
        } name;
    } u;

} LUKSCryptLockHandle;

typedef struct
{
    uint8_t*                    path;
    uint8_t*                    filePath;
    int32_t                     loopFd;

    int32_t                     roDevFd;
    int32_t                     devFd;
    int32_t                     devFdExcl;

    LUKSCryptLockHandle*        lh;

    uint32_t                    oDirect:1;
    uint32_t                    initDone:1;

    /* cached values */
    uint64_t                    alignment;
    uint64_t                    blockSize;
    uint64_t                    loopBlockSize;
} LUKSDevice;

typedef struct _LUKSVolumeKey
{
    int32_t                     id;
    uint64_t                    keyLength;
    const uint8_t*              keyDescription;
    LUKSKeyType                 keyringKeyType;
    LUKSKeySerial               keyId;
    struct _LUKSVolumeKey*      next;
    uint8_t*                    key;
} LUKSVolumeKey;

struct _LUKSCryptDevice
{
    char*                       type;
    LUKSDevice*                 device;
    LUKSDevice*                 metaDataDevice;
    LUKSVolumeKey*              volumeKey;
    int32_t                     rngType;
    uint32_t                    compatibility;
    LUKSCryptPbkdfType          pbkdf;

    uint32_t                    keyInKeyring:1;

    bool                        linkVkToKeyring;
    int32_t                     keyringToLinkVk;
    const uint8_t*              userKeyName1;
    const uint8_t*              userKeyName2;
    LUKSKeyType                 keyringKeyType;

    uint64_t                    dataOffset;
    uint64_t                    metaDataSize;               // Used in LUKS2 format
    uint64_t                    keySlotsSize;               // Used in LUKS2 format

    bool                        memoryHardPbkdfLockEnabled;
    LUKSCryptLockHandle*        pbkdfMemoryHardLock;

    union {
        struct {
            LUKSPhdr                hdr;
            uint8_t*                cipherSpec;
        } luks1;
        struct {
            LUKSCryptParamsPlain    hdr;
            uint8_t*                cipherSpec;
            uint8_t*                cipher;
            const uint8_t*          cipherMode;
            uint32_t                keySize;
        } plain;
        struct {
            uint8_t*                activeName;
            uint8_t                 cipherSpec[C_MAX_CIPHER_LEN * 2 + 1];
            uint8_t                 integritySpec[C_MAX_INTEGRITY_LEN];
            const uint8_t*          cipherMode;
            uint32_t                keySize;
            uint32_t                sectorSize;
        } none;
    } u;

    void    (*log)     (int level, const char* msg, void* usrPtr);
    void*                           logUsrPtr;
    int     (*confirm) (const char* msg, void* usrPtr);
    void*                           confirmUsrPtr;
};
