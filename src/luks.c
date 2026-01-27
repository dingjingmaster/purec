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
#if 0

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/statvfs.h>

#include "utils-sys.h"


#ifndef O_DIRECT
#define O_DIRECT    040000
#endif


#define CRYPT_RNG_URANDOM   0
#define CRYPT_RNG_RANDOM    1


#define SHIFT_4K            12
#define SECTOR_SHIFT        9
#define SECTOR_SIZE         (1 << SECTOR_SHIFT)
#define MAX_SECTOR_SIZE     4096 /* min page size among all platforms */
#define ROUND_SECTOR(x)     (((x) + SECTOR_SIZE - 1) / SECTOR_SIZE)

#define DEFAULT_RNG         "/dev/urandom"
#define RANDOM_DEVICE       "/dev/random"
#define URANDOM_DEVICE      "/dev/urandom"

#define KEY_NOT_VERIFIED            -2
#define KEY_EXTERNAL_VERIFICATION   -1
#define KEY_VERIFIED                0

#define DEFAULT_LOOP_AES_CIPHER     "aes"

static int gsRandomInitialised  = 0;
static int gsUrandomFd          = -1;
static int gsRandomFd           = -1;

#define CONST_CAST(x) (x)(uintptr_t)

#define MISALIGNED(a, b)    ((a) & ((b) - 1))
#define MISALIGNED_4K(a)    MISALIGNED((a), 1 << SHIFT_4K)
#define MISALIGNED_512(a)   MISALIGNED((a), 1 << SECTOR_SHIFT)
#define NOT_POW2(a)         MISALIGNED((a), (a))


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

typedef struct _LUKSSafeAllocation
{
    size_t size;
    bool locked;
    char data[0] __attribute__((aligned(8)));
} LUKSSafeAllocation;
#define OVERHEAD offsetof(LUKSSafeAllocation, data)


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
            LUKSCryptParamsParamsLoopAes hdr;
            char*                   cipherSpec;
            char*                   cipher;
            const char*             cipherMode;
            unsigned int            keySize;
        } loopAes;
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


// device -- start
static size_t _device_alignment_fd(int devFd);
static size_t _device_fs_block_size_fd(int fd);
static int _device_locked(LUKSCryptLockHandle* h);
static const char* _device_path(const LUKSDevice* device);
static int _device_read_test(LUKSCryptDevice*cd, int devFd);
static size_t _device_block_size_fd(int fd, size_t *minSize);
static int _device_ready(LUKSCryptDevice* cd, LUKSDevice* device);
static void _device_free(LUKSCryptDevice* cd, LUKSDevice* device);
static void _device_close(LUKSCryptDevice* cd, LUKSDevice *device);
static int _device_alloc_no_check(LUKSDevice** device, const char* path);
static void _crypt_free_type(LUKSCryptDevice* cd, const char *force_type);
static int _device_alloc(LUKSCryptDevice* cd, LUKSDevice** device, const uint8_t* path);
ssize_t _read_blockwise(int fd, size_t bsize, size_t alignment, void *origBuf, size_t length);

static void crypt_safe_free(void *data);
static int _crypt_random_default_key_rng(void);
static void crypt_set_null_type(LUKSCryptDevice* cd);
void crypt_free_volume_key(LUKSVolumeKey* vk);
static void _crypt_backend_memzero(void *s, size_t n);
static void _crypt_safe_memzero(void *data, size_t size);
static ssize_t _read_buffer(int fd, void *buf, size_t length);
static void *_crypt_backend_memcpy(void *dst, const void *src, size_t n);
static ssize_t __read_buffer(int fd, void *buf, size_t length, volatile int *quit);

static void crypt_random_exit(void);
static int crypt_random_init(LUKSCryptDevice* ctx);
static void crypt_reset_null_type(LUKSCryptDevice* cd);

static int init_crypto(LUKSCryptDevice *ctx);

static void dm_exit_context(void);
void        dm_backend_init(LUKSCryptDevice* cd);
void        dm_backend_exit(LUKSCryptDevice* cd);
int         dm_status_device(LUKSCryptDevice* cd, const char *name);
static int  dm_init_context(LUKSCryptDevice* cd, LUKSDevMapTargetType target);
static int  dm_status_dmi(const char* name, LUKSDevMapInfo* dmi, const char *target, char** statusLine);

static bool _dm_check_versions(LUKSCryptDevice* cd, LUKSDevMapTargetType targetType);


LUKSDevice*     crypt_data_device(LUKSCryptDevice* cd);
LUKSVolumeKey*  crypt_alloc_volume_key(size_t keyLength, const char *key);

static void*    crypt_safe_alloc(size_t size);
void*           crypt_safe_memcpy(void *dst, const void *src, size_t size);

int             crypt_backend_init(void);
void*           crypt_backend_memcpy(void *dst, const void *src, size_t n);
LUKSDevice*     crypt_metadata_device(LUKSCryptDevice* cd);


int             device_size(LUKSDevice* device, uint64_t *size);
void            device_set_block_size(LUKSDevice* device, size_t size);

// openssl -- start
static int openssl_backend_init(bool fips);
// openssl -- end


static int _crypt_format_loopaes    (LUKSCryptDevice* cd, const char *cipher, const char *uuid, size_t volumeKeySize, LUKSCryptParamsParamsLoopAes* params);
static int _crypt_format_plain      (LUKSCryptDevice* cd, const char* cipher, const char* cipherMode, const char* uuid, size_t volumeKeySize, LUKSCryptParamsPlain* params);


// TODO:// 属于 lvm2
extern void dm_lib_release();
// device -- end


static int isPLAIN(const char *type)
{
    return (type && !strcmp(C_CRYPT_PLAIN, type));
}

static int isLUKS1(const char *type)
{
    return (type && !strcmp(C_CRYPT_LUKS1, type));
}

static int isLUKS2(const char *type)
{
    return (type && !strcmp(C_CRYPT_LUKS2, type));
}

static int isLUKS(const char *type)
{
    return (isLUKS2(type) || isLUKS1(type));
}

static int isLOOPAES(const char *type)
{
    return (type && !strcmp(C_CRYPT_LOOP_AES, type));
}

static int isVERITY(const char *type)
{
    return (type && !strcmp(C_CRYPT_VERITY, type));
}

static int isTCRYPT(const char *type)
{
    return (type && !strcmp(C_CRYPT_TCRYPT, type));
}

static int isINTEGRITY(const char *type)
{
    return (type && !strcmp(C_CRYPT_INTEGRITY, type));
}

static int isBITLK(const char *type)
{
    return (type && !strcmp(C_CRYPT_BITLK, type));
}

static int isFVAULT2(const char *type)
{
    return (type && !strcmp(C_CRYPT_FVAULT2, type));
}

static inline void* crypt_zalloc(size_t size)
{
    return calloc(1, size);
}


static int                      _dm_use_count = 0;
static int                      gsCryptoBackendInitialised = 0;
static LUKSCryptDevice*         gsContext = NULL;


int c_luks_crypt_init(LUKSCryptDevice** cd, const uint8_t* device)
{
    int r = 0;
    LUKSCryptDevice* cdT = NULL;

    if (!cd) {
        return -EINVAL;
    }

    cdT = malloc(sizeof(LUKSCryptDevice));
    if (!cdT) {
        return -ENOMEM;
    }
    memset(cdT, 0, sizeof(LUKSCryptDevice));
    r = _device_alloc(NULL, &cdT->device, device);
    if (r < 0) {
        free(cdT);
        return r;
    }

    dm_backend_init (NULL);

    cdT->rngType = _crypt_random_default_key_rng();

    *cd = cdT;

    return 0;
}

void c_luks_crypt_free(LUKSCryptDevice* cd)
{
    if (!cd) {
        return;
    }

    dm_backend_exit(cd);
    crypt_free_volume_key(cd->volumeKey);

    _crypt_free_type(cd, NULL);

    _device_free(cd, cd->device);
    _device_free(cd, cd->metaDataDevice);

    free(CONST_CAST(void*)cd->pbkdf.type);
    free(CONST_CAST(void*)cd->pbkdf.hash);
    free(CONST_CAST(void*)cd->userKeyName1);
    free(CONST_CAST(void*)cd->userKeyName2);

    _crypt_safe_memzero(cd, sizeof(*cd));

    free(cd);
}

int c_luks_crypt_format(LUKSCryptDevice* cd, const uint8_t* type, const uint8_t* cipher, const uint8_t* cipherMode, const uint8_t* uuid, const uint8_t* volumeKey, uint64_t volumeKeySize, void* params)
{
    int r = 0;

    if (!cd || !type) {
        return -EINVAL;
    }

    if (cd->type) {
        return -EINVAL;
    }

    crypt_reset_null_type(cd);

    r = init_crypto(cd);
    if (r < 0) {
        return r;
    }

    if (isPLAIN((const char*) type)) {
        r = _crypt_format_plain(cd, cipher, cipherMode, uuid, volumeKeySize, params);
    }
    // else if (isLUKS1(type)) {
        // r = _crypt_format_luks1(cd, cipher, cipherMode, uuid, volumeKey, volumeKeySize, params);
    // }
    // else if (isLUKS2(type)) {
        // r = _crypt_format_luks2(cd, cipher, cipherMode, uuid, volumeKey, volumeKeySize, params, sectorSizeAutodetect, false);
    // }
    else if (isLOOPAES((const char*) type)) {
        r = _crypt_format_loopaes(cd, cipher, uuid, volumeKeySize, params);
    }
    // else if (isVERITY(type)) {
        // r = _crypt_format_verity(cd, uuid, params);
    // }
    // else if (isINTEGRITY(type)) {
        // r = _crypt_format_integrity(cd, uuid, params, volumeKey, volumeKeySize, false);
    // }
    else {
        r = -EINVAL;
    }

    if (r < 0) {
        crypt_set_null_type(cd);
        crypt_free_volume_key(cd->volumeKey);
        cd->volumeKey = NULL;
    }

    return r;
}

LUKSCryptStatusInfo c_luks_crypt_status(LUKSCryptDevice* cd, const uint8_t* name)
{
    int r = 0;

    if (!name) {
        return LUKS_CRYPT_STATUS_INFO_INVALID;
    }

    if (!cd) {
        dm_backend_init(cd);
    }

    r = dm_status_device(cd, name);

    if (!cd) {
        dm_backend_exit(cd);
    }

    if (r < 0 && r != -ENODEV) {
        return LUKS_CRYPT_STATUS_INFO_INVALID;
    }

    if (r == 0) {
        return LUKS_CRYPT_STATUS_INFO_ACTIVE;
    }

    if (r > 0) {
        return LUKS_CRYPT_STATUS_INFO_BUSY;
    }

    return LUKS_CRYPT_STATUS_INFO_INACTIVE;
}

static int init_crypto(LUKSCryptDevice* ctx)
{
    int r = 0;

    r = crypt_random_init(ctx);
    if (r < 0) {
        return r;
    }

    r = crypt_backend_init();

    return r;
}

static int _device_alloc(LUKSCryptDevice* cd, LUKSDevice** device, const uint8_t* path)
{
    LUKSDevice* dev = NULL;
    int r;

    r = _device_alloc_no_check(&dev, path);
    if (r < 0)
        return r;

    if (dev) {
        r = _device_ready(cd, dev);
        if (!r) {
            dev->initDone = 1;
        }
        else if (r == -ENOTBLK) {
            /* alloc loop later */
        }
        else if (r < 0) {
            free(dev->path);
            free(dev);
            return -ENOTBLK;
        }
    }

    *device = dev;

    return 0;
}

int crypt_backend_init(void)
{
    if (gsCryptoBackendInitialised) {
        return 0;
    }

    if (openssl_backend_init(false)) {
        return -EINVAL;
    }

    gsCryptoBackendInitialised = 1;

    return 0;
}

int crypt_random_init(LUKSCryptDevice* ctx)
{
    if (gsRandomInitialised) {
        return 0;
    }

    /* Used for CRYPT_RND_NORMAL */
    if (gsUrandomFd == -1) {
        gsUrandomFd = open(URANDOM_DEVICE, O_RDONLY | O_CLOEXEC);
    }

    if (gsUrandomFd == -1) {
        goto err;
    }

    /* Used for CRYPT_RND_KEY */
    if (gsRandomFd == -1) {
        gsRandomFd = open(RANDOM_DEVICE, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    }

    if (gsRandomFd == -1) {
        goto err;
    }

    gsRandomInitialised = 1;

    return 0;

err:
    crypt_random_exit();

    return -ENOSYS;
}

static void crypt_random_exit(void)
{
    gsRandomInitialised = 0;

    if(gsRandomFd != -1) {
        (void) close (gsRandomFd);
        gsRandomFd = -1;
    }

    if (gsUrandomFd != -1) {
        (void) close (gsUrandomFd);
        gsUrandomFd = -1;
    }
}

static void _device_free(LUKSCryptDevice* cd, LUKSDevice* device)
{
    if (!device) {
        return;
    }

    _device_close(cd, device);

    if (device->devFdExcl != -1) {
        close(device->devFdExcl);
    }

    if (device->loopFd != -1) {
        close(device->loopFd);
    }

    assert(!_device_locked(device->lh));

    free(device->filePath);
    free(device->path);
    free(device);
}

static int _device_locked(LUKSCryptLockHandle* h)
{
    return (h && (h->type == LUKS_LOCK_TYPE_DEV_LOCK_READ || h->type == LUKS_LOCK_TYPE_DEV_LOCK_WRITE));
}

static void _device_close(LUKSCryptDevice* cd, LUKSDevice *device)
{
    if (!device) {
        return;
    }

    if (device->roDevFd != -1) {
        close(device->roDevFd);
        device->roDevFd = -1;
    }

    if (device->devFd != -1) {
        close(device->devFd);
        device->devFd = -1;
    }
}

static int _device_alloc_no_check(LUKSDevice** device, const char* path)
{
    LUKSDevice* dev = NULL;

    if (!path) {
        *device = NULL;
        return 0;
    }

    dev = malloc(sizeof(LUKSDevice));
    if (!dev) {
        return -ENOMEM;
    }

    memset(dev, 0, sizeof(LUKSDevice));
    dev->path = (uint8_t*) strdup (path);
    if (!dev->path) {
        free(dev);
        return -ENOMEM;
    }

    dev->loopFd = -1;
    dev->roDevFd = -1;
    dev->devFd = -1;
    dev->devFdExcl = -1;
    dev->oDirect = 1;

    *device = dev;

    return 0;
}

static int _device_ready(LUKSCryptDevice* cd, LUKSDevice* device)
{
    int devFd = -1, r = 0;
    struct stat st;
    size_t tmpSize = 0;

    if (!device) {
        return -EINVAL;
    }

    if (device->oDirect) {
        device->oDirect = 0;
        devFd = open(_device_path(device), O_RDONLY | O_DIRECT);
        if (devFd >= 0) {
            if (_device_read_test(cd, devFd) == 0) {
                device->oDirect = 1;
            }
            else {
                close(devFd);
                devFd = -1;
            }
        }
    }

    if (devFd < 0) {
        devFd = open(_device_path(device), O_RDONLY);
    }

    if (devFd < 0) {
        return -EINVAL;
    }

    if (fstat(devFd, &st) < 0) {
        r = -EINVAL;
    }
    else if (!S_ISBLK(st.st_mode))
        r = S_ISREG(st.st_mode) ? -ENOTBLK : -EINVAL;
    if (r == -EINVAL) {
        close(devFd);
        return r;
    }

    /* Allow only increase (loop device) */
    tmpSize = _device_alignment_fd(devFd);
    if (tmpSize > device->alignment) {
        device->alignment = tmpSize;
    }

    tmpSize = _device_block_size_fd(devFd, NULL);
    if (tmpSize > device->blockSize) {
        device->blockSize = tmpSize;
    }

    close(devFd);

    return r;
}

static const char* _device_path(const LUKSDevice* device)
{
    if (!device) {
        return NULL;
    }

    if (device->filePath) {
        return (const char*) device->filePath;
    }

    return (const char*) device->path;
}

static size_t _device_alignment_fd(int devFd)
{
    long alignment = C_DEFAULT_MEM_ALIGNMENT;

#ifdef _PC_REC_XFER_ALIGN
    alignment = fpathconf(devFd, _PC_REC_XFER_ALIGN);
    if (alignment < 0) {
        alignment = C_DEFAULT_MEM_ALIGNMENT;
    }
#endif

    return (size_t) alignment;
}

static size_t _device_block_size_fd(int fd, size_t *minSize)
{
    struct stat st;
    size_t bsize;
    int arg;

    if (fstat(fd, &st) < 0) {
        return 0;
    }

    if (S_ISREG(st.st_mode)) {
        bsize = _device_fs_block_size_fd(fd);
    }
    else {
        if (ioctl(fd, BLKSSZGET, &arg) < 0) {
            bsize = c_utils_sys_get_page_size();
        }
        else {
            bsize = (size_t)arg;
        }
    }

    if (!minSize) {
        return bsize;
    }

    if (S_ISREG(st.st_mode)) {
        /* file can be empty as well */
        if (st.st_size > (ssize_t)bsize) {
            *minSize = bsize;
        }
        else {
            *minSize = st.st_size;
        }
    }
    else {
        /* block device must have at least one block */
        *minSize = bsize;
    }

    return bsize;
}

static size_t _device_fs_block_size_fd(int fd)
{
    size_t maxSize = 4096;

    struct statvfs buf;

    if (!fstatvfs(fd, &buf) && buf.f_bsize && buf.f_bsize <= maxSize) {
        return (size_t)buf.f_bsize;
    }

    return maxSize;
}

static int _device_read_test(LUKSCryptDevice*cd, int devFd)
{
    int r;
    struct stat st;
    char buffer[512];
    size_t minsize = 0, blocksize, alignment;

    if (fstat(devFd, &st) < 0) {
        return -EINVAL;
    }

    if (S_ISBLK(st.st_mode)) {
        return 0;
    }

    blocksize = _device_block_size_fd(devFd, &minsize);
    alignment = _device_alignment_fd(devFd);

    if (!blocksize || !alignment)
        return -EINVAL;

    if (minsize == 0)
        return 0;

    if (minsize > sizeof(buffer))
        minsize = sizeof(buffer);

    if (_read_blockwise(devFd, blocksize, alignment, buffer, minsize) == (ssize_t)minsize) {
        r = 0;
    }
    else {
        r = -EIO;
    }

    _crypt_safe_memzero(buffer, sizeof(buffer));

    return r;
}

ssize_t _read_blockwise(int fd, size_t bsize, size_t alignment, void *origBuf, size_t length)
{
    void *hangoverBuf = NULL, *buf = NULL;
    size_t hangover, solid;
    ssize_t r, ret = -1;

    if (fd == -1 || !origBuf || !bsize || !alignment) {
        return -1;
    }

    hangover = length % bsize;
    solid = length - hangover;

    if ((size_t)origBuf & (alignment - 1)) {
        if (posix_memalign(&buf, alignment, length)) {
            return -1;
        }
    }
    else {
        buf = origBuf;
    }

    r = _read_buffer(fd, buf, solid);
    if (r < 0 || r != (ssize_t)solid)
        goto out;

    if (hangover) {
        if (posix_memalign(&hangoverBuf, alignment, bsize))
            goto out;
        r = _read_buffer(fd, hangoverBuf, bsize);
        if (r <  0 || r < (ssize_t)hangover) {
            goto out;
        }
        memcpy((char *)buf + solid, hangoverBuf, hangover);
    }
    ret = length;
out:
    free(hangoverBuf);
    if (buf != origBuf) {
        if (ret != -1) {
            memcpy(origBuf, buf, length);
        }
        free(buf);
    }

    return ret;
}

static ssize_t __read_buffer(int fd, void *buf, size_t length, volatile int *quit)
{
    ssize_t r, readSize = 0;

    if (fd < 0 || !buf || length > SSIZE_MAX)
        return -EINVAL;

    do {
        r = read(fd, buf, length - readSize);
        if (r == -1 && errno != EINTR)
            return r;
        if (r > 0) {
            /* coverity[overflow:FALSE] */
            readSize += r;
            buf = (uint8_t*)buf + r;
        }
        if (r == 0 || (quit && *quit)) {
            return readSize;
        }
    } while ((size_t)readSize != length);

    return (ssize_t)length;
}

static ssize_t _read_buffer(int fd, void *buf, size_t length)
{
    return __read_buffer(fd, buf, length, NULL);
}

static void _crypt_safe_memzero(void *data, size_t size)
{
    if (!data) {
        return;
    }

    _crypt_backend_memzero(data, size);
}

static void* _crypt_backend_memcpy(void *dst, const void *src, size_t n)
{
    volatile uint8_t *d = (volatile uint8_t *)dst;
    const volatile uint8_t *s = (const volatile uint8_t *)src;

    while(n--) *d++ = *s++;

    return dst;
}

static void _crypt_backend_memzero(void *s, size_t n)
{
    volatile uint8_t *p = (volatile uint8_t *)s;
    while(n--) *p++ = 0;
}

static int _crypt_random_default_key_rng(void)
{
    /* coverity[pointless_string_compare] */
    if (!strcmp(DEFAULT_RNG, RANDOM_DEVICE)) {
        return CRYPT_RNG_RANDOM;
    }

    /* coverity[pointless_string_compare] */
    if (!strcmp(DEFAULT_RNG, URANDOM_DEVICE)) {
        return CRYPT_RNG_URANDOM;
    }

    /* RNG misconfiguration is fatal */
    abort();
}


void dm_backend_init(LUKSCryptDevice* cd)
{
    _dm_use_count++;
    (void) cd;
}


void dm_backend_exit(LUKSCryptDevice* cd)
{
    if (_dm_use_count && (!--_dm_use_count)) {
        dm_lib_release();
    }
}

static void _crypt_free_type(LUKSCryptDevice* cd, const char *forceType)
{
    const char *type = forceType ?: cd->type;

    if (isPLAIN(type)) {
        free(CONST_CAST(void*)cd->u.plain.hdr.hash);
        free(cd->u.plain.cipher);
        free(cd->u.plain.cipherSpec);
    }
    else if (isLUKS2(type)) {
        // LUKS2_reencrypt_free(cd, cd->u.luks2.rh);
        // LUKS2_hdr_free(cd, &cd->u.luks2.hdr);
        // free(cd->u.luks2.keyslot_cipher);
        assert(false);
    }
    else if (isLUKS1(type)) {
        // free(cd->u.luks1.cipher_spec);
        assert(false);
    }
    else if (isLOOPAES(type)) {
        free(CONST_CAST(void*)cd->u.loopAes.hdr.hash);
        free(cd->u.loopAes.cipher);
        free(cd->u.loopAes.cipherSpec);
    }
    else if (isVERITY(type)) {
        assert(false);
        // free(CONST_CAST(void*)cd->u.verity.hdr.hash_name);
        // free(CONST_CAST(void*)cd->u.verity.hdr.data_device);
        // free(CONST_CAST(void*)cd->u.verity.hdr.hash_device);
        // free(CONST_CAST(void*)cd->u.verity.hdr.fec_device);
        // free(CONST_CAST(void*)cd->u.verity.hdr.salt);
        // free(CONST_CAST(void*)cd->u.verity.root_hash);
        // free(cd->u.verity.uuid);
        // device_free(cd, cd->u.verity.fec_device);
    }
    else if (isINTEGRITY(type)) {
        assert(false);
        // free(CONST_CAST(void*)cd->u.integrity.params.integrity);
        // free(CONST_CAST(void*)cd->u.integrity.params.journal_integrity);
        // free(CONST_CAST(void*)cd->u.integrity.params.journal_crypt);
        // crypt_free_volume_key(cd->u.integrity.journal_crypt_key);
        // crypt_free_volume_key(cd->u.integrity.journal_mac_key);
    }
    else if (isBITLK(type)) {
        assert(false);
        // free(cd->u.bitlk.cipher_spec);
        // BITLK_bitlk_metadata_free(&cd->u.bitlk.params);
    }
    else if (!type) {
        free(cd->u.none.activeName);
        cd->u.none.activeName = NULL;
    }

    crypt_set_null_type(cd);
}

static void crypt_set_null_type(LUKSCryptDevice* cd)
{
    free(cd->type);
    cd->type = NULL;
    cd->dataOffset = 0;
    cd->metaDataSize = 0;
    cd->keySlotsSize = 0;
    _crypt_safe_memzero(&cd->u, sizeof(cd->u));
}

void crypt_free_volume_key(LUKSVolumeKey* vk)
{
    LUKSVolumeKey* vkNext;

    while (vk) {
        free(CONST_CAST(void*)vk->keyDescription);
        crypt_safe_free((void*) vk->key);
        vkNext = vk->next;
        free(vk);
        vk = vkNext;
    }
}

static void crypt_safe_free(void *data)
{
    LUKSSafeAllocation* alloc = NULL;
    volatile size_t *s;
    void *p;

    if (!data) {
        return;
    }

    p = (char*) data - OVERHEAD;
    alloc = (LUKSSafeAllocation*) p;

    _crypt_backend_memzero(data, alloc->size);

    if (alloc->locked) {
        munlock(alloc, alloc->size + OVERHEAD);
        alloc->locked = false;
    }

    s = (volatile size_t *)&alloc->size;
    *s = 0x55aa55aa;
    free(alloc);
}

static void crypt_reset_null_type(LUKSCryptDevice* cd)
{
    if (cd->type) {
        return;
    }

    free(cd->u.none.activeName);
    cd->u.none.activeName = NULL;
}


static int openssl_backend_init(bool fips)
{
#if OPENSSL_VERSION_MAJOR >= 3
    int r;
    bool ossl_threads = false;

    /*
     * In FIPS mode we keep default OpenSSL context & global config
     */
    if (!fips) {
        ossl_ctx = OSSL_LIB_CTX_new();
        if (!ossl_ctx)
            return -EINVAL;

        ossl_default = OSSL_PROVIDER_try_load(ossl_ctx, "default", 0);
        if (!ossl_default) {
            OSSL_LIB_CTX_free(ossl_ctx);
            return -EINVAL;
        }

        /* Optional */
        ossl_legacy = OSSL_PROVIDER_try_load(ossl_ctx, "legacy", 0);
    }

    if (OSSL_set_max_threads(ossl_ctx, MAX_THREADS) == 1 &&
        OSSL_get_max_threads(ossl_ctx) == MAX_THREADS)
        ossl_threads = true;

    r = snprintf(backend_version, sizeof(backend_version), "%s %s%s%s%s%s",
        OpenSSL_version(OPENSSL_VERSION),
        ossl_default ? "[default]" : "",
        ossl_legacy  ? "[legacy]" : "",
        fips  ? "[fips]" : "",
        ossl_threads ? "[threads]" : "",
        crypt_backend_flags() & CRYPT_BACKEND_ARGON2 ? "[argon2]" : "");

    if (r < 0 || (size_t)r >= sizeof(backend_version)) {
        openssl_backend_exit();
        return -EINVAL;
    }
#else
    (void) (fips);
#endif

    return 0;
}

static int _crypt_format_plain(LUKSCryptDevice* cd, const char* cipher, const char* cipherMode, const char* uuid, size_t volumeKeySize, LUKSCryptParamsPlain* params)
{
    unsigned int sectorSize = params ? params->sectorSize : SECTOR_SIZE;
    uint64_t devSize;

    if (!cipher || !cipherMode) {
        return -EINVAL;
    }

    if (volumeKeySize > 1024) {
        return -EINVAL;
    }

    if (uuid) {
        return -EINVAL;
    }

    if (cd->metaDataDevice) {
        return -EINVAL;
    }

    if (!sectorSize) {
        sectorSize = SECTOR_SIZE;
    }

    if (sectorSize < SECTOR_SIZE || sectorSize > MAX_SECTOR_SIZE || NOT_POW2(sectorSize)) {
        return -EINVAL;
    }

    if (sectorSize > SECTOR_SIZE && !device_size(cd->device, &devSize)) {
        if (params && params->offset) {
            devSize -= (params->offset * SECTOR_SIZE);
        }
        if (devSize % sectorSize) {
            return -EINVAL;
        }
        device_set_block_size(crypt_data_device(cd), sectorSize);
    }

    if (!(cd->type = strdup(C_CRYPT_PLAIN))) {
        return -ENOMEM;
    }

    cd->u.plain.keySize = volumeKeySize;
    cd->volumeKey = crypt_alloc_volume_key(volumeKeySize, NULL);
    if (!cd->volumeKey) {
        return -ENOMEM;
    }

    if (asprintf((char**) &cd->u.plain.cipherSpec, "%s-%s", cipher, cipherMode) < 0) {
        cd->u.plain.cipherSpec = NULL;
        return -ENOMEM;
    }
    cd->u.plain.cipher = (uint8_t*) strdup(cipher);
    cd->u.plain.cipherMode = cd->u.plain.cipherSpec + strlen(cipher) + 1;

    if (params && params->hash) {
        cd->u.plain.hdr.hash = (uint8_t*) strdup((char*) params->hash);
    }

    cd->u.plain.hdr.offset = params ? params->offset : 0;
    cd->u.plain.hdr.skip = params ? params->skip : 0;
    cd->u.plain.hdr.size = params ? params->size : 0;
    cd->u.plain.hdr.sectorSize = sectorSize;

    if (!cd->u.plain.cipher) {
        return -ENOMEM;
    }

    return 0;
}

int device_size(LUKSDevice* device, uint64_t *size)
{
    struct stat st;
    int devfd, r = -EINVAL;

    if (!device) {
        return -EINVAL;
    }

    devfd = open((char*) device->path, O_RDONLY);
    if (devfd == -1) {
        return -EINVAL;
    }

    if (fstat(devfd, &st) < 0) {
        goto out;
    }

    if (S_ISREG(st.st_mode)) {
        *size = (uint64_t)st.st_size;
        r = 0;
    }
    else if (ioctl(devfd, BLKGETSIZE64, size) >= 0) {
        r = 0;
    }

out:
    close(devfd);

    return r;
}

LUKSDevice* crypt_data_device(LUKSCryptDevice* cd)
{
    return cd->device;
}

LUKSVolumeKey* crypt_alloc_volume_key(size_t keyLength, const char *key)
{
    LUKSVolumeKey* vk = NULL;

    if (keyLength > (SIZE_MAX - sizeof(*vk))) {
        return NULL;
    }

    vk = crypt_zalloc(sizeof(*vk));
    if (!vk) {
        return NULL;
    }

    vk->keyringKeyType = LUKS_KEY_TYPE_INVALID_KEY;
    vk->keyId = -1;
    vk->keyLength = keyLength;
    vk->id = KEY_NOT_VERIFIED;

    /* keyLength 0 is valid => no key */
    if (vk->keyLength && key) {
        vk->key = crypt_safe_alloc(keyLength);
        if (!vk->key) {
            free(vk);
            return NULL;
        }
        crypt_safe_memcpy(vk->key, key, keyLength);
    }

    return vk;
}

static void *crypt_safe_alloc(size_t size)
{
    LUKSSafeAllocation* alloc;

    if (!size || size > (SIZE_MAX - OVERHEAD)) {
        return NULL;
    }

    alloc = malloc(size + OVERHEAD);
    if (!alloc) {
        return NULL;
    }

    _crypt_backend_memzero(alloc, size + OVERHEAD);
    alloc->size = size;

    /* Ignore failure if it is over limit. */
    if (!mlock(alloc, size + OVERHEAD)) {
        alloc->locked = true;
    }

    /* coverity[leaked_storage] */
    return &alloc->data;
}

void *crypt_safe_memcpy(void *dst, const void *src, size_t size)
{
    if (!dst || !src)
        return NULL;

    return crypt_backend_memcpy(dst, src, size);
}

void *crypt_backend_memcpy(void *dst, const void *src, size_t n)
{
    volatile uint8_t *d = (volatile uint8_t *)dst;
    const volatile uint8_t *s = (const volatile uint8_t *)src;

    while(n--) *d++ = *s++;

    return dst;
}

void device_set_block_size(LUKSDevice* device, size_t size)
{
    if (!device) {
        return;
    }

    device->loopBlockSize = size;
}

static int _crypt_format_loopaes(LUKSCryptDevice* cd, const char *cipher, const char *uuid, size_t volumeKeySize, LUKSCryptParamsParamsLoopAes* params)
{
    if (!crypt_metadata_device(cd)) {
        return -EINVAL;
    }

    if (volumeKeySize > 1024) {
        return -EINVAL;
    }

    if (uuid) {
        return -EINVAL;
    }

    if (cd->metaDataDevice) {
        return -EINVAL;
    }

    if (!(cd->type = strdup(C_CRYPT_LOOP_AES))) {
        return -ENOMEM;
    }

    cd->u.loopAes.keySize = volumeKeySize;

    cd->u.loopAes.cipher = strdup(cipher ?: DEFAULT_LOOP_AES_CIPHER);

    if (params && params->hash) {
        cd->u.loopAes.hdr.hash = strdup(params->hash);
    }

    cd->u.loopAes.hdr.offset = params ? params->offset : 0;
    cd->u.loopAes.hdr.skip = params ? params->skip : 0;

    return 0;
}

LUKSDevice* crypt_metadata_device(LUKSCryptDevice* cd)
{
    return cd->metaDataDevice ?: cd->device;
}

int dm_status_device(LUKSCryptDevice* cd, const char *name)
{
    int r;
    LUKSDevMapInfo dmi;
    struct stat st;

    if (strchr(name, '/') && stat(name, &st) < 0) {
        return -ENODEV;
    }

    if (dm_init_context(cd, LUKS_DEV_MAP_UNKNOWN)) {
        return -ENOTSUP;
    }

    r = dm_status_dmi(name, &dmi, NULL, NULL);

    dm_exit_context();

    if (r < 0) {
        return r;
    }

    return (dmi.openCount > 0) ? 1 : 0;
}

static void dm_exit_context(void)
{
    gsContext = NULL;
}

static int dm_init_context(LUKSCryptDevice* cd, LUKSDevMapTargetType target)
{
    gsContext = cd;
    if (!_dm_check_versions(cd, target)) {
        gsContext = NULL;
        return -ENOTSUP;
    }

    return 0;
}

static bool _dm_check_versions(LUKSCryptDevice* cd, LUKSDevMapTargetType targetType)
{
    bool r = true;
// 	struct dm_task *dmt;
// 	struct dm_versions *target, *last_target;
// 	char dm_version[16];
// 	unsigned dm_maj, dm_min, dm_patch;
// 	int r = 0;
//
// 	if ((target_type == DM_CRYPT     && _dm_crypt_checked) ||
// 	    (target_type == DM_VERITY    && _dm_verity_checked) ||
// 	    (target_type == DM_INTEGRITY && _dm_integrity_checked) ||
// 	    (target_type == DM_ZERO      && _dm_zero_checked) ||
// 	    (target_type == DM_LINEAR) ||
// 	    (_dm_crypt_checked && _dm_verity_checked && _dm_integrity_checked && _dm_zero_checked))
// 		return 1;
//
// 	/* Shut up DM while checking */
// 	_quiet_log = 1;
//
// 	_dm_check_target(target_type);
//
// 	if (!(dmt = dm_task_create(DM_DEVICE_LIST_VERSIONS)))
// 		goto out;
//
// 	if (!dm_task_run(dmt))
// 		goto out;
//
// 	if (!dm_task_get_driver_version(dmt, dm_version, sizeof(dm_version)))
// 		goto out;
//
// 	if (!_dm_ioctl_checked) {
// 		if (sscanf(dm_version, "%u.%u.%u", &dm_maj, &dm_min, &dm_patch) != 3)
// 			goto out;
// 		log_dbg(cd, "Detected dm-ioctl version %u.%u.%u.", dm_maj, dm_min, dm_patch);
//
// 		if (_dm_satisfies_version(4, 20, 0, dm_maj, dm_min, dm_patch))
// 			_dm_flags |= DM_SECURE_SUPPORTED;
// #if HAVE_DECL_DM_TASK_DEFERRED_REMOVE
// 		if (_dm_satisfies_version(4, 27, 0, dm_maj, dm_min, dm_patch))
// 			_dm_flags |= DM_DEFERRED_SUPPORTED;
// #endif
// #if HAVE_DECL_DM_DEVICE_GET_TARGET_VERSION
// 		if (_dm_satisfies_version(4, 41, 0, dm_maj, dm_min, dm_patch))
// 			_dm_flags |= DM_GET_TARGET_VERSION_SUPPORTED;
// #endif
// 	}
//
// 	target = dm_task_get_versions(dmt);
// 	do {
// 		last_target = target;
// 		if (!strcmp(DM_CRYPT_TARGET, target->name)) {
// 			_dm_set_crypt_compat(cd, (unsigned)target->version[0],
// 					     (unsigned)target->version[1],
// 					     (unsigned)target->version[2]);
// 		} else if (!strcmp(DM_VERITY_TARGET, target->name)) {
// 			_dm_set_verity_compat(cd, (unsigned)target->version[0],
// 					      (unsigned)target->version[1],
// 					      (unsigned)target->version[2]);
// 		} else if (!strcmp(DM_INTEGRITY_TARGET, target->name)) {
// 			_dm_set_integrity_compat(cd, (unsigned)target->version[0],
// 						 (unsigned)target->version[1],
// 						 (unsigned)target->version[2]);
// 		} else if (!strcmp(DM_ZERO_TARGET, target->name)) {
// 			_dm_set_zero_compat(cd, (unsigned)target->version[0],
// 					    (unsigned)target->version[1],
// 					    (unsigned)target->version[2]);
// 		}
// 		target = VOIDP_CAST(struct dm_versions *)((char *) target + target->next);
// 	} while (last_target != target);
//
// 	r = 1;
// 	if (!_dm_ioctl_checked)
// 		log_dbg(cd, "Device-mapper backend running with UDEV support %sabled.",
// 			_dm_use_udev() ? "en" : "dis");
//
// 	_dm_ioctl_checked = true;
// out:
// 	if (dmt)
// 		dm_task_destroy(dmt);
//
// 	_quiet_log = 0;
	return r;
}

static int dm_status_dmi(const char* name, LUKSDevMapInfo* dmi, const char *target, char **statusLine)
{
    struct dm_task *dmt;
    uint64_t start, length;
    char *target_type, *params = NULL;
    int r = -EINVAL;

    if (!(dmt = dm_task_create(DM_DEVICE_STATUS)))
        return r;

    if (!dm_task_no_flush(dmt))
        goto out;

    if (!dm_task_set_name(dmt, name))
        goto out;

    if (!dm_task_run(dmt))
        goto out;

    if (!dm_task_get_info(dmt, dmi))
        goto out;

    if (!dmi->exists) {
        r = -ENODEV;
        goto out;
    }

    r = -EEXIST;
    dm_get_next_target(dmt, NULL, &start, &length, &target_type, &params);

    if (!target_type || start != 0)
        goto out;

    if (target && strcmp(target_type, target))
        goto out;

    /* for target == NULL check all supported */
    if (!target && (strcmp(target_type, DM_CRYPT_TARGET) &&
            strcmp(target_type, DM_VERITY_TARGET) &&
            strcmp(target_type, DM_INTEGRITY_TARGET) &&
            strcmp(target_type, DM_LINEAR_TARGET) &&
            strcmp(target_type, DM_ZERO_TARGET) &&
            strcmp(target_type, DM_ERROR_TARGET)))
        goto out;
    r = 0;

out:
    if (!r && status_line && !(*status_line = strdup(params)))
        r = -ENOMEM;

    dm_task_destroy(dmt);

    return r;
}

#endif