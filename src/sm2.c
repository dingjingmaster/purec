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
#include "sm2.h"


#define RAND_MAX_BUF_SIZE   256 // requirement of getentropy()
#define sm2_bn_init(r)      memset((r),0,sizeof(Sm2BN))
#define sm2_bn_set_zero(r)  memset((r),0,sizeof(Sm2BN))
#define sm2_bn_set_one(r)   sm2_bn_set_word((r),1)
#define sm2_bn_copy(r,a)    memcpy((r),(a),sizeof(Sm2BN))
#define sm2_bn_clean(r)     memset((r),0,sizeof(Sm2BN))


const Sm2BN SM2_P = {
    0xffffffff, 0xffffffff, 0x00000000, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
};

const Sm2BN SM2_B = {
    0x4d940e93, 0xddbcbd41, 0x15ab8f92, 0xf39789f5,
    0xcf6509a7, 0x4d5a9e4b, 0x9d9f5e34, 0x28e9fa9e,
};

const Sm2JacobianPoint _SM2_G = {
    {
    0x334c74c7, 0x715a4589, 0xf2660be1, 0x8fe30bbf,
    0x6a39c994, 0x5f990446, 0x1f198119, 0x32c4ae2c,
    },
    {
    0x2139f0a0, 0x02df32e5, 0xc62a4740, 0xd0a9877c,
    0x6b692153, 0x59bdcee3, 0xf4f6779c, 0xbc3736a2,
    },
    {
    1, 0, 0, 0, 0, 0, 0, 0,
    },
};
const Sm2JacobianPoint *SM2_G = &_SM2_G;

const Sm2BN SM2_N = {
    0x39d54123, 0x53bbf409, 0x21c6052b, 0x7203df6b,
    0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
};

// u = (p - 1)/4, u + 1 = (p + 1)/4
const Sm2BN SM2_U_PLUS_ONE = {
    0x00000000, 0x40000000, 0xc0000000, 0xffffffff,
    0xffffffff, 0xffffffff, 0xbfffffff, 0x3fffffff,
};

const Sm2BN SM2_ONE     = {1,0,0,0,0,0,0,0};
const Sm2BN SM2_TWO     = {2,0,0,0,0,0,0,0};
const Sm2BN SM2_THREE   = {3,0,0,0,0,0,0,0};


static int rand_bytes(uint8_t *buf, size_t len)
{
    if (!buf) {
        // error_print();
        return -1;
    }
    if (!len || len > RAND_MAX_BUF_SIZE) {
        // error_print();
        return -1;
    }
    if (getentropy(buf, len) != 0) {
        // error_print();
        return -1;
    }
    return 1;
}


static int sm2_bn_check(const Sm2BN a)
{
    int err = 0;
    int i;
    for (i = 0; i < 8; i++) {
        if (a[i] > 0xffffffff) {
            // fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
            err++;
        }
    }
    if (err) {
        return -1;
    }
    else {
        return 1;
    }
}

static int sm2_bn_is_zero(const Sm2BN a)
{
    int i;
    for (i = 0; i < 8; i++) {
        if (a[i] != 0) {
            return 0;
        }
    }

    return 1;
}

static int sm2_bn_is_one(const Sm2BN a)
{
    int i;
    if (a[0] != 1) {
        return 0;
    }
    for (i = 1; i < 8; i++) {
        if (a[i] != 0) {
            return 0;
        }
    }

    return 1;
}

static void sm2_bn_to_bytes(const Sm2BN a, uint8_t out[32])
{
    int i;
    uint8_t *p = out;

#define PUTU32(p,V)     ((p)[0] = (uint8_t)((V) >> 24), (p)[1] = (uint8_t)((V) >> 16), (p)[2] = (uint8_t)((V) >>  8), (p)[3] = (uint8_t)(V))

    for (i = 7; i >= 0; i--) {
        uint32_t ai = (uint32_t)a[i];
        PUTU32(out, ai);
        out += sizeof(uint32_t);
    }
}

static void sm2_bn_from_bytes(Sm2BN r, const uint8_t in[32])
{
#define GETU32(p) ((uint32_t)(p)[0] << 24 | (uint32_t)(p)[1] << 16 | (uint32_t)(p)[2] <<  8 | (uint32_t)(p)[3])
    int i;
    for (i = 7; i >= 0; i--) {
        r[i] = GETU32(in);
        in += sizeof(uint32_t);
    }
}

static int hexchar2int(char c)
{
    if      ('0' <= c && c <= '9') return c - '0';
    else if ('a' <= c && c <= 'f') return c - 'a' + 10;
    else if ('A' <= c && c <= 'F') return c - 'A' + 10;
    else return -1;
}

static int hex2bin(const char *in, size_t inlen, uint8_t *out)
{
    int c;
    if (inlen % 2)
        return -1;

    while (inlen) {
        if ((c = hexchar2int(*in++)) < 0)
            return -1;
        *out = (uint8_t)c << 4;
        if ((c = hexchar2int(*in++)) < 0)
            return -1;
        *out |= (uint8_t)c;
        inlen -= 2;
        out++;
    }
    return 1;
}

static void sm2_bn_to_hex(const Sm2BN a, char hex[64])
{
    int i;
    for (i = 7; i >= 0; i--) {
        int len;
        len = sprintf(hex, "%08x", (uint32_t)a[i]);
        // assert(len == 8);
        if (len != 8) { return; }
        hex += 8;
    }
}

static int sm2_bn_from_hex(Sm2BN r, const char hex[64])
{
    uint8_t buf[32];
    if (hex2bin(hex, 64, buf) < 0) {
        return -1;
    }
    sm2_bn_from_bytes(r, buf);
    return 1;
}

static int sm2_bn_from_asn1_integer(Sm2BN r, const uint8_t *d, size_t dlen)
{
    uint8_t buf[32] = {0};
    if (!d || dlen == 0) {
        // error_print();
        return -1;
    }
    if (dlen > sizeof(buf)) {
        // error_print();
        return -1;
    }
    memcpy(buf + sizeof(buf) - dlen, d, dlen);
    sm2_bn_from_bytes(r, buf);
    return 1;
}

static int sm2_bn_print(FILE *fp, int fmt, int ind, const char *label, const Sm2BN a)
{
    int ret = 0, i;
    // format_print(fp, fmt, ind, "%s: ", label);

    for (i = 7; i >= 0; i--) {
        if (a[i] >= ((uint64_t)1 << 32)) {
            printf("bn_print check failed\n");
        }
        ret += fprintf(fp, "%08x", (uint32_t)a[i]);
    }
    ret += fprintf(fp, "\n");
    return ret;
}

static void sm2_bn_to_bits(const Sm2BN a, char bits[256])
{
    int i, j;
    uint64_t w;
    for (i = 7; i >= 0; i--) {
        w = a[i];
        for (j = 0; j < 32; j++) {
            *bits++ = (w & 0x80000000) ? '1' : '0';
            w <<= 1;
        }
    }
}

static int sm2_bn_cmp(const Sm2BN a, const Sm2BN b)
{
    int i;
    for (i = 7; i >= 0; i--) {
        if (a[i] > b[i]) {
            return 1;
        }
        if (a[i] < b[i]) {
            return -1;
        }
    }
    return 0;
}

static int sm2_bn_equ_hex(const Sm2BN a, const char *hex)
{
    char buf[65] = {0};
    char *p = buf;
    int i;

    for (i = 7; i >= 0; i--) {
        sprintf(p, "%08x", (uint32_t)a[i]);
        p += 8;
    }
    return (strcmp(buf, hex) == 0);
}

static int sm2_bn_is_odd(const Sm2BN a)
{
    return a[0] & 0x01;
}

static void sm2_bn_set_word(Sm2BN r, uint32_t a)
{
    int i;
    r[0] = a;
    for (i = 1; i < 8; i++) {
        r[i] = 0;
    }
}

static int sm2_bn_rshift(Sm2BN ret, const Sm2BN a, unsigned int nbits)
{
    Sm2BN r;
    int i;

    if (nbits > 31) {
        // error_print();
        return -1;
    }
    if (nbits == 0) {
        sm2_bn_copy(ret, a);
    }

    for (i = 0; i < 7; i++) {
        r[i] = a[i] >> nbits;
        r[i] |= (a[i+1] << (32 - nbits)) & 0xffffffff;
    }
    r[i] = a[i] >> nbits;
    sm2_bn_copy(ret, r);
    return 1;
}

static void sm2_bn_add(Sm2BN r, const Sm2BN a, const Sm2BN b)
{
    int i;
    r[0] = a[0] + b[0];

    for (i = 1; i < 8; i++) {
        r[i] = a[i] + b[i] + (r[i-1] >> 32);
    }
    for (i = 0; i < 7; i++) {
        r[i] &= 0xffffffff;
    }
}

static void sm2_bn_sub(Sm2BN ret, const Sm2BN a, const Sm2BN b)
{
    int i;
    Sm2BN r;
    r[0] = ((uint64_t)1 << 32) + a[0] - b[0];
    for (i = 1; i < 7; i++) {
        r[i] = 0xffffffff + a[i] - b[i] + (r[i - 1] >> 32);
        r[i - 1] &= 0xffffffff;
    }
    r[i] = a[i] - b[i] + (r[i - 1] >> 32) - 1;
    r[i - 1] &= 0xffffffff;
    sm2_bn_copy(ret, r);
}

static int sm2_bn_rand_range(Sm2BN r, const Sm2BN range)
{
    uint8_t buf[32];
    do {
        if (rand_bytes(buf, sizeof(buf)) != 1) {
            // error_print();
            return -1;
        }
        sm2_bn_from_bytes(r, buf);
    } while (sm2_bn_cmp(r, range) >= 0);
    return 1;
}

static int sm2_fp_rand(Sm2Fp r)
{
    if (sm2_bn_rand_range(r, SM2_P) != 1) {
        // error_print();
        return -1;
    }
    return 1;
}

static void sm2_fp_add(Sm2Fp r, const Sm2Fp a, const Sm2Fp b)
{
    sm2_bn_add(r, a, b);
    if (sm2_bn_cmp(r, SM2_P) >= 0) {
        sm2_bn_sub(r, r, SM2_P);
    }
}

static void sm2_fp_sub(Sm2Fp r, const Sm2Fp a, const Sm2Fp b)
{
    if (sm2_bn_cmp(a, b) >= 0) {
        sm2_bn_sub(r, a, b);
    }
    else {
        Sm2BN t;
        sm2_bn_sub(t, SM2_P, b);
        sm2_bn_add(r, t, a);
    }
}

static void sm2_fp_dbl(Sm2Fp r, const Sm2Fp a)
{
    sm2_fp_add(r, a, a);
}

static void sm2_fp_tri(Sm2Fp r, const Sm2Fp a)
{
    Sm2BN t;
    sm2_fp_dbl(t, a);
    sm2_fp_add(r, t, a);
}

static void sm2_fp_div2(Sm2Fp r, const Sm2Fp a)
{
    int i;
    sm2_bn_copy(r, a);
    if (r[0] & 0x01) {
        sm2_bn_add(r, r, SM2_P);
    }
    for (i = 0; i < 7; i++) {
        r[i] = (r[i] >> 1) | ((r[i + 1] & 0x01) << 31);
    }
    r[i] >>= 1;
}

static void sm2_fp_neg(Sm2Fp r, const Sm2Fp a)
{
    if (sm2_bn_is_zero(a)) {
        sm2_bn_copy(r, a);
    }
    else {
        sm2_bn_sub(r, SM2_P, a);
    }
}

static void sm2_fp_mul(Sm2Fp r, const Sm2Fp a, const Sm2Fp b)
{
    int i, j;
    uint64_t s[16] = {0};
    Sm2BN d = {0};
    uint64_t u;

    // s = a * b
    for (i = 0; i < 8; i++) {
        u = 0;
        for (j = 0; j < 8; j++) {
            u = s[i + j] + a[i] * b[j] + u;
            s[i + j] = u & 0xffffffff;
            u >>= 32;
        }
        s[i + 8] = u;
    }

    r[0] = s[0] + s[ 8] + s[ 9] + s[10] + s[11] + s[12] + ((s[13] + s[14] + s[15]) << 1);
    r[1] = s[1] + s[ 9] + s[10] + s[11] + s[12] + s[13] + ((s[14] + s[15]) << 1);
    r[2] = s[2];
    r[3] = s[3] + s[ 8] + s[11] + s[12] + s[14] + s[15] + (s[13] << 1);
    r[4] = s[4] + s[ 9] + s[12] + s[13] + s[15] + (s[14] << 1);
    r[5] = s[5] + s[10] + s[13] + s[14] + (s[15] << 1);
    r[6] = s[6] + s[11] + s[14] + s[15];
    r[7] = s[7] + s[ 8] + s[ 9] + s[10] + s[11] + s[15] + ((s[12] + s[13] + s[14] + s[15]) << 1);

    for (i = 1; i < 8; i++) {
        r[i] += r[i - 1] >> 32;
        r[i - 1] &= 0xffffffff;
    }

    d[2] = s[8] + s[9] + s[13] + s[14];
    d[3] = d[2] >> 32;
    d[2] &= 0xffffffff;
    sm2_bn_sub(r, r, d);

    // max times ?
    while (sm2_bn_cmp(r, SM2_P) >= 0) {
        sm2_bn_sub(r, r, SM2_P);
    }
}

static void sm2_fp_sqr(Sm2Fp r, const Sm2Fp a)
{
    sm2_fp_mul(r, a, a);
}

static void sm2_fp_exp(Sm2Fp r, const Sm2Fp a, const Sm2Fp e)
{
    Sm2BN t;
    uint32_t w;
    int i, j;

    sm2_bn_set_one(t);
    for (i = 7; i >= 0; i--) {
        w = (uint32_t)e[i];
        for (j = 0; j < 32; j++) {
            sm2_fp_sqr(t, t);
            if (w & 0x80000000) {
                sm2_fp_mul(t, t, a);
            }
            w <<= 1;
        }
    }

    sm2_bn_copy(r, t);
}

static void sm2_fp_inv(Sm2Fp r, const Sm2Fp a)
{
    Sm2BN a1;
    Sm2BN a2;
    Sm2BN a3;
    Sm2BN a4;
    Sm2BN a5;
    int i;

    sm2_fp_sqr(a1, a);
    sm2_fp_mul(a2, a1, a);
    sm2_fp_sqr(a3, a2);
    sm2_fp_sqr(a3, a3);
    sm2_fp_mul(a3, a3, a2);
    sm2_fp_sqr(a4, a3);
    sm2_fp_sqr(a4, a4);
    sm2_fp_sqr(a4, a4);
    sm2_fp_sqr(a4, a4);
    sm2_fp_mul(a4, a4, a3);
    sm2_fp_sqr(a5, a4);
    for (i = 1; i < 8; i++)
        sm2_fp_sqr(a5, a5);
    sm2_fp_mul(a5, a5, a4);
    for (i = 0; i < 8; i++)
        sm2_fp_sqr(a5, a5);
    sm2_fp_mul(a5, a5, a4);
    for (i = 0; i < 4; i++)
        sm2_fp_sqr(a5, a5);
    sm2_fp_mul(a5, a5, a3);
    sm2_fp_sqr(a5, a5);
    sm2_fp_sqr(a5, a5);
    sm2_fp_mul(a5, a5, a2);
    sm2_fp_sqr(a5, a5);
    sm2_fp_mul(a5, a5, a);
    sm2_fp_sqr(a4, a5);
    sm2_fp_mul(a3, a4, a1);
    sm2_fp_sqr(a5, a4);
    for (i = 1; i< 31; i++)
        sm2_fp_sqr(a5, a5);
    sm2_fp_mul(a4, a5, a4);
    sm2_fp_sqr(a4, a4);
    sm2_fp_mul(a4, a4, a);
    sm2_fp_mul(a3, a4, a2);
    for (i = 0; i < 33; i++)
        sm2_fp_sqr(a5, a5);
    sm2_fp_mul(a2, a5, a3);
    sm2_fp_mul(a3, a2, a3);
    for (i = 0; i < 32; i++)
        sm2_fp_sqr(a5, a5);
    sm2_fp_mul(a2, a5, a3);
    sm2_fp_mul(a3, a2, a3);
    sm2_fp_mul(a4, a2, a4);
    for (i = 0; i < 32; i++)
        sm2_fp_sqr(a5, a5);
    sm2_fp_mul(a2, a5, a3);
    sm2_fp_mul(a3, a2, a3);
    sm2_fp_mul(a4, a2, a4);
    for (i = 0; i < 32; i++)
        sm2_fp_sqr(a5, a5);
    sm2_fp_mul(a2, a5, a3);
    sm2_fp_mul(a3, a2, a3);
    sm2_fp_mul(a4, a2, a4);
    for (i = 0; i < 32; i++)
        sm2_fp_sqr(a5, a5);
    sm2_fp_mul(a2, a5, a3);
    sm2_fp_mul(a3, a2, a3);
    sm2_fp_mul(a4, a2, a4);
    for (i = 0; i < 32; i++)
        sm2_fp_sqr(a5, a5);
    sm2_fp_mul(r, a4, a5);

    sm2_bn_clean(a1);
    sm2_bn_clean(a2);
    sm2_bn_clean(a3);
    sm2_bn_clean(a4);
    sm2_bn_clean(a5);
}

static int sm2_fp_sqrt(Sm2Fp r, const Sm2Fp a)
{
    Sm2BN u;
    Sm2BN y; // temp result, prevent call sm2_fp_sqrt(a, a)

    // r = a^((p + 1)/4) when p = 3 (mod 4)
    sm2_bn_add(u, SM2_P, SM2_ONE);
    sm2_bn_rshift(u, u, 2);
    sm2_fp_exp(y, a, u);

    // check r^2 == a
    sm2_fp_sqr(u, y);
    if (sm2_bn_cmp(u, a) != 0) {
        // error_print();
        return -1;
    }

    sm2_bn_copy(r, y);
    return 1;
}

static void sm2_fn_add(Sm2Fn r, const Sm2Fn a, const Sm2Fn b)
{
    sm2_bn_add(r, a, b);
    if (sm2_bn_cmp(r, SM2_N) >= 0) {
        sm2_bn_sub(r, r, SM2_N);
    }
}

static void sm2_fn_sub(Sm2Fn r, const Sm2Fn a, const Sm2Fn b)
{
    if (sm2_bn_cmp(a, b) >= 0) {
        sm2_bn_sub(r, a, b);
    }
    else {
        Sm2BN t;
        sm2_bn_add(t, a, SM2_N);
        sm2_bn_sub(r, t, b);
    }
}

static void sm2_fn_neg(Sm2Fn r, const Sm2Fn a)
{
    if (sm2_bn_is_zero(a)) {
        sm2_bn_copy(r, a);
    }
    else {
        sm2_bn_sub(r, SM2_N, a);
    }
}

/* bn288 only used in barrett reduction */
static int sm2_bn288_cmp(const uint64_t a[9], const uint64_t b[9])
{
    int i;
    for (i = 8; i >= 0; i--) {
        if (a[i] > b[i]) {
            return 1;
        }
        if (a[i] < b[i]) {
            return -1;
        }
    }
    return 0;
}

static void sm2_bn288_add(uint64_t r[9], const uint64_t a[9], const uint64_t b[9])
{
    int i;
    r[0] = a[0] + b[0];
    for (i = 1; i < 9; i++) {
        r[i] = a[i] + b[i] + (r[i-1] >> 32);
    }
    for (i = 0; i < 8; i++) {
        r[i] &= 0xffffffff;
    }
}

static void sm2_bn288_sub(uint64_t ret[9], const uint64_t a[9], const uint64_t b[9])
{
    int i;
    uint64_t r[9];

    r[0] = ((uint64_t)1 << 32) + a[0] - b[0];
    for (i = 1; i < 8; i++) {
        r[i] = 0xffffffff + a[i] - b[i] + (r[i - 1] >> 32);
        r[i - 1] &= 0xffffffff;
    }
    r[i] = a[i] - b[i] + (r[i - 1] >> 32) - 1;
    r[i - 1] &= 0xffffffff;

    for (i = 0; i < 9; i++) {
        ret[i] = r[i];
    }
}

static void sm2_fn_mul(Sm2BN ret, const Sm2BN a, const Sm2BN b)
{
    Sm2BN r;
    static const uint64_t mu[9] = {
        0xf15149a0, 0x12ac6361, 0xfa323c01, 0x8dfc2096, 1, 1, 1, 1, 1,
    };

    uint64_t s[18];
    uint64_t zh[9];
    uint64_t zl[9];
    uint64_t q[9];
    uint64_t w;
    int i, j;

    /* z = a * b */
    for (i = 0; i < 8; i++) {
        s[i] = 0;
    }
    for (i = 0; i < 8; i++) {
        w = 0;
        for (j = 0; j < 8; j++) {
            w += s[i + j] + a[i] * b[j];
            s[i + j] = w & 0xffffffff;
            w >>= 32;
        }
        s[i + 8] = w;
    }

    /* zl = z mod (2^32)^9 = z[0..8]
     * zh = z // (2^32)^7 = z[7..15] */
    for (i = 0; i < 9; i++) {
        zl[i] = s[i];
        zh[i] = s[7 + i];
    }
    //printf("zl = "); for (i = 8; i >= 0; i--) printf("%08x", (uint32_t)zl[i]); printf("\n");
    //printf("zh = "); for (i = 8; i >= 0; i--) printf("%08x", (uint32_t)zh[i]); printf("\n");

    /* q = zh * mu // (2^32)^9 */
    for (i = 0; i < 9; i++) {
        s[i] = 0;
    }
    for (i = 0; i < 9; i++) {
        w = 0;
        for (j = 0; j < 9; j++) {
            w += s[i + j] + zh[i] * mu[j];
            s[i + j] = w & 0xffffffff;
            w >>= 32;
        }
        s[i + 9] = w;
    }
    for (i = 0; i < 8; i++) {
        q[i] = s[9 + i];
    }
    //printf("q  = "); for (i = 7; i >= 0; i--) printf("%08x", (uint32_t)q[i]); printf("\n");

    /* q = q * n mod (2^32)^9 */
    for (i = 0; i < 17; i++) {
        s[i] = 0;
    }
    for (i = 0; i < 8; i++) {
        w = 0;
        for (j = 0; j < 8; j++) {
            w += s[i + j] + q[i] * SM2_N[j];
            s[i + j] = w & 0xffffffff;
            w >>= 32;
        }
        s[i + 8] = w;
    }
    for (i = 0; i < 9; i++) {
        q[i] = s[i];
    }
    //printf("qn = "); for (i = 8; i >= 0; i--) printf("%08x ", (uint32_t)q[i]); printf("\n");

    /* r = zl - q (mod (2^32)^9) */

    if (sm2_bn288_cmp(zl, q)) {
        sm2_bn288_sub(zl, zl, q);
    } else {
        uint64_t c[9] = {0,0,0,0,0,0,0,0,0x100000000};
        sm2_bn288_sub(q, c, q);
        sm2_bn288_add(zl, q, zl);
    }
    //printf("zl  = "); for (i = 8; i >= 0; i--) printf("%08x ", (uint32_t)zl[i]); printf("\n");
    for (i = 0; i < 8; i++) {
        r[i] = zl[i];
    }
    r[7] += zl[8] << 32;

    /* while r >= p do: r = r - n */
    while (sm2_bn_cmp(r, SM2_N) >= 0) {
        sm2_bn_sub(r, r, SM2_N);
        //printf("r-n = "); for (i = 7; i >= 0; i--) printf("%16llx ", r[i]); printf("\n");
    }
    sm2_bn_copy(ret, r);
}

static void sm2_fn_mul_word(Sm2Fn r, const Sm2Fn a, uint32_t b)
{
    Sm2Fn t;
    sm2_bn_set_word(t, b);
    sm2_fn_mul(r, a, t);
}

static void sm2_fn_sqr(Sm2BN r, const Sm2BN a)
{
    sm2_fn_mul(r, a, a);
}

static void sm2_fn_exp(Sm2BN r, const Sm2BN a, const Sm2BN e)
{
    Sm2BN t;
    uint32_t w;
    int i, j;

    sm2_bn_set_one(t);
    for (i = 7; i >= 0; i--) {
        w = (uint32_t)e[i];
        for (j = 0; j < 32; j++) {
            sm2_fn_sqr(t, t);
            if (w & 0x80000000) {
                sm2_fn_mul(t, t, a);
            }
            w <<= 1;
        }
    }
    sm2_bn_copy(r, t);
}

static void sm2_fn_inv(Sm2BN r, const Sm2BN a)
{
    Sm2BN e;
    sm2_bn_sub(e, SM2_N, SM2_TWO);
    sm2_fn_exp(r, a, e);
}

static int sm2_fn_rand(Sm2BN r)
{
    if (sm2_bn_rand_range(r, SM2_N) != 1) {
        // error_print();
        return -1;
    }
    return 1;
}




void c_sm2_jacobian_point_init(Sm2JacobianPoint* R)
{
    memset(R, 0, sizeof(Sm2JacobianPoint));
    R->x[0] = 1;
    R->y[0] = 1;
}

void c_sm2_jacobian_point_set_xy(Sm2JacobianPoint* R, const Sm2BN x, const Sm2BN y)
{
    sm2_bn_copy(R->x, x);
    sm2_bn_copy(R->y, y);
    sm2_bn_set_one(R->z);
}

void c_sm2_jacobian_point_get_xy(const Sm2JacobianPoint* P, Sm2BN x, Sm2BN y)
{
    if (sm2_bn_is_one(P->z)) {
        sm2_bn_copy(x, P->x);
        if (y) {
            sm2_bn_copy(y, P->y);
        }
    }
    else {
        Sm2BN zInv;
        sm2_fp_inv(zInv, P->z);
        if (y) {
            sm2_fp_mul(y, P->y, zInv);
        }
        sm2_fp_sqr(zInv, zInv);
        sm2_fp_mul(x, P->x, zInv);
        if (y) {
            sm2_fp_mul(y, y, zInv);
        }
    }
}

void c_sm2_jacobian_point_neg(Sm2JacobianPoint* R, const Sm2JacobianPoint* P)
{
    sm2_bn_copy(R->x, P->x);
    sm2_fp_neg(R->y, P->y);
    sm2_bn_copy(R->z, P->z);
}

void c_sm2_jacobian_point_dbl(Sm2JacobianPoint* R, const Sm2JacobianPoint* P)
{
    const uint64_t*     X1 = P->x;
    const uint64_t*     Y1 = P->y;
    const uint64_t*     Z1 = P->z;
    Sm2BN               T1;
    Sm2BN               T2;
    Sm2BN               T3;
    Sm2BN               X3;
    Sm2BN               Y3;
    Sm2BN               Z3;

    if (c_sm2_jacobian_point_is_at_infinity(P)) {
        c_sm2_jacobian_point_copy(R, P);
        return;
    }

    sm2_fp_sqr(T1, Z1);        //printf("T1 = Z1^2    = "); print_bn(T1);
    sm2_fp_sub(T2, X1, T1);    //printf("T2 = X1 - T1 = "); print_bn(T2);
    sm2_fp_add(T1, X1, T1);    //printf("T1 = X1 + T1 = "); print_bn(T1);
    sm2_fp_mul(T2, T2, T1);    //printf("T2 = T2 * T1 = "); print_bn(T2);
    sm2_fp_tri(T2, T2);        //printf("T2 =  3 * T2 = "); print_bn(T2);
    sm2_fp_dbl(Y3, Y1);        //printf("Y3 =  2 * Y1 = "); print_bn(Y3);
    sm2_fp_mul(Z3, Y3, Z1);    //printf("Z3 = Y3 * Z1 = "); print_bn(Z3);
    sm2_fp_sqr(Y3, Y3);        //printf("Y3 = Y3^2    = "); print_bn(Y3);
    sm2_fp_mul(T3, Y3, X1);    //printf("T3 = Y3 * X1 = "); print_bn(T3);
    sm2_fp_sqr(Y3, Y3);        //printf("Y3 = Y3^2    = "); print_bn(Y3);
    sm2_fp_div2(Y3, Y3);    //printf("Y3 = Y3/2    = "); print_bn(Y3);
    sm2_fp_sqr(X3, T2);        //printf("X3 = T2^2    = "); print_bn(X3);
    sm2_fp_dbl(T1, T3);        //printf("T1 =  2 * T1 = "); print_bn(T1);
    sm2_fp_sub(X3, X3, T1);    //printf("X3 = X3 - T1 = "); print_bn(X3);
    sm2_fp_sub(T1, T3, X3);    //printf("T1 = T3 - X3 = "); print_bn(T1);
    sm2_fp_mul(T1, T1, T2);    //printf("T1 = T1 * T2 = "); print_bn(T1);
    sm2_fp_sub(Y3, T1, Y3);    //printf("Y3 = T1 - Y3 = "); print_bn(Y3);

    sm2_bn_copy(R->x, X3);
    sm2_bn_copy(R->y, Y3);
    sm2_bn_copy(R->z, Z3);
}

void c_sm2_jacobian_point_add(Sm2JacobianPoint* R, const Sm2JacobianPoint* P, const Sm2JacobianPoint* Q)
{
    const uint64_t *X1 = P->x;
    const uint64_t *Y1 = P->y;
    const uint64_t *Z1 = P->z;
    const uint64_t *x2 = Q->x;
    const uint64_t *y2 = Q->y;
    Sm2BN T1;
    Sm2BN T2;
    Sm2BN T3;
    Sm2BN T4;
    Sm2BN X3;
    Sm2BN Y3;
    Sm2BN Z3;

    if (c_sm2_jacobian_point_is_at_infinity(Q)) {
        c_sm2_jacobian_point_copy(R, P);
        return;
    }

    if (c_sm2_jacobian_point_is_at_infinity(P)) {
        c_sm2_jacobian_point_copy(R, Q);
        return;
    }

    if (!sm2_bn_is_one(Q->z)) { return; }

    sm2_fp_sqr(T1, Z1);
    sm2_fp_mul(T2, T1, Z1);
    sm2_fp_mul(T1, T1, x2);
    sm2_fp_mul(T2, T2, y2);
    sm2_fp_sub(T1, T1, X1);
    sm2_fp_sub(T2, T2, Y1);
    if (sm2_bn_is_zero(T1)) {
        if (sm2_bn_is_zero(T2)) {
            Sm2JacobianPoint _Q, *Q = &_Q;
            c_sm2_jacobian_point_set_xy(Q, x2, y2);
            c_sm2_jacobian_point_dbl(R, Q);
            return;
        }
        else {
            c_sm2_jacobian_point_set_infinity(R);
            return;
        }
    }
    sm2_fp_mul(Z3, Z1, T1);
    sm2_fp_sqr(T3, T1);
    sm2_fp_mul(T4, T3, T1);
    sm2_fp_mul(T3, T3, X1);
    sm2_fp_dbl(T1, T3);
    sm2_fp_sqr(X3, T2);
    sm2_fp_sub(X3, X3, T1);
    sm2_fp_sub(X3, X3, T4);
    sm2_fp_sub(T3, T3, X3);
    sm2_fp_mul(T3, T3, T2);
    sm2_fp_mul(T4, T4, Y1);
    sm2_fp_sub(Y3, T3, T4);

    sm2_bn_copy(R->x, X3);
    sm2_bn_copy(R->y, Y3);
    sm2_bn_copy(R->z, Z3);
}

void c_sm2_jacobian_point_sub(Sm2JacobianPoint* R, const Sm2JacobianPoint* P, const Sm2JacobianPoint* Q)
{
    Sm2JacobianPoint _T, *T = &_T;
    c_sm2_jacobian_point_neg(T, Q);
    c_sm2_jacobian_point_add(R, P, T);
}

void c_sm2_jacobian_point_mul(Sm2JacobianPoint* R, const Sm2BN k, const Sm2JacobianPoint* P)
{
    char bits[257] = {0};
    Sm2JacobianPoint _Q, *Q = &_Q;
    Sm2JacobianPoint _T, *T = &_T;
    int i;

    // FIXME: point_add need affine, so we can not use point_add
    if (!sm2_bn_is_one(P->z)) {
        Sm2BN x;
        Sm2BN y;
        c_sm2_jacobian_point_get_xy(P, x, y);
        c_sm2_jacobian_point_set_xy(T, x, y);
        P = T;
    }

    c_sm2_jacobian_point_set_infinity(Q);
    sm2_bn_to_bits(k, bits);
    for (i = 0; i < 256; i++) {
        c_sm2_jacobian_point_dbl(Q, Q);
        if (bits[i] == '1') {
            c_sm2_jacobian_point_add(Q, Q, P);
        }
    }
    c_sm2_jacobian_point_copy(R, Q);
}

void c_sm2_jacobian_point_to_bytes(const Sm2JacobianPoint* P, uint8_t out[64])
{
    Sm2BN x;
    Sm2BN y;
    c_sm2_jacobian_point_get_xy(P, x, y);
    sm2_bn_to_bytes(x, out);
    sm2_bn_to_bytes(y, out + 32);
}

void c_sm2_jacobian_point_from_bytes(Sm2JacobianPoint* P, const uint8_t in[64])
{
    sm2_bn_from_bytes(P->x, in);
    sm2_bn_from_bytes(P->y, in + 32);
    sm2_bn_set_word(P->z, 1);
}

void c_sm2_jacobian_point_mul_generator(Sm2JacobianPoint* R, const Sm2BN k)
{
    c_sm2_jacobian_point_mul(R, k, SM2_G);
}

void c_sm2_jacobian_point_mul_sum(Sm2JacobianPoint* R, const Sm2BN t, const Sm2JacobianPoint* P, const Sm2BN s)
{
    Sm2JacobianPoint _sG, *sG = &_sG;
    Sm2BN x;
    Sm2BN y;

    /* T = s * G */
    c_sm2_jacobian_point_mul_generator(sG, s);

    // R = t * P
    c_sm2_jacobian_point_mul(R, t, P);
    c_sm2_jacobian_point_get_xy(R, x, y);
    c_sm2_jacobian_point_set_xy(R, x, y);

    // R = R + T
    c_sm2_jacobian_point_add(R, sG, R);
}

int c_sm2_jacobian_point_is_at_infinity(const Sm2JacobianPoint* P)
{
    return mem_is_zero((uint8_t *)P, sizeof(Sm2Point));
}

int c_sm2_jacobian_point_is_on_curve(const Sm2JacobianPoint* P)
{
    Sm2BN t0;
    Sm2BN t1;
    Sm2BN t2;

    if (sm2_bn_is_one(P->z)) {
        sm2_fp_sqr(t0, P->y);
        sm2_fp_add(t0, t0, P->x);
        sm2_fp_add(t0, t0, P->x);
        sm2_fp_add(t0, t0, P->x);
        sm2_fp_sqr(t1, P->x);
        sm2_fp_mul(t1, t1, P->x);
        sm2_fp_add(t1, t1, SM2_B);
    } else {
        sm2_fp_sqr(t0, P->y);
        sm2_fp_sqr(t1, P->z);
        sm2_fp_sqr(t2, t1);
        sm2_fp_mul(t1, t1, t2);
        sm2_fp_mul(t1, t1, SM2_B);
        sm2_fp_mul(t2, t2, P->x);
        sm2_fp_add(t0, t0, t2);
        sm2_fp_add(t0, t0, t2);
        sm2_fp_add(t0, t0, t2);
        sm2_fp_sqr(t2, P->x);
        sm2_fp_mul(t2, t2, P->x);
        sm2_fp_add(t1, t1, t2);
    }

    if (sm2_bn_cmp(t0, t1) != 0) {
        // error_print();
        return -1;
    }
    return 1;
}

// int c_sm2_jacobian_point_print(FILE* fp, int fmt, int ind, const char* label, const Sm2JacobianPoint* P)
// {
// }

void c_sm2_jacobian_point_from_hex(Sm2JacobianPoint* P, const char hex[128])
{
    sm2_bn_from_hex(P->x, hex);
    sm2_bn_from_hex(P->y, hex + 64);
    sm2_bn_set_one(P->z);
}

int c_sm2_jacobian_point_equ_hex(const Sm2JacobianPoint* P, const char hex[128])
{
    Sm2BN x;
    Sm2BN y;
    Sm2JacobianPoint _T, *T = &_T;

    c_sm2_jacobian_point_get_xy(P, x, y);
    c_sm2_jacobian_point_from_hex(T, hex);

    return (sm2_bn_cmp(x, T->x) == 0) && (sm2_bn_cmp(y, T->y) == 0);
}
