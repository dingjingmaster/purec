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
#ifndef purec_PUREC_SM_2_H
#define purec_PUREC_SM_2_H
#include "common.h"
#include "sm3.h"


C_BEGIN_EXTERN_C

typedef uint64_t    Sm2BN[8];
typedef Sm2BN       Sm2Fp;
typedef Sm2BN       Sm2Fn;

typedef struct
{
    uint8_t             x[32];
    uint8_t             y[32];
} Sm2Point;

typedef struct
{
    Sm2BN               x;
    Sm2BN               y;
    Sm2BN               z;
} Sm2JacobianPoint;

typedef struct
{
    Sm2Point            publicKey;
    uint8_t             privateKey[32];
} Sm2Key;

typedef struct
{
    uint8_t             r[32];
    uint8_t             s[32];
} Sm2Signature;



void c_sm2_jacobian_point_init          (Sm2JacobianPoint* R);
void c_sm2_jacobian_point_set_xy        (Sm2JacobianPoint* R, const Sm2BN x, const Sm2BN y);
void c_sm2_jacobian_point_get_xy        (const Sm2JacobianPoint* P, Sm2BN x, Sm2BN y);
void c_sm2_jacobian_point_neg           (Sm2JacobianPoint* R, const Sm2JacobianPoint* P);
void c_sm2_jacobian_point_dbl           (Sm2JacobianPoint* R, const Sm2JacobianPoint* P);
void c_sm2_jacobian_point_add           (Sm2JacobianPoint* R, const Sm2JacobianPoint* P, const Sm2JacobianPoint* Q);
void c_sm2_jacobian_point_sub           (Sm2JacobianPoint* R, const Sm2JacobianPoint* P, const Sm2JacobianPoint* Q);
void c_sm2_jacobian_point_mul           (Sm2JacobianPoint* R, const Sm2BN k, const Sm2JacobianPoint* P);
void c_sm2_jacobian_point_to_bytes      (const Sm2JacobianPoint* P, uint8_t out[64]);
void c_sm2_jacobian_point_from_bytes    (Sm2JacobianPoint* P, const uint8_t in[64]);
void c_sm2_jacobian_point_mul_generator (Sm2JacobianPoint* R, const Sm2BN k);
void c_sm2_jacobian_point_mul_sum       (Sm2JacobianPoint* R, const Sm2BN t, const Sm2JacobianPoint* P, const Sm2BN s);

int c_sm2_jacobian_point_is_at_infinity (const Sm2JacobianPoint* P);
int c_sm2_jacobian_point_is_on_curve    (const Sm2JacobianPoint* P);
int c_sm2_jacobian_point_print          (FILE *fp, int fmt, int ind, const char *label, const Sm2JacobianPoint* P);

void c_sm2_jacobian_point_from_hex      (Sm2JacobianPoint* P, const char hex[64 * 2]);      // for testing only
int c_sm2_jacobian_point_equ_hex        (const Sm2JacobianPoint* P, const char hex[128]);   // for testing only


C_END_EXTERN_C

#endif // purec_PUREC_SM_2_H