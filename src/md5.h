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
#ifndef purec_PUREC_MD_5_H
#define purec_PUREC_MD_5_H
#include "common.h"


C_BEGIN_EXTERN_C

typedef struct _PACKED
{
    uint32_t total[2];
    uint32_t state[4];
    uint8_t buffer[64];
} Md5Context;

void c_md5_starts (Md5Context* ctx);
void c_md5_update (Md5Context* ctx, const uint8_t* input, uint32_t len);
void c_md5_finish (Md5Context* ctx, uint8_t digest[16]);

void c_md5_result_to_str  (C_IN const uint8_t val[16], C_OUT uint8_t str[32]);
void c_md5_get_result     (C_IN const uint8_t* buffer, C_IN uint32_t length, C_OUT uint8_t md5Val[16]);
void c_md5_get_str_result (C_IN const uint8_t* buffer, C_IN uint32_t length, C_OUT uint8_t md5Val[32]);

C_END_EXTERN_C

#endif // purec_PUREC_MD_5_H