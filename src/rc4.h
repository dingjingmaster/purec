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
#ifndef purec_PUREC_RC_4_H
#define purec_PUREC_RC_4_H

#include "common.h"


C_BEGIN_EXTERN_C

typedef struct _Rc4Context Rc4Context;

struct _Rc4Context
{
    uint32_t                x, y;
    uint8_t                 m[256];
};

void c_rc4_setup         (Rc4Context* ctx, const uint8_t* Key, uint32_t keyLen);
void c_rc4_crypt         (Rc4Context* ctx, uint8_t* data, uint32_t length);

// 增强型加密算法
void c_en_rc4_encrypt    (Rc4Context* ctx, uint8_t* data, uint32_t length);

// 增强型解密算法
void c_en_rc4_decrypt    (Rc4Context* ctx, uint8_t* data, uint32_t length);

C_END_EXTERN_C



#endif // purec_PUREC_RC_4_H