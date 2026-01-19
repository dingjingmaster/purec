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
#include "rc4.h"

void c_rc4_setup(Rc4Context * ctx, const uint8_t * Key, uint32_t keyLen)
{
    uint32_t i, j, k;
    uint8_t *m, a;

    ctx->x = 0;
    ctx->y = 0;
    m = ctx->m;

    for (i = 0; i < 256; i++) {
        m[i] = (uint8_t) i;
    }

    j = k = 0;
    for (i = 0; i < 256; i++) {
        a = m[i];
        j = (uint8_t) (j + a + Key[k]);
        m[i] = m[j]; m[j] = a;
        if( ++k >= keyLen ) k = 0;
    }
}

void c_rc4_crypt(Rc4Context * ctx, uint8_t * data, uint32_t length)
{
    uint32_t i, x, y;
    uint8_t *m, a, b;
    x = ctx->x;
    y = ctx->y;
    m = ctx->m;

    for (i = 0; i < length; i++) {
        x = (uint8_t) (x + 1); a = m[x];
        y = (uint8_t) (y + a);
        m[x] = b = m[y];
        m[y] = a;
        *data++ ^= m[(uint8_t) (a + b)];
    }

    ctx->x = x;
    ctx->y = y;
}

void c_en_rc4_encrypt(Rc4Context * ctx, uint8_t * data, uint32_t length)
{
    uint32_t i, x, y;
    uint8_t *m, a, b;

    x = ctx->x;
    y = ctx->y;
    m = ctx->m;

    for (i = 0; i < length; i++) {
        x = (uint8_t) (x + 1); a = m[x];
        y = (uint8_t) (y + a);
        m[x] = b = m[y];
        m[y] = a;

        data[i] ^= m[(uint8_t)(a + b)];
        data[i] += m[b];
    }

    ctx->x = x;
    ctx->y = y;
}

void c_en_rc4_decrypt(Rc4Context * ctx, uint8_t * data, uint32_t length)
{
    uint32_t i, x, y;
    uint8_t *m, a, b;

    x = ctx->x;
    y = ctx->y;
    m = ctx->m;

    for (i = 0; i < length; i++) {
        x = (uint8_t) (x + 1); a = m[x];
        y = (uint8_t) (y + a);
        m[x] = b = m[y];
        m[y] = a;

        data[i] -= m[b];
        data[i] ^= m[(uint8_t)(a + b)];
    }

    ctx->x = x;
    ctx->y = y;
}

