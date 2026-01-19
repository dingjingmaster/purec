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
#include "base64.h"

static const unsigned char gsBase64Table[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static unsigned int b64_int (unsigned int ch)
{
    // ASCII to base64_int
    // 65-90  Upper Case  >>  0-25
    // 97-122 Lower Case  >>  26-51
    // 48-57  Numbers     >>  52-61
    // 43     Plus (+)    >>  62
    // 47     Slash (/)   >>  63
    // 61     Equal (=)   >>  64~
    if (ch == 43)
        return 62;
    if (ch == 47)
        return 63;
    if (ch == 61)
        return 64;
    if ((ch > 47) && (ch < 58))
        return ch + 4;
    if ((ch > 64) && (ch < 91))
        return ch - 'A';
    if ((ch > 96) && (ch < 123))
        return (ch - 'a') + 26;

    return 0;
}

unsigned int b64e_size(unsigned int inSize)
{
    // size equals 4*floor((1/3)*(in_size+2));
    int i, j = 0;
    for (i = 0; i < inSize; i++) {
        if (i % 3 == 0) {
            j += 1;
        }
    }

    return (4 * j);
}

unsigned int b64d_size(unsigned int inSize)
{
    return ((3 * inSize) / 4);
}


uint8_t* c_base64_encode(const uint8_t* src, uint64_t len, uint64_t* outLen)
{
    if (!src) { return NULL; }

    unsigned int i = 0, j = 0, k = 0, s[3];
    unsigned int bufferLen = b64e_size(len);
    // TODO:// For kernel
    char* out = malloc(bufferLen + 4);
    if (NULL == out) { return NULL; }

    memset(out, 0, bufferLen + 4);

    for (i = 0; i < len; i++) {
        s[j++] = *(src + i);
        if (j == 3) {
            out[k + 0] = gsBase64Table[(s[0] & 255) >> 2];
            out[k + 1] = gsBase64Table[((s[0] & 0x03) << 4) + ((s[1] & 0xF0) >> 4)];
            out[k + 2] = gsBase64Table[((s[1] & 0x0F) << 2) + ((s[2] & 0xC0) >> 6)];
            out[k + 3] = gsBase64Table[s[2] & 0x3F];
            j = 0; k += 4;
        }
    }

    if (j) {
        if (j == 1) {
            s[1] = 0;
        }
        out[k + 0] = gsBase64Table[(s[0] & 255) >> 2];
        out[k + 1] = gsBase64Table[((s[0] & 0x03) << 4) + ((s[1] & 0xF0) >> 4)];
        if (j == 2) {
            out[k + 2] = gsBase64Table[((s[1] & 0x0F) << 2)];
        }
        else {
            out[k + 2] = '=';
        }
        out[k + 3] = '=';
        k += 4;
    }

    out[k] = '\0';

    if (outLen) { *outLen = k; }

    return (uint8_t*) out;
}


uint8_t* c_base64_decode(const uint8_t* src, uint64_t len, uint64_t* outLen)
{
    unsigned int i = 0, j = 0, k = 0, s[4], count = 0;
    unsigned char* out = NULL;

    count = b64d_size(len);

    out = (unsigned char*) malloc(count + 4);
    if (out == NULL) {
        return NULL;
    }
    memset(out, 0, count + 4);

    for (i = 0; i < len; i++) {
        s[j++] = b64_int(*(src + i));
        if (j == 4) {
            out[k + 0] = ((s[0] & 255) << 2) + ((s[1] & 0x30) >> 4);
            if (s[2] != 64) {
                out[k + 1] = ((s[1] & 0x0F) << 4) + ((s[2] & 0x3C) >> 2);
                if ((s[3] != 64)) {
                    out[k + 2] = ((s[2] & 0x03) << 6) + (s[3]); k += 3;
                }
                else {
                    k += 2;
                }
            }
            else {
                k += 1;
            }
            j = 0;
        }
    }

    if (outLen) { *outLen = k; }

    return out;
}



