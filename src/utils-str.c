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
#include "utils-str.h"


void c_utils_str_hex2str(uint8_t* dest, const uint8_t* hex, uint32_t hexBytes)
{
    uint32_t i = 0;
    for (i = 0; i < hexBytes; i++) {
        sprintf((char*) dest, "%02x", *(uint8_t*) hex);
        ++hex;
        dest += 2;
    }
    *dest = '\0';
}

int c_utils_str_get_file_name_and_dir (C_IN const uint8_t* filePath, C_IN_OUT uint8_t* fileName, C_IN uint32_t fileNameLen, C_IN_OUT uint8_t* dirPath, C_IN uint32_t dirPathLen)
{
    int i = 0;
    int j = 0;
    int nameLen = 0;
    const uint8_t* name = NULL;

    if (!filePath || !fileName || !dirPath) { return -1; }

    memset(fileName, 0, fileNameLen);
    memset(dirPath, 0, dirPathLen);

    nameLen = (int) strlen ((char*) filePath);

    for (i = nameLen - 1; ((i >= 0) && ('/' != filePath[i])); name = filePath + i, i--);

    if (!name) { name = filePath; }

    for (i = 0; i < nameLen; i++) {
        if (filePath + i < name) {
            if (i < dirPathLen - 1) {
                dirPath[i] = (uint8_t) filePath[i];
            }
            continue;
        }
        j = (int) (filePath - name) + i;
        if (j < fileNameLen - 1) {
            fileName[j] = (uint8_t) filePath[i];
        }
    }

    return 0;
}


