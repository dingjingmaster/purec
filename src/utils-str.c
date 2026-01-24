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
    int dirEnd = 0;
    int nameLen = 0;
    int dirRealLen = 0;

    if (!filePath || !fileName || !dirPath) { return -1; }

    memset(fileName, 0, fileNameLen);
    memset(dirPath, 0, dirPathLen);

    nameLen = (int) strlen ((char*) filePath);

    for (i = nameLen - 1; ((i >= 0) && ('/' != filePath[i])); i--);

    dirEnd = i;

    for (i = 0; i < nameLen; i++) {
        if (i <= dirEnd) {
            if (i < dirPathLen - 1) {
                dirRealLen++;
                dirPath[i] = (uint8_t) filePath[i];
            }
            continue;
        }

        if (j < fileNameLen - 1) {
            if (filePath[i] == '/') {
                continue;
            }
            fileName[j] = (uint8_t) filePath[i];
        }
    }

    if (dirRealLen > 1 && dirPath[dirRealLen - 1] == '/') {
        dirPath[dirRealLen - 1] = '\0';
    }

    return 0;
}

bool c_utils_str_match_case_insensitive(const uint8_t* str, uint8_t const* pat)
{
        char* class = NULL;
    bool match = false;
    bool inverted = false;
    unsigned char a = 0, b = 0;
    char const *backPat = NULL, *backStr = NULL;

    for (;;) {
        unsigned char c = *str++;
        unsigned char d = *pat++;
        if (c >= 'A' && c <= 'Z') { c += 32; }
        if (d >= 'A' && d <= 'Z') { d += 32; }
        switch (d) {
            case '?': {   /* Wildcard: anything but nul */
                if (c == '\0') {
                    return false;
                }
                break;
            }
            case '*': {  /* Any-length wildcard */
                if (*pat == '\0') {  /* Optimize trailing * case */
                    return true;
                }
                backPat = pat;
                backStr = --str;   /* Allow zero-length match */
                break;
            }
            case '[': { /* Character class */
                if (c == '\0') { /* No possible match */
                    return false;
                }
                match = false;
                inverted = (*pat == '!');
                class = (char*) pat + inverted;
                a = *class++;
                /**
                 * Iterate over each span in the character class.
                 * A span is either a single character a, or a
                 * range a-b.  The first span may begin with ']'.
                 */
                do {
                    b = a;
                    if (a == '\0') { /* Malformed */
                        goto literal;
                    }
                    if (class[0] == '-' && class[1] != ']') {
                        b = class[1];
                        if (b == '\0') {
                            goto literal;
                        }
                        class += 2;
                        /* Any special action if a > b? */
                    }
                    match |= (a <= c && c <= b);
                } while ((a = *class++) != ']');
                if (match == inverted) {
                    goto backtrack;
                }
                pat = class;
                break;
            }
            case '\\': {
                d = *pat++;
                /* fall through */
            }
            default: {   /* Literal character */
literal:
                if (c == d) {
                    if (d == '\0') {
                        return true;
                    }
                    break;
                }
backtrack:
                if (c == '\0' || !backPat) {
                    return false;   /* No point continuing */
                }
                /* Try again from last *, one character later in str. */
                pat = backPat;
                str = ++backStr;
                break;
            }
        }
    }


    return false;
}


