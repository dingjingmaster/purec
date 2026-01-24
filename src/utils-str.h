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
#ifndef purec_PUREC_UTILS_STR_H
#define purec_PUREC_UTILS_STR_H
#include "common.h"


C_BEGIN_EXTERN_C

/**
 * @brief 十六进制转为字符串
 *
 * @param dest
 * @param hex
 * @param hexBytes
 */
void    c_utils_str_hex2str                 (C_OUT uint8_t* dest, C_IN const uint8_t* hex, C_IN uint32_t hexBytes);

/**
 * @brief 获取路径中的文件夹和文件
 * @param filePath
 * @param fileName
 * @param fileNameLen
 * @param dirPath
 * @param dirPathLen
 * @return 成功返回 0
 */
int     c_utils_str_get_file_name_and_dir   (C_IN const uint8_t* filePath, C_IN_OUT uint8_t* fileName, C_IN uint32_t fileNameLen, C_IN_OUT uint8_t* dirPath, C_IN uint32_t dirPathLen);

/**
 * @brief 字符串匹配（大小写不敏感）, 支持的正则元素: ?、*、[]
 * @param str
 * @param pat
 * @return
 */
bool    c_utils_str_match_case_insensitive  (const uint8_t* str, uint8_t const* pat);

C_END_EXTERN_C

#endif // purec_PUREC_UTILS_STR_H