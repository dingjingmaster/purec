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

#include <stdio.h>

#include "../src/utils-str.h"

int main (int argc, char* argv[])
{
    printf("Start test....\n");

    printf("十六进制转为字符串");
    {
        const char hex[] = {0x01, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        char dest[1024] = {0};
        c_utils_str_hex2str((uint8_t*) dest, (uint8_t*) hex, C_ARRAY_COUNT(hex));
        printf("%s\n", dest);
    }

    printf("获取路径中的 文件夹 和 目录\n");
    {
        const char* fullPath = "/a/b/c/d.txt";
        char dirPath[1024] = {0};
        char fileName[1024] = {0};
        c_utils_str_get_file_name_and_dir((uint8_t*) fullPath,
            (uint8_t*) fileName, sizeof(fileName) - 1, (uint8_t*) dirPath, sizeof(dirPath));
        printf("'%s' => '%s' -> '%s'\n", fullPath, dirPath, fileName);
    }

    {
        const char* fullPath = "a/b/c/d.txt";
        char dirPath[1024] = {0};
        char fileName[1024] = {0};
        c_utils_str_get_file_name_and_dir((uint8_t*) fullPath,
            (uint8_t*) fileName, sizeof(fileName) - 1, (uint8_t*) dirPath, sizeof(dirPath));
        printf("'%s' => '%s' -> '%s'\n", fullPath, dirPath, fileName);
    }

    {
        const char* fullPath = "/";
        char dirPath[1024] = {0};
        char fileName[1024] = {0};
        c_utils_str_get_file_name_and_dir((uint8_t*) fullPath,
            (uint8_t*) fileName, sizeof(fileName) - 1, (uint8_t*) dirPath, sizeof(dirPath));
        printf("'%s' => '%s' -> '%s'\n", fullPath, dirPath, fileName);
    }

    {
        const char* fullPath = "";
        char dirPath[1024] = {0};
        char fileName[1024] = {0};
        c_utils_str_get_file_name_and_dir((uint8_t*) fullPath,
            (uint8_t*) fileName, sizeof(fileName) - 1, (uint8_t*) dirPath, sizeof(dirPath));
        printf("'%s' => '%s' -> '%s'\n", fullPath, dirPath, fileName);
    }

    {
        const char* fullPath = " ";
        char dirPath[1024] = {0};
        char fileName[1024] = {0};
        c_utils_str_get_file_name_and_dir((uint8_t*) fullPath,
            (uint8_t*) fileName, sizeof(fileName) - 1, (uint8_t*) dirPath, sizeof(dirPath));
        printf("'%s' => '%s' -> '%s'\n", fullPath, dirPath, fileName);
    }

    printf("Finished!\n");

    return 0;
}
