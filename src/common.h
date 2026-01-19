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
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef purec_PUREC_COMMON_H
#define purec_PUREC_COMMON_H

#ifdef __KERNEL_MODULE__
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <asm/byteorder.h>
#include <linux/fs_stack.h>
#include <linux/build_bug.h>
#define _PACKED __packed

#else
#include <time.h>
#include <stdio.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include <stdlib.h>
#include <dirent.h>
#include <stdbool.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#define _PACKED __attribute__((__packed__))
#endif

#undef C_BEGIN_EXTERN_C
#undef C_END_EXTERN_C
#ifdef  __cplusplus
#define C_BEGIN_EXTERN_C                                                        extern "C" {
#define C_END_EXTERN_C                                                          }
#else
#define C_BEGIN_EXTERN_C
#define C_END_EXTERN_C
#endif


#ifndef C_IN
#define C_IN
#endif

#ifndef C_OUT
#define C_OUT
#endif

#ifndef C_IN_OUT
#define C_IN_OUT
#endif

#ifdef __GNUC__
#define C_GNUC_CHECK_VERSION(major, minor)                                      ((__GNUC__ > (major)) || ((__GNUC__ == (major)) && (__GNUC_MINOR__ >= (minor))))
#else
#define C_GNUC_CHECK_VERSION(major, minor)                                      0
#endif


// 检测 编译器 是否支持 c11 标准
#ifndef C_SUPPORTED_C11
#if defined(__GNUC__) && __GNUC__ >= 4 && __GNUC_MINOR__ >= 7
#define C_SUPPORTED_C11 1
#elif defined(__clang__) && __clang_major__ >= 3 && __clang_minor__ >= 0
#define C_SUPPORTED_C11 1
#else
#define C_SUPPORTED_C11 0
#endif
#endif

#ifndef __KERNEL_MODULE__
// 检查结构体大小是否符合预期
#ifndef C_STRUCT_SIZE_CHECK
#if C_SUPPORTED_C11
#define C_STRUCT_SIZE_CHECK(structType, expectedSize)   _Static_assert((sizeof(structType) == (expectedSize)), "struct size '#structType' is wrong");
#else
#define C_STRUCT_SIZE_CHECK(structType, expectedSize)   typedef char _macros_check_size##structType[((sizeof(structType) == (expectedSize)) ? 1 : -1)];
#endif
#endif
#else
#define C_STRUCT_SIZE_CHECK(structType, expectedSize)   //BUILD_BUG_ON(sizeof(structType) != (expectedSize));
#endif

/* 常用宏函数 -- start */
#ifndef C_FLAG_ON
#define C_FLAG_ON(_F,_SF)                           ((_F) & (_SF))
#endif

#ifndef C_BOOL_FLAG_ON
#define C_BOOL_FLAG_ON(F,SF)                        ((((F) & (SF)) != 0))
#endif

#ifndef C_SET_FLAG
#define C_SET_FLAG(_F,_SF)                          ((_F) |= (_SF))
#endif

#ifndef C_CLEAR_FLAG
#define C_CLEAR_FLAG(_F,_SF)                        ((_F) &= ~(_SF))
#endif

#ifndef C_MIN
#define C_MIN(a,b)                                  ((a) > (b) ? (b) : (a))
#endif

#ifndef C_MAX
#define C_MAX(a,b)                                  ((a) < (b) ? (b) : (a))
#endif

#ifndef C_ARRAY_COUNT
#define C_ARRAY_COUNT(_arr)                         (sizeof(_arr)/sizeof(_arr[0]))
#endif

#ifndef C_FIELD_OFFSET
#define C_FIELD_OFFSET(type,field)                  ((uint64_t)&(((type*)0)->field))
#define C_OFFSET_OF(TYPE,MEMBER)                    ((uint64_t)&((TYPE*)0)->MEMBER)
// #define __builtin_offsetof(type,member)             offsetof(type, member)
#endif

#ifndef C_FIELD_SIZE
#define C_FIELD_SIZE(type,field)                    (sizeof(((type*)0)->field))
#endif

#ifndef C_ALIGN_TO
#define C_ALIGN+TO(_v, _alignment)                  (((uint64_t)(_v) + ((_alignment)-1)) & ~(((uint64_t)(_alignment))-1))
#endif
/* 常用宏函数 -- end   */

#ifdef __KERNEL_MODULE__
static inline unsigned long c_get_regs_arg (struct pt_regs* regs, int n)
{
    switch (n) {
#if defined(ARCH_x86_64)
        case 1: return regs->di;
        case 2: return regs->si;
        case 3: return regs->dx;
        case 4: return regs->cx;
        case 5: return regs->r8;
        case 6: return regs->r9;
#elif defined(ARCH_loongson3)
        case 1:  // a0
        case 2:  // a1
        case 3:  // a2
        case 4:  // a3
            return *(unsigned long*) ((char*) regs + (3 + n) * 8);
#elif defined(ARCH_sw)
        case 1: return regs->r16;
        case 2: return regs->r17;
        case 3: return regs->r18;
        case 4: return regs->r19;
#elif defined(ARCH_arm64)
        case 1: return regs->regs[0];
        case 2: return regs->regs[1];
        case 3: return regs->regs[2];
        case 4: return regs->regs[3];
        case 5: return regs->regs[4];
        case 6: return regs->regs[5];
#elif defined(ARCH_mips)
        case 1: return regs->regs[4];
        case 2: return regs->regs[5];
        case 3: return regs->regs[6];
        case 4: return regs->regs[7];
        case 5: return regs->regs[8];
#elif defined(ARCH_la64)
        case 1: return regs->regs[4];
        case 2: return regs->regs[5];
        case 3: return regs->regs[6];
        case 4: return regs->regs[7];
        case 5: return regs->regs[8];
        case 6: return regs->regs[9];
#endif // ARCH_x86_64
        default: return -1;
    }

    return -1;
}

/**
 * @brief 修改寄存器值
 * @param regs
 * @param n
 * @param v
 * @return
 */
static inline int c_set_regs_arg (struct pt_regs* regs, int n, unsigned long v)
{
    switch (n) {
#if defined(ARCH_x86_64)
        case 1: regs->di = v; return 0;
        case 2: regs->si = v; return 0;
        case 3: regs->dx = v; return 0;
        case 4: regs->cx = v; return 0;
        case 5: regs->r8 = v; return 0;
        case 6: regs->r9 = v; return 0;
#elif defined(ARCH_loongson3)
        case 1:  // a0
        case 2:  // a1
        case 3:  // a2
        case 4:  // a3
            *(unsigned long*) ((char*) regs + (3 + n) * 8) = v; return 0;
#elif defined(ARCH_sw)
        case 1: regs->r16 = v; return 0;
        case 2: regs->r17 = v; return 0;
        case 3: regs->r18 = v; return 0;
        case 4: regs->r19 = v; return 0;
#elif defined(ARCH_arm64)
        case 1: regs->regs[0] = v; return 0;
        case 2: regs->regs[1] = v; return 0;
        case 3: regs->regs[2] = v; return 0;
        case 4: regs->regs[3] = v; return 0;
        case 5: regs->regs[4] = v; return 0;
        case 6: regs->regs[5] = v; return 0;
#elif defined(ARCH_mips)
        case 1: regs->regs[4] = v; return 0;
        case 2: regs->regs[5] = v; return 0;
        case 3: regs->regs[6] = v; return 0;
        case 4: regs->regs[7] = v; return 0;
        case 5: regs->regs[8] = v; return 0;
#elif defined(ARCH_la64)
        case 1: regs->regs[4] = v; return 0;
        case 2: regs->regs[5] = v; return 0;
        case 3: regs->regs[6] = v; return 0;
        case 4: regs->regs[7] = v; return 0;
        case 5: regs->regs[8] = v; return 0;
        case 6: regs->regs[9] = v; return 0;
#endif // ARCH_x86_64
        default: return -1;
    }

    return -1;
}
#endif


#endif // purec_PUREC_COMMON_H
