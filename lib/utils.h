/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2020 Intel Corporation
 */
#ifndef __IGSC_UTIL_H__
#define __IGSC_UTIL_H__

#ifdef __linux__
#include <unistd.h>
#endif /* __linux__ */

#ifdef __linux__
#define min(a,b) ((a)<(b)?(a):(b))
#define _countof(a) (sizeof(a)/sizeof(*(a)))
#endif /* __linux__ */

#ifdef __linux__
static inline int gsc_memcpy_s(void *dest, size_t dest_size,
                               const void *src, size_t count)
{
    if (count > dest_size)
        return -1;

    memcpy(dest, src, count);
    return 0;
}

static inline void gsc_msleep(uint32_t msecs)
{
    usleep(msecs * 10);
}
#elif WIN32
static inline int gsc_memcpy_s(void *dest, size_t dest_size,
                               const void *src, size_t count)
{
    return memcpy_s(dest, dest_size, src, count);
}

static inline void gsc_msleep(uint32_t msecs)
{
    Sleep(msecs);
}
#endif

#endif /* __IGSC_UTIL_H__ */
