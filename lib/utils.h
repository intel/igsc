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

char *igsc_strdup(const char *s);

#ifdef __linux__
#include <limits.h>
#define RSIZE_MAX LONG_MAX
static inline int gsc_memcpy_s(void *dest, size_t dest_size,
                               const void *src, size_t count)
{
    if (!dest || dest_size > RSIZE_MAX)
    {
        return -1;
    }

    if (!src || dest_size < count)
    {
        memset(dest, 0, dest_size);
        return -1;
    }

    if (((src >= dest) && ((char *)src < ((char *)dest + dest_size))) ||
        ((src < dest) && ((char *)src + count - 1 >= (char *)dest)))
    {
        return -1;
    }

    memcpy(dest, src, count);
    return 0;
}

static inline void gsc_msleep(uint32_t msecs)
{
    usleep(msecs * 1000);
}
#ifndef igsc_strdup
#define igsc_strdup strdup
#endif
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
#ifndef igsc_strdup
#define igsc_strdup _strdup
#endif
#endif

int get_device_info_by_devpath(const char *devpath,  struct igsc_device_info *info);

#endif /* __IGSC_UTIL_H__ */
