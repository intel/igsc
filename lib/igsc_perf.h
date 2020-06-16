/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2020 Intel Corporation
 */
#ifndef __IGSC_PERF_H__
#define __IGSC_PERF_H__

#ifdef IGSC_PERF
#ifdef WIN32
#include <Windows.h>
#include <Profileapi.h>
#else
#include <sys/time.h>
#endif // WIN32

struct gsc_perf_cnt {
    unsigned int perf_current_index;
#ifdef WIN32
    LARGE_INTEGER perf_frequency;
    LARGE_INTEGER perf_arr[998];
#else
    struct timeval perf_arr[998];
#endif // WIN32
};
void gsc_pref_cnt_init(struct gsc_perf_cnt *ctx);
void gsc_pref_cnt_checkpoint(struct gsc_perf_cnt *ctx, const char* str);
#else /* IGSC_PERF */
struct gsc_perf_cnt {
    unsigned int perf_current_index;
};

static inline void gsc_pref_cnt_init(struct gsc_perf_cnt *ctx)
{
    (void)ctx;
}

static inline void gsc_pref_cnt_checkpoint(struct gsc_perf_cnt *ctx, const char* str)
{
    (void)ctx;
    (void)str;
};
#endif /* IGSC_PERF */

#endif /* __IGSC_PERF_H__ */
