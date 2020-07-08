/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2020 Intel Corporation
 */
#include <stdio.h>

#include "igsc_perf.h"

#ifdef WIN32
static double to_seconds(struct gsc_perf_cnt *ctx, LARGE_INTEGER from, LARGE_INTEGER to)
{
    return ((double)(to.QuadPart - from.QuadPart) / ctx->perf_frequency.QuadPart);
}

void gsc_pref_cnt_init(struct gsc_perf_cnt *ctx)
{
    if (QueryPerformanceFrequency(&ctx->perf_frequency) != TRUE)
    {
        fprintf(stderr, "Error reading performance frequency\n");
    }

    ctx->perf_current_index = 0;
    if (QueryPerformanceCounter(&ctx->perf_arr[ctx->perf_current_index++]) != TRUE)
    {
        fprintf(stderr, "Error reading performance counter\n");
    }
}

void gsc_pref_cnt_checkpoint(struct gsc_perf_cnt *ctx, const char* str)
{
    if (ctx->perf_current_index >= _countof(ctx->perf_arr))
    {
        fprintf(stderr, "Error: Need to enlarge performance array\n");
        return;
    }

    if (QueryPerformanceCounter(&ctx->perf_arr[ctx->perf_current_index]) != TRUE)
    {
        fprintf(stderr, "Error reading performance counter\n");
        return;
    }
    printf("Checkpoint: %s (%f seconds)\n", str,
           to_seconds(ctx, ctx->perf_arr[ctx->perf_current_index - 1],
                      ctx->perf_arr[ctx->perf_current_index]));
    ctx->perf_current_index++;
}
#else /* LINUX */
#include <stdlib.h>
#define _countof(a) (sizeof(a)/sizeof(*(a)))

static double to_seconds(struct gsc_perf_cnt *ctx, struct timeval from, struct timeval to)
{
    struct timeval _res;
    (void)ctx;

    timersub(&to, &from, &_res);
    return (double)_res.tv_sec + (double)_res.tv_usec / 1000000;
}

void gsc_pref_cnt_init(struct gsc_perf_cnt *ctx)
{
    gettimeofday(&ctx->perf_arr[ctx->perf_current_index++], NULL);
}

void gsc_pref_cnt_checkpoint(struct gsc_perf_cnt *ctx, const char* str)
{
    if (ctx->perf_current_index >= _countof(ctx->perf_arr))
    {
        fprintf(stderr, "Error: Need to enlarge performance array\n");
        return;
    }

    if (gettimeofday(&ctx->perf_arr[ctx->perf_current_index], NULL))
    {
        fprintf(stderr, "Error reading performance counter\n");
        return;
    }
    printf("Checkpoint: %s (%f seconds)\n", str,
           to_seconds(ctx, ctx->perf_arr[ctx->perf_current_index - 1],
                      ctx->perf_arr[ctx->perf_current_index]));
    ctx->perf_current_index++;
}
#endif // WIN32
