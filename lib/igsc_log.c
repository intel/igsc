/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2023 Intel Corporation
 */

#include <time.h>
#include "msvc/config.h"
#include "gcc/config.h"
#include "igsc_lib.h"

static enum igsc_log_level_type igsc_log_level =
#if defined(DEBUG) || defined(_DEBUG)
IGSC_LOG_LEVEL_DEBUG;
#else
IGSC_LOG_LEVEL_ERROR;
#endif

static igsc_log_func_t igsc_log_func = NULL;

void igsc_set_log_level(unsigned int log_level)
{
    if (log_level >= IGSC_LOG_LEVEL_MAX)
    {
        log_level = IGSC_LOG_LEVEL_MAX - 1;
    }
    igsc_log_level = log_level;
}

unsigned int igsc_get_log_level(void)
{
    return igsc_log_level;
}

void igsc_set_log_callback_func(igsc_log_func_t log_f)
{
    igsc_log_func = log_f;
}

igsc_log_func_t igsc_get_log_callback_func(void)
{
    return igsc_log_func;
}

const char *gsc_time(char *buffer, size_t buff_len)
{
    time_t curtime;
    struct tm timeinfo = {0};
    size_t ret;

    if (!buffer)
       return NULL;
    curtime = time(NULL);
    gsc_localtime(&curtime, &timeinfo);
    ret = strftime(buffer, buff_len, "%c", &timeinfo);
    buffer[ret] = 0;
    return buffer;
}

