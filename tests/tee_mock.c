/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2020 Intel Corporation
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "igsc_lib.c"

int mock_driver_init(struct igsc_lib_ctx *lib_ctx)
{
    int status;

    lib_ctx->driver_handle.maxMsgLen = 2048;
    lib_ctx->driver_handle.protcolVer = 1;

    status = driver_working_buffer_alloc(lib_ctx);
    if (status != IGSC_SUCCESS)
    {
        return status;
    }

    lib_ctx->driver_init_called = true;

    return status;
}

void mock_driver_deinit(struct igsc_lib_ctx *lib_ctx)
{
    if (!lib_ctx->driver_init_called)
    {
        return;
    }

    driver_working_buffer_free(lib_ctx);

    lib_ctx->driver_init_called = false;
}
