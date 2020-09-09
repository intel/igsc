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

#include "igsc_lib.h"
#include "../lib/enum/igsc_enum_udev.c"


static void igsc_device_iterator_create_null_inputs(void **status)
{
    assert_int_equal(igsc_device_iterator_create(NULL), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_iterator_next_null_inputs(void **status)
{
    struct igsc_device_iterator *iter;
    struct igsc_device_info info;

    iter = malloc(sizeof(struct igsc_device_iterator));
    iter->entry = NULL;
    iter->enumerate = NULL;

    assert_int_equal(igsc_device_iterator_next(NULL, NULL), IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_device_iterator_next(NULL, &info), IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_device_iterator_next(iter, NULL), IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_device_iterator_next(iter, &info), IGSC_ERROR_DEVICE_NOT_FOUND);

    free(iter);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(igsc_device_iterator_create_null_inputs),
        cmocka_unit_test(igsc_device_iterator_next_null_inputs),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
