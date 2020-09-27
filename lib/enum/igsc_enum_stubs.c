/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2020 Intel Corporation
 */
#include "igsc_lib.h"

struct igsc_device_iterator
{
    uint32_t dummy;
};

int igsc_device_iterator_create(struct igsc_device_iterator **iter)
{
    (void)iter;

    return IGSC_ERROR_NOT_SUPPORTED;
}

void igsc_device_iterator_destroy(struct igsc_device_iterator *iter)
{
    (void)iter;
}

int igsc_device_iterator_next(struct igsc_device_iterator *iter,
                              struct igsc_device_info *info)
{
    (void)iter;
    (void)info;

    return IGSC_ERROR_NOT_SUPPORTED;
}

int get_device_info_by_devpath(const char *devpath,
                               struct igsc_device_info *info)
{
    (void)devpath;
    (void)info;

    return IGSC_ERROR_NOT_SUPPORTED;
}

