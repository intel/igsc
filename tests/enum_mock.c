/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2020 Intel Corporation
 */
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <libudev.h>
#include <linux/limits.h>
#include <unistd.h>
#include <stdbool.h>

#include "igsc_lib.h"

struct igsc_device_iterator
{
    uint32_t dummy;
};

int __wrap_igsc_device_iterator_create(struct igsc_device_iterator **iter)
{
    struct igsc_device_iterator *it = NULL;
    int ret;

    if (iter == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    it = calloc(1, sizeof(*it));
    if (it == NULL)
    {
        return IGSC_ERROR_NOMEM;
    }
    *iter = it;

    return IGSC_SUCCESS;
}

void __wrap_igsc_device_iterator_destroy(struct igsc_device_iterator *iter)
{
    if (iter == NULL)
    {
        return;
    }
    free(iter);
}

int __wrap_igsc_device_iterator_next(struct igsc_device_iterator *iter,
                              struct igsc_device_info *info)
{
    char buf[PATH_MAX];
    const char *prop;

    if (iter == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    return IGSC_SUCCESS;
}


int firmware_update(const char *device_path,
                    const char *image_path,
                    bool allow_downgrade)
{
    fprintf(stderr, "mock %s\n", __func__);
    return EXIT_SUCCESS;
}

int firmware_version(const char *device_path)
{
    fprintf(stderr, "mock %s\n", __func__);
    return EXIT_SUCCESS;
}

int image_version(const char *device_path)
{
    fprintf(stderr, "mock %s\n", __func__);
    return EXIT_SUCCESS;
}

int oprom_update(const char *image_path,
                 struct igsc_device_handle *handle, struct igsc_device_info *dev_info,
                 enum igsc_oprom_type type, bool allow_downgrade)
{
    fprintf(stderr, "mock %s\n", __func__);
    return EXIT_SUCCESS;
}

int oprom_device_version(const char *device_path,
                         enum igsc_oprom_type igsc_oprom_type)
{
    fprintf(stderr, "mock %s\n", __func__);
    return EXIT_SUCCESS;
}

int oprom_image_version(const char *image_path,
                        enum igsc_oprom_type igsc_oprom_type)
{
    fprintf(stderr, "mock %s\n", __func__);
    return EXIT_SUCCESS;
}

int oprom_data_image_supported_devices(const char *image_path)
{
    fprintf(stderr, "mock %s\n", __func__);
    return EXIT_SUCCESS;
}

int oprom_code_image_supported_devices(const char *image_path)
{
    fprintf(stderr, "mock %s\n", __func__);
    return EXIT_SUCCESS;
}

int image_type(const char *image_path)
{
    fprintf(stderr, "mock %s\n", __func__);
    return EXIT_SUCCESS;
}

int get_status(struct igsc_device_handle *handle)
{
    fprintf(stderr, "mock %s\n", __func__);
    return EXIT_SUCCESS;
}

int run_ifr_test(struct igsc_device_handle *handle, uint8_t test_type,
                 uint8_t tiles_mask)
{
    fprintf(stderr, "mock %s\n", __func__);
    return EXIT_SUCCESS;
}

int late_binding(const char *device_path, const char *payload_path, uint32_t type, uint32_t flags)
{
    fprintf(stderr, "mock %s\n", __func__);
    return EXIT_SUCCESS;
}
