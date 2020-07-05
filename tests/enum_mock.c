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
#include "igsc_cli.c"

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

int mock_args_parse(const char *exe_name, int *argc, char **argv[],
                      const struct gsc_op **op, bool *display_help)
{
    return args_parse(exe_name, argc, argv, op, display_help);
}

int mock_firmware_update(const char *device_path,
                         const char *image_path,
                         bool allow_downgrade)
{
    return EXIT_SUCCESS;
}

int mock_firmware_version(const char *device_path)
{
    return EXIT_SUCCESS;
}

int mock_image_version(const char *device_path)
{
    return EXIT_SUCCESS;
}

int mock_oprom_device_version(const char *device_path,
                             enum igsc_oprom_type igsc_oprom_type)
{
    return EXIT_SUCCESS;
}

int mock_oprom_update(const char *image_path, const char *device_path,
                      char *device_path_found, enum igsc_oprom_type type)
{
    return EXIT_SUCCESS;
}

int mock_oprom_image_version(const char *image_path,
                             enum igsc_oprom_type igsc_oprom_type)
{
    return EXIT_SUCCESS;
}
