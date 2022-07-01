/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2022 Intel Corporation
 */
#include "igsc_lib.h"
#include "utils.h"

int gsc_get_device_power_control(const char *devpath, uint8_t *power_control)
{
    (devpath);
    *power_control = GSC_POWER_CONTROL_ON;
    return IGSC_SUCCESS;
}

int gsc_set_device_power_control(const char *devpath, uint8_t power_control)
{
    (devpath);
    (power_control);
    return IGSC_SUCCESS;
}
