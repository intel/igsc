/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2022 Intel Corporation
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <libudev.h>

#include "igsc_lib.h"
#include "igsc_log.h"
#include "utils.h"

int gsc_get_device_power_control(const char *devpath, uint8_t *power_control)
{
    struct udev *udev = NULL;
    struct udev_device *dev = NULL;
    struct udev_device *parent;
    struct stat st;
    const char *val;
    int ret;

    udev = udev_new();
    if (udev == NULL)
    {
        gsc_error("Cannot create udev\n");
        return IGSC_ERROR_NOMEM;
    }

    if (lstat(devpath, &st) < 0)
    {
        gsc_error("Cannot lstat %s\n", devpath);
        ret = IGSC_ERROR_INTERNAL;
        goto out;
    }

    dev = udev_device_new_from_devnum(udev, 'c', st.st_rdev);
    if (dev == NULL)
    {
        gsc_error("Cannot create device for %s\n", devpath);
        ret = IGSC_ERROR_INTERNAL;
        goto out;
    }

    /* Look for the GFX PCI parent */
    parent = udev_device_get_parent_with_subsystem_devtype(dev, "pci", NULL);
    if (parent == NULL)
    {
        gsc_error("Can't find device parent for '%s'\n", udev_device_get_sysname(dev));
        ret = IGSC_ERROR_INTERNAL;
        goto out;
    }

    val = udev_device_get_sysattr_value(parent, "power/control");
    if (!val)
    {
        gsc_error("failed to get power/control on %s\n", udev_device_get_sysname(parent));
        ret = IGSC_ERROR_INTERNAL;
        goto out;
    }
    gsc_debug("got power_control '%s' for %s\n", val, udev_device_get_sysname(parent));

    if (!strcmp(val, "on"))
       *power_control = GSC_POWER_CONTROL_ON;
    else if (!strcmp(val, "auto"))
        *power_control = GSC_POWER_CONTROL_AUTO;
    else
    {
        gsc_error("wrong power_control '%s'\n", val);
        ret = IGSC_ERROR_INTERNAL;
        goto out;
    }

    ret = IGSC_SUCCESS;

out:
    udev_device_unref(dev);
    udev_unref(udev);
    return ret;
}

int gsc_set_device_power_control(const char *devpath, uint8_t power_control)
{
    struct udev *udev = NULL;
    struct udev_device *dev = NULL;
    struct udev_device *parent;
    struct stat st;
    const char *val;
    int ret;

    if (power_control != GSC_POWER_CONTROL_ON && power_control != GSC_POWER_CONTROL_AUTO)
    {
        gsc_error("Wrong power control %u\n", power_control);
        return IGSC_ERROR_INTERNAL;
    }

    udev = udev_new();
    if (udev == NULL)
    {
        gsc_error("Cannot create udev\n");
        return IGSC_ERROR_NOMEM;
    }

    if (lstat(devpath, &st) < 0)
    {
        gsc_error("Cannot lstat %s\n", devpath);
        ret = IGSC_ERROR_INTERNAL;
        goto out;
    }

    dev = udev_device_new_from_devnum(udev, 'c', st.st_rdev);
    if (dev == NULL)
    {
        gsc_error("Cannot create device for %s\n", devpath);
        ret = IGSC_ERROR_INTERNAL;
        goto out;
    }

    /* Look for the GFX PCI parent */
    parent = udev_device_get_parent_with_subsystem_devtype(dev, "pci", NULL);
    if (parent == NULL)
    {
        gsc_error("Can't find device parent for '%s'\n", udev_device_get_sysname(dev));
        ret = IGSC_ERROR_INTERNAL;
        goto out;
    }

    switch (power_control)
    {
    case GSC_POWER_CONTROL_ON:
        val = "on";
        break;
    case GSC_POWER_CONTROL_AUTO:
        val = "auto";
        break;
    }

    ret = udev_device_set_sysattr_value(parent, "power/control", (char *)val);
    if (ret < 0)
    {
        gsc_error("failed to set power/control on %s %d\n", udev_device_get_sysname(parent), ret);
        ret = IGSC_ERROR_INTERNAL;
        goto out;
    }
    gsc_debug("power/control is set to %s on %s\n", val, udev_device_get_sysname(parent));

out:
    udev_device_unref(dev);
    udev_unref(udev);
    return ret;
}
