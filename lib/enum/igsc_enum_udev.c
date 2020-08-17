/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2020 Intel Corporation
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <libudev.h>
#include <inttypes.h>

#include "igsc_lib.h"
#include "igsc_log.h"

struct igsc_device_iterator
{
    struct udev *udev;
    struct udev_enumerate *enumerate;
    struct udev_list_entry *entry;
};

int igsc_device_iterator_create(struct igsc_device_iterator **iter)
{
    struct igsc_device_iterator *it = NULL;
    int ret;

    if (iter == NULL)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    it = calloc(1, sizeof(*it));
    if (it == NULL)
    {
        gsc_error("Can't allocate iterator\n");
        return IGSC_ERROR_NOMEM;
    }

    it->udev = udev_new();
    if (it->udev == NULL)
    {
        gsc_error("Cannot create udev\n");
        ret = IGSC_ERROR_INTERNAL;
        goto clean_iter;
    }

    it->enumerate = udev_enumerate_new(it->udev);
    if (!it->enumerate)
    {
        gsc_error("Cannot create udev_enumerate\n");
        ret = IGSC_ERROR_INTERNAL;
        goto clean_udev;
    }

    udev_enumerate_add_match_sysattr(it->enumerate, "kind", "gscfi");
    udev_enumerate_scan_devices(it->enumerate);
    it->entry = NULL;
    *iter = it;

    return IGSC_SUCCESS;
clean_udev:
    udev_unref(it->udev);
clean_iter:
    free(it);
    return ret;
}

void igsc_device_iterator_destroy(struct igsc_device_iterator *iter)
{
    if (iter == NULL)
    {
        gsc_error("Bad parameters\n");
        return;
    }
    udev_enumerate_unref(iter->enumerate);
    udev_unref(iter->udev);
    free(iter);
}

static int get_device_info(struct udev_device *dev,
                           struct igsc_device_info *info)
{

    struct udev_device *parent;
    const char *prop;
    int ret;

    ret = snprintf(info->name, IGSC_INFO_NAME_SIZE, "/dev/%s",
                   udev_device_get_sysname(dev));
    if (ret < 0 || ret >= IGSC_INFO_NAME_SIZE)
    {
        return IGSC_ERROR_INTERNAL;
    }
    info->name[IGSC_INFO_NAME_SIZE - 1] = '\0';

    /* Look for the GFX PCI parent */
    parent = udev_device_get_parent_with_subsystem_devtype(dev, "pci", NULL);
    if (parent == NULL)
    {
        gsc_error("Can't find device parent for '%s'\n",
                  udev_device_get_sysname(dev));
        return IGSC_ERROR_INTERNAL;
    }

    prop = udev_device_get_property_value(parent, "PCI_ID");
    if (prop)
    {
        sscanf(prop, "%hx:%hx", &info->vendor_id, &info->device_id);
    }
    prop = udev_device_get_property_value(parent, "PCI_SUBSYS_ID");
    if (prop)
    {
        sscanf(prop, "%hx:%hx",
               &info->subsys_vendor_id,
               &info->subsys_device_id);
    }
    prop = udev_device_get_sysname(parent);
    if (prop)
    {
        sscanf(prop, "%*4d:%2" SCNu8 ":%2" SCNu8 ".%2" SCNu8,
               &info->bus,
               &info->dev,
               &info->func);
    }
    return IGSC_SUCCESS;
}

int igsc_device_iterator_next(struct igsc_device_iterator *iter,
                              struct igsc_device_info *info)
{
    struct udev_device *dev;
    int ret;

    if (iter == NULL)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (iter->entry == NULL)
    {
        iter->entry = udev_enumerate_get_list_entry(iter->enumerate);
    }
    else
    {
        iter->entry = udev_list_entry_get_next(iter->entry);
    }
    if (iter->entry == NULL)
    {
        return IGSC_ERROR_DEVICE_NOT_FOUND;
    }

    dev = udev_device_new_from_syspath(udev_enumerate_get_udev(iter->enumerate),
                                       udev_list_entry_get_name(iter->entry));
    if (dev == NULL)
    {
        gsc_error("Can't find device at '%s'\n",
                  udev_list_entry_get_name(iter->entry));
        return IGSC_ERROR_INTERNAL; 
    }

    ret = get_device_info(dev, info);
    if (ret != IGSC_SUCCESS)
    {
        return ret;
    }

    udev_device_unref(dev);

    return IGSC_SUCCESS;
}

int get_device_info_by_devpath(const char *devpath,
			       struct igsc_device_info *info)
{
    struct udev *udev = NULL;
    struct udev_device *dev = NULL;
    struct stat st;
    int ret;

    udev = udev_new();
    if (udev == NULL)
    {
        return IGSC_ERROR_NOMEM;
    }

    if (lstat(devpath, &st) < 0)
    {
        ret = IGSC_ERROR_INTERNAL;
        goto out;
    }

    dev = udev_device_new_from_devnum(udev, 'c', st.st_rdev);
    if (dev == NULL)
    {
        ret = IGSC_ERROR_INTERNAL;
        goto out;
    }

    ret = get_device_info(dev, info);

out:
    udev_device_unref(dev);
    udev_unref(udev);
    return ret;
}
