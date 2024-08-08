/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2021 Intel Corporation
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

    if ((ret = udev_enumerate_add_match_sysattr(it->enumerate, "kind", "gscfi")) < 0)
    {
        gsc_error("Cannot match udev sysattr: %d\n", ret);
        ret = IGSC_ERROR_INTERNAL;
        goto clean_enum;
    }

    if ((ret = udev_enumerate_scan_devices(it->enumerate)) < 0)
    {
        gsc_error("Cannot scan udev devices: %d\n", ret);
        ret = IGSC_ERROR_INTERNAL;
        goto clean_enum;
    }
    it->entry = NULL;
    *iter = it;

    return IGSC_SUCCESS;
clean_enum:
    udev_enumerate_unref(it->enumerate);
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
    const char *sysname;
    const char *prop;
    int ret;

    sysname = udev_device_get_sysname(dev);
    if (!sysname)
    {
        gsc_error("failed to get udev device sysname");
        return IGSC_ERROR_INTERNAL;
    }

    ret = snprintf(info->name, IGSC_INFO_NAME_SIZE, "/dev/%s", sysname);
    if (ret < 0 || ret >= IGSC_INFO_NAME_SIZE)
    {
        gsc_error("snprintf failed with %d", ret);
        return IGSC_ERROR_INTERNAL;
    }
    info->name[IGSC_INFO_NAME_SIZE - 1] = '\0';

    /* Look for the GFX PCI parent */
    parent = udev_device_get_parent_with_subsystem_devtype(dev, "pci", NULL);
    if (parent == NULL)
    {
        gsc_error("Can't find device parent for '%s'\n", sysname);
        return IGSC_ERROR_INTERNAL;
    }

    prop = udev_device_get_property_value(parent, "PCI_ID");
    if (prop)
    {
        sscanf(prop, "%hx:%hx", &info->vendor_id, &info->device_id);
    }
    else
    {
        gsc_error("failed get PCI_ID property value for parent of '%s'", sysname);
        return IGSC_ERROR_INTERNAL;
    }
    prop = udev_device_get_property_value(parent, "PCI_SUBSYS_ID");
    if (prop)
    {
        sscanf(prop, "%hx:%hx",
               &info->subsys_vendor_id,
               &info->subsys_device_id);
    }
    else
    {
        gsc_error("failed get PCI_SUBSYS_ID property value for parent of '%s'", sysname);
        return IGSC_ERROR_INTERNAL;
    }
    prop = udev_device_get_sysname(parent);
    if (prop)
    {
        sscanf(prop, "%4" SCNu16 ":%2" SCNx8 ":%2" SCNx8 ".%2" SCNx8,
	       &info->domain,
               &info->bus,
               &info->dev,
               &info->func);
    }
    else
    {
        gsc_error("failed to get udev device parent sysname of '%s'", sysname);
        return IGSC_ERROR_INTERNAL;
    }
    return IGSC_SUCCESS;
}

int igsc_device_iterator_next(struct igsc_device_iterator *iter,
                              struct igsc_device_info *info)
{
    struct udev_device *dev;
    int ret;

    if (iter == NULL || info == NULL)
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
