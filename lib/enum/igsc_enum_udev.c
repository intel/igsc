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

    it = malloc(sizeof(*it));
    if (it == NULL)
    {
        gsc_error("Can't allocate iterator\n");
        return IGSC_ERROR_NOMEM;
    }

    it->udev = udev_new();
    if (!it->udev)
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
    udev_enumerate_add_match_property(it->enumerate,
                                      "MEI_CL_UUID",
                                      "87d90ca5-3495-4559-8105-3fbfa37b8b79");
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

int igsc_device_iterator_next(struct igsc_device_iterator *iter,
                              struct igsc_device_info *info)
{
    struct udev_device *dev;
    struct udev_device *mei;
    struct udev_device *parent;
    struct udev_device *gparent;
    char buf[PATH_MAX];
    const char *prop;

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
    if (!dev)
    {
        gsc_error("Can't find device at '%s'\n",
                  udev_list_entry_get_name(iter->entry));
        return IGSC_ERROR_INTERNAL; 
    }

    /* parent is mei-gsc platform device, grand parent is i915 card*/
    parent = udev_device_get_parent(dev);
    if (parent)
    {
        gparent = udev_device_get_parent(parent);
        if (gparent)
        {
            prop = udev_device_get_property_value(gparent, "PCI_ID");
            if (prop)
            {
                sscanf(prop, "%hx:%hx",
                       &info->vendor_id, &info->device_id);
            }
            prop = udev_device_get_property_value(gparent, "PCI_SUBSYS_ID");
            if (prop)
            {
                sscanf(prop, "%hx:%hx",
                       &info->subsys_vendor_id, &info->subsys_device_id);
            }
        }
        else
        {
            gsc_error("Can't find device grand parent for '%s'\n",
                      udev_list_entry_get_name(iter->entry));
        }
    }
    else
    {
        gsc_error("Can't find device parent for '%s'\n",
                  udev_list_entry_get_name(iter->entry));
    }

    /* link to associated char device */
    snprintf(buf, PATH_MAX, "%s/mei", udev_device_get_syspath(dev));
    mei = udev_device_new_from_syspath(iter->udev, buf);
    if (mei)
    {
        prop = udev_device_get_property_value(mei, "DEVNAME");
        if (prop)
        {
            strncpy(info->name, prop, IGCS_INFO_NAME_SIZE);
        }
        udev_device_unref(mei);
    }

    udev_device_unref(dev);

    return IGSC_SUCCESS;
}
