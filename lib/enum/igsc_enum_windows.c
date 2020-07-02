/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2020 Intel Corporation
 */
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <initguid.h>
#include <cfgmgr32.h>
#include <devpkey.h>

#include "igsc_lib.h"
#include "igsc_log.h"

DEFINE_GUID(GUID_DEVINTERFACE_HECI_GSC_CHILD,
            0x5315db55, 0xe7c7, 0x4e67,
            0xb3, 0x96, 0x80, 0xa, 0x75, 0xdd, 0x6f, 0xe4);

struct igsc_device_iterator
{
    WCHAR *deviceInterfaceList;
    WCHAR *deviceInterface;
};

int igsc_device_iterator_create(struct igsc_device_iterator **iter)
{
    struct igsc_device_iterator *it = NULL;
    CONFIGRET cr;
    ULONG deviceInterfaceListLength = 0;
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

    cr = CM_Get_Device_Interface_List_SizeW(
                &deviceInterfaceListLength,
                (LPGUID)&GUID_DEVINTERFACE_HECI_GSC_CHILD,
                NULL,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (cr != CR_SUCCESS)
    {
        gsc_error("Error 0x%x retrieving device interface list size.\n", cr);
        ret = IGSC_ERROR_INTERNAL;
        goto clean_it;
    }

    if (deviceInterfaceListLength == 0)
    {
        ret = IGSC_ERROR_DEVICE_NOT_FOUND;
        goto clean_it;
    }

    it->deviceInterfaceList = (PWCHAR)malloc(deviceInterfaceListLength * sizeof(WCHAR));
    if (it->deviceInterfaceList == NULL)
    {
        gsc_error("Error allocating memory for device interface list.\n");
        ret = IGSC_ERROR_NOMEM;
        goto clean_it;
    }
    ZeroMemory(it->deviceInterfaceList, deviceInterfaceListLength * sizeof(WCHAR));

    cr = CM_Get_Device_Interface_ListW(
                (LPGUID)&GUID_DEVINTERFACE_HECI_GSC_CHILD,
                NULL,
                it->deviceInterfaceList,
                deviceInterfaceListLength,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (cr != CR_SUCCESS)
    {
        gsc_error("Error 0x%x retrieving device interface list.\n", cr);
        ret = IGSC_ERROR_INTERNAL;
        goto clean_dev;
    }

    it->deviceInterface = it->deviceInterfaceList;
    *iter = it;

    return IGSC_SUCCESS;
clean_dev:
    free(it->deviceInterfaceList);
clean_it:
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
    free(iter->deviceInterfaceList);
    free(iter);
}

static int gsc_get_property(const PWCHAR deviceInterfaceList,
                            struct igsc_device_info *info)
{
    CONFIGRET cr;
    BYTE DevID[MAX_DEVICE_ID_LEN];
    BYTE *Property;
    WCHAR *p;
    ULONG PropertySize = 0;
    DEVPROPTYPE PropType;
    DEVINST devInst;

    PropertySize = sizeof(DevID);
    cr = CM_Get_Device_Interface_PropertyW(deviceInterfaceList,
                                           &DEVPKEY_Device_InstanceId,
                                           &PropType,
                                           DevID,
                                           &PropertySize,
                                           0);
    if (cr != CR_SUCCESS || (PropType != DEVPROP_TYPE_STRING))
    {
        gsc_error("Error 0x%x retrieving interface property.\n", cr);
        return IGSC_ERROR_INTERNAL;
    }

    cr = CM_Locate_DevNodeW(&devInst, (DEVINSTID_W)DevID, CM_LOCATE_DEVNODE_NORMAL);
    if (cr != CR_SUCCESS)
    {
        gsc_error("Error 0x%x retrieving device node.\n", cr);
        return IGSC_ERROR_INTERNAL;
    }

    PropertySize = 0;
    cr = CM_Get_DevNode_PropertyW(devInst,
                                  &DEVPKEY_Device_Parent,
                                 &PropType,
                                 NULL,
                                 &PropertySize,
                                 0);
    if (cr != CR_BUFFER_SMALL || (PropType != DEVPROP_TYPE_STRING))
    {
        gsc_error("Error 0x%x retrieving device property size.\n", cr);
        return IGSC_ERROR_INTERNAL;
    }

    Property = (BYTE *)malloc(PropertySize);
    if (Property == NULL)
    {
        gsc_error("Error allocating memory for device property.\n");
        return IGSC_ERROR_NOMEM;
    }
    ZeroMemory(Property, PropertySize);

    cr = CM_Get_DevNode_PropertyW(devInst,
                                  &DEVPKEY_Device_Parent,
                                  &PropType,
                                  Property,
                                  &PropertySize,
                                  0);
    if (cr != CR_SUCCESS || (PropType != DEVPROP_TYPE_STRING))
    {
        gsc_error("Error 0x%x retrieving device property.\n", cr);
        return IGSC_ERROR_INTERNAL;
    }

    gsc_debug("Parent Property %ws.\n", (WCHAR *)Property);
    p = wcsstr((WCHAR *)Property, L"VEN_");
    if (p)
    {
        info->vendor_id = (uint16_t)wcstol(p + 4, NULL, 16);
    }
    p = wcsstr((WCHAR *)Property, L"DEV_");
    if (p)
    {
        info->device_id = (uint16_t)wcstol(p + 4, NULL, 16);
    }
    p = wcsstr((WCHAR *)Property, L"SUBSYS_");
    if (p && wcslen(p) > 15) {
        info->subsys_vendor_id = (uint16_t)wcstol(p + 11, NULL, 16);
        p[11] = '\0';
        info->subsys_device_id = (uint16_t)wcstol(p + 7, NULL, 16);
    }

    free(Property);
    return IGSC_SUCCESS;
}

int igsc_device_iterator_next(struct igsc_device_iterator *iter,
                              struct igsc_device_info *info)
{
    if (iter == NULL)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (*(iter->deviceInterface) == UNICODE_NULL)
    {
        return IGSC_ERROR_DEVICE_NOT_FOUND;
    }

    ZeroMemory(info, sizeof(*info));
    wcstombs_s(NULL, info->name, IGCS_INFO_NAME_SIZE - 1,
               iter->deviceInterface, IGCS_INFO_NAME_SIZE - 1);
    gsc_get_property(iter->deviceInterface, info);
    iter->deviceInterface += wcslen(iter->deviceInterface) + 1;

    return IGSC_SUCCESS;
}
