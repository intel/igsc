/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2020-2022 Intel Corporation
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "msvc/config.h"
#include "gcc/config.h"

#include <igsc_lib.h>
#include "igsc_oprom.h"
#include "igsc_log.h"

#include "oprom_parser.h"
#include "utils.h"

#pragma pack(1)
struct compare_version {
        uint16_t  major;
        uint16_t  minor;
        uint16_t  hotfix;
        uint16_t  build;
};
#pragma pack()


int igsc_image_oprom_init(OUT struct igsc_oprom_image **img,
                          IN  const uint8_t *buffer,
                          IN  uint32_t buffer_len)
{

    int ret;

    ret = image_oprom_alloc_handle(img, buffer, buffer_len);
    if (ret != IGSC_SUCCESS)
    {
       return ret;
    }

    ret = image_oprom_parse(*img);
    if (ret != IGSC_SUCCESS)
    {
        image_oprom_free_handle(*img);
        *img = NULL;
    }
    return ret;
}

int igsc_image_oprom_version(IN struct igsc_oprom_image *img,
                             enum igsc_oprom_type type,
                             OUT struct igsc_oprom_version *version)
{
    if (img == NULL || version == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    return image_oprom_get_version(img, type, version);
}

int igsc_image_oprom_type(IN struct igsc_oprom_image *img,
                          OUT uint32_t *oprom_type)
{
    enum igsc_oprom_type img_type;

    if (img == NULL || oprom_type == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    img_type = image_oprom_get_type(img);
    if (img_type == IGSC_OPROM_NONE)
    {
        return IGSC_ERROR_BAD_IMAGE;
    }

    *oprom_type = img_type;

    return IGSC_SUCCESS;
}

int igsc_image_oprom_iterator_reset(IN struct igsc_oprom_image *img)
{
    enum igsc_oprom_type img_type;

    if (img == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    /* If image has no data partition the iterator is not supported */
    img_type = image_oprom_get_type(img);
    if ((img_type & IGSC_OPROM_DATA) == 0)
    {
        return IGSC_ERROR_NOT_SUPPORTED;
    }

    image_oprom_iterator_reset(img);

    return IGSC_SUCCESS;
}

int igsc_image_oprom_iterator_reset_typed(IN struct igsc_oprom_image *img,
                                          IN uint32_t request_type)
{
    enum igsc_oprom_type img_type;

    if (img == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }
    if (request_type != IGSC_OPROM_DATA && request_type != IGSC_OPROM_CODE)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    img_type = image_oprom_get_type(img);
    if ((img_type & request_type) == 0)
    {
        return IGSC_ERROR_NOT_SUPPORTED;
    }

    image_oprom_iterator_reset_4ids(img, request_type);

    return IGSC_SUCCESS;
}


int igsc_image_oprom_iterator_next(IN struct igsc_oprom_image *img,
                                   OUT struct igsc_oprom_device_info *device)
{
    enum igsc_oprom_type img_type;

    if (img == NULL || device == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    /* If image has no data partition the iterator is not supported */
    img_type = image_oprom_get_type(img);
    if ((img_type & IGSC_OPROM_DATA) == 0)
    {
        return IGSC_ERROR_NOT_SUPPORTED;
    }

    return image_oprom_get_next(img, device);
}

int igsc_image_oprom_iterator_next_typed(IN struct igsc_oprom_image *img,
                                         IN uint32_t request_type,
                                         OUT struct igsc_oprom_device_info_4ids *device)
{
    enum igsc_oprom_type img_type;

    if (img == NULL || device == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }
    if (request_type != IGSC_OPROM_DATA && request_type != IGSC_OPROM_CODE)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    img_type = image_oprom_get_type(img);
    if ((img_type & request_type) == 0)
    {
        return IGSC_ERROR_NOT_SUPPORTED;
    }

    return image_oprom_get_next_4ids(img, request_type, device);
}

int igsc_image_oprom_count_devices(IN struct igsc_oprom_image *img,
                                   OUT uint32_t *count)

{
    enum igsc_oprom_type img_type;

    if (img == NULL || count == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    /* If image has no data partition the iterator is not supported */
    img_type = image_oprom_get_type(img);
    if ((img_type & IGSC_OPROM_DATA) == 0)
    {
        return IGSC_ERROR_NOT_SUPPORTED;
    }

    *count = image_oprom_count_devices(img);

    return IGSC_SUCCESS;
}

int igsc_image_oprom_count_devices_typed(IN struct igsc_oprom_image *img,
                                         IN uint32_t request_type,
                                         OUT uint32_t *count)
{
    enum igsc_oprom_type img_type;

    if (img == NULL || count == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }
    if (request_type != IGSC_OPROM_DATA && request_type != IGSC_OPROM_CODE)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    img_type = image_oprom_get_type(img);
    if ((img_type & request_type) == 0)
    {
        return IGSC_ERROR_NOT_SUPPORTED;
    }

    *count = image_oprom_count_devices_4ids(img, request_type);

    return IGSC_SUCCESS;
}

int igsc_image_oprom_supported_devices(IN struct igsc_oprom_image *img,
                                       OUT struct igsc_oprom_device_info *device,
                                       IN OUT uint32_t *count)
{
    int ret;
    uint32_t pos = 0;
    enum igsc_oprom_type img_type;

    if (img == NULL || device == NULL || count == NULL || *count == 0)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    /* If image has no data partition the iterator is not supported */
    img_type = image_oprom_get_type(img);
    if ((img_type & IGSC_OPROM_DATA) == 0)
    {
        return IGSC_ERROR_NOT_SUPPORTED;
    }

    while (((ret = image_oprom_get_next(img, &device[pos++])) == IGSC_SUCCESS) && (pos < *count))
    {
        /* empty */
    }
    if (ret == IGSC_ERROR_DEVICE_NOT_FOUND)
    {
        ret = IGSC_SUCCESS;
    }
    *count = pos;

    return ret;
}

int igsc_image_oprom_supported_devices_typed(IN struct igsc_oprom_image *img,
                                             IN uint32_t request_type,
                                             OUT struct igsc_oprom_device_info_4ids *device,
                                             IN OUT uint32_t *count)
{
    int ret;
    uint32_t pos = 0;
    enum igsc_oprom_type img_type;

    if (img == NULL || device == NULL || count == NULL || *count == 0)
    {
        gsc_error("bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }
    if (request_type != IGSC_OPROM_DATA && request_type != IGSC_OPROM_CODE)
    {
        gsc_error("request_type %u is not supported\n", request_type);
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    img_type = image_oprom_get_type(img);
    if ((img_type & request_type) == 0)
    {
        gsc_error("request type %u does not match image type %u \n", request_type, img_type);
        return IGSC_ERROR_NOT_SUPPORTED;
    }

    gsc_debug("img_type %u, request_type = %u\n", img_type, request_type);

    do
    {
        ret = image_oprom_get_next_4ids(img, request_type, &device[pos++]);
    }
    while (ret == IGSC_SUCCESS && pos < *count);

    if (ret == IGSC_ERROR_DEVICE_NOT_FOUND)
    {
        ret = IGSC_SUCCESS;
    }
    *count = pos;

    return ret;
}

static bool oprom_match_device(struct igsc_device_info *device,
                               struct igsc_oprom_device_info *oprom_device)
{
    return (device->subsys_vendor_id == oprom_device->subsys_vendor_id) &&
           (device->subsys_device_id == oprom_device->subsys_device_id);
}

static bool oprom_match_device_4ids(struct igsc_device_info *device,
                                    struct igsc_oprom_device_info_4ids *oprom_device)
{
    return (device->subsys_vendor_id == oprom_device->subsys_vendor_id) &&
           (device->subsys_device_id == oprom_device->subsys_device_id) &&
           (device->vendor_id == oprom_device->vendor_id) &&
           (device->device_id == oprom_device->device_id);
}

int igsc_image_oprom_has_4ids_extension(IN struct igsc_oprom_image *img,
                                        IN uint32_t request_type,
                                        OUT bool *has_4ids_extension)
{
    if (img == NULL || has_4ids_extension == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (request_type != IGSC_OPROM_CODE && request_type != IGSC_OPROM_DATA)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    *has_4ids_extension = image_oprom_has_4ids_extension(img, request_type);
    return IGSC_SUCCESS;
}

int igsc_image_oprom_has_2ids_extension(IN struct igsc_oprom_image *img,
                                        OUT bool *has_2ids_extension)
{
    if (img == NULL || has_2ids_extension == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    *has_2ids_extension = image_oprom_has_2ids_extension(img);
    return IGSC_SUCCESS;
}

/* The oprom update logic for the 4-IDs allowlist.
 * For the Data portion:
 * If the Device IDs allowlist (37) exists in the update image:
 *    The update is accepted only if the card's {VID, DID, SSVID, SSDID}
 *    is in the update image's Device IDs allowlist.
 * If the Device IDs allowlist (37) doesn't exist in the update image:
 *    The update is accepted only if the card's SSVID and SSDID are zero.
 *
 * For the Code portion:
 * If oprom_code_devid_enforcement flag exists in the SPI Image and is set to True:
 *    The update is accepted only if the update file contains a Device IDs allowlist (37)
 *    and the card's {VID, DID, SSVID, SSDID} is in the update file's Device IDs allowlist.
 * If the flag doesn't exist or is False:
 *    The update is accepted only if the update file does not contain a Device ID allowlist (37)
 *
 * Part of this logic is implemented in this function and part elsewhere
 * when we are dealing with the enforcement.
 */
int igsc_image_oprom_match_device(IN struct igsc_oprom_image *img,
                                  IN enum igsc_oprom_type request_type,
                                  IN struct igsc_device_info *device)

{
    enum igsc_oprom_type img_type;
    struct igsc_oprom_device_info oprom_device;
    struct igsc_oprom_device_info_4ids oprom_device_4ids;
    int ret;
    uint32_t count = 0;
    bool image_4ids;
    bool image_2ids;

    if (img == NULL || device == NULL)
    {
        ret = IGSC_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    if (request_type != IGSC_OPROM_CODE && request_type != IGSC_OPROM_DATA)
    {
        ret = IGSC_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    /* check that there is a match between request type and image type */
    img_type = image_oprom_get_type(img);
    if ((request_type & img_type) == 0)
    {
        ret = IGSC_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    image_4ids = image_oprom_has_4ids_extension(img, request_type);
    image_2ids = image_oprom_has_2ids_extension(img);

    gsc_debug("Image type %u has 4Ids extension: %s, has 2Ids extension: %s\n",
              img_type, image_4ids ? "true" : "false", image_2ids ? "true" : "false");

    if (image_4ids && image_2ids)
    {
        ret = IGSC_ERROR_BAD_IMAGE;
        goto exit;
    }

    if (image_4ids)
    {
        gsc_debug("Device: vid 0x%x did 0x%x ssvid 0x%x ssdid 0x%x\n",
                  device->vendor_id, device->device_id,
                  device->subsys_vendor_id, device->subsys_device_id);

        /* search the device list for a match */
        while ((ret = image_oprom_get_next_4ids(img, request_type, &oprom_device_4ids)) == IGSC_SUCCESS)
        {
            gsc_debug("List: vid 0x%x did 0x%x ssvid 0x%x ssdid 0x%x\n",
                  oprom_device_4ids.vendor_id, oprom_device_4ids.device_id,
                  oprom_device_4ids.subsys_vendor_id, oprom_device_4ids.subsys_device_id);

            if (oprom_match_device_4ids(device, &oprom_device_4ids))
            {
                gsc_debug("Match !\n");
                ret = IGSC_SUCCESS;
                goto exit;
            }
        }
        ret = IGSC_ERROR_NOT_SUPPORTED;
    }
    else if (image_2ids)
    {
        /*
         * The Code partition of OPROM is always supposed to match
         * it the same across all derivatives .
         */
        if (request_type == IGSC_OPROM_CODE)
        {
            ret = IGSC_SUCCESS;
            goto exit;
        }

        /* A special case - device has no sub vendor */
        if (device->subsys_device_id == 0 && device->subsys_vendor_id == 0)
        {
            /* empty device list is ok here */
            igsc_image_oprom_count_devices(img, &count);
            if (count == 0)
            {
                ret = IGSC_SUCCESS;
                goto exit;
            }
        }
        /* search the device list for a match */
        while ((ret = image_oprom_get_next(img, &oprom_device)) == IGSC_SUCCESS)
        {
            if (oprom_match_device(device, &oprom_device))
            {
                ret = IGSC_SUCCESS;
                goto exit;
            }
        }
        ret = IGSC_ERROR_NOT_SUPPORTED;
    }
    else /* Neither 4ids extension nor 2ids one are present */
    {
        /* IGSC_OPROM_CODE case is checked by the 4ids enforcement function */
        if (request_type == IGSC_OPROM_CODE)
        {
            ret = IGSC_SUCCESS;
            goto exit;
        }
        /* For IGSC_OPROM_DATA - check the device ids */
        if (device->subsys_device_id == 0 && device->subsys_vendor_id == 0)
        {
            ret = IGSC_SUCCESS;
            goto exit;
        }
        ret = IGSC_ERROR_NOT_SUPPORTED;
    }

exit:
    return ret;
}

int igsc_image_oprom_release(IN struct igsc_oprom_image *img)
{
    image_oprom_free_handle(img);

    return IGSC_SUCCESS;
}

uint8_t igsc_oprom_version_compare(const struct igsc_oprom_version *image_ver,
                                   const struct igsc_oprom_version *device_ver)
{
    struct compare_version *img_ver = (struct compare_version *)image_ver;
    struct compare_version *dev_ver = (struct compare_version *)device_ver;

    if (image_ver == NULL || device_ver == NULL)
    {
        return IGSC_VERSION_ERROR;
    }

    /*
     * Major numbers mus be the same, unless the device's major is zero,
     * that's because some platforms may come originally with 0 major number.
     */
    if (img_ver->major != dev_ver->major && dev_ver->major != 0)
        return IGSC_VERSION_NOT_COMPATIBLE;

    if (img_ver->minor < dev_ver->minor)
        return IGSC_VERSION_OLDER;

    if (img_ver->minor > dev_ver->minor)
        return IGSC_VERSION_NEWER;

    /* Build needs only to be different, does not have to be bigger */
    if (img_ver->build != dev_ver->build)
        return IGSC_VERSION_NEWER;

    return IGSC_VERSION_EQUAL;
}
