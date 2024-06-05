/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2021-2024 Intel Corporation
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
#include "igsc_log.h"
#include "fw_data_parser.h"
#include "igsc_oprom.h"
#include "igsc_heci.h"

#include "utils.h"

#define MFT_EXT_TYPE_DEVICE_IDS 37
#define MFT_EXT_TYPE_FWDATA_UPDATE 29

#define MAX_SUPPORTED_DEVICE_IDS 128

/* CPD header entry indices */
enum igsc_cpd_enrites_indices {
    CPD_MANIFEST_INDEX = 0,
    CPD_METADATA_INDEX = 2,
    CPD_MAX_INDEX      = 3,
};

#define MANIFEST_SIZE_MAX_VALUE (2 * 1024) /* size in longwords */

#define CPD_HEADER_MARKER 0x44504324

enum FWU_GSC_HECI_METADATA_VERSION
{
    FWU_GSC_HECI_METADATA_DATA_UPDATE_VERSION_1 = 0x0401,
    FWU_GSC_HECI_METADATA_DATA_UPDATE_VERSION_2 = 0x0402,
};

int image_fwdata_get_version(struct igsc_fwdata_image *img,
                             struct igsc_fwdata_version *version)
{
    struct gsc_fwu_heci_image_metadata *metadata = (struct gsc_fwu_heci_image_metadata *)img->layout.table[FWU_FPT_ENTRY_IMAGE_INFO].content;
    struct igsc_fwdata_metadata *meta = (struct igsc_fwdata_metadata *)&metadata->metadata;

    version->oem_manuf_data_version = meta->oem_manuf_data_version;
    version->major_vcn = meta->major_vcn;
    version->major_version = meta->major_fw_version;

    return IGSC_SUCCESS;
}

int image_fwdata_get_version2(struct igsc_fwdata_image* img,
                              struct igsc_fwdata_version2* version)
{
    struct gsc_fwu_heci_image_metadata* metadata = (struct gsc_fwu_heci_image_metadata*)img->layout.table[FWU_FPT_ENTRY_IMAGE_INFO].content;
    struct igsc_fwdata_metadata* meta = (struct igsc_fwdata_metadata*)&metadata->metadata;

    switch (metadata->metadata_format_version)
    {
    case FWU_GSC_HECI_METADATA_DATA_UPDATE_VERSION_1:
        version->data_arb_svn = 0;
        version->format_version = IGSC_FWDATA_FORMAT_VERSION_1;
        break;
    case FWU_GSC_HECI_METADATA_DATA_UPDATE_VERSION_2:
        version->data_arb_svn = meta->data_arb_svn;
        version->format_version = IGSC_FWDATA_FORMAT_VERSION_2;
        break;
    default:
        gsc_error("Bad version format %u\n", metadata->metadata_format_version);
        return IGSC_ERROR_BAD_IMAGE;
    }
    version->flags = 0;
    version->data_arb_svn_fitb = 0;
    version->oem_manuf_data_version = meta->oem_manuf_data_version;
    version->oem_manuf_data_version_fitb = 0;
    version->major_vcn = meta->major_vcn;
    version->major_version = meta->major_fw_version;

    return IGSC_SUCCESS;
}

static int image_fwdata_parse_extensions(struct igsc_fwdata_image *img,
                                         size_t ext_start, size_t ext_end)
{
    size_t cur_offset = ext_start;
    struct mft_ext_header_with_data *header;
    bool device_id_ext = false;
    bool manifest_ext = false;

    while (cur_offset < ext_end)
    {
        header = (struct mft_ext_header_with_data *)(img->cpd_ptr + cur_offset);
        if (header->extension_length < sizeof(*header) ||
            header->extension_length > ext_end - cur_offset)
        {
            gsc_error("Illegal fwdata image (extension length %u)\n",
                      header->extension_length);
            return IGSC_ERROR_BAD_IMAGE;
        }

        if (header->extension_type == MFT_EXT_TYPE_DEVICE_IDS)
        {
            if (header->extension_length < sizeof(*header) + sizeof(struct igsc_fwdata_device_info) ||
                header->extension_length > sizeof(*header) + MAX_SUPPORTED_DEVICE_IDS * sizeof(struct igsc_fwdata_device_info))
            {
                gsc_error("Illegal fwdata image (device extension %u)\n",
                           header->extension_length);
                return IGSC_ERROR_BAD_IMAGE;
            }

            img->dev_ids_ext = (struct mft_fwdata_device_ids_ext *)header;
            device_id_ext = true;
        }

        if (header->extension_type == MFT_EXT_TYPE_FWDATA_UPDATE)
        {
            if (header->extension_length != sizeof(struct mft_fwdata_update_ext))
            {
                gsc_error("Illegal fwdata image (signed data update manifest ext len %u)\n",
                          header->extension_length);
                return IGSC_ERROR_BAD_IMAGE;
            }
            img->fwdata_ext = (struct mft_fwdata_update_ext *)header;
            manifest_ext = true;
        }
        cur_offset += header->extension_length;
    }

    if (!manifest_ext || !device_id_ext)
    {
        gsc_error("Illegal fwdata image (missing extensions)");
        return IGSC_ERROR_BAD_IMAGE;
    }
    return IGSC_SUCCESS;
}

static int image_fwdata_parse_cpd(struct igsc_fwdata_image *img, size_t buf_len)
{
    struct code_partition_directory_header *header = (struct code_partition_directory_header *)img->cpd_ptr;
    struct cpd_image *cpd_img = &img->cpd_img;

    if (buf_len <= sizeof(*header) + header->num_of_entries * sizeof(header->entries[0]) ||
         header->num_of_entries < CPD_MAX_INDEX)
    {
        gsc_error("Illegal fw data cpd image (size/num_of_entries %zu/%u)\n",
                  buf_len, header->num_of_entries);
        return IGSC_ERROR_BAD_IMAGE;
    }

    if (header->header_marker != CPD_HEADER_MARKER)
    {
        gsc_error("Illegal fw data cpd image (header marker 0x%x)\n", header->header_marker);
        return IGSC_ERROR_BAD_IMAGE;
    }

    cpd_img->cpd_header = header;

    gsc_debug("manifest offset = %u\n", header->entries[CPD_MANIFEST_INDEX].offset);

    /* check for integer overflow */
    if (header->entries[CPD_MANIFEST_INDEX].offset > buf_len ||
       (header->entries[CPD_MANIFEST_INDEX].offset + sizeof(struct mft_header) > buf_len))
    {
        gsc_error("Illegal manifest offset %u)\n",
                  header->entries[CPD_MANIFEST_INDEX].offset);
        return IGSC_ERROR_BAD_IMAGE;
    }

    gsc_debug("cpd entry manifest length %u\n", header->entries[CPD_MANIFEST_INDEX].length);
    gsc_debug("cpd entry metadata length %u\n", header->entries[CPD_METADATA_INDEX].length);

    if (header->entries[CPD_MANIFEST_INDEX].length > MANIFEST_SIZE_MAX_VALUE * sizeof(uint32_t))
    {
        gsc_error("Illegal manifest length %u)\n",
                  header->entries[CPD_MANIFEST_INDEX].length);
        return IGSC_ERROR_BAD_IMAGE;
    }

    cpd_img->manifest_header = (struct mft_header *)
                                  (img->cpd_ptr + header->entries[CPD_MANIFEST_INDEX].offset);

    cpd_img->manifest_offset = header->entries[CPD_MANIFEST_INDEX].offset;
    cpd_img->public_key_offset = cpd_img->manifest_offset + sizeof(struct mft_header);
    gsc_debug("public key offset = %zu\n", cpd_img->public_key_offset);

    cpd_img->signature_offset = cpd_img->public_key_offset + sizeof(struct mft_rsa_3k_key);
    gsc_debug("signature offset = %zu\n", cpd_img->signature_offset);

    cpd_img->manifest_ext_start = cpd_img->signature_offset + sizeof (struct rsa_3072_pss_signature);

    if (cpd_img->public_key_offset > buf_len ||
       (cpd_img->public_key_offset + sizeof(struct mft_rsa_3k_key) > buf_len))
    {
        gsc_error("Illegal fwdata cpd image (public key offset %zu)\n",
                  cpd_img->public_key_offset);
        return IGSC_ERROR_BAD_IMAGE;
    }
    cpd_img->public_key =  (struct mft_rsa_3k_key *)
                   (img->cpd_ptr + cpd_img->public_key_offset);

    if (cpd_img->signature_offset > buf_len ||
       (cpd_img->signature_offset + sizeof(struct rsa_3072_pss_signature) > buf_len))
    {
        gsc_error("Illegal fwdata cpd image (signature offset %zu)\n",
                  cpd_img->signature_offset);
        return IGSC_ERROR_BAD_IMAGE;
    }
    cpd_img->signature = (struct rsa_3072_pss_signature *)(img->cpd_ptr + cpd_img->signature_offset);

    if (cpd_img->manifest_ext_start > buf_len)
    {
        gsc_error("Illegal fwdata cpd image (extensions start %zu)\n", cpd_img->manifest_ext_start);
        return IGSC_ERROR_BAD_IMAGE;

    }

    if (cpd_img->manifest_header->size < cpd_img->manifest_header->header_length)
    {
        gsc_error("Illegal fwdata cpd image (header size/length %u/%u)\n",
                  cpd_img->manifest_header->size, cpd_img->manifest_header->header_length);
        return IGSC_ERROR_BAD_IMAGE;
    }

    cpd_img->manifest_ext_end = cpd_img->manifest_ext_start +
                    (cpd_img->manifest_header->size -
                     cpd_img->manifest_header->header_length) * sizeof(uint32_t);
    gsc_debug("manifest end = %zu\n", cpd_img->manifest_ext_end);

    if (cpd_img->manifest_ext_end > buf_len)
    {
        gsc_error("Illegal fwdata cpd image (extensions end %zu)\n", cpd_img->manifest_ext_end);
        return IGSC_ERROR_BAD_IMAGE;
    }

    cpd_img->metadata_start = header->entries[CPD_METADATA_INDEX].offset;
    cpd_img->metadata_end = cpd_img->metadata_start + header->entries[CPD_METADATA_INDEX].length;

    if (cpd_img->metadata_start > buf_len || cpd_img->metadata_end >= buf_len)
    {
        gsc_error("Illegal fwdata cpd image (metadata offset/length %u/%u)\n",
                  header->entries[CPD_METADATA_INDEX].offset,
                  header->entries[CPD_METADATA_INDEX].length);
        return IGSC_ERROR_BAD_IMAGE;
    }

    cpd_img->metadata_start = header->entries[CPD_METADATA_INDEX].offset;
    cpd_img->metadata_end = cpd_img->metadata_start + header->entries[CPD_METADATA_INDEX].length;

    return image_fwdata_parse_extensions(img,
                                         cpd_img->manifest_ext_start,
                                         cpd_img->manifest_ext_end);
}

int image_fwdata_parse(struct igsc_fwdata_image *img)
{
    uint32_t buf_len;

    if (img == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }
    if (img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content == NULL)
    {
        return IGSC_ERROR_BAD_IMAGE;
    }

    img->cpd_ptr = img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;
    buf_len = img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].size;

    return image_fwdata_parse_cpd(img, (size_t) buf_len);
}

uint32_t image_fwdata_count_devices(struct igsc_fwdata_image *img)
{
    uint32_t count = 0;

    if (img->dev_ids_ext)
    {
        gsc_debug("extension_length %u\n", img->dev_ids_ext->extension_length);
        count = (uint32_t)(img->dev_ids_ext->extension_length -
                           sizeof(struct mft_fwdata_device_ids_ext)) /
                           sizeof(struct igsc_fwdata_device_info);
    }

    return count;
}

int image_fwdata_get_device(struct igsc_fwdata_image *img, uint32_t num,
                            struct igsc_fwdata_device_info *device)
{
    uint32_t max_num = image_fwdata_count_devices(img);

    gsc_debug("max_num %u num %u\n", max_num, num);
    if (num < max_num)
    {
        gsc_memcpy_s(device, sizeof(*device),
                     &img->dev_ids_ext->device_ids[num],
                     sizeof(*device));
        return IGSC_SUCCESS;
    }

    return IGSC_ERROR_DEVICE_NOT_FOUND;
}

int image_fwdata_get_next(struct igsc_fwdata_image *img,
                          struct igsc_fwdata_device_info *device)
{
    struct igsc_fwdata_device_info _device;

    memset(&_device, 0, sizeof(_device));

    if (image_fwdata_get_device(img, img->cur_device_pos, &_device) != IGSC_SUCCESS)
    {
        gsc_debug("no more devices\n");
        return IGSC_ERROR_DEVICE_NOT_FOUND;
    }
    img->cur_device_pos++;

    gsc_debug("vid 0x%x, did 0x%x, subsys vid 0x%x, subsys did 0x%x\n",
              _device.vendor_id, _device.device_id,
              _device.subsys_vendor_id, _device.subsys_device_id);

    device->vendor_id = _device.vendor_id;
    device->device_id = _device.device_id;
    device->subsys_vendor_id = _device.subsys_vendor_id;
    device->subsys_device_id = _device.subsys_device_id;

    return IGSC_SUCCESS;
}

void image_fwdata_iterator_reset(struct igsc_fwdata_image *img)
{
    img->cur_device_pos = 0;
}

int image_fwdata_get_buffer(struct igsc_fwdata_image *img,
                            const uint8_t **buffer,
                            uint32_t *buffer_len)
{
    if (img == NULL || buffer == NULL || buffer_len == NULL )
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (img->buffer == NULL || img->buffer_len == 0)
    {
        return IGSC_ERROR_BAD_IMAGE;
    }

    *buffer = img->buffer;
    *buffer_len = img->buffer_len;

    return IGSC_SUCCESS;
}

int image_fwdata_alloc_handle(struct igsc_fwdata_image **img,
                                     const uint8_t *buffer,
                                     uint32_t buffer_len)
{
    struct igsc_fwdata_image *_img;
    void *_buffer;

    if (img == NULL || buffer == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    _img = calloc(1, sizeof(*_img));
    if (_img == NULL)
    {
        return IGSC_ERROR_NOMEM;
    }

    _buffer = calloc(1, buffer_len);
    if (_buffer == NULL)
    {
        free(_img);
        return IGSC_ERROR_NOMEM;
    }

    gsc_memcpy_s(_buffer, buffer_len, buffer, buffer_len);
    _img->buffer = _buffer;
    _img->buffer_len = buffer_len;

    *img = _img;

    return IGSC_SUCCESS;
}

void image_fwdata_free_handle(struct igsc_fwdata_image *img)
{
    if (img != NULL)
    {
        free((void *)img->buffer);
        memset(img, 0, sizeof(*img));
        free(img);
    }
}
