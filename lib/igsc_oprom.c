/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2020 Intel Corporation
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#ifdef __linux__
#include <unistd.h>
#endif /* __linux__ */

#ifdef UNIT_TESTING
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#endif

#include "msvc/config.h"

#include <igsc_lib.h>
#include "igsc_oprom.h"
#include "igsc_log.h"

/* CPD header entry indices */
#define MANIFEST_INDEX 0
#define METADATA_INDEX 2
#define MAX_INDEX      3

/* extension types */
#define MFT_EXT_TYPE_DEVICE_TYPE          7
#define MFT_EXT_TYPE_SIGNED_PACKAGE_INFO  15
#define MFT_EXT_TYPE_IFWI_PART_MAN        22
#define MDF_EXT_TYPE_MODULE_ATTR          10

struct igsc_cpd_image {
    struct code_partition_directory_header *cpd_header;  /**< cpd header */
    size_t manifest_offset;                              /**< offset of the manifest */
    struct mft_header *manifest_header;                  /**< pointer to the manifest header */
    size_t public_key_offset;                            /**< offset of the public key */
    struct mft_rsa_3k_key *public_key;                   /**< pointer to the public key */
    size_t signature_offset;                             /**< offset of the signature */
    struct rsa_3072_pss_signature *signature;            /**< pointer to the signature */
    size_t manifest_ext_start;                           /**< start offset of the manifest extensions */
    size_t manifest_ext_end;                             /**< end offset of the manifest extensions */
    size_t metadata_start;                               /**< start offset of the metadata extensions */
    size_t metadata_end;                                 /**< end offset of the metadata extensions */
    struct mft_oprom_device_type_ext *dev_ext;           /**< oprom devices extension */
};

struct igsc_oprom_image {
    const uint8_t *buffer;                 /**< buffer for oprom image */
    size_t buffer_len;                     /**< length for the oprom image buffer */
    size_t cpd_offset;                     /**< offset of the cpd image inside the buffer */
    const uint8_t *cpd_ptr;                /**< pointer to the start of cpd image inside the buffer */
    struct igsc_cpd_image cpd_img;         /**< cpd image structure */
    struct oprom_pci_data *pci_data;       /**< pointer to pci data inside the buffer */
    struct oprom_header_ext_v2 *v2_header; /**< expansion header version 2 */

    uint32_t cur_device_pos;               /**< iterator's current device position */
};

#if defined(DEBUG) || defined(_DEBUG)
static void debug_print_device_type_ext(struct mft_oprom_device_type_ext *ext)
{
    struct oprom_subsystem_device_id *dev = &ext->device_ids[0];
    uint32_t len = 0;

    gsc_debug("type %u len %u", ext->extension_type, ext->extension_length);
    while (len < ext->extension_length)
    {
        gsc_debug("vid 0x%x did 0x%x\n", dev->vendor_id, dev->device_id);
        len += sizeof(*dev);
        dev++;
    }
}
#else
static inline void debug_print_device_type_ext(struct mft_oprom_device_type_ext *ext)
{
    (void)ext;
}
#endif

static void debug_print_partition_directory_header(struct code_partition_directory_header *h)
{
    (void)h;

    gsc_debug("num_oe %u, hv %u, ev %u hl %u cs %u pn 0x%x crc 0x%x\n",
              h->num_of_entries, h->header_version,
              h->entry_version, h->header_length,
              h->checksum, h->partition_name, h->crc32);
}

static void debug_print_manifest_header(struct mft_header *h)
{
    (void)h;

    gsc_debug("ht 0x%x hl 0x%x hv 0x%x f 0x%x v 0x%x d 0x%x s 0x%x hid 0x%x\n",
              h->header_type, h->header_length, h->header_version,
              h->flags, h->vendor, h->date, h->size, h->header_id);
    gsc_debug("version %x.%x.%x.%x\n",
               h->version.major, h->version.minor,
               h->version.hotfix, h->version.build);
    gsc_debug("ms 0x%x es 0x%x\n", h->modulus_size, h->exponent_size);
}

static void debug_print_struct_sizes(void)
{
    gsc_debug("sizeof(struct mft_header) %ld\n",
               sizeof(struct mft_header));
    gsc_debug("sizeof(struct rsa_3072_pss_signature) %ld\n",
               sizeof(struct rsa_3072_pss_signature));
    gsc_debug("sizeof(struct mft_rsa_3k_key) %ld\n",
               sizeof(struct mft_rsa_3k_key));
}

static void debug_print_pci_data(const struct oprom_pci_data *p)
{
    (void)p;

    gsc_debug("s 0x%x vid 0x%x did 0x%x dlp 0x%x pl 0x%x pr 0x%x cc 0x%x il 0x%x\n",
              p->signature, p->vendor_id, p->device_id,
              p->device_list_pointer, p->pci_data_structure_length,
              p->pci_data_structure_revision, p->class_code, p->image_length);
    gsc_debug("rl 0x%x ct 0x%x lii 0x%x ml 0x%x cp 0x%x pp 0x%x\n",
              p->revision_level, p->code_type, p->last_image_indicator,
              p->max_runtime_image_length, p->conf_util_code_header_pointer,
              p->DMTF_CLP_entry_point_pointer);
}

static int image_oprom_parse_extensions(struct igsc_oprom_image *img,
                                        size_t ext_start, size_t ext_end)
{
    size_t cur_offset = ext_start;
    struct mft_ext_header_with_data *header;

    while (cur_offset < ext_end)
    {
        header = (struct mft_ext_header_with_data *)(img->cpd_ptr + cur_offset);

        if (header->extension_length < sizeof(*header) ||
            header->extension_length > ext_end - ext_start)
        {
            gsc_error("Illegal oprom cpd image (extension length %u)\n",
                      header->extension_length);
            return IGSC_ERROR_INVALID_PARAMETER;
        }

        if (header->extension_type == MFT_EXT_TYPE_DEVICE_TYPE)
        {
            /* TODO: check the exact match */
            if (header->extension_length < sizeof(*header) + sizeof(struct oprom_subsystem_device_id))
            {
                gsc_error("Illegal oprom cpd image (device extension %u)\n",
                           header->extension_length);
                return IGSC_ERROR_INVALID_PARAMETER;
            }

            img->cpd_img.dev_ext = (struct mft_oprom_device_type_ext *)header;
            debug_print_device_type_ext(img->cpd_img.dev_ext);
        }

        if (header->extension_type == MFT_EXT_TYPE_SIGNED_PACKAGE_INFO)
        {
            /* TODO: check the exact match */
            if (header->extension_length < sizeof(struct mft_signed_package_info_ext))
            {
                gsc_error("Illegal oprom cpd image (signed pkg info ext %u)\n",
                           header->extension_length);
                return IGSC_ERROR_INVALID_PARAMETER;
            }
        }

        if (header->extension_type == MFT_EXT_TYPE_IFWI_PART_MAN)
        {
            /* TODO: check the exact match */
            if (header->extension_length < sizeof(struct mft_ifwi_part_man_ext))
            {
                gsc_error("Illegal oprom cpd image (ifwi part ext %u)\n",
                          header->extension_length);
                return IGSC_ERROR_INVALID_PARAMETER;
            }
        }

        if (header->extension_type == MDF_EXT_TYPE_MODULE_ATTR)
        {
            /* TODO: check the exact match */
            if (header->extension_length < sizeof(struct mdf_module_attr_ext))
            {
                gsc_error("Illegal oprom cpd image (mdf module attr ext %u)\n",
                          header->extension_length);
                return IGSC_ERROR_INVALID_PARAMETER;
            }
        }

        cur_offset += header->extension_length;
    }
    return 0;
}


static int image_oprom_parse_cpd(struct igsc_oprom_image *img, size_t buf_len)
{
    struct code_partition_directory_header *header = (struct code_partition_directory_header *)img->cpd_ptr;
    struct igsc_cpd_image *cpd_img = &img->cpd_img;

    if (buf_len <= sizeof(*header) + MAX_INDEX * sizeof(header->entries[0]))
    {
        gsc_error("Illegal oprom cpd image (size %lu)\n", buf_len);
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (header->header_marker != 0x44504324)
    {
        gsc_error("Illegal oprom cpd image (header marker 0x%x)\n", header->header_marker);
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    debug_print_partition_directory_header(header);

    cpd_img->cpd_header = header;

    gsc_debug("manifest offset = %u\n", header->entries[MANIFEST_INDEX].offset);

    if (header->entries[MANIFEST_INDEX].offset > buf_len ||
       (header->entries[MANIFEST_INDEX].offset + sizeof(struct mft_header) > buf_len))
    {
        gsc_error("Illegal manifest offset %u)\n",
                  header->entries[MANIFEST_INDEX].offset);
        return IGSC_ERROR_INVALID_PARAMETER;
    }
    cpd_img->manifest_header = (struct mft_header *)
                                  (img->cpd_ptr + header->entries[MANIFEST_INDEX].offset);

    debug_print_manifest_header(cpd_img->manifest_header);

    cpd_img->manifest_offset = header->entries[MANIFEST_INDEX].offset;
    cpd_img->public_key_offset = cpd_img->manifest_offset + sizeof(struct mft_header);
    gsc_debug("public key offset = %lu\n", cpd_img->public_key_offset);

    cpd_img->signature_offset = cpd_img->public_key_offset + sizeof(struct mft_rsa_3k_key);
    gsc_debug("signature offset = %lu\n", cpd_img->signature_offset);

    cpd_img->manifest_ext_start = cpd_img->signature_offset + sizeof (struct rsa_3072_pss_signature);
    gsc_debug("manifest start = %lu 0x%lx\n", cpd_img->manifest_ext_start,
                                             cpd_img->manifest_ext_start + img->cpd_offset);

    debug_print_struct_sizes();

    if (cpd_img->public_key_offset + sizeof(struct mft_rsa_3k_key) > buf_len)
    {
        gsc_error("Illegal oprom cpd image (public key offset %lu)\n",
                  cpd_img->public_key_offset);
        return IGSC_ERROR_INVALID_PARAMETER;
    }
    cpd_img->public_key =  (struct mft_rsa_3k_key *)
                   (img->cpd_ptr + cpd_img->public_key_offset);

    if (cpd_img->signature_offset + sizeof(struct rsa_3072_pss_signature) > buf_len)
    {
        gsc_error("Illegal oprom cpd image (signature offset %lu)\n",
                  cpd_img->signature_offset);
        return IGSC_ERROR_INVALID_PARAMETER;
    }
    cpd_img->signature = (struct rsa_3072_pss_signature *)(img->cpd_ptr + cpd_img->signature_offset);

    if (cpd_img->manifest_ext_start > buf_len)
    {
        gsc_error("Illegal oprom cpd image (extensions start %lu)\n", cpd_img->manifest_ext_start);
        return IGSC_ERROR_INVALID_PARAMETER;

    }

    if (cpd_img->manifest_header->size < cpd_img->manifest_header->header_length)
    {
        gsc_error("Illegal oprom cpd image (header size/length %u/%u)\n",
                  cpd_img->manifest_header->size, cpd_img->manifest_header->header_length);
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    cpd_img->manifest_ext_end = cpd_img->manifest_ext_start +
                    (cpd_img->manifest_header->size -
                     cpd_img->manifest_header->header_length) * 4;
    gsc_debug("manifest end = %lu\n", cpd_img->manifest_ext_end);

    if (cpd_img->manifest_ext_end > buf_len)
    {
        gsc_error("Illegal oprom cpd image (extensions end %lu)\n", cpd_img->manifest_ext_end);
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    cpd_img->metadata_start = header->entries[METADATA_INDEX].offset;
    cpd_img->metadata_end = cpd_img->metadata_start + header->entries[METADATA_INDEX].length;

    if (cpd_img->metadata_start > buf_len || cpd_img->metadata_end >= buf_len)
    {
        gsc_error("Illegal oprom cpd image (metadata offset/length %u/%u)\n",
                  header->entries[METADATA_INDEX].offset,
                  header->entries[METADATA_INDEX].length);
        return IGSC_ERROR_INVALID_PARAMETER;
    }
    cpd_img->metadata_start = header->entries[METADATA_INDEX].offset;
    cpd_img->metadata_end = cpd_img->metadata_start + header->entries[METADATA_INDEX].length;

    return image_oprom_parse_extensions(img,
                                        cpd_img->manifest_ext_start,
                                        cpd_img->manifest_ext_end);
}

static bool contains_cpd_offset(IN struct igsc_oprom_image *img)
{
    return (img->v2_header->unofficial_payload_offset != 0);
}

static int image_oprom_parse(struct igsc_oprom_image *img)
{
    struct oprom_header_ext_v2 *v2_header;
    struct oprom_pci_data *pci_data;

    /* Note that we assume here that the input oprom image contains */
    /* only one partition - either Data or Code and not both of them together. */
    /* This means that the original oprom image that might have contained both */
    /* should be divided into two images - one for Data and one for Code. */
    /* Also, we assume that the first PCI header has the required code_type */
    /* (Data or Code), otherwise the image is proclaimed illegal. */
    /* The subsequent PCI headers may have different code_type and thus are */
    /* of no interest to us */

    if (img == NULL)
    {
        gsc_error("Wrong oprom image parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    v2_header = (struct oprom_header_ext_v2 *)img->buffer;

    if (v2_header->signature != ROM_SIGNATURE)
    {
        gsc_error("Illegal oprom image structure (signature 0x%x)\n",
                  v2_header->signature);
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (v2_header->pci_data_structure_pointer >= img->buffer_len ||
        v2_header->pci_data_structure_pointer + sizeof(*v2_header) >= img->buffer_len)
    {
        gsc_error("Illegal oprom image structure (pci_data %u %lu)\n",
                  v2_header->pci_data_structure_pointer, img->buffer_len);
        return IGSC_ERROR_INVALID_PARAMETER;
    }
    gsc_debug("pci_data_pointer %ul)\n", v2_header->pci_data_structure_pointer);

    img->v2_header = v2_header;

    pci_data = (struct oprom_pci_data *) (img->buffer + v2_header->pci_data_structure_pointer);

    debug_print_pci_data(pci_data);

    if (pci_data->code_type != OPROM_CODE_TYPE_DATA && pci_data->code_type != OPROM_CODE_TYPE_CODE)
    {
        gsc_error("Illegal oprom image structure (pci code_type 0x%x)\n",
                  pci_data->code_type);
        return IGSC_ERROR_INVALID_PARAMETER;
    }
    /* TODO: Should we check here other fields of pci_data structure ? */

    img->pci_data = pci_data;

    if (contains_cpd_offset(img))
    {
        if (v2_header->unofficial_payload_offset >= img->buffer_len)
        {
            gsc_error("Illegal oprom cpd offset\n");
            return IGSC_ERROR_INVALID_PARAMETER;
        }

        img->cpd_offset = v2_header->unofficial_payload_offset;
        img->cpd_ptr = img->buffer + v2_header->unofficial_payload_offset;

        gsc_debug("cpd_offset %lu\n", img->cpd_offset);

        return image_oprom_parse_cpd(img, img->buffer_len - img->cpd_offset);
    }

    return 0;
}


static int image_oprom_get_version(struct igsc_oprom_image *img,
                                   struct igsc_oprom_version *version)
{
    memcpy(version, &img->cpd_img.manifest_header->version,
           sizeof(struct igsc_oprom_version));
    return IGSC_SUCCESS;
}

static int image_oprom_get_type(struct igsc_oprom_image *img,
                                enum igsc_oprom_type *type)
{
    uint8_t _type;

    _type = img->pci_data->code_type;

    gsc_debug("code_type 0x%x\n", img->pci_data->code_type);

    if (_type == IGSC_OPROM_DATA || _type == IGSC_OPROM_CODE)
    {
       *type = _type;
       return IGSC_SUCCESS;
    }

    return IGSC_ERROR_DEVICE_NOT_FOUND;

}

static uint32_t image_oprom_count_devices(struct igsc_oprom_image *img)
{
    uint32_t count = 0;

    if (img->cpd_img.dev_ext)
    {
        gsc_debug("extension_length %u\n", img->cpd_img.dev_ext->extension_length);
        count = (img->cpd_img.dev_ext->extension_length -
                  sizeof(struct mft_oprom_device_type_ext)) /
                  sizeof(struct oprom_subsystem_device_id);
    }

    return count;
}

static int image_oprom_get_device(struct igsc_oprom_image *img, uint32_t num,
                                  struct oprom_subsystem_device_id *device)
{
    uint32_t max_num = image_oprom_count_devices(img);

    gsc_debug("max_num %u num %u\n", max_num, num);
    if (num < max_num)
    {
        memcpy(device, &img->cpd_img.dev_ext->device_ids[num], sizeof(*device));
        return IGSC_SUCCESS;
    }

    return IGSC_ERROR_DEVICE_NOT_FOUND;
}

static int image_oprom_get_next(struct igsc_oprom_image *img,
                                struct igsc_oprom_device_info *device)
{
    struct oprom_subsystem_device_id _device;

    if (image_oprom_get_device(img, img->cur_device_pos++, &_device) != IGSC_SUCCESS)
    {
        gsc_debug("no more devices\n");
        return IGSC_ERROR_DEVICE_NOT_FOUND;
    }

    gsc_debug("vid 0x%x did 0x%x\n",  _device.vendor_id, _device.device_id);

    device->subsys_vendor_id = _device.vendor_id;
    device->subsys_device_id = _device.device_id;

    return IGSC_SUCCESS;
}

static bool oprom_match_dev(struct igsc_device_info *device,
                            struct igsc_oprom_device_info *oprom_device)
{
    return (device->subsys_vendor_id == oprom_device->subsys_vendor_id) &&
           (device->subsys_device_id == oprom_device->subsys_device_id);
}

static int image_oprom_alloc_handle(struct igsc_oprom_image **img,
                                    const uint8_t *buffer,
                                    uint32_t buffer_len)
{
    struct igsc_oprom_image *_img;
    void *_buffer;

    if (img == NULL || buffer == NULL ||
        buffer_len <= sizeof(struct oprom_header_ext))
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

    memcpy(_buffer, buffer, buffer_len);
    _img->buffer = _buffer;
    _img->buffer_len = buffer_len;

    *img = _img;

    return IGSC_SUCCESS;
}

/* API */

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

    return image_oprom_parse(*img);

}

int igsc_image_oprom_version(IN struct igsc_oprom_image *img,
                             OUT struct igsc_oprom_version *version)
{
    if (img == NULL || version == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    return image_oprom_get_version(img, version);
}

int igsc_image_oprom_type(IN struct igsc_oprom_image *img,
                          OUT enum igsc_oprom_type *type)
{
    if (img == NULL || type == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    return image_oprom_get_type(img, type);
}

int igsc_image_oprom_iterator_reset(IN struct igsc_oprom_image *img)
{
    if (img == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    img->cur_device_pos = 0;

    return IGSC_SUCCESS;
}

int igsc_image_oprom_iterator_next(IN struct igsc_oprom_image *img,
                                   OUT struct igsc_oprom_device_info *device)
{
    if (img == NULL || device == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    return image_oprom_get_next(img, device);
}

int igsc_image_oprom_count_devices(IN struct igsc_oprom_image *img,
                                   OUT uint32_t *count)

{
    if (img == NULL || count == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    *count = image_oprom_count_devices(img);

    return IGSC_SUCCESS;
}

int igsc_image_oprom_supported_devices(IN struct igsc_oprom_image *img,
                                       OUT struct igsc_oprom_device_info *device,
                                       IN OUT uint32_t *count)
{
    int ret;
    uint32_t pos = 0;

    if (img == NULL || device == NULL || count == NULL || *count == 0)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    while (((ret = image_oprom_get_next(img, &device[pos++])) == IGSC_SUCCESS) && (pos <= *count))
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

int igsc_image_oprom_match_device(IN struct igsc_oprom_image *img,
                                  IN struct igsc_device_info *device)

{
    struct igsc_oprom_device_info oprom_device;
    int ret;

    if (img == NULL || device == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    while ((ret = image_oprom_get_next(img, &oprom_device)) == IGSC_SUCCESS)
    {
        if(oprom_match_dev(device, &oprom_device))
        {
            return IGSC_SUCCESS;
        }
    }

    return ret;
}

int igsc_image_oprom_release(IN struct igsc_oprom_image *img)
{
    if (img == NULL)
    {
        return IGSC_SUCCESS;
    }

    free((void *)img->buffer);
    img->buffer = NULL;
    img->buffer_len = 0;
    img->cur_device_pos = 0;

    free(img);

    return IGSC_SUCCESS;
}
