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

#include "msvc/config.h"
#include "gcc/config.h"

#include <igsc_lib.h>
#include "igsc_oprom.h"
#include "igsc_log.h"

#include "utils.h"

/* CPD header entry indices */
#define MANIFEST_INDEX 0
#define METADATA_INDEX 2
#define MAX_INDEX      3

/* extension types */
#define MFT_EXT_TYPE_DEVICE_TYPE          7
#define MFT_EXT_TYPE_SIGNED_PACKAGE_INFO  15
#define MFT_EXT_TYPE_IFWI_PART_MAN        22
#define MDF_EXT_TYPE_MODULE_ATTR          10

#define PCI_DATA_SIGNATURE       0x52494350 /* "PCIR" */
#define PCI_VENDOR_ID            0x8086
#define PCI_DEVICE_ID            0x00
#define PCI_DATA_LENGTH          0x18
#define PCI_DATA_REVISION        0x03
#define PCI_CLASS_CODE           0x00
#define PCI_REVISION_LEVEL       0x00
#define PCI_IMG_SIZE_UNIT_SIZE   512U
#define PCI_LAST_IMAGE_IND_BIT   (1U << 7)

#define PCI_SUBSYSTEM_EFI_BOOT_SRV_DRV    0x00
#define PCI_MACHINE_TYPE_X64              0x00
#define PCI_COMPRESSION_TYPE_UNCOMPRESSED 0x00

#define MANIFEST_SIZE_MAX_VALUE               (2 * 1024) /* size in longwords */
#define METADATA_MAX_SIZE_BYTES               (5 * 1024)

#define MANIFEST_COMPRESSION_TYPE_UNCOMPRESSED 0
#define MANIFEST_COMPRESSION_TYPE_HUFFMAN      1
#define MANIFEST_COMPRESSION_TYPE_LZMA         2

#define CUR_PART_UNDEF 0
#define CUR_PART_CODE  0xC
#define CUR_PART_DATA  0xD

struct cpd_image {
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
    const uint8_t *buffer;                  /**< buffer for oprom image */
    size_t buffer_len;                      /**< length for the oprom image buffer */
    const uint8_t *code_part_ptr;           /**< pointer to the code part of the oprom update */
    uint32_t  code_part_len;                /**< length of the code part of the oprom update */
    const uint8_t *data_part_ptr;           /**< pointer to the data part of the oprom update */
    uint32_t  data_part_len;                /**< length of the data part of the oprom update */
    struct igsc_oprom_version code_version; /**< version of the oprom code partition */
    struct igsc_oprom_version data_version; /**< version of the oprom data partition */
    size_t cpd_offset;                      /**< offset of the cpd image inside the buffer */
    const uint8_t *cpd_ptr;                 /**< pointer to the start of cpd image inside the buffer */
    struct cpd_image cpd_img;               /**< cpd image structure */
    struct oprom_header_ext_v2 *v2_header;  /**< expansion header version 2 */

    uint32_t cur_device_pos;                /**< iterator's current device position */
};

#if defined(DEBUG) || defined(_DEBUG)
static void debug_print_device_type_ext(struct mft_oprom_device_type_ext *ext)
{
    struct oprom_subsystem_device_id *dev = &ext->device_ids[0];
    uint32_t len = sizeof(struct mft_ext_header_with_data);

    gsc_debug("type %u len %u\n", ext->extension_type, ext->extension_length);
    for (; len < ext->extension_length; len += sizeof(*dev))
    {
        gsc_debug("vid 0x%x did 0x%x\n",
                  dev->subsys_vendor_id, dev->subsys_device_id);
        dev++;
    }
}

static void debug_print_oprom_version(enum igsc_oprom_type type,
                                      const struct igsc_oprom_version *oprom_version)
{

    gsc_debug("OPROM %d Version: %02X %02X %02X %02X %02X %02X %02X %02X\n",
           type,
           oprom_version->version[0],
           oprom_version->version[1],
           oprom_version->version[2],
           oprom_version->version[3],
           oprom_version->version[4],
           oprom_version->version[5],
           oprom_version->version[6],
           oprom_version->version[7]);
}

#else
static inline void debug_print_device_type_ext(struct mft_oprom_device_type_ext *ext)
{
    (void)ext;
}

static void debug_print_oprom_version(enum igsc_oprom_type type,
                                      const struct igsc_oprom_version *oprom_version)
{
    (void)type;
    (void)oprom_version;
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
            return IGSC_ERROR_BAD_IMAGE;
        }

        if (header->extension_type == MFT_EXT_TYPE_DEVICE_TYPE)
        {
            if (header->extension_length < sizeof(*header) + sizeof(struct oprom_subsystem_device_id))
            {
                gsc_error("Illegal oprom cpd image (device extension %u)\n",
                           header->extension_length);
                return IGSC_ERROR_BAD_IMAGE;
            }

            img->cpd_img.dev_ext = (struct mft_oprom_device_type_ext *)header;
            debug_print_device_type_ext(img->cpd_img.dev_ext);
        }

        if (header->extension_type == MFT_EXT_TYPE_SIGNED_PACKAGE_INFO)
        {
            if (header->extension_length < sizeof(struct mft_signed_package_info_ext))
            {
                gsc_error("Illegal oprom cpd image (signed pkg info ext %u)\n",
                           header->extension_length);
                return IGSC_ERROR_BAD_IMAGE;
            }
        }

        if (header->extension_type == MFT_EXT_TYPE_IFWI_PART_MAN)
        {
            if (header->extension_length < sizeof(struct mft_ifwi_part_man_ext))
            {
                gsc_error("Illegal oprom cpd image (ifwi part ext %u)\n",
                          header->extension_length);
                return IGSC_ERROR_BAD_IMAGE;
            }
        }

        if (header->extension_type == MDF_EXT_TYPE_MODULE_ATTR)
        {
            if (header->extension_length != sizeof(struct mdf_module_attr_ext))
            {
                gsc_error("Illegal oprom cpd image (mdf module attr ext len %u)\n",
                          header->extension_length);
                return IGSC_ERROR_BAD_IMAGE;
            }

            struct mdf_module_attr_ext *attr_ext = (struct mdf_module_attr_ext*)header;
            if (attr_ext->compression_type != MANIFEST_COMPRESSION_TYPE_UNCOMPRESSED)
            {
                gsc_error("Illegal oprom cpd image (mdf module attr ext comp type %u)\n",
                          attr_ext->compression_type);
                return IGSC_ERROR_BAD_IMAGE;
            }

            gsc_debug("uncompressed_size %u end-start %lu\n",
                      attr_ext->uncompressed_size, ext_end - ext_start);
        }

        cur_offset += header->extension_length;
    }
    return 0;
}


static int image_oprom_parse_cpd(struct igsc_oprom_image *img, size_t buf_len, uint8_t type)
{
    struct code_partition_directory_header *header = (struct code_partition_directory_header *)img->cpd_ptr;
    struct cpd_image *cpd_img = &img->cpd_img;

    if (buf_len <= sizeof(*header) + header->num_of_entries * sizeof(header->entries[0]) ||
         header->num_of_entries < MAX_INDEX)
    {
        gsc_error("Illegal oprom cpd image (size/num_of_entries %lu/%u)\n",
                  buf_len, header->num_of_entries);
        return IGSC_ERROR_BAD_IMAGE;
    }

    if (header->header_marker != 0x44504324)
    {
        gsc_error("Illegal oprom cpd image (header marker 0x%x)\n", header->header_marker);
        return IGSC_ERROR_BAD_IMAGE;
    }

    debug_print_partition_directory_header(header);

    cpd_img->cpd_header = header;

    gsc_debug("manifest offset = %u\n", header->entries[MANIFEST_INDEX].offset);

    if (header->entries[MANIFEST_INDEX].offset > buf_len ||
       (header->entries[MANIFEST_INDEX].offset + sizeof(struct mft_header) > buf_len))
    {
        gsc_error("Illegal manifest offset %u)\n",
                  header->entries[MANIFEST_INDEX].offset);
        return IGSC_ERROR_BAD_IMAGE;
    }

    gsc_debug("cpd entry manifest length %u\n", header->entries[MANIFEST_INDEX].length);
    gsc_debug("cpd entry metadata length %u\n", header->entries[METADATA_INDEX].length);

    if (header->entries[MANIFEST_INDEX].length > MANIFEST_SIZE_MAX_VALUE * sizeof(uint32_t))
    {
        gsc_error("Illegal manifest length %u)\n",
                  header->entries[MANIFEST_INDEX].length);
        return IGSC_ERROR_BAD_IMAGE;
    }

    cpd_img->manifest_header = (struct mft_header *)
                                  (img->cpd_ptr + header->entries[MANIFEST_INDEX].offset);

    debug_print_manifest_header(cpd_img->manifest_header);

    if (type == CUR_PART_DATA)
    {
        gsc_memcpy_s(&img->data_version, sizeof(img->data_version),
                     &cpd_img->manifest_header->version,
                     sizeof(cpd_img->manifest_header->version));
        debug_print_oprom_version(IGSC_OPROM_DATA, &img->data_version);
    }
    else
    {
        gsc_memcpy_s(&img->code_version, sizeof(img->code_version),
                     &cpd_img->manifest_header->version,
                     sizeof(cpd_img->manifest_header->version));
        debug_print_oprom_version(IGSC_OPROM_CODE, &img->code_version);
    }

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
        return IGSC_ERROR_BAD_IMAGE;
    }
    cpd_img->public_key =  (struct mft_rsa_3k_key *)
                   (img->cpd_ptr + cpd_img->public_key_offset);

    if (cpd_img->signature_offset + sizeof(struct rsa_3072_pss_signature) > buf_len)
    {
        gsc_error("Illegal oprom cpd image (signature offset %lu)\n",
                  cpd_img->signature_offset);
        return IGSC_ERROR_BAD_IMAGE;
    }
    cpd_img->signature = (struct rsa_3072_pss_signature *)(img->cpd_ptr + cpd_img->signature_offset);

    if (cpd_img->manifest_ext_start > buf_len)
    {
        gsc_error("Illegal oprom cpd image (extensions start %lu)\n", cpd_img->manifest_ext_start);
        return IGSC_ERROR_BAD_IMAGE;

    }

    if (cpd_img->manifest_header->size < cpd_img->manifest_header->header_length)
    {
        gsc_error("Illegal oprom cpd image (header size/length %u/%u)\n",
                  cpd_img->manifest_header->size, cpd_img->manifest_header->header_length);
        return IGSC_ERROR_BAD_IMAGE;
    }

    cpd_img->manifest_ext_end = cpd_img->manifest_ext_start +
                    (cpd_img->manifest_header->size -
                     cpd_img->manifest_header->header_length) * 4;
    gsc_debug("manifest end = %lu\n", cpd_img->manifest_ext_end);

    if (cpd_img->manifest_ext_end > buf_len)
    {
        gsc_error("Illegal oprom cpd image (extensions end %lu)\n", cpd_img->manifest_ext_end);
        return IGSC_ERROR_BAD_IMAGE;
    }

    cpd_img->metadata_start = header->entries[METADATA_INDEX].offset;
    cpd_img->metadata_end = cpd_img->metadata_start + header->entries[METADATA_INDEX].length;

    if (cpd_img->metadata_start > buf_len || cpd_img->metadata_end >= buf_len)
    {
        gsc_error("Illegal oprom cpd image (metadata offset/length %u/%u)\n",
                  header->entries[METADATA_INDEX].offset,
                  header->entries[METADATA_INDEX].length);
        return IGSC_ERROR_BAD_IMAGE;
    }

    cpd_img->metadata_start = header->entries[METADATA_INDEX].offset;
    cpd_img->metadata_end = cpd_img->metadata_start + header->entries[METADATA_INDEX].length;

    if (image_oprom_parse_extensions(img, cpd_img->metadata_start, cpd_img->metadata_end))
    {
        return IGSC_ERROR_BAD_IMAGE;
    }

    return image_oprom_parse_extensions(img,
                                        cpd_img->manifest_ext_start,
                                        cpd_img->manifest_ext_end);
}

static bool verify_pci_data(struct oprom_pci_data *p_d)
{
   /* Verify PCI data const values */
   return (p_d->signature == PCI_DATA_SIGNATURE &&
           p_d->vendor_id == PCI_VENDOR_ID &&
           p_d->device_id == PCI_DEVICE_ID &&
           p_d->pci_data_structure_length == PCI_DATA_LENGTH &&
           p_d->pci_data_structure_revision == PCI_DATA_REVISION &&
           p_d->class_code == PCI_CLASS_CODE &&
           p_d->revision_level == PCI_REVISION_LEVEL);
}

static bool verify_pci_header(struct oprom_header_ext_v2 *header, size_t buf_len)
{
    if (sizeof(*header) >= buf_len ||
        header->pci_data_structure_pointer >= buf_len ||
        header->pci_data_structure_pointer + sizeof(*header) >= buf_len)
    {
        gsc_error("Illegal oprom image structure : pci_data %d %zd\n",
                  header->pci_data_structure_pointer, buf_len);
        return false;
    }

    return (header->signature == ROM_SIGNATURE);
}

/* Verify pci header values for DATA and CODE section types*/
static bool verify_pci_header_ext(struct oprom_header_ext_v2 *header)
{
    /* Verify PCI header const values */
    return (header->subsystem == PCI_SUBSYSTEM_EFI_BOOT_SRV_DRV &&
            header->machine_type == PCI_MACHINE_TYPE_X64 &&
            header->compression_type == PCI_COMPRESSION_TYPE_UNCOMPRESSED);
}

static bool contains_cpd_offset(IN struct igsc_oprom_image *img)
{
    return (img->v2_header->unofficial_payload_offset != 0);
}

int image_oprom_parse(struct igsc_oprom_image *img)
{
    struct oprom_header_ext_v2 *v2_header;
    struct oprom_pci_data *pci_data;
    size_t offset = 0;
    int ret = 0;
    uint8_t cur_part_type = CUR_PART_UNDEF;
    bool stop = false;

    /* Note that we assume here that the original oprom image may contain both */
    /* the Data and Code sections each followed by unspecified number of other sections. */
    /* Also, we assume that the first PCI header of each has the required code_type */
    /* (Data or Code). The subsequent PCI headers may have different code_type and thus */
    /* we do not parse them, instead we only add them to the correcponding part */

    if (img == NULL)
    {
        gsc_error("Wrong oprom image parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    while (offset < img->buffer_len && !stop)
    {
        v2_header = (struct oprom_header_ext_v2 *)(img->buffer + offset);
        if (!verify_pci_header(v2_header, img->buffer_len - offset))
        {
           gsc_error("Illegal oprom image pci header\n");
           return IGSC_ERROR_BAD_IMAGE;
        }

        gsc_debug("pci_data_pointer %ul\n", v2_header->pci_data_structure_pointer);

        img->v2_header = v2_header;

        pci_data = (struct oprom_pci_data *)(img->buffer + offset +
                                             v2_header->pci_data_structure_pointer);

        if (sizeof(*pci_data) > img->buffer_len - offset - v2_header->pci_data_structure_pointer)
        {
            gsc_error("Illegal oprom image - too small\n");
            return IGSC_ERROR_BAD_IMAGE;
        }

        debug_print_pci_data(pci_data);

        if (pci_data->image_length * PCI_IMG_SIZE_UNIT_SIZE > img->buffer_len - offset)
        {
            gsc_error("Illegal oprom image pci data length %u\n", pci_data->image_length);
            return IGSC_ERROR_BAD_IMAGE;
        }

        if (pci_data->code_type == OPROM_CODE_TYPE_DATA ||
            pci_data->code_type == OPROM_CODE_TYPE_CODE)
        {
            if (!verify_pci_header_ext(v2_header))
            {
               gsc_error("Illegal oprom image pci header for data/code section\n");
               return IGSC_ERROR_BAD_IMAGE;
            }
        }

        if (pci_data->last_image_indicator)
        {
            gsc_debug("Found last_image_indicator 0x%x\n", pci_data->last_image_indicator);
            stop = true;
        }

        if (pci_data->code_type == OPROM_CODE_TYPE_DATA)
        {
            img->data_part_ptr = img->buffer + offset;
            img->data_part_len = pci_data->image_length * PCI_IMG_SIZE_UNIT_SIZE;
            cur_part_type = CUR_PART_DATA;
            gsc_debug("DATA part: offset %ld len %ld\n", offset, img->data_part_len);
        }
        else if (pci_data->code_type == OPROM_CODE_TYPE_CODE)
        {
            img->code_part_ptr = img->buffer + offset;
            img->code_part_len = pci_data->image_length * PCI_IMG_SIZE_UNIT_SIZE;
            cur_part_type = CUR_PART_CODE;
            gsc_debug("CODE part: offset %ld len %ld\n", offset, img->code_part_len);
        }
        else
        {
            /* If the type is neither code nor data - just sum the lengths
             * and continue the loop - no need for parsing of this part.
             */
            if (cur_part_type == CUR_PART_DATA)
            {
                img->data_part_len += pci_data->image_length * PCI_IMG_SIZE_UNIT_SIZE;
                offset += pci_data->image_length * PCI_IMG_SIZE_UNIT_SIZE;
                gsc_debug("DATA part: type 0x%x offset %ld len %ld\n",
                          pci_data->code_type, offset, img->data_part_len);

                continue;
            }
            else if (cur_part_type == CUR_PART_CODE)
            {
                img->code_part_len += pci_data->image_length * PCI_IMG_SIZE_UNIT_SIZE;
                offset += pci_data->image_length * PCI_IMG_SIZE_UNIT_SIZE;
                gsc_debug("CODE part: type 0x%x offset %ld len %ld\n",
                          pci_data->code_type, offset, img->code_part_len);
                continue;
            }
            else
            {
                /* The first section must be either code or data */
                gsc_error("Illegal oprom image structure (pci code_type 0x%x)\n",
                          pci_data->code_type);
                return IGSC_ERROR_BAD_IMAGE;
            }
        }

        if (!verify_pci_data(pci_data))
        {
           gsc_error("Illegal oprom image pci data\n");
           return IGSC_ERROR_BAD_IMAGE;
        }

        if (v2_header->image_size != pci_data->image_length)
        {
            gsc_error("Illegal oprom image pci header/data sizes 0x%x/0x%x)\n",
                      v2_header->image_size, pci_data->image_length);
            return IGSC_ERROR_BAD_IMAGE;
        }

        if (contains_cpd_offset(img))
        {
            if (v2_header->unofficial_payload_offset >= img->buffer_len - offset)
            {
                gsc_error("Illegal oprom cpd offset\n");
                return IGSC_ERROR_BAD_IMAGE;
            }

            img->cpd_offset = v2_header->unofficial_payload_offset;
            img->cpd_ptr = img->buffer + offset + v2_header->unofficial_payload_offset;


            gsc_debug("cpd_offset %lu\n", img->cpd_offset);

            ret = image_oprom_parse_cpd(img, img->buffer_len - offset - img->cpd_offset, cur_part_type);
            if (ret != 0)
                return ret;
        }

        offset += pci_data->image_length * PCI_IMG_SIZE_UNIT_SIZE;
        gsc_debug("buffer offset %lu\n", offset);
    }
    return ret;
}

enum igsc_oprom_type image_oprom_get_type(struct igsc_oprom_image *img)
{
    enum igsc_oprom_type type = IGSC_OPROM_NONE;

    if (img->data_part_ptr && img->data_part_len)
    {
       type |= IGSC_OPROM_DATA;
    }

    if (img->code_part_ptr && img->code_part_len)
    {
       type |= IGSC_OPROM_CODE;
    }

    return type;
}

int image_oprom_get_version(struct igsc_oprom_image *img,
                            enum igsc_oprom_type type,
                            struct igsc_oprom_version *version)
{
    enum igsc_oprom_type img_type;

    img_type = image_oprom_get_type(img);
    if (img_type == IGSC_OPROM_NONE)
    {
        return IGSC_ERROR_BAD_IMAGE;
    }

    if ((img_type & type) == 0)
    {
        return IGSC_ERROR_NOT_SUPPORTED;
    }

    if (type == IGSC_OPROM_DATA)
    {
        gsc_memcpy_s(version, sizeof(*version),
                     &img->data_version,  sizeof(*version));
        return IGSC_SUCCESS;
    }
    else if (type == IGSC_OPROM_CODE)
    {
        gsc_memcpy_s(version, sizeof(*version),
                     &img->code_version,  sizeof(*version));
        return IGSC_SUCCESS;
    }

    return IGSC_ERROR_INVALID_PARAMETER;
}

uint32_t image_oprom_count_devices(struct igsc_oprom_image *img)
{
    uint32_t count = 0;

    if (img->cpd_img.dev_ext)
    {
        gsc_debug("extension_length %u\n", img->cpd_img.dev_ext->extension_length);
        count = (uint32_t)(img->cpd_img.dev_ext->extension_length -
                           sizeof(struct mft_oprom_device_type_ext)) /
                         sizeof(struct oprom_subsystem_device_id);
    }

    return count;
}

int image_oprom_get_device(struct igsc_oprom_image *img, uint32_t num,
                           struct oprom_subsystem_device_id *device)
{
    uint32_t max_num = image_oprom_count_devices(img);

    gsc_debug("max_num %u num %u\n", max_num, num);
    if (num < max_num)
    {
        gsc_memcpy_s(device, sizeof(*device),
                     &img->cpd_img.dev_ext->device_ids[num],
                     sizeof(*device));
        return IGSC_SUCCESS;
    }

    return IGSC_ERROR_DEVICE_NOT_FOUND;
}

int image_oprom_get_next(struct igsc_oprom_image *img,
                         struct igsc_oprom_device_info *device)
{
    struct oprom_subsystem_device_id _device;

    if (image_oprom_get_device(img, img->cur_device_pos, &_device) != IGSC_SUCCESS)
    {
        gsc_debug("no more devices\n");
        return IGSC_ERROR_DEVICE_NOT_FOUND;
    }
    img->cur_device_pos++;

    gsc_debug("vid 0x%x did 0x%x\n",
              _device.subsys_vendor_id, _device.subsys_device_id);

    device->subsys_vendor_id = _device.subsys_vendor_id;
    device->subsys_device_id = _device.subsys_device_id;

    return IGSC_SUCCESS;
}

void image_oprom_iterator_reset(IN struct igsc_oprom_image *img)
{
    img->cur_device_pos = 0;
}

int image_oprom_get_buffer(struct igsc_oprom_image *img,
                           enum igsc_oprom_type type,
                           const uint8_t **buffer,
                           size_t *buffer_len)
{
    enum igsc_oprom_type img_type;

    if (img == NULL || buffer == NULL || buffer_len == NULL )
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (img->buffer == NULL || img->buffer_len == 0)
    {
        return IGSC_ERROR_BAD_IMAGE;
    }

    img_type = image_oprom_get_type(img);
    if (img_type == IGSC_OPROM_NONE)
    {
        return IGSC_ERROR_BAD_IMAGE;
    }

    if ((type & img_type) == 0)
    {
        return IGSC_ERROR_NOT_SUPPORTED;
    }

    if (type == IGSC_OPROM_DATA)
    {
        *buffer = img->data_part_ptr;
        *buffer_len = img->data_part_len;
    }
    else if (type == IGSC_OPROM_CODE)
    {
        *buffer = img->code_part_ptr;
        *buffer_len = img->code_part_len;
    }
    else
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (buffer == NULL || buffer_len == 0)
    {
        return IGSC_ERROR_BAD_IMAGE;
    }

    return IGSC_SUCCESS;
}

int image_oprom_alloc_handle(struct igsc_oprom_image **img,
                             const uint8_t *buffer,
                             uint32_t buffer_len)
{
    struct igsc_oprom_image *_img;
    void *_buffer;

    if (img == NULL || buffer == NULL ||
        buffer_len <= sizeof(struct oprom_header_ext_v2))
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

void image_oprom_free_handle(struct igsc_oprom_image *img)
{
    if (img != NULL)
    {
        free((void *)img->buffer);
        memset(img, 0, sizeof(*img));
    }
    free(img);
}
