/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2021-2024 Intel Corporation
 */

#ifndef __IGSC_FWDATA_PARSER_H__
#define __IGSC_FWDATA_PARSER_H__

#include "igsc_system.h"

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

struct mft_fwdata_device_ids_ext {
    uint32_t extension_type;
    uint32_t extension_length;
    struct igsc_fwdata_device_info device_ids[];
};

struct mft_fwdata_update_ext {
    uint32_t extension_type;
    uint32_t extension_length;
    uint32_t oem_manuf_data_version;
    uint16_t major_vcn;
    uint16_t flags;
};

struct igsc_fwdata_image {
    const uint8_t *buffer;                  /**< buffer for fw data image */
    uint32_t buffer_len;                      /**< length for the fw data image buffer */
    struct gsc_fwu_img_layout layout;
    const uint8_t *cpd_ptr;
    struct cpd_image cpd_img;
    struct mft_fwdata_update_ext *fwdata_ext;
    struct mft_fwdata_device_ids_ext *dev_ids_ext;
    uint32_t cur_device_pos;
};

struct igsc_fwdata_metadata {
    uint32_t oem_manuf_data_version;
    uint16_t major_fw_version;
    uint16_t major_vcn;
    uint8_t  key_index;
    uint8_t  reserved1[3];
    uint32_t data_arb_svn;
    uint8_t  reserved2[16];
};

int image_fwdata_alloc_handle(struct igsc_fwdata_image **img,
                              const uint8_t *buffer, uint32_t buffer_len);
void image_fwdata_free_handle(struct igsc_fwdata_image *img);

int image_fwdata_parse(struct igsc_fwdata_image *img);

int image_fwdata_get_version(struct igsc_fwdata_image *img,
                             struct igsc_fwdata_version *version);
int image_fwdata_get_version2(struct igsc_fwdata_image* img,
                              struct igsc_fwdata_version2* version);

uint32_t image_fwdata_count_devices(struct igsc_fwdata_image *img);

int image_fwdata_get_device(struct igsc_fwdata_image *img, uint32_t num,
                            struct igsc_fwdata_device_info *device);
int image_fwdata_get_next(struct igsc_fwdata_image *img,
                          struct igsc_fwdata_device_info *device);

void image_fwdata_iterator_reset(struct igsc_fwdata_image *img);

int image_fwdata_get_buffer(struct igsc_fwdata_image *img,
                            const uint8_t **buffer,
                            uint32_t *buffer_len);
#endif /* !__IGSC_FWDATA_PARSER_H__ */

