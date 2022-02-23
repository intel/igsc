/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2020 Intel Corporation
 */
#ifndef __IGSC_OPROM_H__
#define __IGSC_OPROM_H__

#include <stdint.h>
#include "igsc_version.h"

/*
 * EXPANSION ROM
 */

#define ROM_SIGNATURE 0xAA55
#define OPROM_CODE_TYPE_DATA 0xf0
#define OPROM_CODE_TYPE_CODE 0xf1

#pragma pack(1)

struct oprom_header_ext_v2 {
    uint16_t signature;
    uint16_t image_size;              /**< Image size in units of 512 bytes */
    uint32_t init_func_entry_point;
    uint16_t subsystem;
    uint16_t machine_type;
    uint16_t compression_type;
    uint8_t  reserved[8];
    uint16_t offset_to_efi_image;
    uint16_t pci_data_structure_pointer;
    uint16_t unofficial_payload_offset;
};

struct oprom_pci_data {
    uint32_t signature;
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t device_list_pointer;
    uint16_t pci_data_structure_length;
    uint32_t pci_data_structure_revision:8;
    uint32_t class_code:24;
    uint16_t image_length;
    uint16_t revision_level;
    uint8_t  code_type;
    uint8_t  last_image_indicator;
    uint16_t max_runtime_image_length;
    uint16_t conf_util_code_header_pointer;
    uint16_t DMTF_CLP_entry_point_pointer;
};

/*
 * MANIFEST
 */

#define SHA384_LEN_BYTES                   48
#define RSA_3072_KEY_LEN_BYTES             384
#define RSA_3072_PKCS_SIGNATURE_LEN_BYTES  RSA_3072_KEY_LEN_BYTES
#define RSA_3K_PSS_DATA_BLOCK_SIZE         (RSA_3072_PKCS_SIGNATURE_LEN_BYTES - SHA384_LEN_BYTES - 1)
#define RSA_3K_PSS_DB_MASK_SIZE            (7 * SHA384_LEN_BYTES)
#define MFT_SHA_SIZE                       SHA384_LEN_BYTES

struct code_partition_directory_entry {
    char     name[12];
    uint32_t offset:25;
    uint32_t huffman_compressed:1;
    uint32_t reserved:6;
    uint32_t length;
    uint8_t  reserved1[4];
};

struct code_partition_directory_header {
    uint32_t header_marker;
    uint32_t num_of_entries;
    uint8_t  header_version;
    uint8_t  entry_version;
    uint8_t  header_length;
    uint8_t  checksum;
    uint32_t partition_name;
    uint32_t crc32;
    struct   code_partition_directory_entry entries[];
};

struct mft_header {
    uint32_t header_type;
    uint32_t header_length;
    uint32_t header_version;
    uint32_t flags;
    uint32_t vendor;
    uint32_t date;
    uint32_t size;
    uint32_t header_id;
    uint32_t internal_version:8;
    uint32_t unique_build_id:24;
    struct   gsc_fwu_version version;
    uint32_t security_version;
    struct   gsc_fwu_version meu_kit_version;
    uint32_t meu_manifest_version;
    uint8_t  general_data[4];
    uint8_t  reserved3[56];
    uint32_t modulus_size;
    uint32_t exponent_size;
};

struct mft_rsa_3k_key {
    uint8_t  modulus[RSA_3072_KEY_LEN_BYTES];
    uint32_t exponent;
};

struct rsa_3072_pss_signature {
    uint8_t DataBlock[RSA_3K_PSS_DATA_BLOCK_SIZE];
    uint8_t Sha384Hash[SHA384_LEN_BYTES];
    uint8_t RightMostByte;
};

struct mft_ext_header_with_data {
    uint32_t extension_type;
    uint32_t extension_length;
    uint8_t  data[];
};

#define MAX_MODULE_NAME_SIZE 12

struct mft_signed_package_info_modules {
    uint8_t  name[MAX_MODULE_NAME_SIZE];
    uint8_t  type;
    uint8_t  hash_algo;
    uint16_t hash_size;
    uint32_t metadata_size;
    uint8_t  metadata_hash[MFT_SHA_SIZE];
};

struct mft_signed_package_info_ext {
    uint32_t extension_type;
    uint32_t extension_length;
    uint32_t package_name;
    uint32_t vcn;
    uint32_t usage_bitmap[4];
    uint32_t svn;
    uint8_t  fw_type;
    uint8_t  fw_sub_type;
    uint8_t  nvm_compatibility:2;
    uint8_t  reserved0:6;
    uint8_t  reserved1[13];
    struct mft_signed_package_info_modules modules[];
};

struct mft_partition_flags {
    uint32_t support_multiple_instances:1;
    uint32_t support_api_version_based_update:2;
    uint32_t action_on_update:1;
    uint32_t obey_full_update_rules:1;
    uint32_t ifr_enable_only:1;
    uint32_t allow_cross_point_update:1;
    uint32_t allow_cross_hotfix_update:1;
    uint32_t partial_update_only:1;
    uint32_t not_measured:1;
    uint32_t reserved:22;
};

struct mft_partition_flags_private {
    uint32_t ignore_fwu_disable_policy:1;
    uint32_t reserved:31;
};

struct mft_ifwi_part_man_ext {
    uint32_t extension_type;
    uint32_t extension_length;
    uint32_t partition_name;
    uint32_t complete_partition_length;
    uint16_t partition_version_minor;
    uint16_t partition_version_major;
    uint32_t data_format_version;
    uint32_t instance_id;
    struct mft_partition_flags partition_flags;
    uint8_t  hash_algo;
    uint8_t  hash_size;
    uint8_t  complete_partition_hash[MFT_SHA_SIZE];
    struct mft_partition_flags_private partition_flags_private;
    uint8_t  reserved[16];
};

struct mdf_global_module_id {
    uint16_t process_number;
    uint16_t vendor_id;
};

struct mdf_module_attr_ext {
    uint32_t extension_type;
    uint32_t extension_length;
    uint8_t  compression_type;
    uint8_t  encryption_type;
    uint8_t  reserved[2];
    uint32_t uncompressed_size;
    uint32_t compressed_size;
    struct mdf_global_module_id global_module_id;
    uint8_t  image_hash[MFT_SHA_SIZE];
};

struct oprom_subsystem_device_id {
    uint16_t subsys_vendor_id;
    uint16_t subsys_device_id;
};

struct mft_oprom_device_type_ext {
    uint32_t extension_type;
    uint32_t extension_length;
    struct oprom_subsystem_device_id device_ids[];
};

struct oprom_subsystem_device_4ids {
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t subsys_vendor_id;
    uint16_t subsys_device_id;
};

struct mft_oprom_device_4ids_array_ext {
    uint32_t extension_type;
    uint32_t extension_length;
    struct oprom_subsystem_device_4ids device_ids[];
};

#pragma pack()

int image_oprom_get_buffer(IN struct igsc_oprom_image *img,
                          IN enum igsc_oprom_type type,
                          OUT const uint8_t **buffer,
                          OUT size_t *buffer_len);
#endif /* !__IGSC_OPROM_H__ */
