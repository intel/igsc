/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2020 Intel Corporation
 */
#ifndef __IGSC_SYSTEM_H__
#define __IGSC_SYSTEM_H__

#include <stdint.h>
#include "igsc_version.h"

#define FPT_HEADER_MARKER  0x54504624  /**< "$FPT" */
#define FPT_HEADER_VERSION 0x21
#define FPT_ENTRY_VERSION  0x10
#define FPT_MAX_ENTERIES   56
#define FPT_HEADER_LENGTH  32
#define GSC_FWU_IUP_NUM 2

#define INFO_HEADER_MARKER (0x4f464e49)
#define FWIM_HEADER_MARKER (0x4d495746)
#define IMGI_HEADER_MARKER (0x49474d49)
#define SDTA_HEADER_MARKER (0x41544447)
#define CKSM_HEADER_MARKER (0x4d534b43)

#pragma pack(1)

struct gsc_fwu_fpt_header {
	uint32_t header_marker;    /**< Header marker, must be 0x54504624 ("$FPT") for this version (see FPT_HEADER_MARKER) */
	uint32_t num_of_entries;   /**< Number of entries following the header */
	uint8_t  header_version;   /**< Must be 0x20 for this version (see FPT_HEADER_VERSION) */
	uint8_t  entry_version;    /**< Must be 0x10 for this version (see FTP_ENTRY_VERSION) */
	uint8_t  header_length;    /**< In bytes, fixed (see FPT_HEADER_LENGTH) */
	uint8_t  redundant :1;     /**< Set to '1' if back up copy of FPT is present */
	uint8_t  reserved  :7;     /**< Reserved Field */
	uint16_t ticks_to_add;     /**< Used by data file system for wear-out prevention attributes */
	uint16_t tokens_to_add;    /**< Used by data file system for wear-out prevention attributes */
	uint32_t uma_size;         /**< Size of UMA to be requested from BIOS (to be deprecated) */
	uint32_t crc32;            /**< CRC32 that covers FPT Header + FPT Entries */
	uint16_t fitc_major;       /**< Major version number of tool that created the image */
	uint16_t fitc_minor;       /**< Minor version number of tool that created the image */
	uint16_t fitc_hotfix;      /**< Hotfix version number of tool that created the image */
	uint16_t fitc_build;       /**< Build version number of tool that created the image */
};

struct gsc_fwu_fpt_entry {
	uint32_t partition_name;   /**< ASCII short name for the partition */
	uint8_t  reserved1[4];     /**< Must be 0 */
	uint32_t offset;           /**< Offset of partition from beginning of CSE region */
	uint32_t length;           /**< Partition length, in bytes */
	uint8_t  reserved2[12];    /**< Must be 0 */
	struct
	{
		uint32_t partition_type     : 7;  /**< Bits 0:6 - partition type. 0 for code, 1 for data, 2 for GLUT (see FPT_ENTRY_PARTITION_TYPE_xxx) */
		uint32_t copy_to_dram_cache : 1;  /**< Bit 7 - partition should be copied to persistent DRAM cache */
		uint32_t reserved1          : 7;  /**< Bits 8:14 reserved, set to 0 */
		uint32_t built_with_length1 : 1;  /**< Bit 15     - Built With Length (indication to flash building tool) */
		uint32_t built_with_length2 : 1;  /**< Bit 16     - Built With Length (indication to flash building tool) */
		uint32_t reserved2          : 7;  /**< Bits 17:23 - reserved, set to 0 */
		uint32_t entry_valid        : 8;  /**< Bits 24:31 - entry valid (0xff - invalid, any other value- valid) */
	} partition_flags;
};

/*! Structure represents a GSC FW sub-partition such as FTPR, RBEP
 */
struct gsc_fwu_fw_image_data {
	struct gsc_fwu_version fw_version;
	uint16_t               flags;
	uint8_t                fw_type;
	uint8_t                fw_sub_type;
	uint32_t               arb_svn;
	uint32_t               tcb_svn;
	uint32_t               vcn;
};

struct gsc_fwu_iup_data {
	uint32_t              iup_name;
	uint16_t              flags;
	uint16_t              reserved;
	uint32_t              svn;
	uint32_t              vcn;
};

struct gsc_fwu_image_data {
	struct gsc_fwu_fw_image_data fw_img_data;               /**< FTPR data */
	struct gsc_fwu_iup_data      iup_data[GSC_FWU_IUP_NUM]; /**< IUP Data */
};

struct gsc_fwu_image_metadata_v1 {
	struct gsc_fwu_external_version overall_version; /**< The version of the overall IFWI image, i.e. the combination of IPs */
	struct gsc_fwu_image_data       update_img_data; /**< Sub-partitions */
};

struct gsc_fwu_fpt_img {
	struct gsc_fwu_fpt_header header;
	struct gsc_fwu_fpt_entry  entry[];
};

#define FWU_GWS_IMAGE_INFO_FORMAT_VERSION 0x1

#define  GSC_IFWI_TAG_SOC2_SKU_BIT BIT(0)
#define  GSC_IFWI_TAG_SOC3_SKU_BIT BIT(1)
#define  GSC_IFWI_TAG_SOC1_SKU_BIT BIT(2)
#define  GSC_IFWI_TAG_SOC4_SKU_BIT BIT(3)

/**
 * @brief firmware update image info
 *
 * @param format_version image info format version
 * @param instance_id bitmask of supported skus
 * @param reserved
 */
struct fwu_gws_image_info {
    uint32_t format_version;
    uint32_t instance_id;
    uint32_t reserved[14];
};

#pragma pack()

enum FWU_FPT_ENTRY {
    FWU_FPT_ENTRY_IMAGE_INFO,
    FWU_FPT_ENTRY_FW_IMAGE,
    FWU_FPT_ENTRY_IMAGE_INSTANCE,
    FWU_FPT_ENTRY_FW_DATA_IMAGE,
    FWU_FPT_ENTRY_CKSM,
    FWU_FPT_ENTRY_NUM
};

struct gsc_fwu_img_entry {
    const uint8_t *content;
    uint32_t size;
};

struct gsc_fwu_img_layout {
    struct gsc_fwu_img_entry table[FWU_FPT_ENTRY_NUM];
};


#define MANDATORY_ENTRY_BITMASK \
    (BIT(FWU_FPT_ENTRY_IMAGE_INFO) | BIT(FWU_FPT_ENTRY_FW_IMAGE))

#define MANDATORY_FWDATA_ENTRY_BITMASK \
    (BIT(FWU_FPT_ENTRY_IMAGE_INFO) | BIT(FWU_FPT_ENTRY_FW_DATA_IMAGE))


#endif /* !__IGSC_SYSTEM_H__ */
