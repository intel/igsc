/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2020-2021 Intel Corporation
 */

#ifndef __IGSC_IFR_HECI_H__
#define __IGSC_IFR_HECI_H__

#pragma pack(1)

enum gfx_diag_group_id {
    GFX_DIAG_IFR_GROUP,
    GFX_DIAG_GROUP_NUM
};

enum ifr_cmd {
    IFR_RUN_TEST_CMD,
    IFR_GET_STATUS_CMD,
    IFR_CMD_NUM
};

enum gfsp_cmd {
    GFSP_CORR_MEM_STAT_CMD      = 1, /**< Get memory correction status */
    GFSP_MEM_ERR_MITIG_STAT_CMD = 2, /**<  Get memory error mitigation status */
    GFSP_MUN_MEM_ERR_CMD        = 3, /**< Get number of memory errors */
    GFSP_MEM_PRP_STAT_CMD       = 4, /**< Get memory PPR status */
    GFSP_MEM_ID_CMD             = 5, /**< Get memory ID */
    GFSP_MEM_NUM
};

struct ifr_msg_hdr {
    uint8_t  group_id;      /**< the target client id registered to process the message */
    uint8_t  command    :7; /**< command specific to HECI client */
    uint8_t  is_response:1; /**< response from client */
    uint8_t  reserved;      /**< reserved bit field */
    uint8_t  result;        /**< result */
};

enum mkhi_group_id {
    MKHI_GROUP_ID_GFX_SRV  = 0x30,
    MKHI_GROUP_ID_GFSP = 0x31,
};

struct mkhi_msg_hdr {
    uint8_t  group_id;      /**< the target client id registered to process the message */
    uint8_t  command    :7; /**< command specific to HECI client */
    uint8_t  is_response:1; /**< response from client */
    uint8_t  reserved;      /**< reserved bit field */
    uint8_t  result;        /**< result */
};

/**
 * @brief Bitmap ifr repairs structure
 */
struct ifr_repairs_bitmap {
    uint32_t dss_en_repair :1;
    uint32_t array_repair  :1;
    uint32_t reserved     :30;
};

struct ifr_run_test_req {
    struct ifr_msg_hdr header;      /**< IFR header */
    uint8_t            test_type;   /**< Requested test to run. */
    uint8_t            tiles_map;   /**< Tiles to run the test on */
    uint16_t           reserved;    /**< Reserved for DWORD alignment */
};

struct ifr_run_test_res {
    struct ifr_msg_hdr header;      /**< IFR header */
    uint8_t            test_type;   /**< Finished test. */
    uint8_t            tiles_map;   /**< Tiles the test ran on */
    uint8_t            run_status;  /**< Test run status */
    uint8_t            reserved;    /**< Reserved for alignment */
    uint32_t           error_code;  /**< 0 - No error. Other values - specific error code for debugging purpose */
};

struct ifr_get_status_req {
    struct ifr_msg_hdr header;      /**< IFR header */
};

struct ifr_get_status_res {
    struct ifr_msg_hdr header;              /**< IFR header */
    uint32_t           supported_tests_map; /**< Bitmap holding the tests supported on the platform */
    uint32_t           repairs_applied_map; /**< Bitmap holding the in field repairs was applied during boot */
    uint8_t            tiles_num;           /**< Number of tiles on the specific SOC */
    uint8_t            reserved[3];         /**< Reserved for DWORD alignment */
};

struct gfsp_get_num_memory_errors_req {
    struct mkhi_msg_hdr header;
    uint32_t gfsp_heci_header;              /* defined by enum gfsp_cmd */
};

struct gfsp_num_memory_errors_per_tile {
    uint32_t num_memory_correctable_errors;   /**< Correctable memory errors on this boot and tile */
    uint32_t num_memory_uncorrectable_errors; /**< Uncorrectable memory errors on this boot and tile */
};

struct gfsp_get_num_memory_errors_res {
    struct mkhi_msg_hdr header;
    uint32_t gfsp_heci_header;                 /* defined by enum gfsp_cmd */
    uint32_t tiles_num;                        /* In Xe_HP SDV - 4, In PVC - 2 */
    struct gfsp_num_memory_errors_per_tile num_memory_errors[];
};

#pragma pack()

#endif /* !__IGSC_IFR_HECI_H__ */
