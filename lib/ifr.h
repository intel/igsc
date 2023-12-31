/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2020-2022 Intel Corporation
 */

#ifndef __IGSC_IFR_HECI_H__
#define __IGSC_IFR_HECI_H__

#include "igsc_heci.h"

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
    GFSP_CORR_MEM_STAT_CMD = 1,      /**< Get memory correction status */
    GFSP_MEM_ERR_MITIG_STAT_CMD = 2, /**< Get memory error mitigation status */
    GFSP_MUN_MEM_ERR_CMD = 3,        /**< Get number of memory errors */
    GFSP_MEM_PRP_STAT_CMD = 4,       /**< Get memory PPR status */
    GFSP_MEM_ID_CMD = 5,             /**< Get memory ID */
    GFSP_SET_ECC_CFG_CMD = 8,        /**< Set ECC Configuration */
    GFSP_GET_ECC_CFG_CMD = 9,        /**< Get ECC Configuration */
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

#define GFX_SRV_MKHI_GET_IP_VERSION_CMD 0x02
#define GFX_SRV_MKHI_LATE_BINDING_CMD 0x12
#define GFX_SRV_MKHI_RUN_IFR_TEST_CMD   0x30
#define GFX_SRV_MKHI_GET_IFR_STATUS_CMD 0x31
#define GFX_SRV_MKHI_GET_IFR_GENERAL_INFO_CMD 0x32
#define GFX_SRV_MKHI_GET_IFR_TILE_REPAIR_INFO_CMD 0x36

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

struct gfsp_get_memory_ppr_status_req {
    struct mkhi_msg_hdr header; /* mkhi heci header */
    uint32_t gfsp_heci_header;  /* gfsp header */
};

struct gfsp_device_mbist_ppr_status {
    uint32_t mbist_test_status;           /* 0 – Pass, Any set bit represents that MBIST on the matching channel has failed */
    uint32_t num_of_ppr_fuses_used_by_fw; /* Number of PPR fuses used by the FW */
    uint32_t num_of_remaining_ppr_fuses;  /* Number of remaining PPR fuses */
};

struct gfsp_get_memory_ppr_status_res {
    struct mkhi_msg_hdr header;                   /* 0x31 for GFSP MKHI command */
    uint32_t gfsp_heci_header;                    /* 4 for Get memory PPR status */
    uint8_t  boot_time_memory_correction_pending; /* 0 - No pending boot time memory correction, */
                                                  /* 1 - Pending boot time memory correction */
    uint8_t  ppr_mode;                            /* 0 – PPR enabled, 1 – PPR disabled, 2 – PPR test mode, */
                                                  /* 3 – PPR auto run on next boot */
    uint8_t  test_run_status;
    uint8_t  reserved;
    uint32_t ras_ppr_applied;                     /* 0 - ppr not applied, 1 - ppr applied, 2 - ppr exhausted */
    uint32_t mbist_completed;                     /* 0 - Not Applied, Any set bit represents mbist completed */
    uint32_t num_devices;                         /* real number of device in the array - in Xe_HP SDV / PVC - should be up to 8 */
    struct   gfsp_device_mbist_ppr_status device_mbist_ppr_status[]; /* Array length is num_devices */
};

/**
 * @brief request to get memory error mitigation status
 *
 * @param header @ref mkhi_msg_hdr, MKHI_GROUP_ID_GFSP for GFSP MKHI command
 * @param gfsp_heci_header contains enum gfsp_cmd GFSP_MEM_ERR_MITIG_STAT_CMD
 */
struct gfsp_get_mem_err_mitigation_status_req {
    struct mkhi_msg_hdr header;
    uint32_t gfsp_heci_header;
};

enum gfsp_health_indicators {
    GFSP_HEALTH_INDICATOR_HEALTHY = 0,
    GFSP_HEALTH_INDICATOR_DEGRADED = 1,
    GFSP_HEALTH_INDICATOR_CRITICAL = 2,
    GFSP_HEALTH_INDICATOR_REPLACE  = 3
};

/* Max tile per card */
#define GFSP_MAX_TILES 4

/**
 * @brief response to the get memory error mitigation status request
 *
 * @param header @ref mkhi_msg_hdr, MKHI_GROUP_ID_GFSP for GFSP MKHI command
 * @param gfsp_heci_header contains enum gfsp_cmd GFSP_MEM_ERR_MITIG_STAT_CMD
 * @param boot_time_memory_correction_pending 0 - No pending boot time memory correction,
 *                                            1 - Pending boot time memory correction
 * @param bank_sparing_applied Bank Sparing status 0 - not applied, 1 - applied, 2 – exhausted
 * @param health_indicator contains enum gfsp_health_indicators
 * @param reserved reserved field
 * @param max_num_of_tiles max number of tiles on the card
 * @param error_mitigation_status A per tile error mitigation status
 * @param error_mitigation_status A per tile health mitigation status
 *
 */
struct gfsp_get_mem_err_mitigation_status_res {
    struct mkhi_msg_hdr header;
    uint32_t gfsp_heci_header;
    uint8_t  boot_time_memory_correction_pending;
    uint8_t  bank_sparing_applied;
    uint8_t  health_indicator; /**< enum gfsp_health_indicators */
    uint8_t  reserved;
    uint32_t max_num_of_tiles;
    uint8_t  error_mitigation_status[GFSP_MAX_TILES];
    uint8_t  health_mitigation_status[GFSP_MAX_TILES];
};

/* IFR extended commands */

enum {
    IFR_TEST_ARRAY_AND_SCAN = 1,
    IFR_TEST_MEMORY_PPR = 2
};

/* New ifr run test request */
struct ifr_run_test_ext_req {
    struct mkhi_msg_hdr header; /**< IFR header */
    uint8_t test; /**< IFR_TEST_ARRAY_AND_SCAN or IFR_TEST_MEMORY_PPR */
    uint8_t reserved[11];
};

enum ifr_pending_reset {
    IFR_PENDING_RESET_NONE,
    IFR_PENDING_RESET_SHALLOW,
    IFR_PENDING_RESET_DEEP
};

/* New ifr run test response for array_and_scan test command */
struct ifr_run_test_array_scan_res {
    struct mkhi_msg_hdr               header;
    uint8_t                           finished_test; /**< ARRAY_AND_SCAN */
    uint8_t                           reserved1[3];
    uint8_t                           status;
    uint8_t                           extended_status;
    uint8_t                           reserved2[2];
    uint8_t                           pending_reset; /**< enum ifr_pending_reset */
    uint8_t                           reserved3[3];
    uint32_t                          error_code;
    uint32_t                          reserved4;
};

/* New ifr run test response for memory ppr test command */
struct ifr_run_test_mem_ppr_res {
    struct mkhi_msg_hdr header;
    uint8_t             finished_test; /**< MEMORY_PPR */
    uint8_t             reserved1[3];
    uint8_t             status;
    uint8_t             reserved2[3];
    uint8_t             pending_reset; /**< enum ifr_pending_reset */
    uint8_t             reserved3[3];
    uint32_t            error_code;
    uint32_t            reserved4;
};

/* New ifr get status request */
struct ifr_get_status_ext_req {
    struct mkhi_msg_hdr header;
};

/* New ifr get status response */
struct ifr_get_status_ext_res {
    struct mkhi_msg_hdr header;
    uint32_t            supported_tests;
    uint32_t            hw_capabilities;
    uint32_t            ifr_applied;
    uint8_t             pending_reset; /**< enum ifr_pending_reset */
    uint8_t             reserved1[3];
    uint32_t            prev_errors;
    uint32_t            reserved2[2];

};

/* Get ifr general info request */
struct ifr_get_general_info_req {
    struct mkhi_msg_hdr header;
    uint8_t             reserved[8];
};

/* Get ifr general info response */
struct ifr_get_general_info_res {
    struct mkhi_msg_hdr header;
    uint16_t            supported_tiles; /**< Number of supported tiles */
    uint8_t             reserved[26];
};

/* Get ifr tile repair info request */
struct ifr_get_tile_repair_info_req {
    struct mkhi_msg_hdr header;
    uint16_t            tile_idx; /**< The index of the tile the info is requested to */
    uint8_t             reserved[6];
};

/* Get ifr tile repair info response */
struct ifr_get_tile_repair_info_res {
    struct mkhi_msg_hdr header;
    uint16_t            requested_tile;                 /**< Index of the requested tile */
    uint8_t             reserved1[2];
    uint16_t            used_array_repair_entries;      /**< Number of array repair entries used by FW */
    uint16_t            available_array_repair_entries; /**< Number of available array repair entries */
    uint16_t            failed_dss;                     /**< Number of failed DSS */
    uint8_t             reserved2[18];
};

/* Set ECC Configuration Request */
struct gfsp_set_ecc_config_req {
    struct mkhi_msg_hdr header;
    uint32_t gfsp_heci_header; /* contains enum gfsp_cmd */
    uint8_t ecc_state;         /**< ECC State: 0 - Disable 1 - Enable */
    uint8_t reserved[3];
};

struct gfsp_set_ecc_config_res {
    struct mkhi_msg_hdr header;
    uint32_t gfsp_heci_header; /* contains enum gfsp_cmd */
    uint8_t cur_ecc_state;     /**< Current ECC State: 0 - Disable 1 - Enable */
    uint8_t pen_ecc_state;     /**< Pending ECC State: 0 - Disable 1 - Enable */
    uint8_t reserved[2];
};

/* Get ECC Configuration Request */
struct gfsp_get_ecc_config_req {
    struct mkhi_msg_hdr header;
    uint32_t gfsp_heci_header; /* contains enum gfsp_cmd */
};

struct gfsp_get_ecc_config_res {
    struct mkhi_msg_hdr header;
    uint32_t gfsp_heci_header; /* contains enum gfsp_cmd */
    uint8_t cur_ecc_state;     /**< Current ECC State: 0 - Disable 1 - Enable */
    uint8_t pen_ecc_state;     /**< Pending ECC State: 0 - Disable 1 - Enable */
    uint8_t reserved[2];
};

/* Generic gfsp Request */
struct gfsp_generic_req {
    struct mkhi_msg_hdr header;
    uint32_t gfsp_heci_header;
    uint8_t buffer[];
};

struct gfsp_generic_res {
    struct mkhi_msg_hdr header;
    uint32_t gfsp_heci_header;
    uint8_t buffer[];
};

/**
 * @defgroup gsc_fw_api_ver GSC Firmware get version API
 * @ingroup  gsc-fw-api
 * @{
 */

/**
 * @enum gsc_heci_partition_version
 * @brief list of partition versions for GSC get version command
 */
enum gsc_heci_partition_version {
    MKHI_GET_IP_VERSION_INVALID    = 0, /**< lower sentinel */
    MKHI_GET_IP_VERSION_EXTERNAL   = 1, /**< graphics firmware */
    MKHI_GET_IP_VERSION_PSC        = 4, /**< PSC version */
    MKHI_GET_IP_VERSION_IFR        = 5, /**< IFR Binary version */
};

/**
 * @brief get version request
 *
 * @param header @ref mkhi_msg_header
 * @param partition firmware partition type @ref gsc_heci_partition_version
 */
struct gsc_heci_version_req {
    struct mkhi_msg_hdr      header;
    uint32_t                 partition;
};

/**
 * @brief get version response
 *
 * @param header @ref mkhi_msg_header
 * @param partition firmware partition type @ref gsc_heci_partition_version
 * @param version_length version length
 * @param version[] version
 */
struct gsc_heci_version_resp {
    struct mkhi_msg_hdr      header;
    uint32_t                 partition;
    uint32_t                 version_length;
    uint8_t                  version[];
};

/** @} */

/**
 * @defgroup csc_fw_api CSC Firmware send Late Binding Command
 * @ingroup  csc-fw-api
 * @{
 */

/**
 * @brief late binding request
 *
 * @param header @ref mkhi_msg_header
 * @param type type of the late binding payload
 * @param flags flags to be passed to the firmware
 * @param reserved[] reserved field
 * @param payload_size size of the payload data
 * @param payload data to be sent to the firmware
 */
struct csc_heci_late_binding_req
{
   struct mkhi_msg_hdr header;
   uint32_t            type;
   uint32_t            flags;
   uint32_t            reserved[2];
   uint32_t            payload_size; // In bytes
   uint8_t             payload[];
};

/**
 * @brief late binding request
 *
 * @param header @ref mkhi_msg_header
 * @param type type of the late binding payload
 * @param reserved[] reserved field
 * @param status status of the late binding command execution by firmware
 */
struct csc_heci_late_binding_resp
{
   struct mkhi_msg_hdr header;
   uint32_t            type;
   uint32_t            reserved[2];
   uint32_t            status;
};
/** @} */

#pragma pack()

#endif /* !__IGSC_IFR_HECI_H__ */
