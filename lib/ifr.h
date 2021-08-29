/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2020 Intel Corporation
 */

#ifndef __IGSC_IFR_HECI_H__
#define __IGSC_IFR_HECI_H__

#pragma pack(1)

enum gfx_diag_group
{
    GFX_DIAG_IFR_GROUP,
    GFX_DIAG_GROUP_NUM
};

enum ifr_cmd
{
    IFR_RUN_TEST_CMD,
    IFR_GET_STATUS_CMD,
    IFR_CMD_NUM
};

/**
 * @brief Bitmap ifr repairs structure
 */
struct ifr_repairs_bitmap
{
    uint32_t dss_en_repair :1;
    uint32_t array_repair  :1;
    uint32_t reserved     :30;
};

struct ifr_msg_hdr
{
    uint8_t  group_id;      /**< the target client id registered to process the message */
    uint8_t  command    :7; /**< command specific to HECI client */
    uint8_t  is_response:1; /**< response from client */
    uint8_t  reserved;      /**< reserved bit field */
    uint8_t  result;        /**< result */
};

struct ifr_run_test_req
{
    struct ifr_msg_hdr header;      /**< IFR header */
    uint8_t            test_type;   /**< Requested test to run. */
    uint8_t            tiles_map;   /**< Tiles to run the test on */
    uint16_t           reserved;    /**< Reserved for DWORD alignment */
};

struct ifr_run_test_res
{
    struct ifr_msg_hdr header;      /**< IFR header */
    uint8_t            test_type;   /**< Finished test. */
    uint8_t            tiles_map;   /**< Tiles the test ran on */
    uint8_t            run_status;  /**< Test run status */
    uint8_t            reserved;    /**< Reserved for alignment */
    uint32_t           error_code;  /**< 0 - No error. Other values - specific error code for debugging purpose */
};

struct ifr_get_status_req
{
    struct ifr_msg_hdr header;
};

struct ifr_get_status_res
{
    struct ifr_msg_hdr header;              /**< IFR header */
    uint32_t           supported_tests_map; /**< Bitmap holding the tests supported on the platform */
    uint32_t           repairs_applied_map; /**< Bitmap holding the in field repairs was applied during boot */
    uint8_t            tiles_num;           /**< Number of tiles on the specific SOC */
    uint8_t            reserved[3];         /**< Reserved for DWORD alignment */
};

#pragma pack()

#endif /* !__IGSC_IFR_HECI_H__ */
