/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (C) 2019-2020 Intel Corporation
 */

/**
 * @file
 * @brief GSC Firmware Interface
 */

#ifndef __IGSC_HECI_H__
#define __IGSC_HECI_H__

#include <stdint.h>
#include "igsc_version.h"

/**
 * @brief The GSC Firmware API
 * @defgroup gsc-fw-api The GSC Firmware API
 *
 * Defines interface between the library and the Firmware
 */

/**
 * @ingroup gsc-fw-api
 * @{
 */
/** GSC firmware update status SUCCESS */
#define GSC_FWU_STATUS_SUCCESS    0x0
/** GSC firmware update status size error */
#define GSC_FWU_STATUS_SIZE_ERROR 0x5
/** GSC firmware update general failure */
#define  GSC_FWU_STATUS_FAILURE 0x9E
/** @} */

/**
 * @defgroup gsc-fw-api-hdr GSC Firmware Update API
 * @ingroup  gsc-fw-api
 * @{
 */

/**
 * @enum gsc_fwu_heci_command_id
 * @brief list of HECI commands accepted by the GSC firmware update client
 */
enum gsc_fwu_heci_command_id {
    GSC_FWU_HECI_COMMAND_ID_INVALID = 0,    /**< lower sentinel command          */
    GSC_FWU_HECI_COMMAND_ID_START,          /**< start firmware updated flow     */
    GSC_FWU_HECI_COMMAND_ID_DATA,           /**< send firmware data to device    */
    GSC_FWU_HECI_COMMAND_ID_END,            /**< last command in update          */
    GSC_FWU_HECI_COMMAND_ID_GET_VERSION,    /**< retrieve version of a firmware  */
    GSC_FWU_HECI_COMMAND_ID_NO_UPDATE,      /**< Do not wait for firmware update */
    GSC_FWU_HECI_COMMAND_ID_GET_IP_VERSION, /**< retrieve version of a partition */
    GSC_FWU_HECI_COMMAND_MAX                /**< upper sentinel command          */
};

/**
 * @enum gsc_fwu_heci_payload_type
 * @brief list of payload types for GSC firmware update commands
 */
enum gsc_fwu_heci_payload_type {
    GSC_FWU_HECI_PAYLOAD_TYPE_INVALID    = 0, /**< lower sentinel */
    GSC_FWU_HECI_PAYLOAD_TYPE_GFX_FW     = 1, /** < graphics firmware */
    GSC_FWU_HECI_PAYLOAD_TYPE_OPROM_DATA = 2, /**< oprom data partition */
    GSC_FWU_HECI_PAYLOAD_TYPE_OPROM_CODE = 3, /**< oprom code partition */
};

#pragma pack(1)

/**
 * @struct gsc_fwu_heci_header
 * @brief  GSF Firmware Update command header
 *
 * @param command_id #gsc_fwu_heci_command_id
 * @param is_response set to 1 in heci response header
 */
struct gsc_fwu_heci_header {
    uint8_t command_id;
    uint8_t is_response : 1;
    uint8_t reserved    : 7;
    uint8_t reserved2[2];
};

/**
 * @brief  GSF Firmware update command response
 *
 * @param header @ref gsc_fwu_heci_header
 * @param status GSC_FWU_STATUS_XXX
 * @param reserved
 */
struct gsc_fwu_heci_response {
    struct gsc_fwu_heci_header header;
    uint32_t                   status;
    uint32_t                   reserved;
};
/** @} */

/**
 * @defgroup gsc_fw_api_ver GSC Firmware Update get version API
 * @ingroup  gsc-fw-api
 * @{
 */

/**
 * @enum gsc_fwu_heci_partition_version
 * @brief list of partition versions for GSC get version command
 */
enum gsc_fwu_heci_partition_version {
    GSC_FWU_HECI_PART_VERSION_INVALID    = 0, /**< lower sentinel */
    GSC_FWU_HECI_PART_VERSION_GFX_FW     = 1, /**< graphics firmware */
    GSC_FWU_HECI_PART_VERSION_OPROM_DATA = 2, /**< oprom data partition */
    GSC_FWU_HECI_PART_VERSION_OPROM_CODE = 3, /**< oprom code partition */
};

/**
 * @brief get version request
 *
 * @param header @ref gsc_fwu_heci_header
 * @param partition firmware partition type @ref gsc_fwu_heci_partition_version
 */
struct gsc_fwu_heci_version_req {
    struct gsc_fwu_heci_header header;
    uint32_t                   partition;
};

/**
 * @brief get version response
 *
 * @param response @ref gsc_fwu_heci_response
 * @param partition firmware partition type @ref gsc_fwu_heci_partition_version
 * @param version_length version length
 * @param version[] version
 */
struct gsc_fwu_heci_version_resp {
    struct gsc_fwu_heci_response response;
    uint32_t                     partition;
    uint32_t                     version_length;
    uint8_t                      version[];
};

/** @} */

/**
 * @defgroup gsc-fw-api-update GSC Firmware Update protocol
 * @ingroup  gsc-fw-api
 * @{
 */

/* TODO: add better definitions */
/** Firmware status register 1 FW update is in idle state */
#define HECI1_CSE_FS_FWUPDATE_STATE_IDLE     0
/** FW initialization completed: all modules initialized */
#define HECI1_CSE_FS_INITSTATE_COMPLETED     1
/** Firmware status register 2  value - firmware update state */
#define HECI1_CSE_GS1_PHASE_FWUPDATE         7

enum gsc_fwu_heci_metadata_version {
    /** GSC Firmware Update metadata version for no metadata case */
    GSC_FWU_HECI_METADATA_VERSION_NONE = 0,
    /** GSC Firmware Update metadata version 1 */
    GSC_FWU_HECI_METADATA_VERSION_1    = 1,
    /** GSC Firmware Update metadata version Upper Sentinel */
    GSC_FWU_HECI_METADATA_VERSION_MAX,
};




/**
 * @struct gsc_fwu_heci_image_metadata
 *
 * @brief The structure of metadata is determined
 *        according to the format version.
 * @see enum gsc_fwu_heci_metadata_version
 * e.g. GSC_FWU_HECI_METADATA_VERSION_1 -> gsc_fwu_image_metadata_v1_t
 */
struct gsc_fwu_heci_image_metadata {
   uint32_t metadata_format_version; /**< meta data version */
   uint8_t  metadata[];              /**< gsc_fwu_image_metadata_vX_t */
};

/**
 * @struct gsc_fwu_heci_start_req
 *
 * @brief firmware update start message
 *
 * @param header @ref gsc_fwu_heci_header
 * @param update_img_length overall message length
 * @param payload_type firmware payload type @ref gsc_fwu_heci_payload_type
 * @param flags start message flags (set to 0)
 * @param reserved[8] reserved
 * @param data @ref gsc_fwu_heci_image_metadata
 * @see enum gsc_fwu_heci_payload_type
 */
struct gsc_fwu_heci_start_req {
    struct gsc_fwu_heci_header header;
    uint32_t                   update_img_length;
    uint32_t                   payload_type;
    uint32_t                   flags;
    uint32_t                   reserved[8];
    uint8_t                    data[];
};

/**
 * @brief firmware update start response
 *
 * @param response @ref gsc_fwu_heci_response
 */
struct gsc_fwu_heci_start_resp {
    struct gsc_fwu_heci_response response;
};

/**
 * @brief firmware update data
 *
 * @param header @ref gsc_fwu_heci_header
 * @param payload_type firmware payload type @ref gsc_fwu_heci_payload_type
 * @param reserved reserved
 * @param data[] firmware payload fragment
 */
struct gsc_fwu_heci_data_req {
    struct gsc_fwu_heci_header header;
    uint32_t                   data_length;
    uint32_t                   reserved;
    uint8_t                    data[];
};

/**
 * @brief firmware update data message response
 *
 * @param response @ref gsc_fwu_heci_response
 */
struct gsc_fwu_heci_data_resp {
    struct gsc_fwu_heci_response response;
};

/**
 * @brief firmware update end message
 *
 * @param header @ref gsc_fwu_heci_header
 * @param reserved
 */
struct gsc_fwu_heci_end_req {
    struct gsc_fwu_heci_header header;
    uint32_t                   reserved;
};

/**
 * @brief firmware update end message response
 *
 * @param response @ref gsc_fwu_heci_response
 */
struct gsc_fwu_heci_end_resp {
    struct gsc_fwu_heci_response response;
};

/** @} */

#pragma pack()

#endif /* !__IGSC_HECI_H__ */
