/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (C) 2019-2021 Intel Corporation
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
#define GSC_FWU_STATUS_SUCCESS                        0x0
/** GSC firmware update status size error */
#define GSC_FWU_STATUS_SIZE_ERROR                     0x5
/** GSC oprom structure is invalid error */
#define GSC_FWU_STATUS_UPDATE_OPROM_INVALID_STRUCTURE 0x1035
/** GSC Update oprom section does not exists error */
#define GSC_FWU_STATUS_UPDATE_OPROM_SECTION_NOT_EXIST 0x1032
/** GSC firmware update status invalid command error */
#define GSC_FWU_STATUS_INVALID_COMMAND                0x8D
/** GSC firmware update status invalid param error */
#define GSC_FWU_STATUS_INVALID_PARAMS                 0x85
/** GSC firmware update general failure */
#define  GSC_FWU_STATUS_FAILURE                       0x9E
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
    GSC_FWU_HECI_COMMAND_ID_INVALID = 0,              /**< lower sentinel command           */
    GSC_FWU_HECI_COMMAND_ID_START,                    /**< start firmware updated flow      */
    GSC_FWU_HECI_COMMAND_ID_DATA,                     /**< send firmware data to device     */
    GSC_FWU_HECI_COMMAND_ID_END,                      /**< last command in update           */
    GSC_FWU_HECI_COMMAND_ID_GET_VERSION,              /**< retrieve version of a firmware   */
    GSC_FWU_HECI_COMMAND_ID_NO_UPDATE,                /**< Do not wait for firmware update  */
    GSC_FWU_HECI_COMMAND_ID_GET_IP_VERSION,           /**< retrieve version of a partition  */
    GSC_FWU_HECI_COMMAND_ID_GET_CONFIG,               /**< get hardwre config               */
    GSC_FWU_HECI_COMMAND_ID_STATUS,                   /**< get status of most recent update */
    GSC_FWU_HECI_COMMAND_ID_GET_GFX_DATA_UPDATE_INFO, /**< get signed firmware data info    */
    GSC_FWU_HECI_COMMAND_ID_GET_SUBSYSTEM_IDS,        /**< get subsystem ids (vid/did)      */
    GSC_FWU_HECI_COMMAND_MAX                          /**< upper sentinel command           */
};

/**
 * @enum gsc_fwu_heci_payload_type
 * @brief list of payload types for GSC firmware update commands
 */
enum gsc_fwu_heci_payload_type {
    GSC_FWU_HECI_PAYLOAD_TYPE_INVALID    = 0, /**< lower sentinel                       */
    GSC_FWU_HECI_PAYLOAD_TYPE_GFX_FW     = 1, /**< graphics firmware                    */
    GSC_FWU_HECI_PAYLOAD_TYPE_OPROM_DATA = 2, /**< oprom data partition                 */
    GSC_FWU_HECI_PAYLOAD_TYPE_OPROM_CODE = 3, /**< oprom code partition                 */
    GSC_FWU_HECI_PAYLOAD_TYPE_IAF_PSC    = 4, /**< acclerator fabric configuration data */
    GSC_FWU_HECI_PAYLOAD_TYPE_FWDATA     = 5, /**< firmware data partition              */
};

#pragma pack(1)

/**
 * @struct mkhi_msg_hdr
 * @brief  MKHI command header
 *
 * @param group_id the target client id registered to process the message
 * @param command command specific to HECI client
 * @param is_response set to 1 in heci response header
 * @param reserved reserved bit field
 * @param result result of the mkhi command
 */
struct mkhi_msg_hdr {
    uint8_t  group_id;
    uint8_t  command    :7;
    uint8_t  is_response:1;
    uint8_t  reserved;
    uint8_t  result;
};

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

/**
 * @brief fwdata get version request
 *
 * @param header @ref gsc_fwu_heci_header
 * @param reserved
 */
struct gsc_fw_data_heci_version_req {
    struct gsc_fwu_heci_header header;
    uint32_t                   reserved[2];
};

/**
 * @brief fwdata get version response
 *
 * @param response @ref gsc_fwu_heci_response
 * @param format_version response format version
 * @param oem_manuf_data_version_nvm oem version in nvm
 * @param oem_manuf_data_version_fitb oem version in fitb
 * @param major_version project major version
 * @param oem_manuf_data_version_fitb_valid
 * @param flags fwdata get version flags
 * @param reserved
 */
struct gsc_fw_data_heci_version_resp {
    struct gsc_fwu_heci_response response;
    uint32_t                     format_version;
    uint32_t                     oem_manuf_data_version_nvm;
    uint32_t                     oem_manuf_data_version_fitb;
    uint16_t                     major_version;
    uint16_t                     major_vcn;
    uint32_t                     oem_manuf_data_version_fitb_valid;
    uint32_t                     flags;
    uint32_t                     reserved[7];
};


/** @} */

/**
 * @defgroup gsc-fw-api-update GSC Firmware Update protocol
 * @ingroup  gsc-fw-api
 * @{
 */

/** Firmware status register 1 - FW update is in idle state bit */
#define HECI1_CSE_FS_FWUPDATE_STATE_IDLE_BIT    (1<<11)
/** Firmware status register 1 - FW initialization completed bit */
#define HECI1_CSE_FS_INITSTATE_COMPLETED_BIT    (1<<9)
/** Firmware status register 1 - FW background operation needed bit */
#define HECI1_CSE_FS_BACKGROUND_OPERATION_NEEDED_BIT (1<<13)
/** Firmware status register 2  value - firmware update state */
#define HECI1_CSE_GS1_PHASE_FWUPDATE       7
/** Firmware status register - firmware update phase bits shift */
#define HECI1_CSE_FS_FWUPD_PHASE_SHIFT    28
/** Firmware status register - firmware update phase bits mask */
#define HECI1_CSE_FS_FWUPD_PHASE_MASK    0xF
/** Firmware status register - firmware update percentage bits shift */
#define HECI1_CSE_FS_FWUPD_PERCENT_SHIFT  16
/** Firmware status register - firmware update percentage bits mask */
#define HECI1_CSE_FS_FWUPD_PERCENT_MASK  0xFF
/** Firmware status register 5 - CP/Chassis mode bits mask */
#define HECI1_CSE_FS_MODE_MASK  0x3
/** Firmware status register 5 - CP mode value */
#define HECI1_CSE_FS_CP_MODE  0x3

enum gsc_fwu_heci_metadata_version {
    /** GSC Firmware Update metadata version for no metadata case */
    GSC_FWU_HECI_METADATA_VERSION_NONE = 0,
    /** GSC Firmware Update metadata version 1 */
    GSC_FWU_HECI_METADATA_VERSION_1    = 1,
    /** GSC Firmware Update metadata version Upper Sentinel */
    GSC_FWU_HECI_METADATA_VERSION_MAX,
};

#define MCHI_GROUP_ID_MCA 0xA
#define MCHI_READ_FILE_EX 0xA

#define FILE_ID_MCA_OEM_VERSION 0x1001f000

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
 * @brief fw update start heci message flags
 *
 * @param force_update whether forced update is requested
 * @param reserved reserved
*/
struct gsc_fwu_heci_start_flags {
        uint32_t  force_update     : 1;
        uint32_t  reserved         : 31;
};

/**
 * @struct gsc_fwu_heci_start_req
 *
 * @brief firmware update start message
 *
 * @param header @ref gsc_fwu_heci_header
 * @param update_img_length overall message length
 * @param payload_type firmware payload type @ref gsc_fwu_heci_payload_type
 * @param flags start message flags @ref struct gsc_fwu_heci_start_flags
 * @param reserved[8] reserved
 * @param data @ref gsc_fwu_heci_image_metadata
 * @see enum gsc_fwu_heci_payload_type
 */
struct gsc_fwu_heci_start_req {
    struct gsc_fwu_heci_header      header;
    uint32_t                        update_img_length;
    uint32_t                        payload_type;
    struct gsc_fwu_heci_start_flags flags;
    uint32_t                        reserved[8];
    uint8_t                         data[];
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
 * @param data_length length of data section
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

/**
 * @brief firmware no update message
 *
 * @param header @ref gsc_fwu_heci_header
 * @param reserved reserved
 */
struct gsc_fwu_heci_no_update_req {
    struct gsc_fwu_heci_header header;
    uint32_t                   reserved;
};

/** @} */

/**
 * @defgroup gsc-fw-api-hdr GSC Firmware Configuration Retrieval API
 * @ingroup  gsc-fw-api
 * @{
 */

/**
 * @brief firmware get config message
 *
 * @param header @ref gsc_fwu_heci_header
 * @param reserved
 */
struct gsc_fwu_heci_get_config_message_req {
   struct gsc_fwu_heci_header header;
   uint32_t                   reserved[2];
};

#define GSC_FWU_GET_CONFIG_FORMAT_VERSION 0x1

/**
 * @brief firmware get config message response
 *
 * @param response @ref gsc_fwu_heci_response
 * @param format_version response format version
 * @param hw_step hw step of the device
 * @param hw_sku hw sku of the device
 * @param oprom_code_devid_enforcement enforcement of the oprom code device ids flag
 * @param flags reserved for future flags
 * @param reserved
 * @param debug_config differentiate between different binaries
 *        for debug or validation purposes
 */
struct gsc_fwu_heci_get_config_message_resp {
    struct gsc_fwu_heci_response response;
    uint32_t                     format_version;
    uint32_t                     hw_step;
    uint32_t                     hw_sku;
    uint32_t                     oprom_code_devid_enforcement : 1;
    uint32_t                     flags                        : 31;
    uint32_t                     reserved[7];
    uint32_t                     debug_config;
};

/**
 * @brief get the Subsystem Vendor ID (SSVID) and Subsystem Device ID (SSDID) of the card
 *
 * @param header @ref gsc_fwu_heci_header
 * @param reserved
 */
struct gsc_fwu_heci_get_subsystem_ids_message_req {
   struct gsc_fwu_heci_header header;
   uint32_t                   reserved[2];
};

/**
 * @brief firmware get the Subsystem IDs message response
 *
 * @param response @ref gsc_fwu_heci_response
 * @param ssvid Subsystem Vendor ID (SSVID)
 * @param ssdid Subsystem Device ID (SSDID)
 * @param reserved
 */
struct gsc_fwu_heci_get_subsystem_ids_message_resp {
    struct gsc_fwu_heci_response    response;
    uint16_t                        ssvid;
    uint16_t                        ssdid;
    uint32_t                        reserved[2];
};

/**
 * @brief request to read a file
 *
 * @param header @ref mkhi_msg_hdr, (MCHI header is the same as MKHI one),
 *               MCHI_GROUP_ID_MCA and MCHI_READ_FILE_EX for MCHI group_id and command
 * @param file_id id of the file to read
 * @param offset offset from the start of the file to read
 * @param data_size size of data to read
 * @param flags flags to pass to the read command (should be 0)
 */
struct mchi_read_file_ex_req {
    struct mkhi_msg_hdr header;
    uint32_t file_id;
    uint32_t offset;
    uint32_t data_size;
    uint8_t flags;
};

/**
 * @brief request to read a file
 *
 * @param header @ref mkhi_msg_hdr, (MCHI header is the same as MKHI one),
 *               MCHI_GROUP_ID_MCA and MCHI_READ_FILE_EX for MCHI group_id and command
 * @param data_size actual size of data that was read
 * @param data file data payload
 */
struct mchi_read_file_ex_res {
    struct mkhi_msg_hdr header;
    uint32_t data_size;
    uint8_t data[];
};

/** @} */

#pragma pack()

#endif /* !__IGSC_HECI_H__ */
