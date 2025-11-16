/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025 Intel Corporation
 */

#ifndef __IGSC_IPL_HECI_H__
#define __IGSC_IPL_HECI_H__

#include "igsc_heci.h"

#pragma pack(1)

#define IPL_HECI_COMMAND_ID_LATE_BINDING 0x01
#define IPL_HECI_COMMAND_ID_LATE_BINDING_GET_INFO 0x02

#define IPL_FLAG_RESPONSE 0x01
 /**
  * @brief IPL HECI header structure
  */
struct ipl_heci_header
{
    uint32_t                command_id; /**< IPL_HECI_COMMAND_ID_LATE_BINDING* */
    uint8_t                 flags; /**< IPL_FLAG_* */
    uint8_t                 reserved[3];
};

struct ipl_heci_rsp_header
{
    struct ipl_heci_header header;
    uint32_t               status; /**< enum csc_late_binding_status */
};

#define CSC_LATE_BINDING_FLAG_FST_CHUNK 0x02
#define CSC_LATE_BINDING_FLAG_LST_CHUNK 0x04

struct ipl_late_binding_request
{
    struct ipl_heci_header header;
    uint32_t               type;                 /**< enum csc_late_binding_type */
    uint32_t               flags;                /**< CSC_LATE_BINDING_FLAG_* */
    uint32_t               reserved;
    uint32_t               total_payload_size;   /**< Size in bytes of all the chunks */
    uint32_t               payload_size;         /**< Size in bytes of the current chunk */
    uint8_t                payload[];
};

struct ipl_late_binding_response
{
    struct ipl_heci_rsp_header  rheader;
    uint32_t                    type;             /**< enum csc_late_binding_type */
    uint32_t                    reserved[2];
};

struct ipl_late_binding_get_info_request
{
    struct ipl_heci_header       header;
    uint32_t                     type;           /**< enum csc_late_binding_type */
    uint32_t                     reserved;
};

struct ipl_late_binding_get_info_response
{
    struct ipl_heci_rsp_header  rheader;
    uint32_t                    type;           /**< enum csc_late_binding_svn_source */
    uint32_t                    svn_source;     /**< CSC_LATE_BINDING_SVN_SOURCE* */
    uint32_t                    min_svn;        /**< SVN value */
    uint32_t                    reserved[2];
};

#pragma pack()

#endif /* !__IGSC_IPL_HECI_H__ */
