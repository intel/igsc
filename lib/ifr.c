/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2020 Intel Corporation
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "msvc/config.h"
#include "gcc/config.h"

#include "igsc_system.h"
#include "igsc_heci.h"
#include "igsc_log.h"

#include <metee.h>

#include "igsc_lib.h"
#include "igsc_internal.h"
#include "ifr.h"

#include "utils.h"

DEFINE_GUID(GUID_METEE_IFR, 0x865e2b45, 0x8fb5, 0x464a,
            0x97, 0xdc, 0x5d, 0x4a, 0xbf, 0x7b, 0x79, 0xa2);

DEFINE_GUID(GUID_METEE_MKHI, 0xe2c2afa2, 0x3817, 0x4d19,
            0x9d, 0x95, 0x6, 0xb1, 0x6b, 0x58, 0x8a, 0x5d);

static int ifr_heci_validate_response_header(struct igsc_lib_ctx *lib_ctx,
                                             struct ifr_msg_hdr *resp_header,
                                             uint32_t command)
{
    int status;

    if (resp_header == NULL)
    {
        status = IGSC_ERROR_INTERNAL;
        goto exit;
    }

    lib_ctx->last_firmware_status = resp_header->result;

    if (resp_header->command != command)
    {
        gsc_error("Invalid command %d\n", resp_header->command);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp_header->is_response == false)
    {
        gsc_error("HECI Response not marked as response\n");
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp_header->reserved != 0)
    {
        gsc_error("HECI message response is leaking data\n");
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    status = IGSC_SUCCESS;

exit:
    return status;
}

int igsc_ifr_get_status(IN  struct igsc_device_handle *handle,
                        OUT uint8_t  *result,
                        OUT uint32_t *supported_tests,
                        OUT uint32_t *ifr_applied,
                        OUT uint8_t  *tiles_num)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len;
    size_t buf_len;
    struct igsc_lib_ctx       *lib_ctx;
    struct ifr_get_status_req *req;
    struct ifr_get_status_res *resp;

    if (!handle || !result || !handle->ctx || !supported_tests || !ifr_applied || !tiles_num)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("in get status, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_IFR);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("IFR is not supported on this device, status %d\n", status);
        return status;
    }

    req = (struct ifr_get_status_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct ifr_get_status_res *)lib_ctx->working_buffer;
    response_len = sizeof(*resp);
    buf_len = lib_ctx->working_buffer_length;

    gsc_debug("validating buffer\n");

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Internal error - failed to validate buffer %d\n", status);
        goto exit;
    }

    memset(req, 0, request_len);
    req->header.group_id = GFX_DIAG_IFR_GROUP;
    req->header.command = IFR_GET_STATUS_CMD;

    gsc_debug("sending command\n");

    status = gsc_tee_command(lib_ctx, req, request_len, resp, buf_len, &received_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        goto exit;
    }

    if (received_len < sizeof(resp->header))
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    *result = resp->header.result;
    gsc_debug("result = %u\n", resp->header.result);

    status = ifr_heci_validate_response_header(lib_ctx, &resp->header,
                                               req->header.command);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        goto exit;
    }

    if (resp->header.result != 0)
    {
       gsc_debug("Get IFR status command failed with result 0x%x\n", resp->header.result);
       status = IGSC_ERROR_PROTOCOL;
       goto exit;
    }

    if (received_len < response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->reserved[0] != 0 || resp->reserved[1] != 0 || resp->reserved[2] != 0)
    {
        gsc_error("IFR Status response is leaking data\n");
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    *supported_tests = resp->supported_tests_map;
    *ifr_applied = resp->repairs_applied_map;
    *tiles_num = resp->tiles_num;

    gsc_debug("get status success\n");

exit:
    gsc_driver_deinit(lib_ctx);

    gsc_debug("ret = %d\n", status);

    return status;
}

int igsc_ifr_run_test(IN struct igsc_device_handle *handle,
                      IN uint8_t   test_type,
                      IN uint8_t   tiles_mask,
                      OUT uint8_t  *result,
                      OUT uint8_t  *run_status,
                      OUT uint32_t *error_code)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len;
    size_t buf_len;
    struct igsc_lib_ctx     *lib_ctx;
    struct ifr_run_test_req *req;
    struct ifr_run_test_res *resp;

    if (!handle || !handle->ctx || !result || !run_status || !error_code)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("in run test, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_IFR);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("IFR is not supported on this device, status %d\n", status);
        return status;
    }

    req = (struct ifr_run_test_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct ifr_run_test_res *)lib_ctx->working_buffer;
    response_len = sizeof(*resp);
    buf_len = lib_ctx->working_buffer_length;

    gsc_debug("validating buffer\n");

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Internal error - failed to validate buffer %d\n", status);
        goto exit;
    }

    memset(req, 0, request_len);
    req->header.group_id = GFX_DIAG_IFR_GROUP;
    req->header.command = IFR_RUN_TEST_CMD;
    req->test_type = test_type;
    req->tiles_map = tiles_mask;

    gsc_debug("sending command\n");

    status = gsc_tee_command(lib_ctx, req, request_len, resp, buf_len, &received_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        goto exit;
    }

    if (received_len < sizeof(resp->header))
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    *result = (uint8_t)resp->header.result;

    status = ifr_heci_validate_response_header(lib_ctx, &resp->header,
                                               req->header.command);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->header.result != 0)
    {
       gsc_debug("Run test command failed with result 0x%x\n", resp->header.result);
       status = IGSC_ERROR_PROTOCOL;
       goto exit;
    }

    if (received_len < response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->test_type != test_type)
    {
        gsc_error("Error in IFR Run Test response - test type do not match %u %u\n",
                  resp->test_type, test_type);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->tiles_map != tiles_mask)
    {
        gsc_error("Error in IFR Run Test response - tiles do not match\n");
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->reserved !=0)
    {
        gsc_error("IFR Status response is leaking data\n");
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }


    *run_status = resp->run_status;
    *error_code = resp->error_code;

    gsc_debug("run test success\n");

exit:
    gsc_driver_deinit(lib_ctx);
    return status;
}

static int gfsp_heci_validate_response_header(struct igsc_lib_ctx *lib_ctx,
                                              struct mkhi_msg_hdr *resp_header,
                                              uint32_t gfsp_heci_header,
                                              uint32_t command)
{
    int status;

    if (resp_header == NULL)
    {
        status = IGSC_ERROR_INTERNAL;
        goto exit;
    }

    lib_ctx->last_firmware_status = resp_header->result;

    if (gfsp_heci_header != command)
    {
        gsc_error("Invalid command %d\n", resp_header->command);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp_header->is_response == false)
    {
        gsc_error("HECI Response not marked as response\n");
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp_header->reserved != 0)
    {
        gsc_error("HECI message response is leaking data\n");
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    status = IGSC_SUCCESS;

exit:
    return status;
}

#define MAX_SUPPORTED_NUM_OF_DEVICE 8 /* In ATS / PVC - should be 8 */

static int gsc_memory_ppr(struct igsc_device_handle *handle,
                          uint32_t *count,
                          struct igsc_ppr_status *ppr_status)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len;
    size_t buf_len;
    struct igsc_lib_ctx *lib_ctx;
    uint32_t i;

    struct gfsp_get_memory_ppr_status_req *req;
    struct gfsp_get_memory_ppr_status_res *resp;


    if (!handle || !handle->ctx || !count)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("in get memory ppr status, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_MKHI);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("IFR is not supported on this device, status %d\n", status);
        return status;
    }

    req = (struct gfsp_get_memory_ppr_status_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct gfsp_get_memory_ppr_status_res *)lib_ctx->working_buffer;
    response_len = sizeof(*resp);
    buf_len = lib_ctx->working_buffer_length;

    gsc_debug("validating buffer\n");

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Internal error - failed to validate buffer %d\n", status);
        goto exit;
    }

    memset(req, 0, request_len);
    req->header.group_id = MKHI_GROUP_ID_GFSP;
    req->header.command = 0;
    req->gfsp_heci_header = GFSP_MEM_PRP_STAT_CMD;

    gsc_debug("sending command\n");

    status = gsc_tee_command(lib_ctx, req, request_len, resp, buf_len, &received_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        goto exit;
    }

    if (received_len < sizeof(resp->header))
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    status = gfsp_heci_validate_response_header(lib_ctx, &resp->header,
                                                resp->gfsp_heci_header,
                                                req->gfsp_heci_header);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        goto exit;
    }

    if (resp->header.result != 0)
    {
       gsc_debug("Get memory PPR status command failed with result 0x%x\n", resp->header.result);
       status = IGSC_ERROR_PROTOCOL;
       goto exit;
    }

    if (received_len < response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->num_devices > MAX_SUPPORTED_NUM_OF_DEVICE)
    {
        gsc_error("Received bad number of devices %u, must not be bigger than %u\n",
                  resp->num_devices, MAX_SUPPORTED_NUM_OF_DEVICE);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (received_len < response_len +
                  resp->num_devices * sizeof(struct gfsp_device_mbist_ppr_status))
    {
        gsc_error("Message size (%zu) cannot contain %u devices\n",
                  received_len, resp->num_devices);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    *count = resp->num_devices;
    if (ppr_status)
    {
        if (resp->num_devices > ppr_status->num_devices)
        {
            gsc_error("Get memory PPR status command failed: buffer too small\n");
            status = IGSC_ERROR_BUFFER_TOO_SMALL;
            goto exit;
        }

        /* copy reply to the external structure */
        ppr_status->boot_time_memory_correction_pending = resp->boot_time_memory_correction_pending;
        ppr_status->ppr_mode = resp->ppr_mode;

        ppr_status->test_run_status = resp->test_run_status;
        ppr_status->ras_ppr_applied = resp->ras_ppr_applied;
        ppr_status->mbist_completed = resp->mbist_completed;
        ppr_status->num_devices = resp->num_devices;
        for (i = 0; i < resp->num_devices; i++)
        {
            ppr_status->device_mbist_ppr_status[i].mbist_test_status =
                                resp->device_mbist_ppr_status[i].mbist_test_status;
            ppr_status->device_mbist_ppr_status[i].num_of_ppr_fuses_used_by_fw =
                                resp->device_mbist_ppr_status[i].num_of_ppr_fuses_used_by_fw;
            ppr_status->device_mbist_ppr_status[i].num_of_remaining_ppr_fuses =
                                resp->device_mbist_ppr_status[i].num_of_remaining_ppr_fuses;
        }
    }
    gsc_debug("get status success\n");

exit:
    gsc_driver_deinit(lib_ctx);

    gsc_debug("ret = %d\n", status);

    return status;
}

int igsc_memory_ppr_devices(IN struct igsc_device_handle *handle,
                            OUT uint32_t *count)
{
    return gsc_memory_ppr(handle, count, NULL);
}

int igsc_memory_ppr_status(IN struct  igsc_device_handle *handle,
                           OUT struct igsc_ppr_status *ppr_status)
{
   uint32_t device_count = 0;
   return gsc_memory_ppr(handle, &device_count, ppr_status);
}

#define MAX_SUPPORTED_NUM_OF_TILES 4 /* In ATS - 4, In PVC - 2 */

static int gsc_gfsp_memory_errors(IN  struct  igsc_device_handle *handle,
                                  IN OUT uint32_t  *num_of_tiles,
                                  OUT struct igsc_gfsp_mem_err *tiles)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len;
    size_t buf_len;
    struct igsc_lib_ctx *lib_ctx;
    struct gfsp_get_num_memory_errors_req *req;
    struct gfsp_get_num_memory_errors_res *resp;

    if (!handle || !handle->ctx || !num_of_tiles)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("in get number of  memory errors, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_MKHI);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("GFSP is not supported on this device, status %d\n", status);
        return status;
    }

    req = (struct gfsp_get_num_memory_errors_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct gfsp_get_num_memory_errors_res *)lib_ctx->working_buffer;
    response_len = sizeof(*resp);
    buf_len = lib_ctx->working_buffer_length;

    gsc_debug("validating buffer\n");

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Internal error - failed to validate buffer %d\n", status);
        goto exit;
    }

    memset(req, 0, request_len);
    req->header.group_id = MKHI_GROUP_ID_GFSP;
    req->header.command = 0;
    req->gfsp_heci_header = GFSP_MUN_MEM_ERR_CMD;

    gsc_debug("sending command\n");

    status = gsc_tee_command(lib_ctx, req, request_len, resp, buf_len, &received_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        goto exit;
    }

    if (received_len < sizeof(resp->header))
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    gsc_debug("result = %u\n", resp->header.result);

    status = gfsp_heci_validate_response_header(lib_ctx, &resp->header,
                                                resp->gfsp_heci_header,
                                                req->gfsp_heci_header);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        goto exit;
    }

    if (resp->header.result != 0)
    {
       gsc_error("Get number of memory errors command failed with result 0x%x\n",
                 resp->header.result);
       status = IGSC_ERROR_PROTOCOL;
       goto exit;
    }

    if (received_len < response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->tiles_num > MAX_SUPPORTED_NUM_OF_TILES)
    {
        gsc_error("Received bad number of tiles %u, must not be bigger than %u\n",
                  resp->tiles_num, MAX_SUPPORTED_NUM_OF_TILES);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (received_len < response_len +
                  resp->tiles_num * sizeof(struct gfsp_num_memory_errors_per_tile))
    {
        gsc_error("Message size (%zu) cannot contain %u tiles\n", received_len, resp->tiles_num);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (tiles)
    {
        if (tiles->num_of_tiles < resp->tiles_num)
        {
           gsc_error("Buffer too small to copy %u tiles\n", resp->tiles_num);
           status = IGSC_ERROR_BUFFER_TOO_SMALL;
           tiles->num_of_tiles = resp->tiles_num;
           goto exit;
        }
        gsc_memcpy_s(tiles->errors, tiles->num_of_tiles * sizeof(struct igsc_gfsp_tile_mem_err),
                 resp->num_memory_errors,
                 resp->tiles_num * sizeof(struct gfsp_num_memory_errors_per_tile));
        tiles->num_of_tiles = resp->tiles_num;
    }
    *num_of_tiles = resp->tiles_num;

    gsc_debug("get status success\n");

exit:
    gsc_driver_deinit(lib_ctx);

    gsc_debug("ret = %d\n", status);

    return status;
}

int igsc_gfsp_count_tiles(IN  struct  igsc_device_handle *handle,
                          OUT uint32_t  *num_of_tiles)
{
    if (!handle || !handle->ctx || !num_of_tiles)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    return gsc_gfsp_memory_errors (handle, num_of_tiles, NULL);

}

int igsc_gfsp_memory_errors(IN struct igsc_device_handle *handle,
                            OUT struct igsc_gfsp_mem_err *tiles)
{
    uint32_t num_of_tiles = 0;

    if (!handle || !handle->ctx || !tiles || tiles->num_of_tiles == 0)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    return gsc_gfsp_memory_errors (handle, &num_of_tiles, tiles);
}
