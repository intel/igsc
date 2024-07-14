/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2023 Intel Corporation
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
    size_t received_len = 0;
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
        gsc_error("Cannot initialize driver, status %d\n", status);
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
    size_t received_len = 0;
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
        gsc_error("Cannot initialize driver, status %d\n", status);
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
        gsc_error("Invalid command %u ~= %u\n", gfsp_heci_header, command);
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

int igsc_gfsp_heci_cmd(struct igsc_device_handle *handle, uint32_t gfsp_cmd,
                       uint8_t* in_buffer, size_t in_buffer_size,
                       uint8_t* out_buffer, size_t out_buffer_size,
                       size_t *actual_out_buffer_size)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t received_data_len;
    size_t buf_len;
    struct igsc_lib_ctx *lib_ctx;

    struct gfsp_generic_req *req;
    struct gfsp_generic_res *resp;

    if (!handle || !handle->ctx || !actual_out_buffer_size ||
        (!in_buffer && in_buffer_size) || (!out_buffer && out_buffer_size))
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    if (in_buffer_size > lib_ctx->working_buffer_length - sizeof(*req))
    {
        gsc_error("Input buffer is too big, must not be bigger than %zd\n",
                  lib_ctx->working_buffer_length - sizeof(*req));
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    gsc_debug("in generic gfsp heci command, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_MKHI);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Cannot initialize driver, status %d\n", status);
        return status;
    }

    req = (struct gfsp_generic_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req) + in_buffer_size;
    memset(req, 0, request_len);
    if (in_buffer)
    {
        gsc_memcpy_s(req->buffer, lib_ctx->working_buffer_length - sizeof(*req),
                     in_buffer, in_buffer_size);
    }

    resp = (struct gfsp_generic_res *)lib_ctx->working_buffer;
    response_len = sizeof(*resp);
    buf_len = lib_ctx->working_buffer_length;

    gsc_debug("validating buffer\n");

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Internal error - failed to validate buffer %d\n", status);
        goto exit;
    }

    req->header.group_id = MKHI_GROUP_ID_GFSP;
    req->header.command = 0;
    req->gfsp_heci_header = gfsp_cmd;

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
                                                gfsp_cmd);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        goto exit;
    }

    if (resp->header.result != 0)
    {
       gsc_debug("Generic gfsp heci command failed with result 0x%x\n", resp->header.result);
       status = IGSC_ERROR_PROTOCOL;
       goto exit;
    }

    if (received_len < response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    received_data_len = received_len - response_len;
    *actual_out_buffer_size = (received_data_len > out_buffer_size) ? out_buffer_size : received_data_len;

    if (out_buffer)
    {
        gsc_memcpy_s(out_buffer, out_buffer_size, resp->buffer, *actual_out_buffer_size);
    }

    if (received_data_len > out_buffer_size)
    {
        gsc_error("Out buffer is too small (%zu), received %zu bytes of data\n", out_buffer_size, received_data_len);
        status = IGSC_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    gsc_debug("Generic gfsp heci command success\n");

exit:
    gsc_driver_deinit(lib_ctx);

    return status;
}

#define MAX_SUPPORTED_NUM_OF_DEVICE 8 /* In Xe_HP SDV / PVC - should be 8 */

static int gsc_memory_ppr(struct igsc_device_handle *handle,
                          uint32_t *count,
                          struct igsc_ppr_status *ppr_status)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
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
        gsc_error("Cannot initialize driver, status %d\n", status);
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
                                                GFSP_MEM_PRP_STAT_CMD);
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

#define MAX_SUPPORTED_NUM_OF_TILES 4 /* In Xe_HP SDV - 4, In PVC - 2 */

static int gsc_gfsp_memory_errors(IN  struct  igsc_device_handle *handle,
                                  IN OUT uint32_t  *num_of_tiles,
                                  OUT struct igsc_gfsp_mem_err *tiles)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
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
        gsc_error("Cannot initialize driver, status %d\n", status);
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

    status = gfsp_heci_validate_response_header(lib_ctx, &resp->header,
                                                resp->gfsp_heci_header,
                                                GFSP_MUN_MEM_ERR_CMD);
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

    return status;
}

int igsc_gfsp_count_tiles(IN  struct igsc_device_handle *handle,
                          OUT uint32_t *max_num_of_tiles)
{
    if (!handle || !handle->ctx || !max_num_of_tiles)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    return gsc_gfsp_memory_errors (handle, max_num_of_tiles, NULL);

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

static int mkhi_heci_validate_response_header(struct igsc_lib_ctx *lib_ctx,
                                              struct mkhi_msg_hdr *resp_header,
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

int igsc_ifr_run_array_scan_test(IN struct igsc_device_handle *handle,
                                 OUT uint32_t *test_status,
                                 OUT uint32_t *extended_status,
                                 OUT uint32_t *pending_reset,
                                 OUT uint32_t *error_code)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;
    struct igsc_lib_ctx *lib_ctx;
    struct ifr_run_test_ext_req *req;
    struct ifr_run_test_array_scan_res *resp;

    if (!handle || !handle->ctx || !test_status || !extended_status || !pending_reset || !error_code)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("in run array/scan test, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_MKHI);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Cannot initialize driver, status %d\n", status);
        return status;
    }

    req = (struct ifr_run_test_ext_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct ifr_run_test_array_scan_res *)lib_ctx->working_buffer;
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
    req->header.group_id = MKHI_GROUP_ID_GFX_SRV;
    req->header.command = GFX_SRV_MKHI_RUN_IFR_TEST_CMD;
    req->test = IFR_TEST_ARRAY_AND_SCAN;

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

    status = mkhi_heci_validate_response_header(lib_ctx, &resp->header,
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

    if (resp->finished_test != IFR_TEST_ARRAY_AND_SCAN)
    {
        gsc_error("Error in IFR Run Test response - test type do not match %u %u\n",
                  resp->finished_test, IFR_TEST_ARRAY_AND_SCAN);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->reserved1[0] || resp->reserved1[1] || resp->reserved1[2] ||
        resp->reserved2[0] || resp->reserved2[1] ||
        resp->reserved3[0] || resp->reserved3[1] || resp->reserved3[2])
    {
        gsc_error("IFR Status response is leaking data\n");
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    *test_status = resp->status;
    *error_code = resp->error_code;
    *extended_status = resp->extended_status;
    *pending_reset = resp->pending_reset;

    gsc_debug("run test success\n");

exit:
    gsc_driver_deinit(lib_ctx);
    return status;
}

int igsc_ifr_run_mem_ppr_test(IN struct igsc_device_handle *handle,
                              OUT uint32_t *test_status,
                              OUT uint32_t *pending_reset,
                              OUT uint32_t *error_code)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;
    struct igsc_lib_ctx *lib_ctx;
    struct ifr_run_test_ext_req *req;
    struct ifr_run_test_mem_ppr_res *resp;

    if (!handle || !handle->ctx || !test_status || !pending_reset || !error_code)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("in run mem ppr test, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_MKHI);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Cannot initialize driver, status %d\n", status);
        return status;
    }

    req = (struct ifr_run_test_ext_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct ifr_run_test_mem_ppr_res *)lib_ctx->working_buffer;
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
    req->header.group_id = MKHI_GROUP_ID_GFX_SRV;
    req->header.command = GFX_SRV_MKHI_RUN_IFR_TEST_CMD;
    req->test = IFR_TEST_MEMORY_PPR;

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

    status = mkhi_heci_validate_response_header(lib_ctx, &resp->header,
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

    if (resp->finished_test != IFR_TEST_MEMORY_PPR)
    {
        gsc_error("Error in IFR Run Test response - test type do not match %u %u\n",
                  resp->finished_test, IFR_TEST_MEMORY_PPR);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->reserved1[0] || resp->reserved1[1] || resp->reserved1[2] ||
        resp->reserved2[0] || resp->reserved2[1] || resp->reserved2[2] ||
        resp->reserved3[0] || resp->reserved3[1] || resp->reserved3[2])
    {
        gsc_error("IFR mem ppr test response is leaking data\n");
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    *test_status = resp->status;
    *error_code = resp->error_code;
    *pending_reset = resp->pending_reset;

    gsc_debug("run test success\n");

exit:
    gsc_driver_deinit(lib_ctx);
    return status;
}

int igsc_ifr_count_tiles(IN  struct igsc_device_handle *handle,
                         OUT uint16_t *supported_tiles)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;
    struct igsc_lib_ctx *lib_ctx;
    struct ifr_get_general_info_req *req;
    struct ifr_get_general_info_res *resp;

    if (!handle || !handle->ctx || !supported_tiles)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("in run ifr count tiles, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_MKHI);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Cannot initialize driver, status %d\n", status);
        return status;
    }

    req = (struct ifr_get_general_info_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct ifr_get_general_info_res *)lib_ctx->working_buffer;
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
    req->header.group_id = MKHI_GROUP_ID_GFX_SRV;
    req->header.command = GFX_SRV_MKHI_GET_IFR_GENERAL_INFO_CMD;

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

    status = mkhi_heci_validate_response_header(lib_ctx, &resp->header,
                                               req->header.command);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->header.result != 0)
    {
       gsc_debug("IFR count tiles command failed with result 0x%x\n", resp->header.result);
       status = IGSC_ERROR_PROTOCOL;
       goto exit;
    }

    if (received_len < response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    for (unsigned int i = 0; i < sizeof(resp->reserved); i++)
    {
        if (resp->reserved[i])
        {
           gsc_error("IFR count tiles response is leaking data on reserved[%u] field: %u\n",
                     i, resp->reserved[i]);
           status = IGSC_ERROR_PROTOCOL;
           goto exit;
        }
    }

    *supported_tiles = resp->supported_tiles;

    gsc_debug("IFR count tiles success\n");

exit:
    gsc_driver_deinit(lib_ctx);
    return status;

}

int igsc_ifr_get_tile_repair_info(IN  struct igsc_device_handle *handle,
                                  IN uint16_t tile_idx,
                                  OUT uint16_t *used_array_repair_entries,
                                  OUT uint16_t *available_array_repair_entries,
                                  OUT uint16_t *failed_dss)
{
    int status;
    unsigned int i;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;
    struct igsc_lib_ctx *lib_ctx;
    struct ifr_get_tile_repair_info_req *req;
    struct ifr_get_tile_repair_info_res *resp;

    if (!handle || !handle->ctx ||
        !used_array_repair_entries ||
        !available_array_repair_entries || !failed_dss)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (MAX_SUPPORTED_NUM_OF_TILES < tile_idx)
    {
        gsc_error("Bad tile number requested: %u\n", tile_idx);
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("in run ifr get tile repair info, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_MKHI);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Cannot initialize driver, status %d\n", status);
        return status;
    }

    req = (struct ifr_get_tile_repair_info_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct ifr_get_tile_repair_info_res *)lib_ctx->working_buffer;
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
    req->header.group_id = MKHI_GROUP_ID_GFX_SRV;
    req->header.command = GFX_SRV_MKHI_GET_IFR_TILE_REPAIR_INFO_CMD;
    req->tile_idx = tile_idx;

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

    status = mkhi_heci_validate_response_header(lib_ctx, &resp->header,
                                               req->header.command);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->header.result != 0)
    {
       gsc_debug("IFR get tile repair info command failed with result 0x%x\n", resp->header.result);
       status = IGSC_ERROR_PROTOCOL;
       goto exit;
    }

    if (received_len < response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (tile_idx != resp->requested_tile)
    {
        gsc_error("Returned tile index %u when %u was requested\n", resp->requested_tile, tile_idx);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    for (i = 0; i < sizeof(resp->reserved1); i ++)
    {
        if (resp->reserved1[i])
        {
           gsc_error("IFR get tile repair info response is leaking data on reserved1[%u] field: %u\n",
                     i, resp->reserved1[i]);
           status = IGSC_ERROR_PROTOCOL;
           goto exit;
        }
    }

    for (i = 0; i < sizeof(resp->reserved2); i ++)
    {
        if (resp->reserved2[i])
        {
           gsc_error("IFR get tile repair info response is leaking data on reserved2[%u] field: %u\n",
                     i, resp->reserved2[i]);
           status = IGSC_ERROR_PROTOCOL;
           goto exit;
        }
    }

    *used_array_repair_entries = resp->used_array_repair_entries;
    *available_array_repair_entries = resp->available_array_repair_entries;
    *failed_dss = resp->failed_dss;

    gsc_debug("IFR get tile repair info success\n");

exit:
    gsc_driver_deinit(lib_ctx);
    return status;
}

int igsc_ifr_get_status_ext(IN struct igsc_device_handle *handle,
                            OUT uint32_t *supported_tests,
                            OUT uint32_t *hw_capabilities,
                            OUT uint32_t *ifr_applied,
                            OUT uint32_t *prev_errors,
                            OUT uint32_t *pending_reset)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;
    struct igsc_lib_ctx *lib_ctx;
    struct ifr_get_status_ext_req *req;
    struct ifr_get_status_ext_res *resp;

    if (!handle || !handle->ctx || !supported_tests || !hw_capabilities ||
        !ifr_applied || !prev_errors || !pending_reset)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("in run get ifr ext status, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_MKHI);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Cannot initialize driver, status %d\n", status);
        return status;
    }

    req = (struct ifr_get_status_ext_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct ifr_get_status_ext_res *)lib_ctx->working_buffer;
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
    req->header.group_id = MKHI_GROUP_ID_GFX_SRV;
    req->header.command = GFX_SRV_MKHI_GET_IFR_STATUS_CMD;

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

    status = mkhi_heci_validate_response_header(lib_ctx, &resp->header,
                                               req->header.command);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->header.result != 0)
    {
       gsc_debug("IFR get status command failed with result 0x%x\n", resp->header.result);
       status = IGSC_ERROR_PROTOCOL;
       goto exit;
    }

    if (received_len < response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->reserved1[0] || resp->reserved1[1] || resp->reserved1[2] ||
        resp->reserved2[0] || resp->reserved2[1])
    {
        gsc_error("IFR Status response is leaking data\n");
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    *supported_tests = resp->supported_tests;
    *hw_capabilities = resp->hw_capabilities;
    *ifr_applied = resp->ifr_applied;
    *prev_errors = resp->prev_errors;
    *pending_reset = resp->pending_reset;

    gsc_debug("IFR get status success\n");

exit:
    gsc_driver_deinit(lib_ctx);
    return status;

}

int igsc_ecc_config_set(IN  struct igsc_device_handle *handle,
                        IN  uint8_t req_ecc_state,
                        OUT uint8_t *cur_ecc_state,
                        OUT uint8_t *pen_ecc_state)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;
    struct igsc_lib_ctx *lib_ctx;
    struct gfsp_set_ecc_config_req *req;
    struct gfsp_set_ecc_config_res *resp;

    if (!handle || !handle->ctx || !cur_ecc_state || !pen_ecc_state)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (!(req_ecc_state == 0 || req_ecc_state == 1))
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("in set ecc config, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_MKHI);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Cannot initialize driver, status %d\n", status);
        return status;
    }

    req = (struct gfsp_set_ecc_config_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct gfsp_set_ecc_config_res *)lib_ctx->working_buffer;
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
    req->gfsp_heci_header = GFSP_SET_ECC_CFG_CMD;
    req->ecc_state = req_ecc_state;

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
                                                GFSP_SET_ECC_CFG_CMD);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        goto exit;
    }

    if (resp->header.result != 0)
    {
       gsc_error("Set ECC config command failed with result 0x%x\n",
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

    *cur_ecc_state = resp->cur_ecc_state;
    *pen_ecc_state = resp->pen_ecc_state;

    gsc_debug("Set ECC config success\n");

exit:
    gsc_driver_deinit(lib_ctx);

    return status;
}

int igsc_ecc_config_get(IN  struct igsc_device_handle *handle,
                        OUT uint8_t *cur_ecc_state,
                        OUT uint8_t *pen_ecc_state)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;
    struct igsc_lib_ctx *lib_ctx;
    struct gfsp_get_ecc_config_req *req;
    struct gfsp_get_ecc_config_res *resp;

    if (!handle || !handle->ctx || !cur_ecc_state || !pen_ecc_state)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("in get ecc config, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_MKHI);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Cannot initialize driver, status %d\n", status);
        return status;
    }

    req = (struct gfsp_get_ecc_config_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct gfsp_get_ecc_config_res *)lib_ctx->working_buffer;
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
    req->gfsp_heci_header = GFSP_GET_ECC_CFG_CMD;

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
                                                GFSP_GET_ECC_CFG_CMD);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        goto exit;
    }

    if (resp->header.result != 0)
    {
       gsc_error("Get ECC config command failed with result 0x%x\n",
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

    *cur_ecc_state = resp->cur_ecc_state;
    *pen_ecc_state = resp->pen_ecc_state;

    gsc_debug("Get ECC config success\n");

exit:
    gsc_driver_deinit(lib_ctx);

    return status;
}

int igsc_device_update_late_binding_config(IN struct  igsc_device_handle *handle,
                                           IN uint32_t type, /* enum csc_late_binding_type */
                                           IN uint32_t flags,
                                           IN uint8_t *payload, IN size_t payload_size,
                                           OUT uint32_t *cmd_status) /* enum csc_late_binding_status */
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;
    struct igsc_lib_ctx *lib_ctx;

    struct csc_heci_late_binding_resp *resp;
    struct csc_heci_late_binding_req *req;

    if (!handle || !handle->ctx || cmd_status == NULL || payload == NULL || payload_size == 0)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    if (type != CSC_LATE_BINDING_TYPE_FAN_TABLE && type != CSC_LATE_BINDING_TYPE_VR_CONFIG)
    {
        gsc_error("Wrong payload type %u\n", type);
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if ((flags & ~(uint32_t)CSC_LATE_BINDING_FLAGS_IS_PERSISTENT_MASK) != 0)
    {
        gsc_error("Wrong flags value 0x%x\n", flags);
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    gsc_debug("in late binding, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_MKHI);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Cannot initialize driver, status %d\n", status);
        return status;
    }

    req = (struct csc_heci_late_binding_req *)lib_ctx->working_buffer;
    buf_len = lib_ctx->working_buffer_length;
    if (payload_size > buf_len - sizeof(*req))
    {
        gsc_error("Payload size is too big %zu\n", payload_size);
        status = IGSC_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    request_len = sizeof(*req) + payload_size;
    resp = (struct csc_heci_late_binding_resp *)lib_ctx->working_buffer;
    response_len = sizeof(*resp);

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status != IGSC_SUCCESS)
    {
        goto exit;
    }

    memset(req, 0, request_len);
    req->header.command = GFX_SRV_MKHI_LATE_BINDING_CMD;
    req->header.group_id = MKHI_GROUP_ID_GFX_SRV;
    req->type = type;
    req->flags = flags;
    req->payload_size = (uint32_t)payload_size;
    if (gsc_memcpy_s(req->payload, buf_len - sizeof(*req), payload, payload_size))
    {
        gsc_error("Copy of payload data failed\n");
        status = IGSC_ERROR_INTERNAL;
        goto exit;
    }

    status = gsc_tee_command(lib_ctx, req, request_len, resp, buf_len, &received_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response (%d)\n", status);
        goto exit;
    }

    if (received_len < sizeof(*resp))
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    status = mkhi_heci_validate_response_header(lib_ctx, &resp->header,
                                                GFX_SRV_MKHI_LATE_BINDING_CMD);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response (%d)\n", status);
        goto exit;
    }

    if (received_len != response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->type != type)
    {
        gsc_error("Received wrong payload type in response from firmware %u, expected %u\n",
                  resp->type, type);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->reserved[0] != 0 || resp->reserved[1] != 0 )
    {
        gsc_error("HECI message response is leaking data\n");
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    gsc_debug("success, status %u\n", resp->status);

    *cmd_status = resp->status;
    status = IGSC_SUCCESS;

exit:
    gsc_driver_deinit(lib_ctx);

    return status;

}

static int gsc_get_version(struct igsc_lib_ctx *lib_ctx,
                           uint32_t partition,
                           uint8_t *version, size_t version_length)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;

    struct gsc_heci_version_resp *resp;
    struct gsc_heci_version_req *req;

    if (version == NULL)
    {
        return IGSC_ERROR_INTERNAL;
    }

    req = (struct gsc_heci_version_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct gsc_heci_version_resp *)lib_ctx->working_buffer;
    response_len = sizeof(*resp) + version_length;
    buf_len = lib_ctx->working_buffer_length;

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status != IGSC_SUCCESS)
    {
        return status;
    }

    memset(req, 0, request_len);
    req->header.command = GFX_SRV_MKHI_GET_IP_VERSION_CMD;
    req->header.group_id = MKHI_GROUP_ID_GFX_SRV;
    req->partition = partition;
    status = gsc_tee_command(lib_ctx, req, request_len, resp, buf_len, &received_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response (%d)\n", status);
        goto exit;
    }

    if (received_len < sizeof(*resp))
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    status = mkhi_heci_validate_response_header(lib_ctx, &resp->header, GFX_SRV_MKHI_GET_IP_VERSION_CMD);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response (%d)\n", status);
        goto exit;
    }

    if (received_len != response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->partition != partition)
    {
        gsc_error("Invalid HECI message response payload (%u)\n", resp->partition);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->version_length != version_length)
    {
        gsc_error("Invalid HECI message response version_length (%u)\n", resp->version_length);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (gsc_memcpy_s(version, version_length,
                     resp->version, resp->version_length))
    {
        gsc_error("Copy of version data failed\n");
        status = IGSC_ERROR_INTERNAL;
        goto exit;
    }

    status = IGSC_SUCCESS;

exit:
    return status;
}

static int gsc_get_generic_version(IN  struct igsc_device_handle *handle,
                                   uint32_t partition,
                                   uint8_t *version, size_t version_length)
{
    struct igsc_lib_ctx *lib_ctx;
    int ret;

    if (!handle || !handle->ctx || !version)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    ret = gsc_driver_init(lib_ctx, &GUID_METEE_MKHI);
    if (ret != IGSC_SUCCESS)
    {
        gsc_error("Cannot initialize driver, status %d\n", ret);
        return ret;
    }

    ret = gsc_get_version(lib_ctx, partition, version, version_length);
    if (ret != IGSC_SUCCESS)
    {
        gsc_error("Cannot get version for the partition, status %d\n", ret);
        goto exit;
    }

exit:
    gsc_driver_deinit(lib_ctx);

    return ret;

}

int igsc_device_psc_version(IN  struct igsc_device_handle *handle,
                            OUT struct igsc_psc_version *version)
{
    return gsc_get_generic_version(handle, MKHI_GET_IP_VERSION_PSC,
                                   (uint8_t *)version, sizeof(*version));
}

int igsc_device_ifr_bin_version(IN  struct igsc_device_handle *handle,
                                OUT struct igsc_ifr_bin_version *version)
{
    return gsc_get_generic_version(handle, MKHI_GET_IP_VERSION_IFR,
                                   (uint8_t *)version, sizeof(*version));
}

int igsc_gfsp_get_health_indicator(IN struct igsc_device_handle *handle,
                                   OUT uint8_t *health_indicator)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;
    struct igsc_lib_ctx *lib_ctx;
    struct gfsp_get_mem_err_mitigation_status_req *req;
    struct gfsp_get_mem_err_mitigation_status_res *resp;

    if (!handle || !handle->ctx || !health_indicator)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("in get memory health indicator, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_MKHI);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("GFSP is not supported on this device, status %d\n", status);
        return status;
    }

    req = (struct gfsp_get_mem_err_mitigation_status_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct gfsp_get_mem_err_mitigation_status_res *)lib_ctx->working_buffer;
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
    req->gfsp_heci_header = GFSP_MEM_ERR_MITIG_STAT_CMD;

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
                                                GFSP_MEM_ERR_MITIG_STAT_CMD);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        goto exit;
    }

    if (resp->header.result != 0)
    {
       gsc_error("Get memory health indicator command failed with result 0x%x\n",
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

    if (resp->max_num_of_tiles > GFSP_MAX_TILES)
    {
        gsc_error("Received bad number of tiles %u, must not be bigger than %u\n",
                  resp->max_num_of_tiles, GFSP_MAX_TILES);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    *health_indicator = resp->health_indicator;

    gsc_debug("get status success\n");

exit:
    gsc_driver_deinit(lib_ctx);

    gsc_debug("ret = %d\n", status);

    return status;
}
