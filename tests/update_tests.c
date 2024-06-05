/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2023 Intel Corporation
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include <metee.h>

#include "igsc_system.h"
#include "igsc_lib.h"
#include "igsc_heci.h"
#include "igsc_internal.h"
#include "dev_info_mock.c"
#include "oprom_parser.c"

typedef void (*respons_genartor_get_ver_f)(struct gsc_fwu_heci_version_resp *, void *);
typedef void (*respons_genartor_fwu_start_f)(struct gsc_fwu_heci_start_resp *);
typedef void (*respons_genartor_fwu_data_f)(struct gsc_fwu_heci_data_resp *);
typedef void (*respons_genartor_fwu_data_info_f)(struct gsc_fw_data_heci_version_resp *);
typedef void (*respons_genartor_get_config_f)(struct gsc_fwu_heci_get_config_message_resp *);
typedef void (*respons_genartor_get_subsystem_ids_f)(struct gsc_fwu_heci_get_subsystem_ids_message_resp *);

TEESTATUS TeeInit(PTEEHANDLE handle, const GUID *guid, const char *device)
{
    return 0;
}

TEESTATUS TeeInitHandle(PTEEHANDLE handle, const GUID *guid,
                        const TEE_DEVICE_HANDLE device_handle)
{
    return 0;
}

TEESTATUS TeeConnect(PTEEHANDLE handle)
{
    return 0;
}

TEESTATUS TeeRead(PTEEHANDLE handle, void *buffer, size_t bufferSize,
                  size_t *pNumOfBytesRead, uint32_t timeout)
{
    struct gsc_fwu_heci_version_resp *fw_version = buffer;

    if (bufferSize < sizeof(*fw_version))
    {
        return TEE_INSUFFICIENT_BUFFER;
    }

    memset(fw_version, 0, sizeof(*fw_version));

    fw_version->response.header.command_id = GSC_FWU_HECI_COMMAND_ID_GET_IP_VERSION;
    fw_version->response.header.is_response = 1;
    fw_version->response.status = 0;
    fw_version->response.reserved = 0;
    fw_version->partition = GSC_FWU_HECI_PART_VERSION_GFX_FW;
    fw_version->version_length = sizeof(struct igsc_fw_version);

    if (pNumOfBytesRead)
    {
        *pNumOfBytesRead = sizeof(*fw_version) + fw_version->version_length;
    }

    return 0;
}

TEESTATUS TeeWrite(PTEEHANDLE handle, const void *buffer, size_t bufferSize,
                   size_t *numberOfBytesWritten, uint32_t timeout)
{
    if (numberOfBytesWritten)
    {
        *numberOfBytesWritten = bufferSize;
    }
    return 0;
}

#define STATIC_FSTS0_BITS 0x55

TEESTATUS TeeFWStatus(PTEEHANDLE handle, uint32_t fwStatusNum, uint32_t *fwStatus)
{
    uint32_t val = 0;

    if (fwStatusNum == 0)
    {
        static int fwsts0_count = 0;
        const int fwsts0_threshold = 100;

        val = STATIC_FSTS0_BITS;
        if (fwsts0_count < fwsts0_threshold)
        {
            fwsts0_count ++;
        }
        else
        {
            val |= HECI1_CSE_FS_INITSTATE_COMPLETED_BIT;
        }
    }
    else if (fwStatusNum == 1)
    {
        static int fwsts1_count = 0;
        const int fwsts1_threshold = 100;
        val = (HECI1_CSE_GS1_PHASE_FWUPDATE << HECI1_CSE_FS_FWUPD_PHASE_SHIFT) |
              (fwsts1_count << HECI1_CSE_FS_FWUPD_PERCENT_SHIFT);
        if (fwsts1_count < fwsts1_threshold)
        {
            fwsts1_count ++;
        }
    }
    *fwStatus = val;

    return 0;
}

void TEEAPI TeeDisconnect(PTEEHANDLE handle)
{
}

uint32_t TEEAPI TeeGetLogLevel(IN const PTEEHANDLE handle)
{
    return 0;
}

uint32_t TEEAPI TeeSetLogLevel(IN PTEEHANDLE handle, IN uint32_t log_level)
{
    return 0;
}

TEESTATUS TEEAPI TeeSetLogCallback(IN const PTEEHANDLE handle, TeeLogCallback log_callback)
{
    return 0;
}

int driver_working_buffer_alloc(struct igsc_lib_ctx *lib_ctx);
void driver_working_buffer_free(struct igsc_lib_ctx *lib_ctx);

int gsc_driver_init(struct igsc_lib_ctx *lib_ctx, const GUID *guid)
{
    int status;

    UNUSED_VAR(guid);

    lib_ctx->driver_handle.maxMsgLen = 2048;
    lib_ctx->driver_handle.protcolVer = 1;

    status = driver_working_buffer_alloc(lib_ctx);
    if (status != IGSC_SUCCESS)
    {
        return status;
    }

    lib_ctx->driver_init_called = true;

    return status;
}

void gsc_driver_deinit(struct igsc_lib_ctx *lib_ctx)
{
    if (!lib_ctx->driver_init_called)
    {
        return;
    }

    driver_working_buffer_free(lib_ctx);

    lib_ctx->driver_init_called = false;
}

static int group_setup(void **state)
{
    struct igsc_device_handle *handle;

    *state = malloc(sizeof(*handle));
    if (*state == NULL)
    {
        return -1;
    }

    handle = *state;

    igsc_device_init_by_device(handle, "/dev/mei0");

    return 0;
}

static int group_teardown(void **state)
{
    struct igsc_device_handle *handle = *state;

    handle->ctx->device_path = 0;

    igsc_device_close(handle);

    free(*state);
    return 0;
}

#define FW_VER_RESPONSE_SIZE \
    (sizeof(struct gsc_fwu_heci_version_resp) + sizeof(struct igsc_fw_version))
#define OPROM_VER_RESPONSE_SIZE  \
    (sizeof(struct gsc_fwu_heci_version_resp) + sizeof(struct igsc_oprom_version))
#define FWU_START_RESPONSE_SIZE      sizeof(struct gsc_fwu_heci_start_resp)
#define FWU_DATA_RESPONSE_SIZE       sizeof(struct gsc_fwu_heci_data_resp)
#define FWU_DATA_INFO_RESPONSE_SIZE  sizeof(struct gsc_fw_data_heci_version_resp)
#define GET_SYSTEM_IDS_RESPONSE_SIZE sizeof(struct gsc_fwu_heci_get_subsystem_ids_message_resp)
#define GET_CONFIG_RESPONSE_SIZE     sizeof(struct gsc_fwu_heci_get_config_message_resp)

static const struct igsc_fw_version fw_version_dg01 = {
    .project = {'D', 'G', '0', '1'},
    .hotfix  = 0,
    .build   = 0,
};

static const struct igsc_fw_version fw_version_dg02 = {
    .project = {'D', 'G', '0', '2'},
    .hotfix  = 0,
    .build   = 0,
};

static const struct igsc_oprom_version oprom_version = {
    0, 0, 0, 0, 0, 0, 0, 0
};

static int create_response_get_ver(const struct gsc_fwu_heci_version_req *req,
                                   struct gsc_fwu_heci_version_resp *resp,
                                   void *version)
{
    resp->response.header = req->header;
    resp->response.header.is_response = 1;
    resp->response.status = GSC_FWU_STATUS_SUCCESS;
    resp->response.reserved = 0;
    resp->partition = req->partition;

    if (resp->partition == GSC_FWU_HECI_PART_VERSION_GFX_FW)
    {
        resp->version_length = sizeof(fw_version_dg02);
        memcpy(version, &fw_version_dg02, sizeof(fw_version_dg02));
    }
    else if (resp->partition == GSC_FWU_HECI_PART_VERSION_OPROM_DATA ||
             resp->partition == GSC_FWU_HECI_PART_VERSION_OPROM_CODE )
    {
        resp->version_length = sizeof(oprom_version);
        memcpy(version, &oprom_version, sizeof(oprom_version));
    }
    else
    {
        return -1;
    }

    return IGSC_SUCCESS;
}

int gsc_tee_command_get_ver(struct igsc_lib_ctx *lib_ctx,
                            void *req_buf, size_t request_len,
                            void *resp_buf, size_t buf_size,
                            size_t *response_len)
{

    int ret;
    respons_genartor_get_ver_f update_resp = mock_type(respons_genartor_get_ver_f);
    int status = mock_type(int);
    int resp_len = mock_type(int);
    uint8_t version_buf[100];

    struct gsc_fwu_heci_version_req *req = req_buf;
    struct gsc_fwu_heci_version_resp resp = {0};
    void *version = version_buf;

    ret = create_response_get_ver(req, &resp, version);
    update_resp(&resp, version);

    if (ret != IGSC_SUCCESS)
    {
        return -1;
    }

    memcpy(resp_buf, &resp, sizeof(resp));
    memcpy(resp_buf + sizeof(resp), version, resp.version_length);

    *response_len = resp_len;

    return status;
}

static void create_response_fwu_data_info(const struct gsc_fw_data_heci_version_req *req,
                                          struct gsc_fw_data_heci_version_resp *resp)
{
    resp->response.header = req->header;
    resp->response.header.is_response = 1;
    resp->response.header.reserved = 0;
    resp->response.header.reserved2[0] = 0;
    resp->response.header.reserved2[1] = 0;
    resp->response.status = GSC_FWU_STATUS_SUCCESS;
    resp->response.reserved = 0;

    resp->format_version = 0;
    resp->oem_manuf_data_version_nvm = 0;
    resp->oem_manuf_data_version_fitb = 0;
    resp->major_version = 0;
    resp->major_vcn = 0;
    resp->flags = 0;
    for (unsigned int i = 0; i < 6; i++)
    {
        resp->reserved[i] = 0;
    }
}

int gsc_tee_command_fwu_data_info(struct igsc_lib_ctx *lib_ctx,
                                  void *req_buf, size_t request_len,
                                  void *resp_buf, size_t buf_size,
                                  size_t *response_len)
{
    respons_genartor_fwu_data_info_f update_resp = mock_type(respons_genartor_fwu_data_info_f);
    int status = mock_type(int);
    int resp_len = mock_type(int);

    struct gsc_fw_data_heci_version_req *req = req_buf;
    struct gsc_fw_data_heci_version_resp resp = {0};

    create_response_fwu_data_info(req, &resp);
    update_resp(&resp);

    memcpy(resp_buf, &resp, sizeof(resp));

    *response_len = resp_len;

    return status;
}

static void create_response_fwu_start(const struct gsc_fwu_heci_start_req *req,
                                      struct gsc_fwu_heci_start_resp *resp)
{
    resp->response.header = req->header;
    resp->response.header.is_response = 1;
    resp->response.header.reserved = 0;
    resp->response.header.reserved2[0] = 0;
    resp->response.header.reserved2[1] = 0;
    resp->response.status = GSC_FWU_STATUS_SUCCESS;
    resp->response.reserved = 0;
}

int gsc_tee_command_fwu_start(struct igsc_lib_ctx *lib_ctx,
                              void *req_buf, size_t request_len,
                              void *resp_buf, size_t buf_size,
                              size_t *response_len)
{

    respons_genartor_fwu_start_f update_resp = mock_type(respons_genartor_fwu_start_f);
    int status = mock_type(int);
    int resp_len = mock_type(int);

    struct gsc_fwu_heci_start_req *req = req_buf;
    struct gsc_fwu_heci_start_resp resp = {0};

    create_response_fwu_start(req, &resp);
    update_resp(&resp);

    memcpy(resp_buf, &resp, sizeof(resp));

    *response_len = resp_len;

    return status;
}

static void create_response_fwu_data(const struct gsc_fwu_heci_data_req *req,
                                     struct gsc_fwu_heci_data_resp *resp)
{
    resp->response.header = req->header;
    resp->response.header.is_response = 1;
    resp->response.header.reserved = 0;
    resp->response.header.reserved2[0] = 0;
    resp->response.header.reserved2[1] = 0;
    resp->response.status = GSC_FWU_STATUS_SUCCESS;
    resp->response.reserved = 0;
}

int gsc_tee_command_fwu_data(struct igsc_lib_ctx *lib_ctx,
                              void *req_buf, size_t request_len,
                              void *resp_buf, size_t buf_size,
                              size_t *response_len)
{

    respons_genartor_fwu_data_f update_resp = mock_type(respons_genartor_fwu_data_f);
    int status = mock_type(int);
    int resp_len = mock_type(int);

    struct gsc_fwu_heci_data_req *req = req_buf;
    struct gsc_fwu_heci_data_resp resp = {0};

    create_response_fwu_data(req, &resp);
    update_resp(&resp);

    memcpy(resp_buf, &resp, sizeof(resp));

    *response_len = resp_len;

    return status;
}

static void create_response_get_config(const struct gsc_fwu_heci_get_config_message_req *req,
                                       struct gsc_fwu_heci_get_config_message_resp *resp)
{
    resp->response.header = req->header;
    resp->response.header.is_response = 1;
    resp->response.header.reserved = 0;
    resp->response.header.reserved2[0] = 0;
    resp->response.header.reserved2[1] = 0;
    resp->response.status = GSC_FWU_STATUS_SUCCESS;
    resp->response.reserved = 0;

    resp->format_version = GSC_FWU_GET_CONFIG_FORMAT_VERSION;
    resp->hw_step = 0;
    resp->hw_sku = 0;
    resp->oprom_code_devid_enforcement = 0;
    resp->flags = 0;
    resp->debug_config = 0;

    for (unsigned int i = 0; i < 7; i++)
    {
        resp->reserved[i] = 0;
    }
}

int gsc_tee_command_get_config(struct igsc_lib_ctx *lib_ctx,
                               void *req_buf, size_t request_len,
                               void *resp_buf, size_t buf_size,
                               size_t *response_len)
{

    respons_genartor_get_config_f update_resp = mock_type(respons_genartor_get_config_f);
    int status = mock_type(int);
    int resp_len = mock_type(int);

    struct gsc_fwu_heci_get_config_message_req *req = req_buf;
    struct gsc_fwu_heci_get_config_message_resp resp = {0};

    create_response_get_config(req, &resp);
    update_resp(&resp);

    memcpy(resp_buf, &resp, sizeof(resp));

    *response_len = resp_len;

    return status;
}

static void create_response_get_system_ids(const struct gsc_fwu_heci_get_subsystem_ids_message_req *req,
                                           struct gsc_fwu_heci_get_subsystem_ids_message_resp *resp)
{
    resp->response.header = req->header;
    resp->response.header.is_response = 1;
    resp->response.header.reserved = 0;
    resp->response.header.reserved2[0] = 0;
    resp->response.header.reserved2[1] = 0;
    resp->response.status = GSC_FWU_STATUS_SUCCESS;
    resp->response.reserved = 0;

    resp->ssvid = 0x8086;
    resp->ssdid = 0x56A0;

    for (unsigned int i = 0; i < 2; i++)
    {
        resp->reserved[i] = 0;
    }
}

int gsc_tee_command_get_subsystem_ids(struct igsc_lib_ctx *lib_ctx,
                                      void *req_buf, size_t request_len,
                                      void *resp_buf, size_t buf_size,
                                      size_t *response_len)
{

    respons_genartor_get_subsystem_ids_f update_resp = mock_type(respons_genartor_get_subsystem_ids_f);
    int status = mock_type(int);
    int resp_len = mock_type(int);

    struct gsc_fwu_heci_get_subsystem_ids_message_req *req = req_buf;
    struct gsc_fwu_heci_get_subsystem_ids_message_resp resp = {0};

    create_response_get_system_ids(req, &resp);
    update_resp(&resp);

    memcpy(resp_buf, &resp, sizeof(resp));

    *response_len = resp_len;

    return status;
}

int gsc_tee_command(struct igsc_lib_ctx *lib_ctx,
                    void *req_buf, size_t request_len,
                    void *resp_buf, size_t buf_size,
                    size_t *response_len)
{
    struct gsc_fwu_heci_header *header = (struct gsc_fwu_heci_header *)req_buf;

    switch (header->command_id) {
    case GSC_FWU_HECI_COMMAND_ID_GET_IP_VERSION:
       return gsc_tee_command_get_ver(lib_ctx, req_buf, request_len, resp_buf, buf_size, response_len);
    case GSC_FWU_HECI_COMMAND_ID_START:
        return gsc_tee_command_fwu_start(lib_ctx, req_buf, request_len, resp_buf, buf_size, response_len);
    case GSC_FWU_HECI_COMMAND_ID_DATA:
        return gsc_tee_command_fwu_data(lib_ctx, req_buf, request_len, resp_buf, buf_size, response_len);
    case GSC_FWU_HECI_COMMAND_ID_GET_GFX_DATA_UPDATE_INFO:
        return gsc_tee_command_fwu_data_info(lib_ctx, req_buf, request_len, resp_buf, buf_size, response_len);
    case GSC_FWU_HECI_COMMAND_ID_GET_CONFIG:
        return gsc_tee_command_get_config(lib_ctx, req_buf, request_len, resp_buf, buf_size, response_len);
    case GSC_FWU_HECI_COMMAND_ID_GET_SUBSYSTEM_IDS:
        return gsc_tee_command_get_subsystem_ids(lib_ctx, req_buf, request_len, resp_buf, buf_size, response_len);
    case GSC_FWU_HECI_COMMAND_ID_END:
    case GSC_FWU_HECI_COMMAND_ID_NO_UPDATE:
        /* END  and NO_UPDATE commands call directly TeeWrite so it should not come here */
        /* Falling through */
    default:
        /* unknown command - fail the test */
        assert_true(false);
        return IGSC_ERROR_INVALID_PARAMETER;
    }
}

#define PERCENT_100 100

static void progress_percentage_func(uint32_t done, uint32_t total, void *ctx)
{
    uint32_t percent = (done * PERCENT_100) / total;

    UNUSED_VAR(ctx);

    if (percent > PERCENT_100)
    {
        percent = PERCENT_100;
    }

    printf("Progress %d/%d:%2d%%\n", done, total, percent);
}

static uint8_t global_buffer[1024*5];

static void setup_oprom_image(struct igsc_oprom_image *img)
{
    img->buffer = global_buffer;
    img->buffer_len = sizeof(global_buffer);
    img->code_part_ptr = img->buffer;
    img->data_part_ptr = img->buffer;
    img->data_part_len = sizeof(global_buffer);
    img->code_part_len = sizeof(global_buffer);
}

/* get_config response generators */
void good_response_get_config(struct gsc_fwu_heci_get_config_message_resp *resp)
{
    UNUSED_VAR(resp);
}

void bad_size_get_config(struct gsc_fwu_heci_get_config_message_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_SIZE_ERROR;
}

void bad_command_id_get_config(struct gsc_fwu_heci_get_config_message_resp *resp)
{
    resp->response.header.command_id = 0;
}

void bad_command_id2_get_config(struct gsc_fwu_heci_get_config_message_resp *resp)
{
    resp->response.header.command_id ++;
}

void bad_is_response_get_config(struct gsc_fwu_heci_get_config_message_resp *resp)
{
    resp->response.header.is_response = 0;
}

void bad_reserved_get_config(struct gsc_fwu_heci_get_config_message_resp *resp)
{
    resp->response.reserved = 1;
}

void bad_header_reserved_get_config(struct gsc_fwu_heci_get_config_message_resp *resp)
{
    resp->response.header.reserved = 1;
}

void bad_header_reserved2_get_config(struct gsc_fwu_heci_get_config_message_resp *resp)
{
    resp->response.header.reserved2[0] = 3;
}

void bad_header_reserved3_get_config(struct gsc_fwu_heci_get_config_message_resp *resp)
{
    resp->response.header.reserved2[1] = 4;
}

void bad_status_get_config(struct gsc_fwu_heci_get_config_message_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_FAILURE;
}

void bad_command_param_get_config(struct gsc_fwu_heci_get_config_message_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_INVALID_PARAMS;
}

void bad_format_version_get_config(struct gsc_fwu_heci_get_config_message_resp *resp)
{
    resp->format_version = GSC_FWU_GET_CONFIG_FORMAT_VERSION + 1;
}

void bad_hw_sku_get_config(struct gsc_fwu_heci_get_config_message_resp *resp)
{
    resp->hw_sku = 18;
}

static void test_get_config_good(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_hw_config hw_config = {0};

    will_return(gsc_tee_command_get_config, &good_response_get_config);
    will_return(gsc_tee_command_get_config, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_config, GET_CONFIG_RESPONSE_SIZE);

    ret = igsc_device_hw_config(handle, &hw_config);

    assert_true(ret == IGSC_SUCCESS);
}

static void test_get_config_dg01(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_hw_config hw_config = {0};

    will_return(gsc_tee_command_get_config, &good_response_get_config);
    will_return(gsc_tee_command_get_config, IGSC_ERROR_NOT_SUPPORTED);
    will_return(gsc_tee_command_get_config, GET_CONFIG_RESPONSE_SIZE);

    ret = igsc_device_hw_config(handle, &hw_config);

    assert_true(ret == IGSC_ERROR_NOT_SUPPORTED);
}

static void test_get_config_bad_size(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_hw_config hw_config = {0};

    will_return(gsc_tee_command_get_config, &bad_size_get_config);
    will_return(gsc_tee_command_get_config, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_config, GET_CONFIG_RESPONSE_SIZE);

    ret = igsc_device_hw_config(handle, &hw_config);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_config_bad_command_id(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_hw_config hw_config = {0};

    will_return(gsc_tee_command_get_config, &bad_command_id_get_config);
    will_return(gsc_tee_command_get_config, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_config, GET_CONFIG_RESPONSE_SIZE);

    ret = igsc_device_hw_config(handle, &hw_config);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_config_bad_command_id2(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_hw_config hw_config = {0};

    will_return(gsc_tee_command_get_config, &bad_command_id2_get_config);
    will_return(gsc_tee_command_get_config, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_config, GET_CONFIG_RESPONSE_SIZE);

    ret = igsc_device_hw_config(handle, &hw_config);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_config_bad_is_response(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_hw_config hw_config = {0};

    will_return(gsc_tee_command_get_config, &bad_is_response_get_config);
    will_return(gsc_tee_command_get_config, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_config, GET_CONFIG_RESPONSE_SIZE);

    ret = igsc_device_hw_config(handle, &hw_config);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_config_bad_reserved(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_hw_config hw_config = {0};

    will_return(gsc_tee_command_get_config, &bad_reserved_get_config);
    will_return(gsc_tee_command_get_config, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_config, GET_CONFIG_RESPONSE_SIZE);

    ret = igsc_device_hw_config(handle, &hw_config);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_config_bad_header_reserved(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_hw_config hw_config = {0};

    will_return(gsc_tee_command_get_config, &bad_header_reserved_get_config);
    will_return(gsc_tee_command_get_config, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_config, GET_CONFIG_RESPONSE_SIZE);

    ret = igsc_device_hw_config(handle, &hw_config);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_config_bad_header_reserved2(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_hw_config hw_config = {0};

    will_return(gsc_tee_command_get_config, &bad_header_reserved2_get_config);
    will_return(gsc_tee_command_get_config, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_config, GET_CONFIG_RESPONSE_SIZE);

    ret = igsc_device_hw_config(handle, &hw_config);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_config_bad_header_reserved3(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_hw_config hw_config = {0};

    will_return(gsc_tee_command_get_config, &bad_header_reserved3_get_config);
    will_return(gsc_tee_command_get_config, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_config, GET_CONFIG_RESPONSE_SIZE);

    ret = igsc_device_hw_config(handle, &hw_config);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_config_bad_status(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_hw_config hw_config = {0};

    will_return(gsc_tee_command_get_config, &bad_status_get_config);
    will_return(gsc_tee_command_get_config, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_config, GET_CONFIG_RESPONSE_SIZE);

    ret = igsc_device_hw_config(handle, &hw_config);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_config_bad_command_param(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_hw_config hw_config = {0};

    will_return(gsc_tee_command_get_config, &bad_command_param_get_config);
    will_return(gsc_tee_command_get_config, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_config, GET_CONFIG_RESPONSE_SIZE);

    ret = igsc_device_hw_config(handle, &hw_config);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_config_bad_format_version(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_hw_config hw_config = {0};

    will_return(gsc_tee_command_get_config, &bad_format_version_get_config);
    will_return(gsc_tee_command_get_config, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_config, GET_CONFIG_RESPONSE_SIZE);

    ret = igsc_device_hw_config(handle, &hw_config);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_config_bad_hw_sku(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_hw_config hw_config = {0};

    will_return(gsc_tee_command_get_config, &bad_hw_sku_get_config);
    will_return(gsc_tee_command_get_config, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_config, GET_CONFIG_RESPONSE_SIZE);

    ret = igsc_device_hw_config(handle, &hw_config);

    assert_true(ret != IGSC_SUCCESS);
}

/* get_system_ids response generators */
void good_response_get_subsystem_ids(struct gsc_fwu_heci_get_subsystem_ids_message_resp *resp)
{
    UNUSED_VAR(resp);
}

void bad_size_get_subsystem_ids(struct gsc_fwu_heci_get_subsystem_ids_message_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_SIZE_ERROR;
}

void bad_command_id_get_subsystem_ids(struct gsc_fwu_heci_get_subsystem_ids_message_resp *resp)
{
    resp->response.header.command_id = 0;
}

void bad_command_id2_get_subsystem_ids(struct gsc_fwu_heci_get_subsystem_ids_message_resp *resp)
{
    resp->response.header.command_id ++;
}

void bad_is_response_get_subsystem_ids(struct gsc_fwu_heci_get_subsystem_ids_message_resp *resp)
{
    resp->response.header.is_response = 0;
}

void bad_reserved_get_subsystem_ids(struct gsc_fwu_heci_get_subsystem_ids_message_resp *resp)
{
    resp->response.reserved = 1;
}

void bad_header_reserved_get_subsystem_ids(struct gsc_fwu_heci_get_subsystem_ids_message_resp *resp)
{
    resp->response.header.reserved = 1;
}

void bad_header_reserved2_get_subsystem_ids(struct gsc_fwu_heci_get_subsystem_ids_message_resp *resp)
{
    resp->response.header.reserved2[0] = 3;
}

void bad_header_reserved3_get_subsystem_ids(struct gsc_fwu_heci_get_subsystem_ids_message_resp *resp)
{
    resp->response.header.reserved2[1] = 4;
}

void bad_status_get_subsystem_ids(struct gsc_fwu_heci_get_subsystem_ids_message_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_FAILURE;
}

void bad_command_param_get_subsystem_ids(struct gsc_fwu_heci_get_subsystem_ids_message_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_INVALID_PARAMS;
}

/* get_subsystem_ids tets */

static void test_get_subsystem_ids_good(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_subsystem_ids ssids = {0};

    will_return(gsc_tee_command_get_subsystem_ids, &good_response_get_subsystem_ids);
    will_return(gsc_tee_command_get_subsystem_ids, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_subsystem_ids, GET_SYSTEM_IDS_RESPONSE_SIZE);

    ret = igsc_device_subsystem_ids(handle, &ssids);

    assert_true(ret == IGSC_SUCCESS);
}

static void test_get_subsystem_ids_bad_size(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_subsystem_ids ssids = {0};

    will_return(gsc_tee_command_get_subsystem_ids, &bad_size_get_subsystem_ids);
    will_return(gsc_tee_command_get_subsystem_ids, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_subsystem_ids, GET_SYSTEM_IDS_RESPONSE_SIZE);

    ret = igsc_device_subsystem_ids(handle, &ssids);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_subsystem_ids_bad_command_id(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_subsystem_ids ssids = {0};

    will_return(gsc_tee_command_get_subsystem_ids, &bad_command_id_get_subsystem_ids);
    will_return(gsc_tee_command_get_subsystem_ids, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_subsystem_ids, GET_SYSTEM_IDS_RESPONSE_SIZE);

    ret = igsc_device_subsystem_ids(handle, &ssids);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_subsystem_ids_bad_command_id2(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_subsystem_ids ssids = {0};

    will_return(gsc_tee_command_get_subsystem_ids, &bad_command_id2_get_subsystem_ids);
    will_return(gsc_tee_command_get_subsystem_ids, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_subsystem_ids, GET_SYSTEM_IDS_RESPONSE_SIZE);

    ret = igsc_device_subsystem_ids(handle, &ssids);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_subsystem_ids_bad_is_response(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_subsystem_ids ssids = {0};

    will_return(gsc_tee_command_get_subsystem_ids, &bad_is_response_get_subsystem_ids);
    will_return(gsc_tee_command_get_subsystem_ids, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_subsystem_ids, GET_SYSTEM_IDS_RESPONSE_SIZE);

    ret = igsc_device_subsystem_ids(handle, &ssids);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_subsystem_ids_bad_reserved(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_subsystem_ids ssids = {0};

    will_return(gsc_tee_command_get_subsystem_ids, &bad_reserved_get_subsystem_ids);
    will_return(gsc_tee_command_get_subsystem_ids, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_subsystem_ids, GET_SYSTEM_IDS_RESPONSE_SIZE);

    ret = igsc_device_subsystem_ids(handle, &ssids);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_subsystem_ids_bad_header_reserved(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_subsystem_ids ssids = {0};

    will_return(gsc_tee_command_get_subsystem_ids, &bad_header_reserved_get_subsystem_ids);
    will_return(gsc_tee_command_get_subsystem_ids, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_subsystem_ids, GET_SYSTEM_IDS_RESPONSE_SIZE);

    ret = igsc_device_subsystem_ids(handle, &ssids);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_subsystem_ids_bad_header_reserved2(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_subsystem_ids ssids = {0};

    will_return(gsc_tee_command_get_subsystem_ids, &bad_header_reserved2_get_subsystem_ids);
    will_return(gsc_tee_command_get_subsystem_ids, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_subsystem_ids, GET_SYSTEM_IDS_RESPONSE_SIZE);

    ret = igsc_device_subsystem_ids(handle, &ssids);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_subsystem_ids_bad_header_reserved3(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_subsystem_ids ssids = {0};

    will_return(gsc_tee_command_get_subsystem_ids, &bad_header_reserved3_get_subsystem_ids);
    will_return(gsc_tee_command_get_subsystem_ids, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_subsystem_ids, GET_SYSTEM_IDS_RESPONSE_SIZE);

    ret = igsc_device_subsystem_ids(handle, &ssids);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_subsystem_ids_bad_status(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_subsystem_ids ssids = {0};

    will_return(gsc_tee_command_get_subsystem_ids, &bad_status_get_subsystem_ids);
    will_return(gsc_tee_command_get_subsystem_ids, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_subsystem_ids, GET_SYSTEM_IDS_RESPONSE_SIZE);

    ret = igsc_device_subsystem_ids(handle, &ssids);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_get_subsystem_ids_bad_command_param(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_subsystem_ids ssids = {0};

    will_return(gsc_tee_command_get_subsystem_ids, &bad_command_param_get_subsystem_ids);
    will_return(gsc_tee_command_get_subsystem_ids, IGSC_SUCCESS);
    will_return(gsc_tee_command_get_subsystem_ids, GET_SYSTEM_IDS_RESPONSE_SIZE);

    ret = igsc_device_subsystem_ids(handle, &ssids);

    assert_true(ret != IGSC_SUCCESS);
}

/* fw_start and fw_data response generators */
void good_response_fwu_start(struct gsc_fwu_heci_start_resp *resp)
{
    UNUSED_VAR(resp);
}

void good_response_fwu_data(struct gsc_fwu_heci_data_resp *resp)
{
    UNUSED_VAR(resp);
}

void bad_size_fwu_start(struct gsc_fwu_heci_start_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_SIZE_ERROR;
}

void bad_size_fwu_data(struct gsc_fwu_heci_data_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_SIZE_ERROR;
}

void bad_command_id_fwu_start(struct gsc_fwu_heci_start_resp *resp)
{
    resp->response.header.command_id = 0;
}

void bad_command_id_fwu_data(struct gsc_fwu_heci_data_resp *resp)
{
    resp->response.header.command_id = 0;
}

void bad_command_id2_fwu_start(struct gsc_fwu_heci_start_resp *resp)
{
    resp->response.header.command_id ++;
}

void bad_command_id2_fwu_data(struct gsc_fwu_heci_data_resp *resp)
{
    resp->response.header.command_id ++;
}

void bad_is_response_fwu_start(struct gsc_fwu_heci_start_resp *resp)
{
    resp->response.header.is_response = 0;
}

void bad_is_response_fwu_data(struct gsc_fwu_heci_data_resp *resp)
{
    resp->response.header.is_response = 0;
}

void bad_reserved_fwu_start(struct gsc_fwu_heci_start_resp *resp)
{
    resp->response.reserved = 1;
}

void bad_reserved_fwu_data(struct gsc_fwu_heci_data_resp *resp)
{
    resp->response.reserved = 1;
}

void bad_status_fwu_start(struct gsc_fwu_heci_start_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_FAILURE;
}

void bad_status_fwu_data(struct gsc_fwu_heci_data_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_FAILURE;
}

void bad_oprom_signature_fwu_start(struct gsc_fwu_heci_start_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_UPDATE_OPROM_INVALID_STRUCTURE;
}

void bad_oprom_signature_fwu_data(struct gsc_fwu_heci_data_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_UPDATE_OPROM_INVALID_STRUCTURE;
}

void status_oprom_section_not_exist_fwu_start(struct gsc_fwu_heci_start_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_UPDATE_OPROM_SECTION_NOT_EXIST;
}

void status_oprom_section_not_exist_fwu_data(struct gsc_fwu_heci_data_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_UPDATE_OPROM_SECTION_NOT_EXIST;
}

void bad_command_param_fwu_start(struct gsc_fwu_heci_start_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_INVALID_PARAMS;
}

void bad_command_param_fwu_data(struct gsc_fwu_heci_data_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_INVALID_PARAMS;
}

void bad_header_reserved_fw_start(struct gsc_fwu_heci_start_resp *resp)
{
    resp->response.header.reserved = 1;
}

void bad_header_reserved_fw_data(struct gsc_fwu_heci_data_resp *resp)
{
    resp->response.header.reserved = 1;
}

void bad_header_reserved2_fw_start(struct gsc_fwu_heci_start_resp *resp)
{
    resp->response.header.reserved2[0] = 3;
}

void bad_header_reserved2_fw_data(struct gsc_fwu_heci_data_resp *resp)
{
    resp->response.header.reserved2[0] = 0xff;
}

void bad_header_reserved3_fw_start(struct gsc_fwu_heci_start_resp *resp)
{
    resp->response.header.reserved2[1] = 4;
}

void bad_header_reserved3_fw_data(struct gsc_fwu_heci_data_resp *resp)
{
    resp->response.header.reserved2[1] = 4;
}

/* oprom data, oprom code and iaf fw update tests */
static void test_oprom_code_update_good(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &good_response_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &good_response_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &good_response_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret == IGSC_SUCCESS);
}

static void test_oprom_data_update_good(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_DATA;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &good_response_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &good_response_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &good_response_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret == IGSC_SUCCESS);
}

static void test_iaf_update_good(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &good_response_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &good_response_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &good_response_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret == IGSC_SUCCESS);
}

static void test_oprom_code_null_handle(void **state)
{
    int ret;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    ret = igsc_device_oprom_update(NULL, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_data_null_handle(void **state)
{
    int ret;
    uint32_t oprom_type = IGSC_OPROM_DATA;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    ret = igsc_device_oprom_update(NULL, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_iaf_update_null_handle(void **state)
{
    int ret;

    ret = igsc_iaf_psc_update(NULL, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_code_null_img(void **state)
{
    int ret;
    uint32_t oprom_type = IGSC_OPROM_CODE;

    struct igsc_device_handle *handle = *state;

    ret = igsc_device_oprom_update(handle, oprom_type, NULL,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_data_null_img(void **state)
{
    int ret;
    uint32_t oprom_type = IGSC_OPROM_DATA;

    struct igsc_device_handle *handle = *state;

    ret = igsc_device_oprom_update(handle, oprom_type, NULL,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_iaf_update_null_buffer(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    ret = igsc_iaf_psc_update(handle, NULL, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_iaf_update_zero_buffer_size(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    ret = igsc_iaf_psc_update(handle, global_buffer, 0,
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_code_null_ctx(void **state)
{
    int ret;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;
    struct igsc_device_handle *handle = malloc(sizeof(struct igsc_device_handle));

    setup_oprom_image(&img);

    handle->ctx = NULL;

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);
    free(handle);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_data_null_ctx(void **state)
{
    int ret;
    uint32_t oprom_type = IGSC_OPROM_DATA;
    struct igsc_oprom_image img;
    struct igsc_device_handle *handle = malloc(sizeof(struct igsc_device_handle));

    setup_oprom_image(&img);

    handle->ctx = NULL;

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);
    free(handle);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_iaf_update_null_ctx(void **state)
{
    int ret;
    struct igsc_device_handle *handle = malloc(sizeof(struct igsc_device_handle));

    handle->ctx = NULL;

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    free(handle);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_start_bad_response_size(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &bad_size_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_data_bad_response_size(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_size_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_start_bad_response_size(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &bad_size_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_data_bad_response_size(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_size_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_start_bad_command_id(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &bad_command_id_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_data_bad_command_id(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_command_id_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_start_bad_command_id(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &bad_command_id_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_data_bad_command_id(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_command_id_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_start_bad_command_id2(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &bad_command_id2_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_data_bad_command_id2(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_command_id2_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_start_bad_command_id2(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &bad_command_id2_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_data_bad_command_id2(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_command_id2_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_start_bad_is_response(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &bad_is_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_data_bad_is_response(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &good_response_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_is_response_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_start_bad_is_response(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &bad_is_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_data_bad_is_response(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_is_response_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_start_bad_reserved(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &bad_reserved_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_data_bad_reserved(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_reserved_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_data_bad_reserved(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_reserved_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_start_bad_reserved(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &bad_reserved_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_start_bad_status(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &bad_status_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_data_bad_status(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_status_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_data_bad_status(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_status_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_start_bad_status(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &bad_status_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);


    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_start_bad_oprom_signature(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &bad_oprom_signature_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_data_bad_oprom_signature(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_oprom_signature_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_data_bad_oprom_signature(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_oprom_signature_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_start_bad_oprom_signature(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &bad_oprom_signature_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_start_status_oprom_section_not_exist(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &status_oprom_section_not_exist_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_data_status_oprom_section_not_exist(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &status_oprom_section_not_exist_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);
    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_data_status_oprom_section_not_exist(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &status_oprom_section_not_exist_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_start_status_oprom_section_not_exist(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &status_oprom_section_not_exist_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_start_bad_command_param(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &bad_command_param_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_data_bad_command_param(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img;

    setup_oprom_image(&img);

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_command_param_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_device_oprom_update(handle, oprom_type, &img,
                                   progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_data_bad_command_param(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &good_response_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    will_return(gsc_tee_command_fwu_data, &bad_command_param_fwu_data);
    will_return(gsc_tee_command_fwu_data, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_data, FWU_DATA_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwu_iaf_start_bad_command_param(void **state)
{
    int ret;
    struct igsc_device_handle *handle = *state;

    will_return(gsc_tee_command_fwu_start, &bad_command_param_fwu_start);
    will_return(gsc_tee_command_fwu_start, IGSC_SUCCESS);
    will_return(gsc_tee_command_fwu_start, FWU_START_RESPONSE_SIZE);

    ret = igsc_iaf_psc_update(handle, global_buffer, sizeof(global_buffer),
                              progress_percentage_func, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

int main(void)
{
    const struct CMUnitTest tests[] = {

        cmocka_unit_test(test_oprom_code_update_good),
        cmocka_unit_test(test_oprom_data_update_good),
        cmocka_unit_test(test_iaf_update_good),
        cmocka_unit_test(test_oprom_code_null_handle),
        cmocka_unit_test(test_oprom_data_null_handle),
        cmocka_unit_test(test_iaf_update_null_handle),
        cmocka_unit_test(test_oprom_code_null_img),
        cmocka_unit_test(test_oprom_data_null_img),
        cmocka_unit_test(test_iaf_update_null_buffer),
        cmocka_unit_test(test_iaf_update_zero_buffer_size),
        cmocka_unit_test(test_oprom_code_null_ctx),
        cmocka_unit_test(test_oprom_data_null_ctx),
        cmocka_unit_test(test_iaf_update_null_ctx),
        cmocka_unit_test(test_fwu_start_bad_response_size),
        cmocka_unit_test(test_fwu_data_bad_response_size),
        cmocka_unit_test(test_fwu_iaf_start_bad_response_size),
        cmocka_unit_test(test_fwu_iaf_data_bad_response_size),
        cmocka_unit_test(test_fwu_start_bad_command_id),
        cmocka_unit_test(test_fwu_data_bad_command_id),
        cmocka_unit_test(test_fwu_iaf_start_bad_command_id),
        cmocka_unit_test(test_fwu_iaf_data_bad_command_id),
        cmocka_unit_test(test_fwu_start_bad_command_id2),
        cmocka_unit_test(test_fwu_data_bad_command_id2),
        cmocka_unit_test(test_fwu_iaf_start_bad_command_id2),
        cmocka_unit_test(test_fwu_iaf_data_bad_command_id2),
        cmocka_unit_test(test_fwu_start_bad_is_response),
        cmocka_unit_test(test_fwu_data_bad_is_response),
        cmocka_unit_test(test_fwu_iaf_start_bad_is_response),
        cmocka_unit_test(test_fwu_iaf_data_bad_is_response),
        cmocka_unit_test(test_fwu_start_bad_reserved),
        cmocka_unit_test(test_fwu_data_bad_reserved),
        cmocka_unit_test(test_fwu_iaf_data_bad_reserved),
        cmocka_unit_test(test_fwu_iaf_start_bad_reserved),
        cmocka_unit_test(test_fwu_start_bad_status),
        cmocka_unit_test(test_fwu_data_bad_status),
        cmocka_unit_test(test_fwu_iaf_data_bad_status),
        cmocka_unit_test(test_fwu_iaf_start_bad_status),
        cmocka_unit_test(test_fwu_start_bad_oprom_signature),
        cmocka_unit_test(test_fwu_data_bad_oprom_signature),
        cmocka_unit_test(test_fwu_iaf_data_bad_oprom_signature),
        cmocka_unit_test(test_fwu_iaf_start_bad_oprom_signature),
        cmocka_unit_test(test_fwu_start_status_oprom_section_not_exist),
        cmocka_unit_test(test_fwu_data_status_oprom_section_not_exist),
        cmocka_unit_test(test_fwu_iaf_data_status_oprom_section_not_exist),
        cmocka_unit_test(test_fwu_iaf_start_status_oprom_section_not_exist),
        cmocka_unit_test(test_fwu_start_bad_command_param),
        cmocka_unit_test(test_fwu_data_bad_command_param),
        cmocka_unit_test(test_fwu_iaf_data_bad_command_param),
        cmocka_unit_test(test_fwu_iaf_start_bad_command_param),

        cmocka_unit_test(test_get_subsystem_ids_good),
        cmocka_unit_test(test_get_subsystem_ids_bad_size),
        cmocka_unit_test(test_get_subsystem_ids_bad_command_id),
        cmocka_unit_test(test_get_subsystem_ids_bad_command_id2),
        cmocka_unit_test(test_get_subsystem_ids_bad_is_response),
        cmocka_unit_test(test_get_subsystem_ids_bad_reserved),
        cmocka_unit_test(test_get_subsystem_ids_bad_header_reserved),
        cmocka_unit_test(test_get_subsystem_ids_bad_header_reserved2),
        cmocka_unit_test(test_get_subsystem_ids_bad_header_reserved3),
        cmocka_unit_test(test_get_subsystem_ids_bad_status),
        cmocka_unit_test(test_get_subsystem_ids_bad_command_param),

        cmocka_unit_test(test_get_config_good),
        cmocka_unit_test(test_get_config_dg01),
        cmocka_unit_test(test_get_config_bad_size),
        cmocka_unit_test(test_get_config_bad_command_id),
        cmocka_unit_test(test_get_config_bad_command_id2),
        cmocka_unit_test(test_get_config_bad_is_response),
        cmocka_unit_test(test_get_config_bad_reserved),
        cmocka_unit_test(test_get_config_bad_header_reserved),
        cmocka_unit_test(test_get_config_bad_header_reserved2),
        cmocka_unit_test(test_get_config_bad_header_reserved3),
        cmocka_unit_test(test_get_config_bad_status),
        cmocka_unit_test(test_get_config_bad_command_param),
        cmocka_unit_test(test_get_config_bad_format_version),
        cmocka_unit_test(test_get_config_bad_hw_sku),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
