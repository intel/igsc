/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025 Intel Corporation
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
#include "ipl.h"

#define MAX_MSG_LEN 4096
#define MIN_SVN 5

TEESTATUS TeeInit(PTEEHANDLE handle, const GUID* guid, const char* device)
{
    return 0;
}

TEESTATUS TeeInitHandle(PTEEHANDLE handle, const GUID* guid,
    const TEE_DEVICE_HANDLE device_handle)
{
    return 0;
}

TEESTATUS TeeConnect(PTEEHANDLE handle)
{
    return 0;
}

TEESTATUS TeeRead(PTEEHANDLE handle, void* buffer, size_t bufferSize,
    size_t* pNumOfBytesRead, uint32_t timeout)
{
    struct ipl_late_binding_response *rsp = buffer;

    if (bufferSize < sizeof(*rsp))
    {
        return TEE_INSUFFICIENT_BUFFER;
    }

    memset(rsp, 0, sizeof(*rsp));

    rsp->rheader.header.command_id = IPL_HECI_COMMAND_ID_LATE_BINDING;
    rsp->rheader.header.flags = IPL_FLAG_RESPONSE;

    rsp->type = CSC_LATE_BINDING_TYPE_DGDIAG;

    if (pNumOfBytesRead)
    {
        *pNumOfBytesRead = sizeof(*rsp);
    }

    return 0;
}

TEESTATUS TeeWrite(PTEEHANDLE handle, const void* buffer, size_t bufferSize,
    size_t* numberOfBytesWritten, uint32_t timeout)
{
    if (numberOfBytesWritten)
    {
        *numberOfBytesWritten = bufferSize;
    }
    return 0;
}

TEESTATUS TeeFWStatus(PTEEHANDLE handle, uint32_t fwStatusNum, uint32_t* fwStatus)
{
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

int driver_working_buffer_alloc(struct igsc_lib_ctx* lib_ctx);
void driver_working_buffer_free(struct igsc_lib_ctx* lib_ctx);

int gsc_driver_init(struct igsc_lib_ctx* lib_ctx, const GUID* guid)
{
    int status;

    UNUSED_VAR(guid);

    lib_ctx->driver_handle.maxMsgLen = MAX_MSG_LEN;
    lib_ctx->driver_handle.protcolVer = 1;

    status = driver_working_buffer_alloc(lib_ctx);
    if (status != IGSC_SUCCESS)
    {
        return status;
    }

    lib_ctx->driver_init_called = true;

    igsc_set_log_level(IGSC_LOG_LEVEL_TRACE);

    return status;
}

void gsc_driver_deinit(struct igsc_lib_ctx* lib_ctx)
{
    if (!lib_ctx->driver_init_called)
    {
        return;
    }

    driver_working_buffer_free(lib_ctx);

    lib_ctx->driver_init_called = false;
}

static int group_setup(void** state)
{
    struct igsc_device_handle* handle;

    *state = malloc(sizeof(*handle));
    if (*state == NULL)
    {
        return -1;
    }

    handle = *state;

    igsc_device_init_by_device(handle, "/dev/mei0");

    return 0;
}

static int group_teardown(void** state)
{
    struct igsc_device_handle* handle = *state;

    handle->ctx->device_path = 0;

    igsc_device_close(handle);

    free(*state);
    return 0;
}

typedef void (*response_generator_late_bind_f)(struct ipl_late_binding_response*);
typedef void (*response_generator_late_bind_info_f)(struct ipl_late_binding_get_info_response*);

static void create_response_late_bind(const struct ipl_late_binding_request* req,
    struct ipl_late_binding_response* resp)
{
    resp->rheader.header = req->header;
    resp->rheader.header.flags = IPL_FLAG_RESPONSE;
    resp->rheader.status = CSC_LATE_BINDING_STATUS_SUCCESS;
    resp->type = req->type;
    resp->reserved[0] = 0;
    resp->reserved[1] = 0;
}

static void create_response_late_bind_info(const struct ipl_late_binding_get_info_request* req,
    struct ipl_late_binding_get_info_response* resp)
{
    resp->rheader.header = req->header;
    resp->rheader.header.flags = IPL_FLAG_RESPONSE;
    resp->rheader.status = CSC_LATE_BINDING_STATUS_SUCCESS;

    resp->min_svn = MIN_SVN;
    resp->svn_source = CSC_LATE_BINDING_SVN_SOURCE_SPI;
    resp->type = req->type;
    resp->reserved[0] = 0;
    resp->reserved[1] = 0;
}

int gsc_tee_command_late_bind(struct igsc_lib_ctx* lib_ctx,
    void* req_buf, size_t request_len,
    void* resp_buf, size_t buf_size,
    size_t* response_len)
{

    response_generator_late_bind_f update_resp = mock_type(response_generator_late_bind_f);
    int status = mock_type(int);
    int resp_len = mock_type(int);
    bool first = mock_type(bool);
    bool last = mock_type(bool);
    size_t total_size = mock_type(size_t);
    size_t size = mock_type(size_t);

    struct ipl_late_binding_request* req = req_buf;
    struct ipl_late_binding_response resp = { 0 };

    if (first && !(req->flags & CSC_LATE_BINDING_FLAG_FST_CHUNK))
    {
        fail_msg("first chunk is not marked 0x%08X", req->flags);
    }

    if (last && !(req->flags & CSC_LATE_BINDING_FLAG_LST_CHUNK))
    {
        fail_msg("last chunk is not marked 0x%08X", req->flags);
    }

    if (req->total_payload_size != total_size)
    {
        fail_msg("Total size is wrong %zu != %zu", req->total_payload_size, total_size);
    }

    if (req->payload_size != size)
    {
        fail_msg("Size is wrong %zu != %zu", req->payload_size, size);
    }

    create_response_late_bind(req, &resp);
    update_resp(&resp);

    memcpy(resp_buf, &resp, sizeof(resp));

    *response_len = resp_len;

    return status;
}

int gsc_tee_command_late_bind_info(struct igsc_lib_ctx* lib_ctx,
    void* req_buf, size_t request_len,
    void* resp_buf, size_t buf_size,
    size_t* response_len)
{

    response_generator_late_bind_info_f update_resp = mock_type(response_generator_late_bind_info_f);
    int status = mock_type(int);
    int resp_len = mock_type(int);

    struct ipl_late_binding_get_info_request* req = req_buf;
    struct ipl_late_binding_get_info_response resp = { 0 };

    create_response_late_bind_info(req, &resp);
    update_resp(&resp);

    memcpy(resp_buf, &resp, sizeof(resp));

    *response_len = resp_len;

    return status;
}

int gsc_tee_command(struct igsc_lib_ctx* lib_ctx,
    void* req_buf, size_t request_len,
    void* resp_buf, size_t buf_size,
    size_t* response_len)
{
    struct ipl_heci_header* header = (struct ipl_heci_header*)req_buf;

    switch (header->command_id) {
    case IPL_HECI_COMMAND_ID_LATE_BINDING:
        return gsc_tee_command_late_bind(lib_ctx, req_buf, request_len, resp_buf, buf_size, response_len);
    case IPL_HECI_COMMAND_ID_LATE_BINDING_GET_INFO:
        return gsc_tee_command_late_bind_info(lib_ctx, req_buf, request_len, resp_buf, buf_size, response_len);
    default:
        /* unknown command - fail the test */
        assert_true(false);
        return IGSC_ERROR_INVALID_PARAMETER;
    }
}

void good_response_gsc_tee_command(struct ipl_late_binding_response *resp)
{
    UNUSED_VAR(resp);
}

void bad_response_gsc_tee_command_status(struct ipl_late_binding_response *resp)
{
    resp->rheader.status = CSC_LATE_BINDING_STATUS_TIMEOUT;
}

void bad_response_gsc_tee_command_type(struct ipl_late_binding_response *resp)
{
    resp->type = CSC_LATE_BINDING_TYPE_INVALID;
}

/* tests igsc_device_update_late_binding_config2 */

static void test_igsc_device_update_late_binding_config2_good(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
    uint8_t payload[10] = { 0 };
    size_t payload_size = 10;

    will_return(gsc_tee_command_late_bind, &good_response_gsc_tee_command);
    will_return(gsc_tee_command_late_bind, IGSC_SUCCESS);
    will_return(gsc_tee_command_late_bind, sizeof(struct ipl_late_binding_response));
    will_return(gsc_tee_command_late_bind, true);
    will_return(gsc_tee_command_late_bind, true);
    will_return(gsc_tee_command_late_bind, 10);
    will_return(gsc_tee_command_late_bind, 10);

    ret = igsc_device_update_late_binding_config2(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, 0, payload, payload_size, &cmd_status);

    assert_true(ret == IGSC_SUCCESS);
}

static void test_igsc_device_update_late_binding_config2_good_chunked(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
#define MSG_SIZE MAX_MSG_LEN + 10
    uint8_t payload[MSG_SIZE] = { 0 };
    size_t payload_size = MSG_SIZE;

    will_return(gsc_tee_command_late_bind, &good_response_gsc_tee_command);
    will_return(gsc_tee_command_late_bind, IGSC_SUCCESS);
    will_return(gsc_tee_command_late_bind, sizeof(struct ipl_late_binding_response));
    will_return(gsc_tee_command_late_bind, true);
    will_return(gsc_tee_command_late_bind, false);
    will_return(gsc_tee_command_late_bind, MSG_SIZE);
    will_return(gsc_tee_command_late_bind, MAX_MSG_LEN - sizeof(struct ipl_late_binding_request));

    will_return(gsc_tee_command_late_bind, &good_response_gsc_tee_command);
    will_return(gsc_tee_command_late_bind, IGSC_SUCCESS);
    will_return(gsc_tee_command_late_bind, sizeof(struct ipl_late_binding_response));
    will_return(gsc_tee_command_late_bind, false);
    will_return(gsc_tee_command_late_bind, true);
    will_return(gsc_tee_command_late_bind, MSG_SIZE);
    will_return(gsc_tee_command_late_bind, 10 + sizeof(struct ipl_late_binding_request));

    ret = igsc_device_update_late_binding_config2(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, 0, payload, payload_size, &cmd_status);

    assert_true(ret == IGSC_SUCCESS);
}

static void test_igsc_device_update_late_binding_config2_bad_size(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
    uint8_t payload[10] = { 0 };
    size_t payload_size = 10;

    will_return(gsc_tee_command_late_bind, &good_response_gsc_tee_command);
    will_return(gsc_tee_command_late_bind, IGSC_SUCCESS);
    will_return(gsc_tee_command_late_bind, 2); /* smaller then header*/
    will_return(gsc_tee_command_late_bind, true);
    will_return(gsc_tee_command_late_bind, true);
    will_return(gsc_tee_command_late_bind, 10);
    will_return(gsc_tee_command_late_bind, 10);

    ret = igsc_device_update_late_binding_config2(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, 0, payload, payload_size, &cmd_status);

    assert_true(ret == IGSC_ERROR_PROTOCOL);
}

static void test_igsc_device_update_late_binding_config2_bad_size2(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
    uint8_t payload[10] = { 0 };
    size_t payload_size = 10;

    will_return(gsc_tee_command_late_bind, &good_response_gsc_tee_command);
    will_return(gsc_tee_command_late_bind, IGSC_SUCCESS);
    will_return(gsc_tee_command_late_bind, 14);/* bigger then header*/
    will_return(gsc_tee_command_late_bind, true);
    will_return(gsc_tee_command_late_bind, true);
    will_return(gsc_tee_command_late_bind, 10);
    will_return(gsc_tee_command_late_bind, 10);

    ret = igsc_device_update_late_binding_config2(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, 0, payload, payload_size, &cmd_status);

    assert_true(ret == IGSC_ERROR_PROTOCOL);
}

static void test_igsc_device_update_late_binding_config2_bad_status(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
    uint8_t payload[10] = { 0 };
    size_t payload_size = 10;

    will_return(gsc_tee_command_late_bind, &bad_response_gsc_tee_command_status);
    will_return(gsc_tee_command_late_bind, IGSC_SUCCESS);
    will_return(gsc_tee_command_late_bind, sizeof(struct ipl_late_binding_response));
    will_return(gsc_tee_command_late_bind, true);
    will_return(gsc_tee_command_late_bind, true);
    will_return(gsc_tee_command_late_bind, 10);
    will_return(gsc_tee_command_late_bind, 10);

    ret = igsc_device_update_late_binding_config2(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, 0, payload, payload_size, &cmd_status);

    assert_true(ret == IGSC_ERROR_INTERNAL);
}

static void test_igsc_device_update_late_binding_config2_bad_type(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
    uint8_t payload[10] = { 0 };
    size_t payload_size = 10;

    will_return(gsc_tee_command_late_bind, &bad_response_gsc_tee_command_type);
    will_return(gsc_tee_command_late_bind, IGSC_SUCCESS);
    will_return(gsc_tee_command_late_bind, sizeof(struct ipl_late_binding_response));
    will_return(gsc_tee_command_late_bind, true);
    will_return(gsc_tee_command_late_bind, true);
    will_return(gsc_tee_command_late_bind, 10);
    will_return(gsc_tee_command_late_bind, 10);

    ret = igsc_device_update_late_binding_config2(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, 0, payload, payload_size, &cmd_status);

    assert_true(ret == IGSC_ERROR_PROTOCOL);
}

/* input validation igsc_device_update_late_binding_config2 */

static void test_igsc_device_update_late_binding_config2_null_handle(void** state)
{
    int ret;

    uint32_t cmd_status = 0;
    uint8_t payload[10] = { 0 };
    size_t payload_size = 10;

    ret = igsc_device_update_late_binding_config2(NULL,
        CSC_LATE_BINDING_TYPE_DGDIAG, 0, payload, payload_size, &cmd_status);

    assert_true(ret == IGSC_ERROR_INVALID_PARAMETER);
}

static void test_igsc_device_update_late_binding_config2_bad_flags(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
    uint8_t payload[10] = { 0 };
    size_t payload_size = 10;

    ret = igsc_device_update_late_binding_config2(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, 0xFF, payload, payload_size, &cmd_status);

    assert_true(ret == IGSC_ERROR_INVALID_PARAMETER);
}

static void test_igsc_device_update_late_binding_config2_null_payload(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
    size_t payload_size = 10;

    ret = igsc_device_update_late_binding_config2(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, 0, NULL, payload_size, &cmd_status);

    assert_true(ret == IGSC_ERROR_INVALID_PARAMETER);
}

static void test_igsc_device_update_late_binding_config2_bad_payload_size(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
    uint8_t payload[10] = { 0 };
    size_t payload_size = 10;

    ret = igsc_device_update_late_binding_config2(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, 0, payload, 0, &cmd_status);

    assert_true(ret == IGSC_ERROR_INVALID_PARAMETER);
}

static void test_igsc_device_update_late_binding_config2_null_cmd_status(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint8_t payload[10] = { 0 };
    size_t payload_size = 10;

    ret = igsc_device_update_late_binding_config2(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, 0, payload, payload_size, NULL);

    assert_true(ret == IGSC_ERROR_INVALID_PARAMETER);
}

/* tests igsc_device_get_late_binding_info_ */

static void test_igsc_device_update_late_binding_info_good(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
    uint32_t svn_source = 0;
    uint32_t min_svn = 0;

    will_return(gsc_tee_command_late_bind_info, &good_response_gsc_tee_command);
    will_return(gsc_tee_command_late_bind_info, IGSC_SUCCESS);
    will_return(gsc_tee_command_late_bind_info, sizeof(struct ipl_late_binding_get_info_response));

    ret = igsc_device_get_late_binding_info(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, &svn_source, &min_svn, &cmd_status);

    assert_true(ret == IGSC_SUCCESS);
    assert_true(min_svn == MIN_SVN);
    assert_true(svn_source == CSC_LATE_BINDING_SVN_SOURCE_SPI);
}

static void test_igsc_device_update_late_binding_info_bad_size(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
    uint32_t svn_source = 0;
    uint32_t min_svn = 0;

    will_return(gsc_tee_command_late_bind_info, &good_response_gsc_tee_command);
    will_return(gsc_tee_command_late_bind_info, IGSC_SUCCESS);
    will_return(gsc_tee_command_late_bind_info, 2); /* smaller then header*/

    ret = igsc_device_get_late_binding_info(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, &svn_source, &min_svn, &cmd_status);

    assert_true(ret == IGSC_ERROR_PROTOCOL);
}

static void test_igsc_device_update_late_binding_info_bad_size2(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
    uint32_t svn_source = 0;
    uint32_t min_svn = 0;

    will_return(gsc_tee_command_late_bind_info, &good_response_gsc_tee_command);
    will_return(gsc_tee_command_late_bind_info, IGSC_SUCCESS);
    will_return(gsc_tee_command_late_bind_info, 14); /* bigger then header*/

    ret = igsc_device_get_late_binding_info(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, &svn_source, &min_svn, &cmd_status);

    assert_true(ret == IGSC_ERROR_PROTOCOL);
}

static void test_igsc_device_update_late_binding_info_bad_status(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
    uint32_t svn_source = 0;
    uint32_t min_svn = 0;

    will_return(gsc_tee_command_late_bind_info, &bad_response_gsc_tee_command_status);
    will_return(gsc_tee_command_late_bind_info, IGSC_SUCCESS);
    will_return(gsc_tee_command_late_bind_info, sizeof(struct ipl_late_binding_get_info_response));

    ret = igsc_device_get_late_binding_info(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, &svn_source, &min_svn, &cmd_status);

    assert_true(ret == IGSC_ERROR_INTERNAL);
}

static void test_igsc_device_update_late_binding_info_bad_type(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
    uint32_t svn_source = 0;
    uint32_t min_svn = 0;

    will_return(gsc_tee_command_late_bind_info, &bad_response_gsc_tee_command_type);
    will_return(gsc_tee_command_late_bind_info, IGSC_SUCCESS);
    will_return(gsc_tee_command_late_bind_info, sizeof(struct ipl_late_binding_get_info_response));

    ret = igsc_device_get_late_binding_info(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, &svn_source, &min_svn, &cmd_status);

    assert_true(ret == IGSC_ERROR_PROTOCOL);
}

/* input validation igsc_device_get_late_binding_info */

static void test_igsc_device_update_late_binding_info_null_handle(void** state)
{
    int ret;

    uint32_t cmd_status = 0;
    uint32_t svn_source = 0;
    uint32_t min_svn = 0;

    ret = igsc_device_get_late_binding_info(NULL,
        CSC_LATE_BINDING_TYPE_DGDIAG, &svn_source, &min_svn, &cmd_status);

    assert_true(ret == IGSC_ERROR_INVALID_PARAMETER);
}

static void test_igsc_device_update_late_binding_info_null_svn_source(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
    uint32_t min_svn = 0;

    ret = igsc_device_get_late_binding_info(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, NULL, &min_svn, &cmd_status);

    assert_true(ret == IGSC_ERROR_INVALID_PARAMETER);
}

static void test_igsc_device_update_late_binding_info_null_min_svn(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t cmd_status = 0;
    uint32_t svn_source = 0;

    ret = igsc_device_get_late_binding_info(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, &svn_source, NULL, &cmd_status);

    assert_true(ret == IGSC_ERROR_INVALID_PARAMETER);
}

static void test_igsc_device_update_late_binding_info_null_cmd_status(void** state)
{
    int ret;

    struct igsc_device_handle* handle = *state;
    uint32_t svn_source = 0;
    uint32_t min_svn = 0;

    ret = igsc_device_get_late_binding_info(handle,
        CSC_LATE_BINDING_TYPE_DGDIAG, &svn_source, &min_svn, NULL);

    assert_true(ret == IGSC_ERROR_INVALID_PARAMETER);
}
int main(void)
{
    const struct CMUnitTest tests[] = {

        cmocka_unit_test(test_igsc_device_update_late_binding_config2_good),
        cmocka_unit_test(test_igsc_device_update_late_binding_config2_good_chunked),
        cmocka_unit_test(test_igsc_device_update_late_binding_config2_bad_size),
        cmocka_unit_test(test_igsc_device_update_late_binding_config2_bad_size2),
        cmocka_unit_test(test_igsc_device_update_late_binding_config2_bad_status),
        cmocka_unit_test(test_igsc_device_update_late_binding_config2_bad_type),

        cmocka_unit_test(test_igsc_device_update_late_binding_config2_null_handle),
        cmocka_unit_test(test_igsc_device_update_late_binding_config2_bad_flags),
        cmocka_unit_test(test_igsc_device_update_late_binding_config2_null_payload),
        cmocka_unit_test(test_igsc_device_update_late_binding_config2_bad_payload_size),
        cmocka_unit_test(test_igsc_device_update_late_binding_config2_null_cmd_status),

        cmocka_unit_test(test_igsc_device_update_late_binding_info_good),
        cmocka_unit_test(test_igsc_device_update_late_binding_info_bad_size),
        cmocka_unit_test(test_igsc_device_update_late_binding_info_bad_size2),
        cmocka_unit_test(test_igsc_device_update_late_binding_info_bad_status),
        cmocka_unit_test(test_igsc_device_update_late_binding_info_bad_type),

        cmocka_unit_test(test_igsc_device_update_late_binding_info_null_handle),
        cmocka_unit_test(test_igsc_device_update_late_binding_info_null_svn_source),
        cmocka_unit_test(test_igsc_device_update_late_binding_info_null_min_svn),
        cmocka_unit_test(test_igsc_device_update_late_binding_info_null_cmd_status),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
