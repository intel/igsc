/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2024 Intel Corporation
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "test_strdup.h"

#include <metee.h>

#include "igsc_system.h"
#include "igsc_lib.h"
#include "igsc_heci.h"
#include "igsc_internal.h"
#include "dev_info_mock.c"

typedef void (*response_generator_f)(struct gsc_fw_data_heci_version_resp*);


int driver_working_buffer_alloc(struct igsc_lib_ctx *lib_ctx);
void driver_working_buffer_free(struct igsc_lib_ctx *lib_ctx);
int gsc_driver_init(struct igsc_lib_ctx *lib_ctx, const GUID *guid)
{
    int status;

    (void)guid;

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

    igsc_device_close(handle);

    free(*state);
    return 0;
}

struct gsc_fw_data_heci_version_resp fdwata_ver =
{
	.format_version = IGSC_FWDATA_FORMAT_VERSION_1,
	.oem_manuf_data_version_nvm = 1,
	.oem_manuf_data_version_fitb = 2,
	.major_version = 3,
	.major_vcn = 4,
	.flags = 0,
	.data_arb_svn_nvm = 6,
	.data_arb_svn_fitb = 7,
	.reserved = {0, 0, 0, 0, 0, 0},
};

#define FWDATA_RESPONSE_SIZE  \
    (sizeof(struct gsc_fw_data_heci_version_resp))

static int create_response(struct gsc_fw_data_heci_version_req *req,
                           struct gsc_fw_data_heci_version_resp *resp)
{
    *resp = fdwata_ver;
    resp->response.header = req->header;
    resp->response.header.is_response = 1;
    resp->response.status = GSC_FWU_STATUS_SUCCESS;
    resp->response.reserved = 0;

    return IGSC_SUCCESS;
}

int gsc_tee_command(struct igsc_lib_ctx *lib_ctx,
                    void *req_buf, size_t request_len,
                    void *resp_buf, size_t buf_size,
                    size_t *response_len)
{
    int ret;
    response_generator_f update_resp = mock_type(response_generator_f);
    int status = mock_type(int);

    struct gsc_fw_data_heci_version_req *req = req_buf;
    struct gsc_fw_data_heci_version_resp resp;

    ret = create_response(req, &resp);
    update_resp(&resp);

    if (ret != IGSC_SUCCESS)
    {
        return -1;
    }

    memcpy(resp_buf, &resp, sizeof(resp));

    *response_len = FWDATA_RESPONSE_SIZE;

    return status;
}

void good_response(struct gsc_fw_data_heci_version_resp *resp)
{
    (void)resp;
}

void format2_good_response(struct gsc_fw_data_heci_version_resp *resp)
{
    resp->format_version = IGSC_FWDATA_FORMAT_VERSION_2;
}

void bad_size(struct gsc_fw_data_heci_version_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_SIZE_ERROR;
}

void bad_command_id(struct gsc_fw_data_heci_version_resp *resp)
{
    resp->response.header.command_id = 0;
}

void bad_is_response(struct gsc_fw_data_heci_version_resp *resp)
{
    resp->response.header.is_response = 0;
}

void bad_reserved(struct gsc_fw_data_heci_version_resp *resp)
{
    resp->response.reserved = 1;
}

void bad_status(struct gsc_fw_data_heci_version_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_FAILURE;
}

void bad_heci_message(struct gsc_fw_data_heci_version_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_INVALID_COMMAND;
}

void bad_command_param(struct gsc_fw_data_heci_version_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_INVALID_PARAMS;
}

static void test_fwdata_version_good(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fwdata_version2 version;

    will_return(gsc_tee_command, &good_response);
    will_return(gsc_tee_command, IGSC_SUCCESS);

    ret = igsc_device_fwdata_version2(handle, &version);

    assert_true(ret == IGSC_SUCCESS);

    assert_true(version.format_version == IGSC_FWDATA_FORMAT_VERSION_1);
    assert_true(version.oem_manuf_data_version == 1);
    assert_true(version.oem_manuf_data_version_fitb == 2);
    assert_true(version.major_version == 3);
    assert_true(version.major_vcn == 4);
    assert_true(version.flags == 0);
    assert_true(version.data_arb_svn == 0);
    assert_true(version.data_arb_svn_fitb == 0);
}

static void test_fwdata_version_good2(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fwdata_version2 version;

    will_return(gsc_tee_command, &format2_good_response);
    will_return(gsc_tee_command, IGSC_SUCCESS);

    ret = igsc_device_fwdata_version2(handle, &version);

    assert_true(ret == IGSC_SUCCESS);

    assert_true(version.format_version == IGSC_FWDATA_FORMAT_VERSION_2);
    assert_true(version.oem_manuf_data_version == 1);
    assert_true(version.oem_manuf_data_version_fitb == 2);
    assert_true(version.major_version == 3);
    assert_true(version.major_vcn == 4);
    assert_true(version.flags == 0);
    assert_true(version.data_arb_svn == 6);
    assert_true(version.data_arb_svn_fitb == 7);
}

static void test_fwdata_version_null_handle(void **state)
{
    int ret;

    struct igsc_device_handle *handle = NULL;
    struct igsc_fwdata_version2 version;

    ret = igsc_device_fwdata_version2(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_version_null_version(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;

    ret = igsc_device_fwdata_version2(handle, NULL);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_version_null_ctx(void **state)
{
    int ret;

    struct igsc_device_handle *handle = malloc(sizeof(struct igsc_device_handle));
    struct igsc_fwdata_version2 version;

    handle->ctx = NULL;

    ret = igsc_device_fwdata_version2(handle, &version);
    free(handle);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_version_bad_command_id(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fwdata_version2 version;

    will_return(gsc_tee_command, &bad_command_id);
    will_return(gsc_tee_command, IGSC_SUCCESS);

    ret = igsc_device_fwdata_version2(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}


static void test_fwdata_version_bad_response_is_response(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fwdata_version2 version;

    will_return(gsc_tee_command, &bad_is_response);
    will_return(gsc_tee_command, IGSC_SUCCESS);

    ret = igsc_device_fwdata_version2(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_version_bad_reserved(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fwdata_version2 version;

    will_return(gsc_tee_command, &bad_reserved);
    will_return(gsc_tee_command, IGSC_SUCCESS);

    ret = igsc_device_fwdata_version2(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_version_bad_status(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fwdata_version2 version;

    will_return(gsc_tee_command, &bad_status);
    will_return(gsc_tee_command, IGSC_SUCCESS);

    ret = igsc_device_fwdata_version2(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_version_bad_heci_message(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fwdata_version2 version;

    will_return(gsc_tee_command, &bad_heci_message);
    will_return(gsc_tee_command, IGSC_SUCCESS);

    ret = igsc_device_fwdata_version2(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_version_bad_command_param(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fwdata_version2 version;

    will_return(gsc_tee_command, &bad_command_param);
    will_return(gsc_tee_command, IGSC_SUCCESS);

    ret = igsc_device_fwdata_version2(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fwdata_version_good),
        cmocka_unit_test(test_fwdata_version_good2),
        cmocka_unit_test(test_fwdata_version_null_handle),
        cmocka_unit_test(test_fwdata_version_null_version),
        cmocka_unit_test(test_fwdata_version_null_ctx),
        cmocka_unit_test(test_fwdata_version_bad_command_id),
        cmocka_unit_test(test_fwdata_version_bad_response_is_response),
        cmocka_unit_test(test_fwdata_version_bad_reserved),
        cmocka_unit_test(test_fwdata_version_bad_status),
        cmocka_unit_test(test_fwdata_version_bad_heci_message),
        cmocka_unit_test(test_fwdata_version_bad_command_param),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
