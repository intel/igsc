/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2020 Intel Corporation
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

#include "igsc_lib.h"
#include "igsc_heci.h"
#include "dev_info_mock.c"

typedef void (*respons_genartor_f)(struct gsc_fwu_heci_version_resp *);

int mock_driver_init(struct igsc_lib_ctx *lib_ctx);
void mock_driver_deinit(struct igsc_lib_ctx *lib_ctx);

int driver_init(struct igsc_lib_ctx *lib_ctx)
{
    return mock_driver_init(lib_ctx);
}

void driver_deinit(struct igsc_lib_ctx *lib_ctx)
{
    mock_driver_deinit(lib_ctx);
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

struct igsc_fw_version fw_version = {
    .project = {0, 0, 0, 0},
    .hotfix  = 0,
    .build   = 0,
};

struct igsc_oprom_version oprom_version = {
    0, 0, 0, 0, 0, 0, 0, 0
};

#define FW_RESPONSE_SIZE \
    (sizeof(struct gsc_fwu_heci_version_resp) + sizeof(struct igsc_fw_version))
#define OPROM_RESPONSE_SIZE  \
    (sizeof(struct gsc_fwu_heci_version_resp) + sizeof(struct igsc_oprom_version))

static int create_response(struct gsc_fwu_heci_version_req *req,
                           struct gsc_fwu_heci_version_resp *resp,
                           void **version)
{
    resp->response.header = req->header;
    resp->response.header.is_response = 1;
    resp->response.status = GSC_FWU_STATUS_SUCCESS;
    resp->response.reserved = 0;
    resp->partition = req->partition;

    if (resp->partition == GSC_FWU_HECI_PART_VERSION_GFX_FW)
    {
        resp->version_length = sizeof(fw_version);
        *version = &fw_version;
    }
    else if (resp->partition == GSC_FWU_HECI_PART_VERSION_OPROM_DATA ||
             resp->partition == GSC_FWU_HECI_PART_VERSION_OPROM_CODE )
    {
        resp->version_length = sizeof(oprom_version);
        *version = &oprom_version;
    }
    else
    {
        return -1;
    }

    return IGSC_SUCCESS;
}

int gsc_tee_command(struct igsc_lib_ctx *lib_ctx,
                    void *req_buf, size_t request_len,
                    void *resp_buf, size_t buf_size,
                    size_t *response_len)
{

    int ret;
    respons_genartor_f update_resp = mock_type(respons_genartor_f);
    int status = mock_type(int);
    int resp_len = mock_type(int);

    struct gsc_fwu_heci_version_req *req = req_buf;
    struct gsc_fwu_heci_version_resp resp;
    void *version;

    ret = create_response(req, &resp, &version);
    update_resp(&resp);

    if (ret != IGSC_SUCCESS)
    {
        return -1;
    }

    memcpy(resp_buf, &resp, sizeof(resp));
    memcpy(resp_buf + sizeof(resp), version, resp.version_length);

    *response_len = resp_len;

    return status;
}

void good_response(struct gsc_fwu_heci_version_resp *resp)
{
    (void)resp;
}

void bad_size(struct gsc_fwu_heci_version_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_SIZE_ERROR;
}

void bad_command_id(struct gsc_fwu_heci_version_resp *resp)
{
    resp->response.header.command_id = 0;
}

void bad_is_response(struct gsc_fwu_heci_version_resp *resp)
{
    resp->response.header.is_response = 0;
}

void bad_version_length(struct gsc_fwu_heci_version_resp *resp)
{
    resp->version_length = 0;
}

void bad_reserved(struct gsc_fwu_heci_version_resp *resp)
{
    resp->response.reserved = 1;
}

void bad_status(struct gsc_fwu_heci_version_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_FAILURE;
}

void bad_oprom_signature(struct gsc_fwu_heci_version_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_UPDATE_OPROM_INVALID_STRUCTURE;
}

void status_oprom_section_not_exist(struct gsc_fwu_heci_version_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_UPDATE_OPROM_SECTION_NOT_EXIST;
}

void bad_heci_message(struct gsc_fwu_heci_version_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_INVALID_COMMAND;
}

void bad_command_param(struct gsc_fwu_heci_version_resp *resp)
{
    resp->response.status = GSC_FWU_STATUS_INVALID_PARAMS;
}

void bad_partition(struct gsc_fwu_heci_version_resp *resp)
{
    if (resp->partition == GSC_FWU_HECI_PART_VERSION_GFX_FW)
    {
        resp->partition = GSC_FWU_HECI_PART_VERSION_OPROM_DATA;
    }
    else if (resp->partition == GSC_FWU_HECI_PART_VERSION_OPROM_DATA ||
             resp->partition == GSC_FWU_HECI_PART_VERSION_OPROM_CODE )
    {
        resp->partition = GSC_FWU_HECI_PART_VERSION_GFX_FW;
    }
}

static void test_fw_version_good(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version;

    will_return(gsc_tee_command, &good_response);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, FW_RESPONSE_SIZE);

    ret = igsc_device_fw_version(handle, &version);

    assert_true(ret == IGSC_SUCCESS);
}

static void test_fw_version_bad_response_size(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version;

    will_return(gsc_tee_command, &bad_size);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, FW_RESPONSE_SIZE);

    ret = igsc_device_fw_version(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fw_version_bad_command_id(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version;

    will_return(gsc_tee_command, &bad_command_id);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, FW_RESPONSE_SIZE);

    ret = igsc_device_fw_version(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}


static void test_fw_version_bad_response_is_response(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version;

    will_return(gsc_tee_command, &bad_is_response);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, FW_RESPONSE_SIZE);

    ret = igsc_device_fw_version(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fw_version_bad_version_length(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version;

    will_return(gsc_tee_command, &bad_version_length);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, FW_RESPONSE_SIZE);

    ret = igsc_device_fw_version(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fw_version_bad_reserved(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version;

    will_return(gsc_tee_command, &bad_reserved);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, FW_RESPONSE_SIZE);

    ret = igsc_device_fw_version(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fw_version_bad_partition(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version;

    will_return(gsc_tee_command, &bad_partition);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, FW_RESPONSE_SIZE);

    ret = igsc_device_fw_version(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fw_version_bad_status(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version;

    will_return(gsc_tee_command, &bad_status);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, FW_RESPONSE_SIZE);

    ret = igsc_device_fw_version(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fw_version_bad_response_length(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version;

    will_return(gsc_tee_command, &good_response);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, sizeof(struct gsc_fwu_heci_version_resp));

    ret = igsc_device_fw_version(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fw_version_bad_oprom_signature(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version;

    will_return(gsc_tee_command, &bad_oprom_signature);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, FW_RESPONSE_SIZE);

    ret = igsc_device_fw_version(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fw_version_status_oprom_section_not_exist(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version;

    will_return(gsc_tee_command, &status_oprom_section_not_exist);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, FW_RESPONSE_SIZE);

    ret = igsc_device_fw_version(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fw_version_bad_heci_message(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version;

    will_return(gsc_tee_command, &bad_heci_message);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, FW_RESPONSE_SIZE);

    ret = igsc_device_fw_version(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fw_version_bad_command_param(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version;

    will_return(gsc_tee_command, &bad_command_param);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, FW_RESPONSE_SIZE);

    ret = igsc_device_fw_version(handle, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_data_version_good(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &good_response);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_DATA, &version);

    assert_true(ret == IGSC_SUCCESS);
}

static void test_oprom_data_bad_response_size(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_size);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_DATA, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_data_bad_command_id(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_command_id);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_DATA, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_data_bad_response_is_response(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_is_response);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_DATA, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_data_bad_version_length(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_version_length);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_DATA, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_data_bad_reserved(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_reserved);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_DATA, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_data_bad_partition(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_partition);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_DATA, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_data_bad_status(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_status);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_DATA, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_data_bad_response_length(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &good_response);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, sizeof(struct gsc_fwu_heci_version_resp));

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_DATA, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_data_bad_oprom_signature(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_oprom_signature);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_DATA, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_data_status_oprom_section_not_exist(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &status_oprom_section_not_exist);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_DATA, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_data_bad_heci_message(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_heci_message);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_DATA, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_data_bad_command_param(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_command_param);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_DATA, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_code_version_good(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &good_response);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_CODE, &version);

    assert_true(ret == IGSC_SUCCESS);
}

static void test_oprom_code_bad_response_size(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_size);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_CODE, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_code_bad_command_id(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_command_id);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_CODE, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_code_bad_response_is_response(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_is_response);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_CODE, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_code_bad_version_length(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_version_length);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_CODE, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_code_bad_reserved(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_reserved);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_CODE, &version);

    assert_true(ret != IGSC_SUCCESS);

}

static void test_oprom_code_bad_partition(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_partition);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_CODE, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_code_bad_status(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_status);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_CODE, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_code_bad_response_length(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &good_response);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, sizeof(struct gsc_fwu_heci_version_resp));

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_CODE, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_code_bad_oprom_signature(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_oprom_signature);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_CODE, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_code_status_oprom_section_not_exist(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &status_oprom_section_not_exist);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_CODE, &version);

    assert_true(ret != IGSC_SUCCESS);

}
static void test_oprom_code_bad_heci_message(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_heci_message);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_CODE, &version);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_code_bad_command_param(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_oprom_version version;

    will_return(gsc_tee_command, &bad_command_param);
    will_return(gsc_tee_command, IGSC_SUCCESS);
    will_return(gsc_tee_command, OPROM_RESPONSE_SIZE);

    ret = igsc_device_oprom_version(handle, IGSC_OPROM_CODE, &version);

    assert_true(ret != IGSC_SUCCESS);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fw_version_good),
        cmocka_unit_test(test_fw_version_bad_response_size),
        cmocka_unit_test(test_fw_version_bad_command_id),
        cmocka_unit_test(test_fw_version_bad_response_is_response),
        cmocka_unit_test(test_fw_version_bad_version_length),
        cmocka_unit_test(test_fw_version_bad_reserved),
        cmocka_unit_test(test_fw_version_bad_partition),
        cmocka_unit_test(test_fw_version_bad_response_length),
        cmocka_unit_test(test_fw_version_bad_status),
        cmocka_unit_test(test_fw_version_bad_oprom_signature),
        cmocka_unit_test(test_fw_version_status_oprom_section_not_exist),
        cmocka_unit_test(test_fw_version_bad_heci_message),
        cmocka_unit_test(test_fw_version_bad_command_param),
        cmocka_unit_test(test_oprom_data_version_good),
        cmocka_unit_test(test_oprom_data_bad_response_size),
        cmocka_unit_test(test_oprom_data_bad_command_id),
        cmocka_unit_test(test_oprom_data_bad_response_is_response),
        cmocka_unit_test(test_oprom_data_bad_version_length),
        cmocka_unit_test(test_oprom_data_bad_reserved),
        cmocka_unit_test(test_oprom_data_bad_partition),
        cmocka_unit_test(test_oprom_data_bad_status),
        cmocka_unit_test(test_oprom_data_bad_response_length),
        cmocka_unit_test(test_oprom_data_bad_oprom_signature),
        cmocka_unit_test(test_oprom_data_status_oprom_section_not_exist),
        cmocka_unit_test(test_oprom_data_bad_heci_message),
        cmocka_unit_test(test_oprom_data_bad_command_param),
        cmocka_unit_test(test_oprom_code_version_good),
        cmocka_unit_test(test_oprom_code_bad_response_size),
        cmocka_unit_test(test_oprom_code_bad_command_id),
        cmocka_unit_test(test_oprom_code_bad_response_is_response),
        cmocka_unit_test(test_oprom_code_bad_version_length),
        cmocka_unit_test(test_oprom_code_bad_reserved),
        cmocka_unit_test(test_oprom_code_bad_partition),
        cmocka_unit_test(test_oprom_code_bad_status),
        cmocka_unit_test(test_oprom_code_bad_response_length),
        cmocka_unit_test(test_oprom_code_bad_oprom_signature),
        cmocka_unit_test(test_oprom_code_status_oprom_section_not_exist),
        cmocka_unit_test(test_oprom_code_bad_heci_message),
        cmocka_unit_test(test_oprom_code_bad_command_param),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
