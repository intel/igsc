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

#include "test_strdup.h"

#include <metee.h>

#include "igsc_system.h"
#include "igsc_lib.h"
#include "igsc_heci.h"
#include "igsc_internal.h"
#include "dev_info_mock.c"

TEESTATUS TeeInit(PTEEHANDLE handle, const GUID *guid, const char *device)
{
    TEESTATUS status = mock_type(TEESTATUS);
    return status;
}

TEESTATUS TeeInitHandle(PTEEHANDLE handle, const GUID *guid,
            const TEE_DEVICE_HANDLE device_handle)
{
    return 0;
}

TEESTATUS TeeConnect(PTEEHANDLE handle)
{
    handle->maxMsgLen = 4096;
    handle->protcolVer = 1;

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
        *pNumOfBytesRead = sizeof(struct gsc_fwu_heci_version_resp) + sizeof(struct igsc_fw_version);
    }
    return TEE_SUCCESS;
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

TEESTATUS TeeFWStatus(PTEEHANDLE handle, uint32_t fwStatusNum, uint32_t *fwStatus)
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

static void test_fw_version_good(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version;

    will_return_count(TeeInit, TEE_DEVICE_NOT_READY, 2);
    will_return(TeeInit, TEE_SUCCESS);

    ret = igsc_device_fw_version(handle, &version);
    assert_true(ret == IGSC_SUCCESS);
}

static void test_fw_version_not_ready(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version = {0};

    will_return_count(TeeInit, TEE_DEVICE_NOT_READY, 3);

    ret = igsc_device_fw_version(handle, &version);
    assert_true(ret == IGSC_ERROR_INTERNAL);
}

static void test_fw_version_not_found(void **state)
{
    int ret;

    struct igsc_device_handle *handle = *state;
    struct igsc_fw_version version;

    will_return(TeeInit, TEE_DEVICE_NOT_FOUND);

    ret = igsc_device_fw_version(handle, &version);
    assert_true(ret == IGSC_ERROR_DEVICE_NOT_FOUND);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fw_version_good),
        cmocka_unit_test(test_fw_version_not_ready),
        cmocka_unit_test(test_fw_version_not_found),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
