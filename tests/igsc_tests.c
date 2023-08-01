/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2023 Intel Corporation
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
#include "oprom_parser.c"
#include "ifr.c"
#include "dev_info_mock.c"

static struct igsc_device_handle g_handle;
static uint64_t g_ctx;

static int group_setup(void **state)
{
    *state = &g_handle;
    g_handle.ctx = (struct igsc_lib_ctx *)&g_ctx;

    return 0;
}

void *__real__test_calloc(size_t nmemb, size_t size,
                          const char* file, const int line);
void *__wrap__test_calloc(size_t nmemb, size_t size)
{
    int fail = mock_type(int);

    if (fail)
    {
        return NULL;
    }
    else
    {
        return __real__test_calloc(nmemb, size, __FILE__, __LINE__);
    }
}

void *__real__test_malloc(size_t nmemb, size_t size,
                          const char* file, const int line);
void *__wrap__test_malloc(size_t nmemb, size_t size)
{
    int fail = mock_type(int);

    if (fail)
    {
        return NULL;
    }
    else
    {
        return __real__test_calloc(nmemb, size, __FILE__, __LINE__);
    }
}

int __real_image_oprom_parse(struct igsc_oprom_image *img);

int __wrap_image_oprom_parse(struct igsc_oprom_image *img)
{
    return IGSC_SUCCESS;
}

/**
 * @brief A test to check if calloc() in igsc_device_init_by_device()
 *        returned NULL.
 *
 * @param state unit testing state
 */
static void test_device_init_calloc_ok(void **state)
{
    struct igsc_device_handle *handle = *state;
    int ret;

    will_return(__wrap__test_calloc, 0);
    will_return(__wrap__test_calloc, 0);

    ret = igsc_device_init_by_device(handle, " ");

    assert_int_not_equal(ret, IGSC_ERROR_NOMEM);
    igsc_device_close(handle);
}

/**
 * @brief A test to check if calloc() in igsc_device_init_by_device()
 *        returned NULL.
 *
 * @param state unit testing state
 */
static void test_device_init_calloc_fail_1(void **state)
{
    struct igsc_device_handle *handle = *state;
    int ret;

    will_return(__wrap__test_calloc, 1);

    ret = igsc_device_init_by_device(handle, "");

    assert_int_equal(ret, IGSC_ERROR_NOMEM);
    igsc_device_close(handle);
}

/**
 * @brief A test to check if calloc() in igsc_device_init_by_device()
 *        returned NULL.
 *
 * @param state unit testing state
 */
static void test_device_init_calloc_fail_2(void **state)
{
    struct igsc_device_handle *handle = *state;
    int ret;

    will_return(__wrap__test_calloc, 0);
    will_return(__wrap__test_calloc, 1); /* strdup */

    ret = igsc_device_init_by_device(handle, " ");

    assert_int_equal(ret, IGSC_ERROR_NOMEM);

    igsc_device_close(handle);
}

/**
 * @brief A test to check if igsc_image_get_type() return error when
 *        NULL buffer is sent.
 *
 * @param state unit testing state
 */
static void test_get_type_null_1(void **state)
{
    int ret;
    uint8_t type;

    ret = igsc_image_get_type(NULL, 100, &type);

    assert_int_equal(ret, IGSC_ERROR_INVALID_PARAMETER);
}

/**
 * @brief A test to check if igsc_image_get_type() return error when
 *        NULL type pointer is sent.
 *
 * @param state unit testing state
 */
static void test_get_type_null_2(void **state)
{
    int ret;
    uint8_t buffer;

    ret = igsc_image_get_type(&buffer, sizeof(buffer), NULL);

    assert_int_equal(ret, IGSC_ERROR_INVALID_PARAMETER);
}

/**
 * @brief A test to check if igsc_image_get_type() return error when
 *        zero buffer_len is sent.
 *
 * @param state unit testing state
 */
static void test_get_type_null_3(void **state)
{
    int ret;
    uint8_t buffer;
    uint8_t type;

    ret = igsc_image_get_type(&buffer, 0, &type);

    assert_int_equal(ret, IGSC_ERROR_INVALID_PARAMETER);
}

/**
 * @brief A test to check if igsc_device_init_by_device() return error when
 *        NULL handle is send.
 *
 * @param state unit testing state
 */
static void test_device_init_null_1(void **state)
{
    int ret;

    ret = igsc_device_init_by_device(NULL, " ");

    assert_int_equal(ret, IGSC_ERROR_INVALID_PARAMETER);

    igsc_device_close(NULL);
}

/**
 * @brief A test to check if igsc_device_init_by_device return error when NULL handle is send
 *
 * @param state unit testing state
 */
static void test_device_init_null_2(void **state)
{

    struct igsc_device_handle *handle = *state;
    int ret;

    ret = igsc_device_init_by_device(handle, NULL);

    assert_int_equal(ret, IGSC_ERROR_INVALID_PARAMETER);

    igsc_device_close(NULL);
}

/**
 * @brief A test to check if igsc_device_close return error when NULL handle is send
 *
 * @param state unit testing state
 */
static void test_device_close_null(void **state)
{
    int ret;

    ret = igsc_device_close(NULL);

    assert_int_equal(ret, IGSC_ERROR_INVALID_PARAMETER);
}

/**
 * @brief A test to check if calloc() in igsc_device_init_by_handle() returned NULL
 *
 * @param state unit testing state
 */
static void test_device_init_by_handle_calloc_ok(void **state)
{
    struct igsc_device_handle *handle = *state;
    int ret;

    will_return(__wrap__test_calloc, 0);

    ret = igsc_device_init_by_handle(handle, (igsc_handle_t)1);

    assert_int_not_equal(ret, IGSC_ERROR_NOMEM);

    igsc_device_close(handle);
}

/**
 * @brief A test to check if calloc() in igsc_device_init_by_handle() returned NULL
 *
 * @param state unit testing state
 */
static void test_device_init_by_handle_calloc_fail_1(void **state)
{
    struct igsc_device_handle *handle = *state;
    int ret;

    will_return(__wrap__test_calloc, 1);

    ret = igsc_device_init_by_handle(handle, (igsc_handle_t)1);

    assert_int_equal(ret, IGSC_ERROR_NOMEM);

    igsc_device_close(handle);
}

/**
 * @brief A test to check if igsc_device_init_by_handle() return error when
 *        NULL handle is send.
 *
 * @param state unit testing state
 */
static void test_device_init_by_handle_null(void **state)
{
    int ret;

    ret = igsc_device_init_by_handle(NULL, (igsc_handle_t)1);

    assert_int_equal(ret, IGSC_ERROR_INVALID_PARAMETER);

    igsc_device_close(NULL);
}

/**
 * @brief A test to check if igsc_device_init_by_handle() return error
 *        when handle is invalid.
 *
 * @param state unit testing state
 */
static void test_device_init_by_handle_invalid(void **state)
{
    struct igsc_device_handle *handle = *state;
    int ret;

    ret = igsc_device_init_by_handle(handle, IGSC_INVALID_DEVICE_HANDLE);

    assert_int_equal(ret, IGSC_ERROR_INVALID_PARAMETER);

    igsc_device_close(NULL);
}

static void igsc_device_init_by_device_info_null_1(void **state)
{
    const struct igsc_device_info dev_info;
    int ret;

    ret = igsc_device_init_by_device_info(NULL, &dev_info);

    assert_int_equal(ret, IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_init_by_device_info_null_2(void **state)
{
    struct igsc_device_handle *handle = *state;
    int ret;

    ret = igsc_device_init_by_device_info(handle, NULL);

    assert_int_equal(ret, IGSC_ERROR_INVALID_PARAMETER);
}
static void igsc_device_get_device_info_null_1(void **state)
{
    struct igsc_device_info dev_info;
    int ret;

    ret = igsc_device_get_device_info(NULL, &dev_info);

    assert_int_equal(ret, IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_get_device_info_null_2(void **state)
{
    struct igsc_device_handle *handle = *state;
    int ret;

    ret = igsc_device_get_device_info(handle, NULL);

    assert_int_equal(ret, IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_get_device_info_null_3(void **state)
{
    struct igsc_device_handle handle = {
        .ctx = NULL,
    };
    struct igsc_device_info dev_info;
    int ret;

    ret = igsc_device_get_device_info(&handle, &dev_info);

    assert_int_equal(ret, IGSC_ERROR_INVALID_PARAMETER);
}

static void test_image_oprom_init_calloc_fail(void **state)
{
    struct igsc_oprom_image *img = NULL;
    const uint8_t buf[100];

    will_return(__wrap__test_calloc, 1);

    assert_int_equal(igsc_image_oprom_init(&img, buf, 100), IGSC_ERROR_NOMEM);
    igsc_image_oprom_release(img);


    will_return(__wrap__test_calloc, 0);
    will_return(__wrap__test_calloc, 1);

    assert_int_equal(igsc_image_oprom_init(&img, buf, 100), IGSC_ERROR_NOMEM);
    igsc_image_oprom_release(img);
}

static void igsc_hwconfig_null_inputs(void **state)
{
    struct igsc_hw_config hw_config =
    {
        .format_version = 1
    };

    assert_int_equal(igsc_hw_config_compatible(NULL, NULL), IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_hw_config_compatible(&hw_config, NULL), IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_hw_config_compatible(NULL, &hw_config), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_fw_update_null_inputs(void **state)
{
    struct igsc_device_handle *handle = *state;
    const uint8_t buffer;
    const uint32_t buffer_len = 10;
    igsc_progress_func_t progress_f;
    int ctx;
    struct igsc_fw_update_flags flags = {0};

    assert_int_equal(igsc_device_fw_update(NULL, &buffer, buffer_len, progress_f, (void *)&ctx),IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_device_fw_update(handle, NULL, buffer_len, progress_f, (void *)&ctx),IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_device_fw_update_ex(NULL, &buffer, buffer_len, progress_f, (void *)&ctx, flags),IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_device_fw_update_ex(handle, NULL, buffer_len, progress_f, (void *)&ctx, flags),IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_fw_update_buffer_len_zero(void **state)
{
    struct igsc_device_handle *handle = *state;
    const uint8_t buffer;
    const uint32_t buffer_len = 0;
    igsc_progress_func_t progress_f;
    int ctx;
    struct igsc_fw_update_flags flags = {0};

    assert_int_equal(igsc_device_fw_update(handle, &buffer, buffer_len, progress_f, (void *)&ctx),IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_device_fw_update_ex(handle, &buffer, buffer_len, progress_f, (void *)&ctx, flags),IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_oprom_update_null_inputs(void **state)
{
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    unsigned char buf[10];
    struct igsc_oprom_image img = {
        .buffer = buf,
        .buffer_len = 10,
        .code_part_len = 10,
        .code_part_ptr = (void *)10,
    };
    igsc_progress_func_t progress_f = NULL;

    assert_int_equal(igsc_device_oprom_update(handle, oprom_type, NULL,  progress_f, NULL), IGSC_ERROR_INVALID_PARAMETER);

    assert_int_equal(igsc_device_oprom_update(NULL, oprom_type, &img,  progress_f, NULL), IGSC_ERROR_INVALID_PARAMETER);

    img.buffer = NULL;
    assert_int_equal(igsc_device_oprom_update(handle, oprom_type, &img,  progress_f, NULL), IGSC_ERROR_BAD_IMAGE);

}

static void igsc_device_oprom_update_buffer_len_zero(void **state)
{
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = IGSC_OPROM_CODE;
    struct igsc_oprom_image img = {
        .buffer_len = 0,
    };
    igsc_progress_func_t progress_f = NULL;

    assert_int_equal(igsc_device_oprom_update(handle, oprom_type, &img,  progress_f, NULL), IGSC_ERROR_BAD_IMAGE);
}

static void igsc_device_oprom_update_bad_type(void **state)
{
    struct igsc_device_handle *handle = *state;
    uint32_t oprom_type = 3; /* bad type */
    igsc_progress_func_t progress_f = NULL;
    unsigned char buf[1];
    struct igsc_oprom_image img = {
        .buffer = buf,
        .buffer_len = sizeof(buf),
    };

    assert_int_equal(igsc_device_oprom_update(handle, oprom_type, &img,  progress_f, NULL), IGSC_ERROR_INVALID_PARAMETER);
}

static void test_params_version_null(void **state)
{
    struct igsc_fw_version ver;

    memset(&ver, 0, sizeof(ver));

    assert_int_equal(igsc_fw_version_compare(NULL, NULL), IGSC_VERSION_ERROR);
    assert_int_equal(igsc_fw_version_compare(NULL, &ver), IGSC_VERSION_ERROR);
    assert_int_equal(igsc_fw_version_compare(&ver, NULL), IGSC_VERSION_ERROR);
}

static void test_params_version_non_compatible(void **state)
{
    struct igsc_fw_version img_ver;
    struct igsc_fw_version dev_ver;

    memset(&img_ver, 0, sizeof(img_ver));
    memset(&dev_ver, 0, sizeof(dev_ver));

    img_ver.project[0] = 20;
    dev_ver.project[0] = 19;
    assert_int_equal(igsc_fw_version_compare(&img_ver, &dev_ver),
                     IGSC_VERSION_NOT_COMPATIBLE);
}

static void test_params_version_compare_older(void **state)
{
    struct igsc_fw_version img_ver;
    struct igsc_fw_version dev_ver;

    memset(&img_ver, 0, sizeof(img_ver));
    memset(&dev_ver, 0, sizeof(dev_ver));

    img_ver.project[0] = 19;
    dev_ver.project[0] = 19;

    img_ver.hotfix = 1;
    dev_ver.hotfix = 2;
    assert_int_equal(igsc_fw_version_compare(&img_ver, &dev_ver), IGSC_VERSION_OLDER);
}

static void test_params_version_compare_older2(void **state)
{
    struct igsc_fw_version img_ver;
    struct igsc_fw_version dev_ver;

    memset(&img_ver, 0, sizeof(img_ver));
    memset(&dev_ver, 0, sizeof(dev_ver));

    img_ver.project[0] = 19;
    dev_ver.project[0] = 19;
    img_ver.hotfix = 2;
    dev_ver.hotfix = 2;
    img_ver.build = 10;
    dev_ver.build = 12;
    assert_int_equal(igsc_fw_version_compare(&img_ver, &dev_ver), IGSC_VERSION_OLDER);
}

static void test_params_version_compare_newer(void **state)
{
    struct igsc_fw_version img_ver;
    struct igsc_fw_version dev_ver;

    memset(&img_ver, 0, sizeof(img_ver));
    memset(&dev_ver, 0, sizeof(dev_ver));

    img_ver.project[0] = 19;
    dev_ver.project[0] = 19;
    img_ver.hotfix = 3;
    dev_ver.hotfix = 2;
    assert_int_equal(igsc_fw_version_compare(&img_ver, &dev_ver), IGSC_VERSION_NEWER);
}

static void test_params_version_compare_newer2(void **state)
{
    struct igsc_fw_version img_ver;
    struct igsc_fw_version dev_ver;

    memset(&img_ver, 0, sizeof(img_ver));
    memset(&dev_ver, 0, sizeof(dev_ver));

    img_ver.project[0] = 19;
    dev_ver.project[0] = 19;

    img_ver.hotfix = 2;
    dev_ver.hotfix = 2;
    img_ver.build = 12;
    dev_ver.build = 10;
    assert_int_equal(igsc_fw_version_compare(&img_ver, &dev_ver), IGSC_VERSION_NEWER);
}

static void test_params_version_compare_equal(void **state)
{
    struct igsc_fw_version img_ver;
    struct igsc_fw_version dev_ver;

    memset(&img_ver, 0, sizeof(img_ver));
    memset(&dev_ver, 0, sizeof(dev_ver));

    img_ver.project[0] = 19;
    dev_ver.project[0] = 19;


    img_ver.hotfix = 2;
    dev_ver.hotfix = 2;
    img_ver.build = 10;
    dev_ver.build = 10;
    assert_int_equal(igsc_fw_version_compare(&img_ver, &dev_ver), IGSC_VERSION_EQUAL);
}

static void igsc_device_update_device_info_bad_handle(void **state)
{
    struct igsc_device_info dev_info;

    assert_int_equal(igsc_device_update_device_info(NULL, &dev_info), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_update_device_info_bad_info(void **state)
{
    struct igsc_device_handle *handle = *state;

    assert_int_equal(igsc_device_update_device_info(handle, NULL), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_subsystem_ids_bad_handle(void **state)
{
    struct igsc_subsystem_ids ids;

    assert_int_equal(igsc_device_subsystem_ids(NULL, &ids), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_subsystem_ids_bad_ids(void **state)
{
    struct igsc_device_handle *handle = *state;

    assert_int_equal(igsc_device_subsystem_ids(handle, NULL), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_oem_version_bad_handle(void **state)
{
    struct igsc_oem_version version;

    assert_int_equal(igsc_device_oem_version(NULL, &version), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_oem_version_bad_version(void **state)
{
    struct igsc_device_handle *handle = *state;

    assert_int_equal(igsc_device_oem_version(handle, NULL), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_psc_version_bad_handle(void **state)
{
    struct igsc_psc_version version;

    assert_int_equal(igsc_device_psc_version(NULL, &version), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_psc_version_bad_version(void **state)
{
    struct igsc_device_handle *handle = *state;

    assert_int_equal(igsc_device_psc_version(handle, NULL), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_ifr_bin_version_bad_handle(void **state)
{
    struct igsc_ifr_bin_version version;

    assert_int_equal(igsc_device_ifr_bin_version(NULL, &version), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_device_ifr_bin_version_bad_version(void **state)
{
    struct igsc_device_handle *handle = *state;

    assert_int_equal(igsc_device_ifr_bin_version(handle, NULL), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_gfsp_get_health_indicator_bad_handle(void **state)
{
    uint8_t health_indicator;

    assert_int_equal(igsc_gfsp_get_health_indicator(NULL, &health_indicator), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_gfsp_get_health_indicator_bad_indicator(void **state)
{
    struct igsc_device_handle *handle = *state;

    assert_int_equal(igsc_gfsp_get_health_indicator(handle, NULL), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_gfsp_heci_cmd_bad_handle(void **state)
{
    uint8_t buffer;
    size_t actual_response_size;

    assert_int_equal(igsc_gfsp_heci_cmd(NULL, 0x30, &buffer, 1,
                                        &buffer, 1, &actual_response_size), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_gfsp_heci_cmd_bad_in_buf(void **state)
{
    struct igsc_device_handle *handle = *state;
    uint8_t buffer;
    size_t actual_response_size;

    assert_int_equal(igsc_gfsp_heci_cmd(handle, 0x31, NULL, 1,
                                        &buffer, 1, &actual_response_size), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_gfsp_heci_cmd_bad_out_buf(void **state)
{
    struct igsc_device_handle *handle = *state;
    uint8_t buffer;
    size_t actual_response_size;

    assert_int_equal(igsc_gfsp_heci_cmd(handle, 0x30, &buffer, 1,
                                        NULL, 1, &actual_response_size), IGSC_ERROR_INVALID_PARAMETER);
}

static void igsc_gfsp_heci_cmd_bad_actual_response_size(void **state)
{
    struct igsc_device_handle *handle = *state;
    uint8_t buffer;

    assert_int_equal(igsc_gfsp_heci_cmd(handle, 0x30, &buffer, 1,
                                        &buffer, 1, NULL), IGSC_ERROR_INVALID_PARAMETER);
}

int main(void)
{
    const struct CMUnitTest device_image_tests[] = {
        cmocka_unit_test(test_device_init_calloc_ok),
        cmocka_unit_test(test_device_init_calloc_fail_1),
        cmocka_unit_test(test_device_init_calloc_fail_2),
        cmocka_unit_test(test_device_init_null_1),
        cmocka_unit_test(test_device_init_null_2),
        cmocka_unit_test(test_device_close_null),
        cmocka_unit_test(test_device_init_by_handle_calloc_ok),
        cmocka_unit_test(test_device_init_by_handle_calloc_fail_1),
        cmocka_unit_test(test_device_init_by_handle_null),
        cmocka_unit_test(test_device_init_by_handle_invalid),
        cmocka_unit_test(igsc_device_init_by_device_info_null_1),
        cmocka_unit_test(igsc_device_init_by_device_info_null_2),
        cmocka_unit_test(igsc_device_get_device_info_null_1),
        cmocka_unit_test(igsc_device_get_device_info_null_2),
        cmocka_unit_test(igsc_device_get_device_info_null_3),
        cmocka_unit_test(igsc_device_fw_update_null_inputs),
        cmocka_unit_test(igsc_device_fw_update_buffer_len_zero),
        cmocka_unit_test(igsc_hwconfig_null_inputs),
        cmocka_unit_test(test_image_oprom_init_calloc_fail),
        cmocka_unit_test(igsc_device_oprom_update_bad_type),
        cmocka_unit_test(igsc_device_update_device_info_bad_handle),
        cmocka_unit_test(igsc_device_update_device_info_bad_info),
        cmocka_unit_test(igsc_device_subsystem_ids_bad_handle),
        cmocka_unit_test(igsc_device_subsystem_ids_bad_ids),
    };

    const struct CMUnitTest version_cmp_tests[] = {
        cmocka_unit_test(test_params_version_null),
        cmocka_unit_test(test_params_version_non_compatible),
        cmocka_unit_test(test_params_version_compare_older),
        cmocka_unit_test(test_params_version_compare_older2),
        cmocka_unit_test(test_params_version_compare_newer),
        cmocka_unit_test(test_params_version_compare_newer2),
        cmocka_unit_test(test_params_version_compare_equal),
    };

    const struct CMUnitTest get_type_tests[] = {
        cmocka_unit_test(test_get_type_null_1),
        cmocka_unit_test(test_get_type_null_2),
        cmocka_unit_test(test_get_type_null_3),
    };

    const struct CMUnitTest get_version_tests[] = {
        cmocka_unit_test(igsc_device_oem_version_bad_handle),
        cmocka_unit_test(igsc_device_oem_version_bad_version),
        cmocka_unit_test(igsc_device_psc_version_bad_handle),
        cmocka_unit_test(igsc_device_psc_version_bad_version),
        cmocka_unit_test(igsc_device_ifr_bin_version_bad_handle),
        cmocka_unit_test(igsc_device_ifr_bin_version_bad_version),
    };

    const struct CMUnitTest gfsp_get_health_indicator_tests[] = {
        cmocka_unit_test(igsc_gfsp_get_health_indicator_bad_handle),
        cmocka_unit_test(igsc_gfsp_get_health_indicator_bad_indicator),
    };

    const struct CMUnitTest gfsp_heci_cmd_tests[] = {
        cmocka_unit_test(igsc_gfsp_heci_cmd_bad_handle),
        cmocka_unit_test(igsc_gfsp_heci_cmd_bad_in_buf),
        cmocka_unit_test(igsc_gfsp_heci_cmd_bad_out_buf),
        cmocka_unit_test(igsc_gfsp_heci_cmd_bad_actual_response_size),
    };

    int status = cmocka_run_group_tests(device_image_tests, group_setup, NULL);
    status += cmocka_run_group_tests(version_cmp_tests, group_setup, NULL);
    status += cmocka_run_group_tests(get_type_tests, group_setup, NULL);
    status += cmocka_run_group_tests(get_version_tests, group_setup, NULL);
    status += cmocka_run_group_tests(gfsp_get_health_indicator_tests, group_setup, NULL);

    return status;
}
