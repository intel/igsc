#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

char *test_strdup(const char *s)
{
    size_t len = strlen(s);
    char *d = calloc(1, len + 1);
    if (d == NULL)
    {
        return NULL;
    }
    memcpy(d, s, len + 1);
    return d;
}

#include "igsc_lib.h"
#include "dev_info_mock.c"

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
    struct igsc_device_handle handle;
    int ret;

    will_return(__wrap__test_calloc, 0);
    will_return(__wrap__test_calloc, 0);

    ret = igsc_device_init_by_device(&handle, " ");

    assert_int_not_equal(ret, IGSC_ERROR_NOMEM);
    igsc_device_close(&handle);
}

/**
 * @brief A test to check if calloc() in igsc_device_init_by_device()
 *        returned NULL.
 *
 * @param state unit testing state
 */
static void test_device_init_calloc_fail_1(void **state)
{
    struct igsc_device_handle handle;
    int ret;

    will_return(__wrap__test_calloc, 1);

    ret = igsc_device_init_by_device(&handle, "");

    assert_int_equal(ret, IGSC_ERROR_NOMEM);
    igsc_device_close(&handle);
}

/**
 * @brief A test to check if calloc() in igsc_device_init_by_device()
 *        returned NULL.
 *
 * @param state unit testing state
 */
static void test_device_init_calloc_fail_2(void **state)
{
    struct igsc_device_handle handle;
    int ret;

    will_return(__wrap__test_calloc, 0);
    will_return(__wrap__test_calloc, 1); /* strdup */

    ret = igsc_device_init_by_device(&handle, " ");

    assert_int_equal(ret, IGSC_ERROR_NOMEM);

    igsc_device_close(&handle);
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

    struct igsc_device_handle handle;
    int ret;

    ret = igsc_device_init_by_device(&handle, NULL);

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
    struct igsc_device_handle handle;
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
    struct igsc_device_handle handle;
    int ret;

    will_return(__wrap__test_calloc, 0);

    ret = igsc_device_init_by_handle(&handle, (igsc_handle_t)1);

    assert_int_not_equal(ret, IGSC_ERROR_NOMEM);

    igsc_device_close(&handle);
}

/**
 * @brief A test to check if calloc() in igsc_device_init_by_handle() returned NULL
 *
 * @param state unit testing state
 */
static void test_device_init_by_handle_calloc_fail_1(void **state)
{
    struct igsc_device_handle handle;
    int ret;

    will_return(__wrap__test_calloc, 1);

    ret = igsc_device_init_by_handle(&handle, (igsc_handle_t)1);

    assert_int_equal(ret, IGSC_ERROR_NOMEM);

    igsc_device_close(&handle);
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

    struct igsc_device_handle handle;
    int ret;

    ret = igsc_device_init_by_handle(&handle, IGSC_INVALID_DEVICE_HANDLE);

    assert_int_equal(ret, IGSC_ERROR_INVALID_PARAMETER);

    igsc_device_close(NULL);
}


static void test_image_oprom_init_calloc_fail(void **status)
{
    struct igsc_oprom_image *img = NULL;
    const char buf[100];

    will_return(__wrap__test_calloc, 1);

    assert_int_equal(igsc_image_oprom_init(&img, buf, 100), IGSC_ERROR_NOMEM);
    igsc_image_oprom_release(img);


    will_return(__wrap__test_calloc, 0);
    will_return(__wrap__test_calloc, 1);

    assert_int_equal(igsc_image_oprom_init(&img, buf, 100), IGSC_ERROR_NOMEM);
    igsc_image_oprom_release(img);
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
        cmocka_unit_test(test_image_oprom_init_calloc_fail),
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

    int status = cmocka_run_group_tests(device_image_tests, NULL, NULL);
    status += cmocka_run_group_tests(version_cmp_tests, NULL, NULL);

    return status;
}
