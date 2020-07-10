#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>

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
 * @brief A test to check if calloc() in igsc_device_init() returned NULL
 *
 * @param state unit testing state
 */
static void test_device_init_calloc_ok(void **state)
{
    struct igsc_device_handle handle;
    int ret;

    will_return(__wrap__test_calloc, 0);
    will_return(__wrap__test_calloc, 0);

    assert_int_not_equal(igsc_device_init_by_device(&handle, " "), IGSC_ERROR_NOMEM);
    igsc_device_close(&handle);
}

/**
 * @brief A test to check if calloc() in igsc_device_init() returned NULL
 *
 * @param state unit testing state
 */
static void test_device_init_calloc_fail_1(void **state)
{
    struct igsc_device_handle handle;

    will_return(__wrap__test_calloc, 1);

    assert_int_equal(igsc_device_init_by_device(&handle, ""), IGSC_ERROR_NOMEM);
    igsc_device_close(&handle);
}

/**
 * @brief A test to check if calloc() in igsc_device_init() returned NULL
 *
 * @param state unit testing state
 */
static void test_device_init_calloc_fail_2(void **state)
{
    struct igsc_device_handle handle;
    int ret;

    will_return(__wrap__test_calloc, 0);
    will_return(__wrap__test_calloc, 1); /* strdup */

    assert_int_equal(igsc_device_init_by_device(&handle, " "), IGSC_ERROR_NOMEM);
    igsc_device_close(&handle);
}

/**
 * @brief A test to check if igsc_device_init return error when NULL handle is send
 *
 * @param state unit testing state
 */
static void test_device_init_null_1(void **state)
{
    assert_int_equal(igsc_device_init_by_device(NULL, " "), IGSC_ERROR_INVALID_PARAMETER);
    igsc_device_close(NULL);
}

/**
 * @brief A test to check if igsc_device_init return error when NULL handle is send
 *
 * @param state unit testing state
 */
static void test_device_init_null_2(void **state)
{

    struct igsc_device_handle handle;

    assert_int_equal(igsc_device_init_by_device(&handle, NULL), IGSC_ERROR_INVALID_PARAMETER);
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

    assert_int_equal(igsc_device_close(NULL), IGSC_ERROR_INVALID_PARAMETER);
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

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_device_init_calloc_ok),
        cmocka_unit_test(test_device_init_calloc_fail_1),
        cmocka_unit_test(test_device_init_calloc_fail_2),
        cmocka_unit_test(test_device_init_null_1),
        cmocka_unit_test(test_device_init_null_2),
        cmocka_unit_test(test_device_close_null),
        cmocka_unit_test(test_image_oprom_init_calloc_fail),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
