#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>

#include "igsc_lib.h"

int __real_image_oprom_parse(struct igsc_oprom_image *img);

int __wrap_image_oprom_parse(struct igsc_oprom_image *img)
{
    return IGSC_SUCCESS;
}

enum igsc_oprom_type __real_image_oprom_get_type(struct igsc_oprom_image *img);
enum igsc_oprom_type __wrap_image_oprom_get_type(struct igsc_oprom_image *img)
{
    return mock_type(enum igsc_oprom_type);
}

uint8_t buf[1024];

static int group_setup(void **state)
{
    struct igsc_oprom_image *img = NULL;
    int ret;

    ret = igsc_image_oprom_init(&img, buf, sizeof(buf));
    if (ret != IGSC_SUCCESS)
    {
        return -1;
    }

    *state = img;

    return 0;
}

static int group_teardown(void **state)
{
    struct igsc_oprom_image *img = *state;

    igsc_image_oprom_release(img);

    return 0;
}

static void test_params_image_oprom_init(void **state)
{
    struct igsc_oprom_image *img = *state;

    assert_int_equal(igsc_image_oprom_init(NULL, NULL, 0), IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_image_oprom_init(&img, buf , 0), IGSC_ERROR_INVALID_PARAMETER);
}

static void test_params_image_oprom_version(void **state)
{
    struct igsc_oprom_image *img = *state;

    assert_int_equal(igsc_image_oprom_version(NULL, 0, NULL), IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_image_oprom_version(img, 0, NULL), IGSC_ERROR_INVALID_PARAMETER);
}

static void test_params_image_oprom_type(void **state)
{
    struct igsc_oprom_image *img = *state;

    assert_int_equal(igsc_image_oprom_type(NULL, NULL), IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_image_oprom_version(img, 0, NULL), IGSC_ERROR_INVALID_PARAMETER);
}

static void test_params_image_oprom_count_devices(void **state)
{
    struct igsc_oprom_image *img = *state;

    assert_int_equal(igsc_image_oprom_count_devices(NULL, NULL), IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_image_oprom_count_devices(img, NULL), IGSC_ERROR_INVALID_PARAMETER);
}

static void test_params_image_oprom_supported_devices(void **state)
{
    struct igsc_oprom_image *img = *state;
    struct igsc_oprom_device_info devices[1];
    uint32_t count = 1;

    assert_int_equal(igsc_image_oprom_supported_devices(NULL, NULL, NULL), IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_image_oprom_supported_devices(img, NULL, NULL), IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_image_oprom_supported_devices(img, devices, NULL), IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_image_oprom_supported_devices(img, NULL, &count), IGSC_ERROR_INVALID_PARAMETER);
}

static void test_params_image_oprom_match_device(void **state)
{
    struct igsc_oprom_image *img = *state;

    assert_int_equal(igsc_image_oprom_match_device(NULL, IGSC_OPROM_NONE, NULL), IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_image_oprom_match_device(img, IGSC_OPROM_NONE, NULL), IGSC_ERROR_INVALID_PARAMETER);
}

static void test_params_image_oprom_iterator_reset(void **state)
{
    struct igsc_oprom_image *img = *state;

    assert_int_equal(igsc_image_oprom_iterator_reset(NULL), IGSC_ERROR_INVALID_PARAMETER);

    will_return(__wrap_image_oprom_get_type, IGSC_OPROM_NONE);
    assert_int_equal(igsc_image_oprom_iterator_reset(img), IGSC_ERROR_NOT_SUPPORTED);

    will_return(__wrap_image_oprom_get_type, IGSC_OPROM_CODE);
    assert_int_equal(igsc_image_oprom_iterator_reset(img), IGSC_ERROR_NOT_SUPPORTED);

    will_return(__wrap_image_oprom_get_type, IGSC_OPROM_DATA);
    assert_int_equal(igsc_image_oprom_iterator_reset(img), IGSC_SUCCESS);

}

static void test_params_image_oprom_iterator_next(void **state)
{
    struct igsc_oprom_image *img = *state;

    assert_int_equal(igsc_image_oprom_iterator_next(NULL, NULL), IGSC_ERROR_INVALID_PARAMETER);
    assert_int_equal(igsc_image_oprom_iterator_next(img, NULL), IGSC_ERROR_INVALID_PARAMETER);
}

static void test_params_image_oprom_release(void **state)
{
    struct igsc_oprom_image *img = *state;

    assert_int_equal(igsc_image_oprom_release(NULL), IGSC_SUCCESS);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_params_image_oprom_init),
        cmocka_unit_test(test_params_image_oprom_version),
        cmocka_unit_test(test_params_image_oprom_type),
        cmocka_unit_test(test_params_image_oprom_count_devices),
        cmocka_unit_test(test_params_image_oprom_supported_devices),
        cmocka_unit_test(test_params_image_oprom_match_device),
        cmocka_unit_test(test_params_image_oprom_iterator_reset),
        cmocka_unit_test(test_params_image_oprom_iterator_next),
        cmocka_unit_test(test_params_image_oprom_release)
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
