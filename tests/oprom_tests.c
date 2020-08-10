#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#pragma pack(1)
struct compare_version {
        uint16_t  major;
        uint16_t  minor;
        uint16_t  hotfix;
        uint16_t  build;
};
#pragma pack()

static void test_params_version_null(void **state)
{
    struct igsc_oprom_version ver;
    memset(&ver, 0, sizeof(ver));

    assert_int_equal(igsc_oprom_version_compare(NULL, NULL), IGSC_VERSION_ERROR);
    assert_int_equal(igsc_oprom_version_compare(NULL, &ver), IGSC_VERSION_ERROR);
    assert_int_equal(igsc_oprom_version_compare(&ver, NULL), IGSC_VERSION_ERROR);
}

static void test_params_version_non_compatible(void **state)
{
    struct compare_version img_ver;
    struct compare_version dev_ver;

    memset(&img_ver, 0, sizeof(img_ver));
    memset(&dev_ver, 0, sizeof(dev_ver));

    img_ver.major = 20;
    dev_ver.major = 19;
    assert_int_equal(igsc_oprom_version_compare((const struct igsc_oprom_version *)&img_ver,
                                                (const struct igsc_oprom_version *)&dev_ver),
                     IGSC_VERSION_NOT_COMPATIBLE);
}

static void test_params_version_older(void **state)
{
    struct compare_version img_ver;
    struct compare_version dev_ver;

    memset(&img_ver, 0, sizeof(img_ver));
    memset(&dev_ver, 0, sizeof(dev_ver));

    img_ver.major = 19;
    dev_ver.major = 19;

    img_ver.minor = 1;
    dev_ver.minor = 2;
    assert_int_equal(igsc_oprom_version_compare((const struct igsc_oprom_version *)&img_ver,
                                                (const struct igsc_oprom_version *)&dev_ver),
                     IGSC_VERSION_OLDER);
}

static void test_params_version_newer_minor(void **state)
{
    struct compare_version img_ver;
    struct compare_version dev_ver;

    memset(&img_ver, 0, sizeof(img_ver));
    memset(&dev_ver, 0, sizeof(dev_ver));

    img_ver.major = 19;
    dev_ver.major = 19;

    img_ver.minor = 3;
    dev_ver.minor = 2;
    assert_int_equal(igsc_oprom_version_compare((const struct igsc_oprom_version *)&img_ver,
                                                (const struct igsc_oprom_version *)&dev_ver),
                     IGSC_VERSION_NEWER);
}

static void test_params_version_newer_build1(void **state)
{
    struct compare_version img_ver;
    struct compare_version dev_ver;

    memset(&img_ver, 0, sizeof(img_ver));
    memset(&dev_ver, 0, sizeof(dev_ver));

    img_ver.major = 19;
    dev_ver.major = 19;

    img_ver.minor = 2;
    dev_ver.minor = 2;
    img_ver.build = 100;
    dev_ver.build = 10;
    assert_int_equal(igsc_oprom_version_compare((const struct igsc_oprom_version *)&img_ver,
                                                (const struct igsc_oprom_version *)&dev_ver),
                     IGSC_VERSION_NEWER);
}

static void test_params_version_newer_build2(void **state)
{
    struct compare_version img_ver;
    struct compare_version dev_ver;

    memset(&img_ver, 0, sizeof(img_ver));
    memset(&dev_ver, 0, sizeof(dev_ver));

    img_ver.major = 19;
    dev_ver.major = 19;

    img_ver.minor = 2;
    dev_ver.minor = 2;
    img_ver.build = 10;
    dev_ver.build = 100;
    assert_int_equal(igsc_oprom_version_compare((const struct igsc_oprom_version *)&img_ver,
                                                (const struct igsc_oprom_version *)&dev_ver),
                     IGSC_VERSION_NEWER);
}

static void test_params_version_newer_equal(void **state)
{
    struct compare_version img_ver;
    struct compare_version dev_ver;

    memset(&img_ver, 0, sizeof(img_ver));
    memset(&dev_ver, 0, sizeof(dev_ver));

    img_ver.major = 19;
    dev_ver.major = 19;

    img_ver.minor = 2;
    dev_ver.minor = 2;
    img_ver.build = 10;
    dev_ver.build = 10;
    assert_int_equal(igsc_oprom_version_compare((const struct igsc_oprom_version *)&img_ver,
                                                (const struct igsc_oprom_version *)&dev_ver),
                     IGSC_VERSION_EQUAL);
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

    const struct CMUnitTest version_cmp_tests[] = {
        cmocka_unit_test(test_params_version_null),
        cmocka_unit_test(test_params_version_non_compatible),
        cmocka_unit_test(test_params_version_older),
        cmocka_unit_test(test_params_version_newer_minor),
        cmocka_unit_test(test_params_version_newer_build1),
        cmocka_unit_test(test_params_version_newer_build2),
        cmocka_unit_test(test_params_version_newer_equal),
    };

    int status = cmocka_run_group_tests(tests, group_setup, group_teardown);
    status += cmocka_run_group_tests(version_cmp_tests, NULL, NULL);

    return status;
}
