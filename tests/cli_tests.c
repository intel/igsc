#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <cmocka.h>

#include "test_strdup.h"

#include "igsc_lib.h"
#include "dev_info_mock.c"
#include "../src/igsc_cli.c"

static void test_arg_free(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++)
    {
        free(argv[i]);
    }
}

static int group_setup(void **state)
{
    char **argv;

    argv = calloc(10, sizeof (char *));
    if (argv == NULL)
    {
        return -1;
    }

    argv[0] = test_strdup("igsc");

    *state = argv;

    return 0;
}

static int group_teardown(void **state)
{
    char **argv = *state;
    free(argv[0]);
    free(argv);
    *state = NULL;
    return 0;
}

/**
 * test case: ./igsc
 */
static void test_empty(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_FAILURE);
}

/**
 * test case: ./igsc -q
 */
static void test_quite(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("-q");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_FAILURE);
}

/**
 * test case: ./igsc -v
 */
static void test_verbose(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("-v");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_FAILURE);
}


/**
 * test case: igsc -h
 */
static void test_help_short(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("-h");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test case: igsc --help
 */
static void test_help_long(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("--help");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test case: igsc help
 */
static void test_help(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("help");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test case: igsc -h fw
 */
static void test_fw_help(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("-h");
    argv[argc++] = test_strdup("fw");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test case: igsc oprom-code -h
 */
static void test_oprom_code_help(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("--help");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc image-type --image <file-path>
 */
static void test_image_type_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("image-type");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("fw.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc image-type
 */
static void test_image_type_bad_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("image-type");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc image-type --image
 */
static void test_image_type_bad_2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("image-type");
    argv[argc++] = test_strdup("--image");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc image-type --image <image> <extra parameter>
 * extra parameter
 */
static void test_image_type_bad_3(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("image-type");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc image-type --device <image>
 */
static void test_image_type_bad_4(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("image-type");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc fw update --image <image> --device <device>
 */
static void test_fw_update_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("fw.img");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc fw update -d <device> --image <image>
 */
static void test_fw_update_2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("-d");
    argv[argc++] = test_strdup("/dev/mei0");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("fw.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc fw update --image <image>
 */
static void test_fw_update_3(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("fw.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc fw update
 */
static void test_fw_update_bad_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("update");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc fw update --image
 */
static void test_fw_update_bad_2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--image");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc fw update fw.img
 */
static void test_fw_update_bad_3(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("fw.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc fw update --image fw.img --device
 */
static void test_fw_update_bad_4(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("fw.img");
    argv[argc++] = test_strdup("--device");
    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc fw update --image fw.img -d
 */
static void test_fw_update_bad_5(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("fw.img");
    argv[argc++] = test_strdup("-d");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc fw hwconfig
 */
static void test_fw_hwconfig_bad_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("hwconfig");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc fw hwconfig --image
 */
static void test_fw_hwconfig_bad_2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("hwconfig");
    argv[argc++] = test_strdup("--image");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc fw hwconfig fw.img
 */
static void test_fw_hwconfig_bad_3(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("hwconfig");
    argv[argc++] = test_strdup("fw.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc fw hwconfig --image fw.img --device
 */
static void test_fw_hwconfig_bad_4(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("hwconfig");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("fw.img");
    argv[argc++] = test_strdup("--device");
    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc fw hwconfig --image fw.img -d
 */
static void test_fw_hwconfig_bad_5(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("hwconfig");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("fw.img");
    argv[argc++] = test_strdup("-d");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}


/**
 * test: igsc fw version --image fw.img
 */
static void test_fw_version_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("fw.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc fw version --device /dev/mei0
 */
static void test_fw_version_2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc fw version fw.img
 */
static void test_fw_version_bad_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("fw.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc fw version --device
 */
static void test_fw_version_bad_2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--device");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc oprom-data update --image oprom.img
 */
static void test_oprom_data_update_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-data update --device /dev/mei0 --image oprom.img
 */
static void test_oprom_data_update_2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-data update --allow-downgrade --device /dev/mei0 --image oprom.img
 */
static void test_oprom_data_update_3(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--allow-downgrade");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-data update -i oprom.img -d /dev/mei0
 */
static void test_oprom_data_update_4(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("-i");
    argv[argc++] = test_strdup("oprom.img");
    argv[argc++] = test_strdup("-d");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-data update
 */
static void test_oprom_data_update_bad_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("update");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc oprom-data update --device /dev/mei0
 */
static void test_oprom_data_update_bad_2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc oprom-data version --device /dev/mei0
 */
static void test_oprom_data_version_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-data version --image oprom.img
 */
static void test_oprom_data_version_2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-data version
 */
static void test_oprom_data_version_3(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("version");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-data version --image
 */
static void test_oprom_data_version_bad_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--image");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc oprom-data version --device
 */
static void test_oprom_data_version_bad_2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--device");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc oprom-data update oprom.img
 */
static void test_oprom_data_version_bad_3(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc oprom-data supported-devices --image img
 */
static void test_oprom_data_supported_devices_good1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("supported-devices");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-data supported-devices -i img
 */
static void test_oprom_data_supported_devices_good2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("supported-devices");
    argv[argc++] = test_strdup("-i");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-code supported-devices --image img
 */
static void test_oprom_code_supported_devices_good1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("supported-devices");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-code supported-devices -i img
 */
static void test_oprom_code_supported_devices_good2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("supported-devices");
    argv[argc++] = test_strdup("-i");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}


/**
 * test: igsc oprom-data supported-devices
 */
static void test_oprom_data_supported_devices_bad1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("supported-devices");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc oprom-code supported-devices
 */
static void test_oprom_code_supported_devices_bad1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("supported-devices");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}


/**
 * test: igsc oprom-code update --image oprom.img
 */
static void test_oprom_code_update_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-code update --device /dev/mei --image oprom.img
 */
static void test_oprom_code_update_2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-code update --allow-downgrade --device /dev/mei --image oprom.img
 */
static void test_oprom_code_update_3(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--allow-downgrade");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-code update -i oprom.img -d /dev/mei
 */
static void test_oprom_code_update_4(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("-i");
    argv[argc++] = test_strdup("oprom.img");
    argv[argc++] = test_strdup("-d");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-code update
 */
static void test_oprom_code_update_bad_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("update");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc oprom-code update --device /dev/mei
 */
static void test_oprom_code_update_bad_2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc oprom-code version --device /dev/mei0
 */
static void test_oprom_code_version_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-code version --image oprom.img
 */
static void test_oprom_code_version_2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-code version
 */
static void test_oprom_code_version_3(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("version");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc oprom-code version --image
 */
static void test_oprom_code_version_bad_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--image");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc oprom-code version --device
 */
static void test_oprom_code_version_bad_2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--device");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc oprom-code update oprom.img
 */
static void test_oprom_code_version_bad_3(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("oprom.img");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: progress_bar
 */
static void test_progress_bar(void **state)
{
    (void)state;
    uint32_t done = 0;
    uint32_t total = 100;

    for (done = 0; done <= total; done++)
    {
        progress_bar_func(done, total, NULL);
    }
    printf("\n");
}

static void test_progress_bar_2(void **state)
{
    (void)state;
    uint32_t done = 0;
    uint32_t total = 90;

    for (done = 0; done <= total; done += 2)
    {
        progress_bar_func(done, total, NULL);
    }
    printf("\n");
}

static void test_progress_percent(void **state)
{
    (void)state;
    uint32_t done = 0;
    uint32_t total = 100;

    for (done = 0; done <= total; done++)
    {
        progress_percentage_func(done, total, NULL);
    }
    printf("\n");
}

static void test_progress_percent_2(void **state)
{
    (void)state;
    uint32_t done = 0;
    uint32_t total = 90;

    for (done = 0; done <= total; done += 2)
    {
        progress_percentage_func(done, total, NULL);
    }
    printf("\n");
}


/**
 * igsc fw version --image <image>
 * igsc fw update --image <image>
 */

#undef main
int main(void)
{
    int status = 0;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_empty),
        cmocka_unit_test(test_quite),
        cmocka_unit_test(test_verbose),
        cmocka_unit_test(test_help_short),
        cmocka_unit_test(test_help_long),
        cmocka_unit_test(test_help),
        cmocka_unit_test(test_fw_help),
        cmocka_unit_test(test_oprom_code_help),
        cmocka_unit_test(test_image_type_bad_1),
        cmocka_unit_test(test_image_type_bad_2),
        cmocka_unit_test(test_image_type_bad_3),
        cmocka_unit_test(test_image_type_bad_4),
        cmocka_unit_test(test_image_type_1),
        cmocka_unit_test(test_fw_update_1),
        cmocka_unit_test(test_fw_update_2),
        cmocka_unit_test(test_fw_update_3),
        cmocka_unit_test(test_fw_update_bad_1),
        cmocka_unit_test(test_fw_update_bad_2),
        cmocka_unit_test(test_fw_update_bad_3),
        cmocka_unit_test(test_fw_update_bad_4),
        cmocka_unit_test(test_fw_update_bad_5),
        cmocka_unit_test(test_fw_hwconfig_bad_1),
        cmocka_unit_test(test_fw_hwconfig_bad_2),
        cmocka_unit_test(test_fw_hwconfig_bad_3),
        cmocka_unit_test(test_fw_hwconfig_bad_4),
        cmocka_unit_test(test_fw_hwconfig_bad_5),
        cmocka_unit_test(test_fw_version_1),
        cmocka_unit_test(test_fw_version_2),
        cmocka_unit_test(test_fw_version_bad_1),
        cmocka_unit_test(test_fw_version_bad_2),
        cmocka_unit_test(test_oprom_data_update_1),
        cmocka_unit_test(test_oprom_data_update_2),
        cmocka_unit_test(test_oprom_data_update_3),
        cmocka_unit_test(test_oprom_data_update_4),
        cmocka_unit_test(test_oprom_data_update_bad_1),
        cmocka_unit_test(test_oprom_data_update_bad_2),
        cmocka_unit_test(test_oprom_data_version_1),
        cmocka_unit_test(test_oprom_data_version_2),
        cmocka_unit_test(test_oprom_data_version_3),
        cmocka_unit_test(test_oprom_data_version_bad_1),
        cmocka_unit_test(test_oprom_data_version_bad_2),
        cmocka_unit_test(test_oprom_data_version_bad_3),
        cmocka_unit_test(test_oprom_data_supported_devices_good1),
        cmocka_unit_test(test_oprom_data_supported_devices_good2),
        cmocka_unit_test(test_oprom_data_supported_devices_bad1),
        cmocka_unit_test(test_oprom_code_supported_devices_good1),
        cmocka_unit_test(test_oprom_code_supported_devices_good2),
        cmocka_unit_test(test_oprom_code_supported_devices_bad1),
        cmocka_unit_test(test_oprom_code_update_1),
        cmocka_unit_test(test_oprom_code_update_2),
        cmocka_unit_test(test_oprom_code_update_3),
        cmocka_unit_test(test_oprom_code_update_4),
        cmocka_unit_test(test_oprom_code_update_bad_1),
        cmocka_unit_test(test_oprom_code_update_bad_2),
        cmocka_unit_test(test_oprom_code_version_1),
        cmocka_unit_test(test_oprom_code_version_2),
        cmocka_unit_test(test_oprom_code_version_3),
        cmocka_unit_test(test_oprom_code_version_bad_1),
        cmocka_unit_test(test_oprom_code_version_bad_2),
        cmocka_unit_test(test_oprom_code_version_bad_3),
    };

    const struct CMUnitTest progress_bar_tests[] = {
        cmocka_unit_test(test_progress_bar),
        cmocka_unit_test(test_progress_bar_2),
        cmocka_unit_test(test_progress_percent),
        cmocka_unit_test(test_progress_percent_2),
    };

    status += cmocka_run_group_tests(progress_bar_tests, NULL, NULL);
    status += cmocka_run_group_tests(tests, group_setup, group_teardown);

    return status;
}
