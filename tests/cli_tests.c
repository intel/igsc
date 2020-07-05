#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <cmocka.h>

#include "igsc_lib.h"

typedef int (*gsc_op)(int argc, char *argv[]);

struct gsc_op {
    const char *name;
    gsc_op    op;
    const char  *usage; /* usage title */
    const char  *help;  /* help */
};

int mock_args_parse(const char *exe_name, int *argc, char **argv[],
                      const struct gsc_op **op, bool *display_help);

int mock_firmware_update(const char *device_path,
                           const char *image_path,
                           bool allow_downgrade);

int mock_firmware_version(const char *device_path);

int mock_image_version(const char *device_path);

int mock_oprom_device_version(const char *device_path,
                              enum igsc_oprom_type igsc_oprom_type);

int mock_oprom_update(const char *image_path, const char *device_path,
                      char *device_path_found, enum igsc_oprom_type type);

int mock_oprom_image_version(const char *image_path,
                             enum igsc_oprom_type igsc_oprom_type);

int firmware_update(const char *device_path,
                           const char *image_path,
                           bool allow_downgrade)
{
    return mock_firmware_update(device_path, image_path, allow_downgrade);
}

int firmware_version(const char *device_path)
{
    return mock_firmware_version(device_path);
}

int image_version(const char *device_path)
{
    return mock_image_version(device_path);
}

int oprom_device_version(const char *device_path,
                         enum igsc_oprom_type igsc_oprom_type)
{
    return mock_oprom_device_version(device_path, igsc_oprom_type);
}

int oprom_update(const char *image_path, const char *device_path,
                 char *device_path_found, enum igsc_oprom_type type)
{
    return mock_oprom_update(image_path, device_path, device_path_found, type);
}

int oprom_image_version(const char *image_path, enum igsc_oprom_type igsc_oprom_type)
{
    return mock_oprom_image_version(image_path, igsc_oprom_type);
}

static char *test_strdup(const char *str)
{
    char *new_str = malloc(strlen(str) + 1);
    if (new_str)
    {
        strcpy(new_str, str);
    }

    return new_str;
}

static void test_arg_free(int argc, char *argv[])
{
    for (int i = 0; i < argc; i++)
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

    *state = argv;

    return 0;
}

static int group_teardown(void **state)
{
    free(*state);
    return 0;
}

static int __main(int argc, char *argv[])
{
    const char *exec_name = "igsc";
    const struct gsc_op *op = NULL;
    bool display_help = false;
    int ret;

    ret = mock_args_parse(exec_name, &argc, &argv, &op, &display_help);
    if (ret)
    {
        return EXIT_FAILURE;
    }

    if (display_help)
    {
        return EXIT_SUCCESS;
    }

    if (op == NULL)
    {
         return EXIT_FAILURE;
    }

    return op->op(argc, argv);
}

/**
 * test case: ./igsc
 */
static void test_help_error(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 0;

    ret = __main(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test case: igsc -h
 */
static void test_help_short(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 0;

    argv[argc++] = test_strdup("-h");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("--help");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("help");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("-h");
    argv[argc++] = test_strdup("fw");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("--help");

    ret = __main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc fw update --image <image> --device <device>
 */
static void test_fw_update_1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 0;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("fw.img");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("-d");
    argv[argc++] = test_strdup("/dev/mei0");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("fw.img");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("fw.img");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("update");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--image");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("fw.img");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("fw.img");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("fw.img");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("fw");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--device");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--allow-downgrade");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("-i");
    argv[argc++] = test_strdup("oprom.img");
    argv[argc++] = test_strdup("-d");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("update");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("version");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--image");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--device");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-data");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("oprom.img");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--allow-downgrade");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("-i");
    argv[argc++] = test_strdup("oprom.img");
    argv[argc++] = test_strdup("-d");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("update");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("update");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--image");
    argv[argc++] = test_strdup("oprom.img");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("version");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--image");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("--device");

    ret = __main(argc, argv);

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
    int argc = 0;

    argv[argc++] = test_strdup("oprom-code");
    argv[argc++] = test_strdup("version");
    argv[argc++] = test_strdup("oprom.img");

    ret = __main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}


/**
 * igsc fw version --image <image>
 * igsc fw update --image <image>
 */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_help_error),
        cmocka_unit_test(test_help_short),
        cmocka_unit_test(test_help_long),
        cmocka_unit_test(test_help),
        cmocka_unit_test(test_fw_help),
        cmocka_unit_test(test_oprom_code_help),
        cmocka_unit_test(test_fw_update_1),
        cmocka_unit_test(test_fw_update_2),
        cmocka_unit_test(test_fw_update_3),
        cmocka_unit_test(test_fw_update_bad_1),
        cmocka_unit_test(test_fw_update_bad_2),
        cmocka_unit_test(test_fw_update_bad_3),
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

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
